"""The real Store, backed by Redis."""

from __future__ import annotations

import redis


class RedisStore:
    """Talks to Redis. Same eight methods as MemoryStore."""

    def __init__(self, url: str, max_len: int = 100_000) -> None:
        # decode_responses=True makes Redis hand back str instead of bytes.
        self._client = redis.Redis.from_url(url, decode_responses=True)
        self._max_len = max_len
        self._client.ping()

    # --- stream side ---

    def ensure_group(self, stream: str, group: str) -> None:
        try:
            # id="0" so a group created after events exist still sees them.
            self._client.xgroup_create(stream, group, id="0", mkstream=True)
        except redis.ResponseError as err:
            # BUSYGROUP just means it already exists, which is the normal case.
            if "BUSYGROUP" not in str(err):
                raise

    def append(self, stream: str, fields: dict[str, str]) -> str:
        return self._client.xadd(
            stream, fields, maxlen=self._max_len, approximate=True
        )

    def trim(self, stream: str, maxlen: int) -> int:
        return int(self._client.xtrim(stream, maxlen=maxlen, approximate=False))

    def read_group(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int,
        block_ms: int = 0,
    ) -> list[tuple[str, dict[str, str]]]:
        # ">" means "entries never delivered to this group".
        response = self._client.xreadgroup(
            group,
            consumer,
            {stream: ">"},
            count=count,
            block=block_ms or None,
        )
        return _flatten(response)

    def read_pending(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int,
    ) -> list[tuple[str, dict[str, str]]]:
        # "0" means "entries already delivered to me but not yet acked".
        response = self._client.xreadgroup(
            group, consumer, {stream: "0"}, count=count
        )
        return _flatten(response)

    def ack(self, stream: str, group: str, *ids: str) -> int:
        if not ids:
            return 0
        return self._client.xack(stream, group, *ids)

    # --- key side ---

    def get(self, key: str) -> str | None:
        return self._client.get(key)

    def set(self, key: str, value: str, ttl_seconds: float | None = None) -> None:
        # ex= is what makes a throttle expire on its own, with no cleanup code.
        self._client.set(key, value, ex=int(ttl_seconds) if ttl_seconds else None)

    def keys(self, pattern: str) -> list[str]:
        # scan_iter rather than KEYS, which blocks Redis across large keyspaces.
        return list(self._client.scan_iter(match=pattern, count=500))

    def close(self) -> None:
        self._client.close()


def _flatten(response) -> list[tuple[str, dict[str, str]]]:
    """xreadgroup returns [(stream, [(id, fields), ...])]. We only want the entries."""
    if not response:
        return []
    entries: list[tuple[str, dict[str, str]]] = []
    for _stream, items in response:
        entries.extend(items)
    return entries
