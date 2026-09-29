"""
An in-memory Store. No Redis required.

Lets the pipeline be tested without a database running. Ported from the Go
memory.go, including its expiry trick: keys expire when read, not on a
background timer, so there are no threads to leak or shut down.
"""

from __future__ import annotations

import fnmatch
import itertools
import time


class MemoryStore:
    """A pretend Redis, backed by plain dictionaries."""

    def __init__(self) -> None:
        self._keys: dict[str, tuple[str, float | None]] = {}
        self._streams: dict[str, list[tuple[str, dict[str, str]]]] = {}
        self._cursors: dict[tuple[str, str], int] = {}
        self._pending: dict[tuple[str, str], set[str]] = {}
        self._counter = itertools.count(1)

    # --- stream side ---

    def ensure_group(self, stream: str, group: str) -> None:
        """Start tracking a group's read position. Safe to call repeatedly."""
        self._streams.setdefault(stream, [])
        self._cursors.setdefault((stream, group), 0)
        self._pending.setdefault((stream, group), set())

    def append(self, stream: str, fields: dict[str, str]) -> str:
        entry_id = f"{next(self._counter)}-0"
        # dict(fields) copies, so a caller reusing their dict can't rewrite history.
        self._streams.setdefault(stream, []).append((entry_id, dict(fields)))
        return entry_id

    def read_group(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int,
        block_ms: int = 0,
    ) -> list[tuple[str, dict[str, str]]]:
        """Read up to `count` entries this group hasn't seen yet."""
        self.ensure_group(stream, group)

        entries = self._streams.get(stream, [])
        start = self._cursors[(stream, group)]
        batch = entries[start : start + count]

        self._cursors[(stream, group)] = start + len(batch)
        for entry_id, _ in batch:
            self._pending[(stream, group)].add(entry_id)

        # block_ms ignored: with no other writers there is nothing to wait for.
        return batch

    def read_pending(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int,
    ) -> list[tuple[str, dict[str, str]]]:
        """Re-read entries handed out but never acked."""
        self.ensure_group(stream, group)
        pending = self._pending[(stream, group)]
        if not pending:
            return []
        return [
            (eid, fields)
            for eid, fields in self._streams.get(stream, [])
            if eid in pending
        ][:count]

    def ack(self, stream: str, group: str, *ids: str) -> int:
        pending = self._pending.setdefault((stream, group), set())
        acked = 0
        for entry_id in ids:
            if entry_id in pending:
                pending.remove(entry_id)
                acked += 1
        return acked

    def trim(self, stream: str, maxlen: int) -> int:
        """
        Drop the oldest entries, as XTRIM MAXLEN does.

        Only the memory store has this. It exists so trim detection can be
        tested against a stream that really lost entries, rather than against a
        mock that agrees with whatever the detector believes.
        """
        entries = self._streams.get(stream) or []
        dropped = max(0, len(entries) - maxlen)
        if dropped:
            self._streams[stream] = entries[dropped:]
            # Cursors count from the head, so they move with it. Without this a
            # group would re-read entries it had already consumed.
            for (s, g), cursor in list(self._cursors.items()):
                if s == stream:
                    self._cursors[(s, g)] = max(0, cursor - dropped)
        return dropped

    # --- key side ---

    def get(self, key: str) -> str | None:
        """Read a key. None if missing or expired."""
        entry = self._keys.get(key)
        if entry is None:
            return None

        value, expires_at = entry

        # Expiry is checked on read, not by a timer. An expired key is
        # indistinguishable from a missing one, so no sweeper thread is needed.
        if expires_at is not None and time.time() > expires_at:
            del self._keys[key]
            return None

        return value

    def set(self, key: str, value: str, ttl_seconds: float | None = None) -> None:
        expires_at = time.time() + ttl_seconds if ttl_seconds else None
        self._keys[key] = (value, expires_at)

    def keys(self, pattern: str) -> list[str]:
        return [
            k
            for k in list(self._keys)
            if fnmatch.fnmatch(k, pattern) and self.get(k) is not None
        ]

    def close(self) -> None:
        pass
