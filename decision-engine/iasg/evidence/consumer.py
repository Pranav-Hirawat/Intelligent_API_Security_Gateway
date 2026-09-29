"""
Reads evidence off the iasg:events stream.

Uses a consumer group so restarts neither lose nor replay events. Entries are
acked only after a cycle finishes -- acking on read would drop evidence
whenever the agent crashed mid-cycle.

A "clear campaigns" reset does not trim this stream -- raw events are kept --
but it does write a watermark (settings.reset_watermark_key), and this
consumer refuses to turn any entry older than that watermark into Evidence.
Those entries are still read and acked like any other (so a crash-recovery
replay or a consumer that fell behind can't leave them stuck pending
forever); they're just never handed to correlation, which is what stops
pre-reset evidence from immediately reconstituting the campaign that was
just cleared.
"""

from __future__ import annotations

from iasg.config import Settings
from iasg.models import Evidence
from iasg.store.base import Store


class EvidenceConsumer:
    def __init__(self, store: Store, settings: Settings) -> None:
        self._store = store
        self._settings = settings
        self._stream = settings.evidence_stream
        self._group = settings.consumer_group
        self._consumer = settings.consumer_name
        self._store.ensure_group(self._stream, self._group)
        self._recovered = False
        self._read_ids: list[str] = []

    def fetch(self) -> list[Evidence]:
        """Return this cycle's evidence, oldest first."""
        entries: list[tuple[str, dict[str, str]]] = []

        # On the first run, reclaim anything a previous crash left unacked.
        if not self._recovered:
            entries.extend(
                self._store.read_pending(
                    self._stream, self._group, self._consumer,
                    self._settings.batch_size,
                )
            )
            self._recovered = True

        entries.extend(
            self._store.read_group(
                self._stream, self._group, self._consumer,
                self._settings.batch_size,
            )
        )

        # Every entry read has to be acked, not just the ones that produced
        # Evidence. The gateway writes one entry per request and most requests
        # are clean, so from_stream_entry returns [] for the majority of them;
        # acking only what became Evidence left every clean request pending
        # forever, growing the PEL without bound and making read_pending replay
        # the whole backlog on each restart.
        self._read_ids.extend(eid for eid, _ in entries)

        watermark = _reset_watermark_ms(self._store, self._settings.reset_watermark_key)
        out: list[Evidence] = []
        for eid, fields in entries:
            if watermark and _stream_id_ms(eid) < watermark:
                continue
            out.extend(Evidence.from_stream_entry(eid, fields))
        return out

    def ack(self, evidence: list[Evidence] | None = None) -> int:
        """Mark this cycle's entries as processed. Called only after a cycle succeeds.

        `evidence` is still accepted so a caller can ack records it obtained
        some other way, but it is no longer the source of truth: what this
        consumer read is.
        """
        ids = list(self._read_ids)
        if evidence:
            ids.extend(e.stream_id for e in evidence if e.stream_id)

        ids = list(dict.fromkeys(i for i in ids if i))
        if not ids:
            return 0

        acked = self._store.ack(self._stream, self._group, *ids)
        # Cleared only on success, so a store that raised is retried rather
        # than silently forgotten.
        self._read_ids.clear()
        return acked


def _reset_watermark_ms(store: Store, key: str) -> int:
    raw = store.get(key)
    try:
        return int(raw) if raw else 0
    except (TypeError, ValueError):
        return 0


def _stream_id_ms(entry_id: str) -> int:
    """The millisecond half of a Redis stream id ("<ms>-<seq>") -- ids sort by
    this first, so comparing it against a watermark needs no clock sync
    between whatever produced the entry and whatever set the watermark."""
    try:
        return int(entry_id.split("-", 1)[0])
    except (ValueError, IndexError):
        return 0
