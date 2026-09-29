"""Consume telemetry into completed, privacy-safe 60-second windows."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone

from iasg.anomaly.extract import WindowRow, extract
from iasg.anomaly.health import health_by_window
from iasg.anomaly.quality import WindowHealth
from iasg.anomaly.records import (
    RequestRecord,
    arrival_from_json,
    completion_fields,
    parse_ts,
    record_from_event,
)
from iasg.anomaly.windows import window_end, window_start
from iasg.config import Settings
from iasg.store.base import Store


@dataclass(frozen=True)
class CompletedWindow:
    row: WindowRow
    route_counts: dict[tuple[str, str], int]
    safe_to_learn: bool
    fired: tuple[str, ...]


class WindowConsumer:
    """A separate consumer group so clean traffic remains available here."""

    def __init__(self, store: Store, settings: Settings) -> None:
        self._store = store
        self._arrivals_stream = settings.arrival_stream
        self._events_stream = settings.evidence_stream
        self._health_stream = settings.health_stream
        self._group = settings.window_consumer_group
        self._consumer = settings.window_consumer_name
        self._batch = settings.batch_size
        self._grace = timedelta(seconds=max(0, settings.window_completion_grace_seconds))
        self._arrivals: dict[str, RequestRecord] = {}
        self._completions: dict[str, RequestRecord] = {}
        self._flags: dict[str, tuple[str, tuple[str, ...]]] = {}
        self._health: list[dict] = []
        self._recovered: set[str] = set()
        for stream in (self._arrivals_stream, self._events_stream, self._health_stream):
            self._store.ensure_group(stream, self._group)

    def completed(self, now: datetime | None = None) -> list[CompletedWindow]:
        caught_up = all((
            self._drain(self._arrivals_stream, "arrival"),
            self._drain(self._events_stream, "event"),
            self._drain(self._health_stream, "health"),
        ))
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

        # A partial Redis backlog must never be mistaken for a quiet completed
        # minute. Keep the accumulated records and finish on the next cycle.
        if not caught_up:
            return []

        records: dict[str, RequestRecord] = dict(self._arrivals)
        records.update(self._completions)
        ready_starts = {
            window_start(record.arrival_ts)
            for record in records.values()
            if window_end(window_start(record.arrival_ts)) + self._grace <= now
        }
        if not ready_starts:
            return []

        grouped: dict[tuple[str, datetime], list[RequestRecord]] = {}
        for record in records.values():
            start = window_start(record.arrival_ts)
            if start in ready_starts:
                grouped.setdefault((record.ip, start), []).append(record)

        finished: list[CompletedWindow] = []
        health = health_by_window(self._health)
        for (_, start), rows in sorted(grouped.items(), key=lambda item: item[0]):
            route_counts = Counter((row.method, row.route_template) for row in rows)
            ids = {row.request_id for row in rows}
            decisions = [self._flags.get(request_id, ("", ()))[0] for request_id in ids]
            fired = sorted({
                signal
                for request_id in ids
                for signal in self._flags.get(request_id, ("", ()))[1]
            })
            # Missing completions are incomplete observation, not proof of
            # normality.  Any detector hit or prior enforcement also excludes
            # the window so attacks and policy-shaped traffic cannot teach the
            # baseline what "normal" means.
            safe = (
                all(request_id in self._completions for request_id in ids)
                and all(decision == "allow" for decision in decisions)
                and not fired
            )
            # Missing heartbeat coverage is explicitly untrusted. extract's
            # permissive default remains useful to older callers that do not
            # perform baseline learning.
            row = extract(
                rows,
                start,
                window_end(start),
                health.get(start, WindowHealth(fully_observed=False)),
            )
            finished.append(CompletedWindow(
                row=row,
                route_counts=dict(route_counts),
                safe_to_learn=safe and row.quality.interval_fully_observed,
                fired=tuple(fired),
            ))

        for request_id, record in list(records.items()):
            if window_start(record.arrival_ts) in ready_starts:
                self._arrivals.pop(request_id, None)
                self._completions.pop(request_id, None)
                self._flags.pop(request_id, None)
        self._health = [
            beat
            for beat in self._health
            if (at := parse_ts(beat.get("at"))) is not None
            and window_start(at) not in ready_starts
        ]
        return finished

    def _drain(self, stream: str, payload_field: str) -> bool:
        """Drain bounded batches; false means the stream may still have backlog."""
        batch = max(1, self._batch)
        if stream not in self._recovered:
            for _ in range(20):
                entries = self._store.read_pending(
                    stream, self._group, self._consumer, batch
                )
                if not entries:
                    break
                self._consume(stream, payload_field, entries)
                if len(entries) < batch:
                    break
            else:
                return False
            self._recovered.add(stream)

        for _ in range(20):
            entries = self._store.read_group(
                stream, self._group, self._consumer, batch
            )
            if not entries:
                return True
            self._consume(stream, payload_field, entries)
            if len(entries) < batch:
                return True
        return False

    def _consume(
        self,
        stream: str,
        payload_field: str,
        entries: list[tuple[str, dict[str, str]]],
    ) -> None:
        for _, fields in entries:
            try:
                payload = json.loads(fields.get(payload_field, "{}"))
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            if payload_field == "health":
                self._health.append(payload)
                continue
            if payload_field == "arrival":
                record = arrival_from_json(payload)
                if record is not None:
                    self._arrivals[record.request_id] = record
                continue

            record = record_from_event(payload)
            if record is None:
                continue
            existing = self._arrivals.get(record.request_id)
            if existing is not None:
                record = replace(existing, **completion_fields(payload))
            self._completions[record.request_id] = record
            self._flags[record.request_id] = (
                str(payload.get("decision") or ""),
                tuple(str(item) for item in (payload.get("fired") or []) if item),
            )
        self._store.ack(stream, self._group, *(entry_id for entry_id, _ in entries))
