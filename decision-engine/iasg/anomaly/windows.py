"""Assign telemetry to UTC-aligned 60-second windows by arrival time."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from iasg.anomaly.spec import WINDOW_SECONDS


def window_start(ts: datetime) -> datetime:
    ts = ts.astimezone(timezone.utc)
    epoch_seconds = int(ts.timestamp())
    return datetime.fromtimestamp(
        epoch_seconds - (epoch_seconds % WINDOW_SECONDS), tz=timezone.utc
    )


def window_end(start: datetime) -> datetime:
    return start + timedelta(seconds=WINDOW_SECONDS)
