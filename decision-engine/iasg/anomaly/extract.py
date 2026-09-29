"""Represent one completed telemetry window for adaptive baseline learning."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Sequence

from iasg.anomaly.quality import WindowHealth, WindowQuality
from iasg.anomaly.records import RequestRecord


@dataclass(frozen=True)
class WindowRow:
    ip: str
    window_start: datetime
    quality: WindowQuality


def extract(
    records: Sequence[RequestRecord],
    window_start: datetime,
    _as_of: datetime,
    health: WindowHealth | None = None,
) -> WindowRow:
    if not records:
        raise ValueError("a completed telemetry window requires at least one request")
    health = health or WindowHealth()
    return WindowRow(
        ip=records[0].ip,
        window_start=window_start,
        quality=WindowQuality(interval_fully_observed=health.fully_observed),
    )
