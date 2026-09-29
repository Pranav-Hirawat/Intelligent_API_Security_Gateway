"""Turn gateway heartbeats into one trustworthy verdict per window."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from iasg.anomaly.quality import WindowHealth
from iasg.anomaly.records import parse_ts
from iasg.anomaly.windows import window_start


def health_by_window(
    entries: Iterable[dict], trim_losses: bool = False
) -> dict[datetime, WindowHealth]:
    """Fold cumulative counters and heartbeat continuity into minute verdicts."""
    seen: dict[datetime, list[dict]] = {}
    for entry in entries:
        at = parse_ts(entry.get("at"))
        if at is None:
            continue
        seen.setdefault(window_start(at), []).append(entry)

    verdicts: dict[datetime, WindowHealth] = {}
    for start, beats in seen.items():
        beats.sort(key=lambda beat: _integer(beat.get("seq"), -1))
        seqs = [_integer(beat.get("seq"), -1) for beat in beats]
        contiguous = (
            len(seqs) == 60
            and seqs == list(range(seqs[0], seqs[0] + 60))
        )
        first, last = beats[0], beats[-1]
        dropped = max(
            0,
            _integer(last.get("droppedTotal"))
            + _integer(last.get("arrivalsDroppedTotal"))
            - _integer(first.get("droppedTotal"))
            - _integer(first.get("arrivalsDroppedTotal")),
        )
        verdicts[start] = WindowHealth(
            dropped=dropped,
            fully_observed=contiguous and dropped == 0 and not trim_losses,
        )
    return verdicts


def _integer(value, default: int = 0) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return default
