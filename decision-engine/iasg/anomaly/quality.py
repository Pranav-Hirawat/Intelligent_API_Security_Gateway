"""Coverage information used to decide whether a window may teach a baseline."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WindowQuality:
    interval_fully_observed: bool = True


@dataclass(frozen=True)
class WindowHealth:
    dropped: int = 0
    fully_observed: bool = True
