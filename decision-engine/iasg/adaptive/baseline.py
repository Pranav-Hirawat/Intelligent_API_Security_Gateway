"""Endpoint-specific rolling baselines over trusted 60-second windows."""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol

from iasg.adaptive.config import BaselineConfig
from iasg.anomaly.spec import UNMATCHED_ROUTE


@dataclass(frozen=True)
class EndpointKey:
    method: str
    route_template: str

    @classmethod
    def of(cls, method: str, route_template: str) -> "EndpointKey":
        method = (method or "GET").strip().upper()
        route = (route_template or UNMATCHED_ROUTE).split("?", 1)[0]
        if route != UNMATCHED_ROUTE and not route.startswith("/"):
            route = UNMATCHED_ROUTE
        return cls(method=method, route_template=route)

    @property
    def label(self) -> str:
        return f"{self.method} {self.route_template}"


@dataclass
class BaselineSummary:
    method: str
    route_template: str
    sample_count: int = 0
    statistic: float = 0.0
    mad: float = 0.0
    derived_threshold: int = 0
    observed_rate: int = 0
    last_update: datetime | None = None
    last_threshold_change: datetime | None = None
    version: int = 0
    ready: bool = False
    samples: list[float] = field(default_factory=list, repr=False)

    @property
    def key(self) -> EndpointKey:
        return EndpointKey.of(self.method, self.route_template)


class BaselineRepository(Protocol):
    def get_baseline(self, key: EndpointKey) -> BaselineSummary | None: ...
    def save_baseline(self, summary: BaselineSummary) -> None: ...
    def list_baselines(self) -> list[BaselineSummary]: ...


class MemoryBaselineRepository:
    def __init__(self) -> None:
        self._rows: dict[EndpointKey, BaselineSummary] = {}

    def get_baseline(self, key: EndpointKey) -> BaselineSummary | None:
        return self._rows.get(key)

    def save_baseline(self, summary: BaselineSummary) -> None:
        self._rows[summary.key] = summary

    def list_baselines(self) -> list[BaselineSummary]:
        return sorted(self._rows.values(), key=lambda row: row.key.label)


class BaselineLearner:
    def __init__(self, repository: BaselineRepository, config: BaselineConfig) -> None:
        self.repository = repository
        self.config = config

    def observe(
        self,
        key: EndpointKey,
        requests_in_window: int,
        *,
        trusted: bool,
        now: datetime | None = None,
    ) -> BaselineSummary:
        """Record the visible rate; only trusted observations enter learning."""
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        current = self.repository.get_baseline(key) or BaselineSummary(
            method=key.method, route_template=key.route_template
        )
        current.observed_rate = max(0, int(requests_in_window))
        current.last_update = now

        if trusted:
            samples = [*current.samples, float(current.observed_rate)]
            current.samples = samples[-self.config.rolling_windows :]
            current.sample_count = len(current.samples)
            current.statistic = statistics.median(current.samples)
            deviations = [abs(value - current.statistic) for value in current.samples]
            current.mad = statistics.median(deviations)
            proposed = math.ceil(
                current.statistic
                + self.config.mad_multiplier * max(current.mad, self.config.minimum_mad)
            )
            proposed = max(
                self.config.minimum_threshold_rpm,
                min(self.config.maximum_threshold_rpm, proposed),
            )
            ready = current.sample_count >= self.config.warmup_windows
            if self._may_change(current, proposed, ready, now):
                current.derived_threshold = proposed
                current.last_threshold_change = now
                current.version += 1
            elif current.derived_threshold == 0:
                # Warm-up thresholds are visible for explanation but cannot
                # authorise enforcement until ready becomes true.
                current.derived_threshold = proposed
            current.ready = ready

        self.repository.save_baseline(current)
        return current

    def _may_change(
        self, current: BaselineSummary, proposed: int, ready: bool, now: datetime
    ) -> bool:
        if current.derived_threshold <= 0:
            return True
        if ready and not current.ready:
            return True
        difference = abs(proposed - current.derived_threshold) / max(
            current.derived_threshold, 1
        )
        if difference < self.config.hysteresis_ratio:
            return False
        if current.last_threshold_change is None:
            return True
        return now - current.last_threshold_change >= timedelta(
            seconds=self.config.cooldown_seconds
        )

    @staticmethod
    def deviation(summary: BaselineSummary | None, observed: int) -> float:
        if summary is None or not summary.ready or summary.derived_threshold <= 0:
            return 0.0
        return max(0.0, (observed - summary.derived_threshold) / summary.derived_threshold)
