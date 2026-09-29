"""The opt-in baseline path may throttle, but never broaden into blocking."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from iasg.adaptive.baseline import BaselineSummary, EndpointKey, MemoryBaselineRepository
from iasg.adaptive.config import AdaptiveConfig
from iasg.adaptive.controller import AdaptiveController
from iasg.adaptive.lifecycle import MemoryLifecycleRepository
from iasg.adaptive.risk import calculate_risk
from iasg.adaptive.windows import CompletedWindow
from iasg.anomaly.extract import WindowRow
from iasg.anomaly.quality import WindowQuality
from iasg.config import Settings
from iasg.models import ACTION_MONITOR, ACTION_THROTTLE, PolicyDecision
from iasg.policy.writer import PolicyWriter
from iasg.store.memory import MemoryStore


NOW = datetime(2026, 9, 17, tzinfo=timezone.utc)
KEY = EndpointKey.of("GET", "/api/products")


def baseline() -> BaselineSummary:
    return BaselineSummary(
        method=KEY.method,
        route_template=KEY.route_template,
        sample_count=3,
        statistic=2,
        mad=0,
        derived_threshold=5,
        ready=True,
        samples=[2, 2, 2],
    )


def behavioural_config(enabled: bool) -> AdaptiveConfig:
    base = AdaptiveConfig()
    return replace(
        base,
        baseline=replace(base.baseline, warmup_windows=3),
        guardrails=replace(
            base.guardrails,
            behavioural_throttle_enabled=enabled,
            behavioural_throttle_minimum_deviation=2.0,
        ),
    ).validate()


def test_ready_baseline_can_only_authorise_an_explicit_opt_in_throttle():
    disabled = calculate_risk(
        behavioural_config(False), None, [], endpoint=KEY, baseline=baseline(), observed_rate=20
    )
    enabled = calculate_risk(
        behavioural_config(True), None, [], endpoint=KEY, baseline=baseline(), observed_rate=20
    )

    assert disabled.action == ACTION_MONITOR
    assert enabled.action == ACTION_THROTTLE
    assert enabled.confidence == 1.0
    assert enabled.explanation["final"]["behavioural_throttle_authorized"] is True
    assert enabled.explanation["deterministic_evidence_count"] == 0


def test_behavioural_burst_is_endpoint_scoped_and_not_learned_as_normal():
    config = behavioural_config(True)
    baselines = MemoryBaselineRepository()
    baselines.save_baseline(baseline())
    controller = AdaptiveController(baselines, MemoryLifecycleRepository(), config)
    window = CompletedWindow(
        row=WindowRow(
            ip="203.0.113.120",
            window_start=NOW,
            quality=WindowQuality(),
        ),
        route_counts={("GET", "/api/products"): 20},
        safe_to_learn=True,
        fired=(),
    )

    staged = controller.observe([window])

    decision, enforce, _ = staged[0]
    assert enforce and decision.action == ACTION_THROTTLE
    assert (decision.method, decision.route_template) == ("GET", "/api/products")
    # The trigger window stays visible as observed traffic but cannot teach the
    # baseline that the burst was ordinary.
    assert baselines.get_baseline(KEY).sample_count == 3
    assert baselines.get_baseline(KEY).observed_rate == 20


def test_writer_rechecks_the_opt_in_baseline_constraints_at_redis_boundary():
    config = behavioural_config(True)
    result = calculate_risk(config, None, [], endpoint=KEY, baseline=baseline(), observed_rate=20)
    decision = PolicyDecision(
        ip="203.0.113.120",
        action=result.action,
        campaign_id="",
        confidence=result.confidence,
        ttl_seconds=config.guardrails.throttle_duration_seconds,
        requests_per_minute=result.requests_per_minute,
        source="adaptive",
        mode="automatic",
        method=KEY.method,
        route_template=KEY.route_template,
        scope="client_endpoint",
        explanation=result.explanation,
    )
    store = MemoryStore()

    written, notes = PolicyWriter(store, replace(Settings(), adaptive=config)).write([decision])

    assert written == 1 and notes == []
    assert store.keys("policy:203.0.113.120:*")
