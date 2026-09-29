"""Properties of the adaptive decision and analyst-control path."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone

from iasg.adaptive.baseline import BaselineLearner, EndpointKey, MemoryBaselineRepository
from iasg.adaptive.config import AdaptiveConfig
from iasg.adaptive.controller import AdaptiveController
from iasg.adaptive.lifecycle import (
    STATUS_APPROVED,
    STATUS_PENDING,
    STATUS_RECOMMENDED,
    Lifecycle,
    MemoryLifecycleRepository,
)
from iasg.adaptive.risk import calculate_risk
from iasg.adaptive.windows import WindowConsumer
from iasg.config import Settings
from iasg.models import ACTION_MONITOR, ACTION_TEMP_BLOCK, ACTION_THROTTLE, Campaign, Evidence, PolicyDecision
from iasg.policy.writer import PolicyWriter
from iasg.store.memory import MemoryStore


NOW = datetime(2026, 9, 8, tzinfo=timezone.utc)


def campaign(confidence=0.95) -> Campaign:
    return Campaign(
        campaign_id="c1", type="Credential Stuffing", confidence=confidence,
        ips=["203.0.113.5"], reason="repeated login failures", severity="high",
        event_count=12,
    )


def evidence(count=3):
    return [
        Evidence(
            timestamp=NOW + timedelta(seconds=index), ip="203.0.113.5",
            endpoint="/api/login", method="POST", detector="bruteforce",
            severity="high",
        )
        for index in range(count)
    ]


def test_login_and_products_learn_different_thresholds():
    cfg = dataclasses.replace(
        AdaptiveConfig().baseline, warmup_windows=3, cooldown_seconds=0,
        minimum_threshold_rpm=1, maximum_threshold_rpm=1000,
    )
    repository = MemoryBaselineRepository()
    learner = BaselineLearner(repository, cfg)
    login, products = EndpointKey.of("POST", "/api/login"), EndpointKey.of("GET", "/api/products")
    for index in range(3):
        at = NOW + timedelta(minutes=index)
        learner.observe(login, 5, trusted=True, now=at)
        learner.observe(products, 100, trusted=True, now=at)
    assert repository.get_baseline(login).derived_threshold < repository.get_baseline(products).derived_threshold


def test_attack_and_enforced_windows_never_enter_the_baseline():
    repository = MemoryBaselineRepository()
    learner = BaselineLearner(repository, dataclasses.replace(AdaptiveConfig().baseline, warmup_windows=3))
    key = EndpointKey.of("POST", "/api/login")
    learner.observe(key, 500, trusted=False, now=NOW)
    summary = repository.get_baseline(key)
    assert summary.sample_count == 0 and summary.observed_rate == 500 and not summary.ready


def test_baseline_threshold_is_clamped_and_cooldown_prevents_oscillation():
    cfg = dataclasses.replace(
        AdaptiveConfig().baseline, warmup_windows=3, minimum_threshold_rpm=10,
        maximum_threshold_rpm=50, cooldown_seconds=300, hysteresis_ratio=0,
    )
    repository = MemoryBaselineRepository()
    learner, key = BaselineLearner(repository, cfg), EndpointKey.of("GET", "/api/products")
    for index in range(3):
        learner.observe(key, 1000, trusted=True, now=NOW + timedelta(minutes=index))
    summary = repository.get_baseline(key)
    assert summary.derived_threshold == 50
    learner.observe(key, 1, trusted=True, now=NOW + timedelta(minutes=3))
    assert repository.get_baseline(key).version == summary.version


def test_risk_is_bounded_and_fully_explained_without_ml():
    result = calculate_risk(AdaptiveConfig(), campaign(), evidence(100))
    assert 0 <= result.score <= 100 and 0 <= result.confidence <= 1
    assert set(result.explanation["components"]) == {"deterministic", "behavioural", "campaign"}
    assert result.explanation["final"]["configuration_version"] == 1


def test_two_signals_on_one_request_are_not_two_blocking_observations():
    rows = [dataclasses.replace(row, stream_id="same-request") for row in evidence(2)]
    result = calculate_risk(AdaptiveConfig(), campaign(), rows)
    assert result.explanation["deterministic_evidence_count"] == 1
    assert result.action != ACTION_TEMP_BLOCK


def test_warmup_behaviour_cannot_create_enforcement():
    result = calculate_risk(AdaptiveConfig(), None, [], observed_rate=10000)
    assert result.action == ACTION_MONITOR
    assert result.explanation["baseline"]["baseline_ready"] is False


def decision(action=ACTION_THROTTLE) -> PolicyDecision:
    return PolicyDecision(
        ip="203.0.113.5", action=action, campaign_id="c1", confidence=0.9,
        ttl_seconds=300, risk_score=80,
        explanation={"deterministic_evidence_count": 3, "final": {}},
    )


def test_modes_have_materially_different_lifecycles():
    cases = [("monitor", STATUS_RECOMMENDED, False), ("manual", STATUS_PENDING, False), ("automatic", STATUS_RECOMMENDED, True)]
    for mode, status, enforce in cases:
        row, should_enforce, _ = Lifecycle(MemoryLifecycleRepository()).stage(
            decision(), dataclasses.replace(AdaptiveConfig(), mode=mode), now=NOW,
        )
        assert (row.status, should_enforce) == (status, enforce)


def test_manual_mode_requires_an_explicit_approval_transition():
    repository = MemoryLifecycleRepository()
    lifecycle = Lifecycle(repository)
    row, enforce, _ = lifecycle.stage(decision(), dataclasses.replace(AdaptiveConfig(), mode="manual"), now=NOW)
    assert not enforce and lifecycle.approved() == []
    repository.mark_status(row.decision.policy_id, STATUS_APPROVED, "analyst")
    assert lifecycle.approved() == [row.decision]


def test_active_same_scope_policy_is_never_renewed_by_recurring_evidence():
    lifecycle = Lifecycle(MemoryLifecycleRepository())
    row, enforce, _ = lifecycle.stage(dataclasses.replace(decision(), issued_at=NOW), AdaptiveConfig(), now=NOW)
    assert enforce
    lifecycle.activated(row.decision)
    _, enforce, why = lifecycle.stage(dataclasses.replace(decision(), issued_at=NOW + timedelta(seconds=10)), AdaptiveConfig(), now=NOW + timedelta(seconds=10))
    assert not enforce and "not renewed" in why


def test_automatic_mode_cannot_exceed_its_action_ceiling():
    base = AdaptiveConfig()
    guarded = dataclasses.replace(base, guardrails=dataclasses.replace(base.guardrails, maximum_automatic_action="throttle"))
    assert calculate_risk(guarded, campaign(), evidence(20)).action == ACTION_THROTTLE


def test_writer_rechecks_every_automatic_action_ceiling_at_redis_boundary():
    base = AdaptiveConfig()
    guarded = dataclasses.replace(base, guardrails=dataclasses.replace(base.guardrails, maximum_automatic_action="monitor"))
    proposed = dataclasses.replace(decision(ACTION_THROTTLE), source="adaptive", requests_per_minute=60, mode="automatic")
    written, notes = PolicyWriter(MemoryStore(), dataclasses.replace(Settings(), adaptive=guarded)).write([proposed])
    assert written == 0 and any("action ceiling" in note for note in notes)


def test_writer_rechecks_monitor_mode_at_the_redis_boundary():
    base = AdaptiveConfig()
    settings, store = dataclasses.replace(Settings(), adaptive=dataclasses.replace(base, mode="monitor")), MemoryStore()
    written, notes = PolicyWriter(store, settings).write([dataclasses.replace(decision(ACTION_TEMP_BLOCK), source="adaptive", mode="monitor")])
    assert written == 0 and store.keys("policy:*") == []
    assert any("cannot auto-enforce" in note for note in notes)


def test_adaptive_policy_uses_canonical_temporary_block_wire_action():
    proposed = dataclasses.replace(decision(ACTION_TEMP_BLOCK), source="adaptive", mode="automatic")
    store = MemoryStore()
    written, _ = PolicyWriter(store, Settings()).write([proposed])
    assert written == 1
    assert json.loads(store.get(f"policy:{proposed.ip}"))["action"] == "temporary_block"


def test_runtime_learning_requires_complete_heartbeat_coverage():
    store = MemoryStore()
    settings = dataclasses.replace(Settings(), batch_size=10)
    arrival = {"requestId": "r1", "arrivalTs": NOW.isoformat(), "ip": "203.0.113.5", "method": "POST", "path": "/api/login", "routeTemplate": "/api/login"}
    event = {**arrival, "ts": (NOW + timedelta(seconds=1)).isoformat(), "responseOrigin": "backend", "upstreamStatus": 401, "decision": "allow", "fired": []}
    store.append(settings.arrival_stream, {"arrival": json.dumps(arrival)})
    store.append(settings.evidence_stream, {"event": json.dumps(event)})
    for offset in range(60):
        store.append(settings.health_stream, {"health": json.dumps({"at": (NOW + timedelta(seconds=offset)).isoformat(), "seq": offset + 1, "droppedTotal": 0, "arrivalsDroppedTotal": 0})})
    rows = WindowConsumer(store, settings).completed(NOW + timedelta(minutes=1, seconds=5))
    assert len(rows) == 1 and rows[0].safe_to_learn
    assert rows[0].route_counts == {("POST", "/api/login"): 1}


def test_signature_decision_is_complete_without_a_completed_rate_window():
    controller = AdaptiveController(MemoryBaselineRepository(), MemoryLifecycleRepository(), AdaptiveConfig())
    rows = [Evidence(timestamp=NOW, ip="203.0.113.5", endpoint="/api/search", method="GET", detector="sqli", severity="high")]
    selected, _, _ = controller.decisions(campaign(0.9), rows)[0]
    assert selected.risk_score > 0
    assert selected.explanation["deterministic_evidence_count"] == 1


def test_emergency_blocklist_is_an_explicit_global_override_even_in_monitor_mode():
    base = AdaptiveConfig()
    cfg = dataclasses.replace(base, mode="monitor", guardrails=dataclasses.replace(base.guardrails, blocklist=("203.0.113.0/24",)))
    selected, enforce, _ = AdaptiveController(MemoryBaselineRepository(), MemoryLifecycleRepository(), cfg).decisions(campaign(0.1), evidence(1))[0]
    assert enforce and selected.action == ACTION_TEMP_BLOCK and selected.mode == "manual_override"


def test_emergency_override_bypasses_adaptive_change_cooldown():
    lifecycle = Lifecycle(MemoryLifecycleRepository())
    active, _, _ = lifecycle.stage(dataclasses.replace(decision(ACTION_THROTTLE), issued_at=NOW), AdaptiveConfig(), now=NOW)
    lifecycle.activated(active.decision)
    emergency = dataclasses.replace(decision(ACTION_TEMP_BLOCK), issued_at=NOW + timedelta(seconds=1), source="human", mode="manual_override")
    staged, enforce, why = lifecycle.stage(emergency, AdaptiveConfig(), now=NOW + timedelta(seconds=1))
    assert enforce and staged.decision.supersedes_policy_id == active.decision.policy_id
    assert "explicit operator" in why
