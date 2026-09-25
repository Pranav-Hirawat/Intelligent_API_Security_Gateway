"""
The adaptive guardrails, re-checked where policy is written.

The controller already applies these when it decides. The writer applies them
again because it is the only code that can reach the gateway: a controller
bug, a stale config, or a hand-edited recommendation must still stop here.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from iasg.adaptive.config import AdaptiveConfig
from iasg.config import Settings
from iasg.models import ACTION_ALLOW, ACTION_TEMP_BLOCK, ACTION_THROTTLE, PolicyDecision
from iasg.policy.writer import PolicyWriter, parse_networks, within
from iasg.store.memory import MemoryStore

IP = "203.0.113.5"


def decision(action=ACTION_THROTTLE, **changes) -> PolicyDecision:
    fields = dict(
        ip=IP, action=action, campaign_id="7", confidence=0.9, ttl_seconds=900,
        source="adaptive", requests_per_minute=60,
        explanation={"deterministic_evidence_count": 3},
    )
    fields.update(changes)
    return PolicyDecision(**fields)


def config(mode="automatic", **guardrails) -> AdaptiveConfig:
    base = AdaptiveConfig()
    return replace(base, mode=mode, guardrails=replace(base.guardrails, **guardrails))


def write(d: PolicyDecision, adaptive: AdaptiveConfig | None = None, **settings):
    store = MemoryStore()
    s = replace(Settings(), adaptive=adaptive or AdaptiveConfig(), **settings)
    written, notes = PolicyWriter(store, s).write([d])
    return written, notes, store


def behavioural(**baseline) -> dict:
    return {
        "deterministic_evidence_count": 0,
        "final": {"behavioural_throttle_authorized": True},
        "baseline": {"baseline_ready": True, "deviation": 5.0, **baseline},
    }


def test_a_decision_inside_every_guardrail_is_written():
    for d in (decision(), decision(ACTION_TEMP_BLOCK, ttl_seconds=1800)):
        written, notes, store = write(d)
        assert written == 1, notes
        assert store.get(f"policy:{IP}")


REFUSED = [
    ("monitor mode", decision(), config("monitor"), "monitor mode cannot auto-enforce"),
    ("manual mode", decision(), config("manual"), "manual mode cannot auto-enforce"),
    ("action ceiling", decision(ACTION_TEMP_BLOCK), config(maximum_automatic_action="throttle"),
     "temp_block exceeds the automatic action ceiling"),
    ("too long", decision(ttl_seconds=5000), None, "duration exceeds the configured maximum"),
    ("throttle confidence", decision(confidence=0.3), None, "confidence is below the throttle minimum"),
    ("throttle evidence", decision(explanation={}), None, "deterministic evidence is below the throttle minimum"),
    ("rate too low", decision(requests_per_minute=5), None, "throttle rate is outside configured bounds"),
    ("rate too high", decision(requests_per_minute=1000), None, "throttle rate is outside configured bounds"),
    ("block confidence", decision(ACTION_TEMP_BLOCK, confidence=0.6), None,
     "confidence is below the temporary-block minimum"),
    ("block evidence", decision(ACTION_TEMP_BLOCK, explanation={"deterministic_evidence_count": 1}), None,
     "deterministic evidence is below the temporary-block minimum"),
    ("behavioural off", decision(explanation=behavioural(), method="GET", route_template="/api/x"), None,
     "behavioural throttles are disabled"),
    ("baseline not ready", decision(explanation=behavioural(baseline_ready=False), method="GET", route_template="/api/x"),
     config(behavioural_throttle_enabled=True), "behavioural throttle requires a ready baseline"),
    ("small deviation", decision(explanation=behavioural(deviation=1.0), method="GET", route_template="/api/x"),
     config(behavioural_throttle_enabled=True), "behavioural deviation is below the throttle minimum"),
    ("whole address", decision(explanation=behavioural()), config(behavioural_throttle_enabled=True),
     "behavioural throttle must be endpoint scoped"),
]


@pytest.mark.parametrize("d,adaptive,reason", [r[1:] for r in REFUSED], ids=[r[0] for r in REFUSED])
def test_a_decision_outside_a_guardrail_is_refused_with_its_reason(d, adaptive, reason):
    written, notes, store = write(d, adaptive)
    assert written == 0
    assert store.keys("policy:*") == []
    assert notes == [f"skipped {IP} ({reason})"]


def test_an_opted_in_behavioural_throttle_on_one_endpoint_is_written():
    d = decision(explanation=behavioural(), method="GET", route_template="/api/products")
    written, notes, store = write(d, config(behavioural_throttle_enabled=True))
    assert written == 1, notes
    (key,) = store.keys("policy:*")
    assert key.startswith(f"policy:{IP}:"), "an endpoint throttle must not cover the whole address"


def test_an_approved_decision_is_written_in_manual_mode():
    """Manual mode means a human approves; the approval is what it waits for."""
    written, notes, _ = write(decision(source="approved"), config("manual"))
    assert written == 1, notes


def test_an_approval_still_cannot_exceed_the_guardrails():
    written, notes, _ = write(decision(source="approved", confidence=0.1), config("manual"))
    assert written == 0
    assert "confidence is below the throttle minimum" in notes[0]


def test_a_human_instruction_is_not_held_to_the_controllers_minimums():
    """Someone who says block anyway has seen something the numbers have not."""
    written, notes, _ = write(decision(source="human", confidence=0.0, explanation={}))
    assert written == 1, notes


def test_the_emergency_allowlist_stops_enforcement_but_not_an_allow():
    adaptive = config(allowlist=("203.0.113.0/24",))
    written, notes, _ = write(decision(ACTION_TEMP_BLOCK), adaptive)
    assert written == 0
    assert notes == [f"skipped {IP} (emergency allowlist)"]

    written, _, store = write(decision(ACTION_ALLOW), adaptive)
    assert written == 1
    assert json.loads(store.get(f"policy:{IP}"))["action"] == ACTION_ALLOW


def test_a_config_applied_mid_run_governs_the_next_write():
    store = MemoryStore()
    writer = PolicyWriter(store, replace(Settings(), adaptive=AdaptiveConfig()))
    writer.apply_config(config("monitor"))
    written, notes = writer.write([decision()])
    assert written == 0
    assert "monitor mode cannot auto-enforce" in notes[0]


def test_an_invalid_config_is_refused_before_it_can_govern_anything():
    writer = PolicyWriter(MemoryStore(), Settings())
    with pytest.raises(ValueError):
        writer.apply_config(config("yolo"))


def test_unreadable_allowlist_entries_and_addresses_match_nothing():
    networks = parse_networks(("203.0.113.0/24", "not-a-network"))
    assert len(networks) == 1
    assert within("203.0.113.9", networks)
    assert not within("not-an-ip", networks)
