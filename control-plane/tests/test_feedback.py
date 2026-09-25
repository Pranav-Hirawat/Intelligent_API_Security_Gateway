"""
Human overrides, and what the agent remembers from being overruled.

An admin writes an instruction to a stream; it beats whatever the agent
decided, and the direction of the disagreement is tallied against the campaign
type. Once the same correction has been made often enough the agent starts
making it itself -- by one rung, never more, and never past the safety checks,
which run afterwards and are not learnable.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone

from iasg.adaptive.config import AdaptiveConfig
from iasg.config import Settings
from iasg.feedback import overrides as human
from iasg.feedback.memory import FeedbackMemory
from iasg.feedback.overrides import Override, OverrideChannel
from iasg.models import (
    ACTION_ESCALATE,
    ACTION_MONITOR,
    ACTION_TEMP_BLOCK,
    ACTION_THROTTLE,
    Campaign,
    Evidence,
    PolicyDecision,
)
from iasg.runner import Runner
from iasg.store.memory import MemoryStore

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def settings(**overrides):
    return dataclasses.replace(Settings(), **overrides)


def decision(ip="203.0.113.5", action=ACTION_THROTTLE):
    return PolicyDecision(ip=ip, action=action, campaign_id="1",
                          confidence=0.6, ttl_seconds=900, reason="test")


def campaign(ips=("203.0.113.5",), confidence=0.6, severity="high", **kw):
    fields = dict(
        campaign_id="1", type="Credential Stuffing", confidence=confidence,
        ips=list(ips), reason="test", severity=severity,
        first_seen=NOW, last_seen=NOW, event_count=10,
    )
    fields.update(kw)
    return Campaign(**fields)


def instruct(store, ip="203.0.113.5", action="temp_block", actor="pranav", reason=""):
    store.append("iasg_overrides", {
        "ip": ip, "action": action, "actor": actor, "reason": reason,
    })


# --- reading instructions ---

def test_an_instruction_is_read_once():
    store = MemoryStore()
    channel = OverrideChannel(store, settings())
    instruct(store)

    assert len(channel.pending()) == 1
    assert channel.pending() == [], "the same instruction was applied twice"


def test_the_later_instruction_for_an_address_wins():
    store = MemoryStore()
    channel = OverrideChannel(store, settings())
    instruct(store, action="throttle")
    instruct(store, action="temp_block")

    (only,) = channel.pending()
    assert only.action == ACTION_TEMP_BLOCK


def test_an_unreadable_action_is_refused_rather_than_written():
    """Acting on a misspelled action would put nonsense in front of the gateway."""
    assert Override.from_fields({"ip": "203.0.113.5", "action": "blok"}) is None
    assert Override.from_fields({"ip": "", "action": "temp_block"}) is None
    assert Override.from_fields({"ip": "203.0.113.5", "action": ""}) is None


def test_an_unreadable_instruction_is_not_retried_forever():
    store = MemoryStore()
    channel = OverrideChannel(store, settings())
    instruct(store, action="nonsense")

    assert channel.pending() == []
    assert channel.pending() == []


# --- applying them ---

def test_a_human_action_replaces_the_agents():
    config = AdaptiveConfig()
    applied, lessons, notes = human.apply(
        [decision(action=ACTION_THROTTLE)],
        {"203.0.113.5": Override("203.0.113.5", ACTION_TEMP_BLOCK, "pranav")},
        config,
    )

    assert applied[0].action == ACTION_TEMP_BLOCK
    assert applied[0].ttl_seconds == config.guardrails.temporary_block_duration_seconds
    assert applied[0].source == "human"
    assert "pranav" in applied[0].reason
    assert lessons == [(ACTION_THROTTLE, ACTION_TEMP_BLOCK)]
    assert "agent said throttle" in notes[0]


def test_agreement_teaches_nothing():
    applied, lessons, notes = human.apply(
        [decision(action=ACTION_THROTTLE)],
        {"203.0.113.5": Override("203.0.113.5", ACTION_THROTTLE, "pranav")},
        AdaptiveConfig(),
    )

    assert applied[0].action == ACTION_THROTTLE
    assert lessons == [], "confirming the agent was recorded as a correction"
    assert "confirmed" in notes[0]


def test_untouched_addresses_are_left_alone():
    applied, lessons, _ = human.apply([decision(ip="198.51.100.7")], {}, AdaptiveConfig())

    assert applied[0].action == ACTION_THROTTLE
    assert lessons == []


def test_an_instruction_about_an_unseen_address_still_writes_policy():
    """Blocking an address the agent never saw is the plainest use of this."""
    loose = human.standalone(
        {"198.51.100.7": Override("198.51.100.7", ACTION_TEMP_BLOCK, "pranav", "spam")},
        handled=set(),
        config=AdaptiveConfig(),
    )

    (only,) = loose
    assert only.ip == "198.51.100.7"
    assert only.action == ACTION_TEMP_BLOCK
    assert only.source == "human"
    assert "spam" in only.reason


def test_an_address_a_campaign_already_covered_is_not_written_twice():
    loose = human.standalone(
        {"203.0.113.5": Override("203.0.113.5", ACTION_TEMP_BLOCK, "pranav")},
        handled={"203.0.113.5"},
        config=AdaptiveConfig(),
    )
    assert loose == []


def test_an_escalate_override_cannot_outstand_the_configured_maximum():
    """
    ACTION_ESCALATE's own default (1 hour) is longer than the default policy
    ceiling (30 minutes). A human's instruction is not exempt from the same
    rail that binds the agent -- see AdaptiveConfig.guardrails.
    """
    config = AdaptiveConfig()
    loose = human.standalone(
        {"198.51.100.7": Override("198.51.100.7", ACTION_ESCALATE, "pranav")},
        handled=set(),
        config=config,
    )

    (only,) = loose
    assert only.ttl_seconds == config.guardrails.maximum_policy_duration_seconds


def test_a_humans_explicit_ttl_is_still_capped_at_the_maximum():
    config = AdaptiveConfig()
    loose = human.standalone(
        {
            "198.51.100.7": Override(
                "198.51.100.7", ACTION_TEMP_BLOCK, "pranav",
                ttl_seconds=config.guardrails.maximum_policy_duration_seconds * 10,
            )
        },
        handled=set(),
        config=config,
    )

    (only,) = loose
    assert only.ttl_seconds == config.guardrails.maximum_policy_duration_seconds


# --- remembering them ---

def memory(**config):
    return FeedbackMemory(MemoryStore(), settings(**config))


def test_one_correction_is_not_a_rule():
    m = memory()
    m.record("Credential Stuffing", ACTION_THROTTLE, ACTION_TEMP_BLOCK)

    assert m.bias_for("Credential Stuffing") == 0


def test_a_repeated_correction_shifts_the_recommendation():
    m = memory()
    for _ in range(2):
        m.record("Credential Stuffing", ACTION_THROTTLE, ACTION_TEMP_BLOCK)

    assert m.bias_for("Credential Stuffing") == 1


def test_corrections_downward_are_learned_too():
    m = memory()
    for _ in range(2):
        m.record("Reconnaissance", ACTION_TEMP_BLOCK, ACTION_MONITOR)

    assert m.bias_for("Reconnaissance") == -1


def test_disagreement_between_people_cancels_out():
    """A type humans genuinely differ on stays where the evidence put it."""
    m = memory()
    for _ in range(3):
        m.record("Reconnaissance", ACTION_THROTTLE, ACTION_TEMP_BLOCK)
    for _ in range(3):
        m.record("Reconnaissance", ACTION_THROTTLE, ACTION_MONITOR)

    assert m.bias_for("Reconnaissance") == 0


def test_agreement_is_never_recorded():
    m = memory()
    for _ in range(5):
        m.record("Reconnaissance", ACTION_THROTTLE, ACTION_THROTTLE)

    assert m.bias_for("Reconnaissance") == 0


def test_types_are_learned_separately():
    m = memory()
    for _ in range(2):
        m.record("Reconnaissance", ACTION_MONITOR, ACTION_THROTTLE)

    assert m.bias_for("Reconnaissance") == 1
    assert m.bias_for("Distributed Flood") == 0


def test_what_was_learned_can_be_read_back():
    m = memory()
    for _ in range(2):
        m.record("Reconnaissance", ACTION_MONITOR, ACTION_THROTTLE)

    assert "stronger" in m.explain("Reconnaissance")
    assert m.explain("Distributed Flood") == ""


def test_learning_survives_storage():
    store = MemoryStore()
    FeedbackMemory(store, settings()).record(
        "Reconnaissance", ACTION_MONITOR, ACTION_THROTTLE
    )
    FeedbackMemory(store, settings()).record(
        "Reconnaissance", ACTION_MONITOR, ACTION_THROTTLE
    )

    assert FeedbackMemory(store, settings()).bias_for("Reconnaissance") == 1


# --- the whole loop ---

def seed(store, ip="203.0.113.5", n=6, offset=0):
    for i in range(n):
        store.append("iasg:events", Evidence(
            timestamp=NOW + timedelta(seconds=offset + i), ip=ip,
            endpoint="/api/login", detector="bruteforce", severity="high",
            user_agent="curl/8.4.0", details={"failedLogins": 9},
        ).to_stream_fields())


def test_an_override_reaches_redis_and_is_remembered():
    store = MemoryStore()
    runner = Runner(settings(), store)

    seed(store)
    instruct(store, ip="203.0.113.5", action="temp_block", reason="confirmed")
    result = runner.cycle()

    assert result.overridden, "the override was not applied"
    written = store.get("policy:203.0.113.5")
    assert written and "temp_block" in written and "human" in written

    campaign_type = result.campaigns[0].type
    assert runner.feedback.all().get(campaign_type, {}).get("up") == 1


def test_repeated_corrections_are_remembered_by_the_next_run():
    store = MemoryStore()
    runner = Runner(settings(), store)

    for cycle_n in range(2):
        seed(store, offset=cycle_n * 600)
        instruct(store, action="temp_block")
        runner.cycle()

    assert Runner(settings(), store).feedback.bias_for("Brute Force") == 1


def test_an_instruction_lands_even_with_no_attack_this_cycle():
    """An admin should not have to wait for a campaign to block an address."""
    store = MemoryStore()
    runner = Runner(settings(), store)

    instruct(store, ip="198.51.100.7", action="temp_block", actor="pranav")
    result = runner.cycle()

    assert result.evidence_count == 0
    assert [d.ip for d in result.manual] == ["198.51.100.7"]
    assert store.get("policy:198.51.100.7")


def test_an_instruction_cannot_police_an_allowlisted_range_through_the_runner():
    store = MemoryStore()
    runner = Runner(settings(allowlist=("198.51.100.0/24",)), store)

    instruct(store, ip="198.51.100.7", action="temp_block")
    result = runner.cycle()

    assert store.get("policy:198.51.100.7") is None
    assert any("allowlisted" in n for n in result.notes)
