"""
Asking "is this response safe?" separately from "is this malicious?".

The honest limit is that the gateway reports attacks and never ordinary
traffic, so nothing here can measure how many real users sit behind an
address. These checks work with what is observable -- ranges an operator
declared, how many distinct clients an address speaks for, and what policy is
already standing -- and the difference between the declared and the inferred
is load-bearing, not cosmetic.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone

from iasg.config import Settings
from iasg.models import (
    ACTION_ALLOW,
    ACTION_ESCALATE,
    ACTION_MONITOR,
    ACTION_TEMP_BLOCK,
    ACTION_THROTTLE,
    Evidence,
    PolicyDecision,
)
from iasg.policy.simulation import Simulator
from iasg.store.memory import MemoryStore

NOW = datetime.now(timezone.utc)

# How long each action stands; the simulator preserves whatever the decision carried.
TTL = {ACTION_ALLOW: 900, ACTION_MONITOR: 300, ACTION_THROTTLE: 900, ACTION_TEMP_BLOCK: 1800, ACTION_ESCALATE: 3600}


def settings(**overrides):
    return dataclasses.replace(Settings(), **overrides)


def decision(ip="203.0.113.5", action=ACTION_TEMP_BLOCK, confidence=0.8, **kw):
    return PolicyDecision(
        ip=ip, action=action, campaign_id="1", confidence=confidence,
        ttl_seconds=TTL[action], reason="test", **kw,
    )


def traffic(ip="203.0.113.5", agents=("curl/8.4.0",)):
    return [
        Evidence(timestamp=NOW + timedelta(seconds=n), ip=ip, endpoint="/api/login",
                 detector="bruteforce", severity="high", user_agent=agent)
        for n, agent in enumerate(agents)
    ]


def review(decisions, evidence=(), store=None, **config):
    sim = Simulator(store or MemoryStore(), settings(**config))
    return sim.review(list(decisions), list(evidence))


# --- nothing configured changes nothing ---

def test_an_unconfigured_simulator_approves_everything():
    """The default path must be exactly what it was before this existed."""
    approved, notes = review([decision(), decision(ip="203.0.113.9")])

    assert len(approved) == 2
    assert notes == []


# --- declared configuration ---

def test_an_allowlisted_address_gets_no_policy_at_all():
    approved, notes = review([decision()], allowlist=("203.0.113.0/24",))

    assert approved == []
    assert "allowlisted" in notes[0]


def test_an_explicit_allow_can_release_an_allowlisted_address_from_reflex():
    approved, notes = review(
        [decision(action=ACTION_ALLOW, source="human")],
        allowlist=("203.0.113.0/24",),
    )

    assert approved[0].action == ACTION_ALLOW
    assert notes == []


def test_the_allowlist_leaves_other_addresses_alone():
    approved, _ = review(
        [decision(ip="203.0.113.5"), decision(ip="198.51.100.7")],
        allowlist=("203.0.113.0/24",),
    )

    assert [d.ip for d in approved] == ["198.51.100.7"]


def test_a_declared_shared_range_is_slowed_not_cut_off():
    approved, notes = review([decision()], shared_ranges=("203.0.113.0/24",))

    (only,) = approved
    assert only.action == ACTION_THROTTLE
    assert only.ttl_seconds == TTL[ACTION_THROTTLE]
    assert "temp_block -> throttle" in notes[0]


def test_softening_records_why_in_the_reason():
    approved, _ = review([decision()], shared_ranges=("203.0.113.0/24",))

    assert "reduced from temp_block" in approved[0].reason
    assert "declared a shared range" in approved[0].reason


def test_a_gentler_action_on_a_shared_range_is_left_alone():
    approved, notes = review(
        [decision(action=ACTION_MONITOR)], shared_ranges=("203.0.113.0/24",)
    )

    assert approved[0].action == ACTION_MONITOR
    assert notes == []


def test_a_single_declared_address_works_without_a_prefix():
    approved, _ = review([decision()], allowlist=("203.0.113.5",))
    assert approved == []


def test_unparseable_configuration_is_ignored_rather_than_fatal():
    approved, _ = review([decision()], allowlist=("not-an-address", "  "))
    assert len(approved) == 1


# --- inference, and the evasion route it would otherwise open ---

def test_many_distinct_clients_soften_an_uncertain_block():
    busy = traffic(agents=[f"Mozilla/5.0 (device {n})" for n in range(6)])
    approved, notes = review([decision(confidence=0.7)], busy)

    assert approved[0].action == ACTION_THROTTLE
    assert "distinct clients" in notes[0]


def test_a_confident_campaign_is_not_softened_by_client_variety():
    """
    Otherwise rotating the User-Agent enough would turn a block into a
    throttle, and the heuristic becomes an evasion route.
    """
    busy = traffic(agents=[f"Mozilla/5.0 (device {n})" for n in range(20)])
    approved, notes = review([decision(confidence=0.95)], busy)

    assert approved[0].action == ACTION_TEMP_BLOCK
    assert "applying temp_block anyway" in notes[0]


def test_few_clients_change_nothing():
    approved, notes = review([decision(confidence=0.7)], traffic(agents=("curl/8.4.0",)))

    assert approved[0].action == ACTION_TEMP_BLOCK
    assert notes == []


# --- not undoing our own working policy ---

def test_a_weaker_proposal_does_not_replace_a_standing_stronger_one():
    """
    Campaigns are re-decided every cycle. Without this, the quiet caused by a
    block could downgrade the block that caused the quiet.
    """
    store = MemoryStore()
    store.set("policy:203.0.113.5", json.dumps({"action": ACTION_ESCALATE}))

    approved, notes = review([decision(action=ACTION_THROTTLE)], store=store)

    assert approved == []
    assert "keeps standing escalate" in notes[0]


def test_a_stronger_proposal_replaces_a_standing_weaker_one():
    store = MemoryStore()
    store.set("policy:203.0.113.5", json.dumps({"action": ACTION_THROTTLE}))

    approved, _ = review([decision(action=ACTION_TEMP_BLOCK)], store=store)

    assert approved[0].action == ACTION_TEMP_BLOCK


def test_an_unreadable_standing_policy_does_not_block_the_cycle():
    store = MemoryStore()
    store.set("policy:203.0.113.5", "{not json")

    approved, _ = review([decision()], store=store)
    assert len(approved) == 1


# --- who each check binds ---

def test_a_human_passes_through_the_inferred_checks():
    """A person who says block anyway has seen something this cannot."""
    busy = traffic(agents=[f"Mozilla/5.0 (device {n})" for n in range(20)])
    approved, _ = review([decision(confidence=0.5, source="human")], busy)

    assert approved[0].action == ACTION_TEMP_BLOCK


def test_a_human_may_weaken_a_standing_policy():
    """Unblocking a false positive is the point of an override."""
    store = MemoryStore()
    store.set("policy:203.0.113.5", json.dumps({"action": ACTION_ESCALATE}))

    approved, _ = review(
        [decision(action=ACTION_THROTTLE, source="human")], store=store
    )

    assert approved[0].action == ACTION_THROTTLE


def test_a_human_cannot_police_an_allowlisted_range():
    """
    Declared configuration outranks an instruction typed in a hurry. This is
    one deliberate operator decision beating another, not the agent refusing
    a person.
    """
    approved, notes = review(
        [decision(source="human")], allowlist=("203.0.113.0/24",)
    )

    assert approved == []
    assert "allowlisted" in notes[0]


def test_a_human_is_still_capped_on_a_declared_shared_range():
    approved, _ = review(
        [decision(source="human")], shared_ranges=("203.0.113.0/24",)
    )

    assert approved[0].action == ACTION_THROTTLE
