"""
Every seeded scenario must correlate into the campaign it is meant to show.

These are the demo. If one silently stops producing the shape it advertises,
the first anyone notices is mid-presentation.
"""

from __future__ import annotations

import pytest

from iasg.config import Settings
from iasg.correlation.agent import CorrelationAgent
from iasg.runner import Runner
from iasg.store.memory import MemoryStore
from tools.seed_evidence import SCENARIOS


def analyse(name):
    return CorrelationAgent().analyse(SCENARIOS[name]())


def policies_written(name):
    """What the real cycle turns a scenario into: the policy keys the gateway would read."""
    store = MemoryStore()
    for e in SCENARIOS[name]():
        store.append("iasg:events", e.to_stream_fields())
    Runner(Settings(), store).cycle()
    return store.keys("policy:*")


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_every_scenario_produces_evidence(name):
    assert SCENARIOS[name](), f"{name} generated nothing"


@pytest.mark.parametrize(
    "name,expected",
    [
        ("credential-stuffing", "Credential Stuffing"),
        ("brute-force", "Brute Force"),
        ("flood", "Distributed Flood"),
        ("enumeration", "Reconnaissance"),
        ("path-traversal", "Reconnaissance"),
        ("recon", "Reconnaissance"),
        ("sqli", "SQL Injection Probing"),
    ],
)
def test_scenario_is_classified_as_advertised(name, expected):
    campaigns = analyse(name)
    assert campaigns, f"{name} formed no campaign"
    assert campaigns[0].type == expected


# The shape, not the detector, is what separates these two.
def test_one_ip_one_account_is_brute_force_not_stuffing():
    (campaign,) = analyse("brute-force")

    assert campaign.type == "Brute Force"
    assert len(campaign.ips) == 1
    assert analyse("credential-stuffing")[0].type == "Credential Stuffing"


# The case that could not be actioned at all before solo confidence existed.
def test_a_sustained_lone_attacker_is_blockable():
    (campaign,) = analyse("brute-force")

    assert campaign.confidence >= 0.75
    assert policies_written("brute-force")


def test_every_attack_scenario_is_actioned():
    for name in ("credential-stuffing", "brute-force", "flood",
                 "enumeration", "path-traversal", "recon", "sqli"):
        assert policies_written(name), f"{name} produced no policy"


# The one scenario that must NOT group. Unrelated traffic looking like a
# campaign is worse than missing a real one.
def test_noise_forms_no_campaign():
    assert analyse("noise") == []


def test_traversal_and_enumeration_share_a_campaign_type():
    """Different detectors, same conclusion: someone is looking around."""
    assert analyse("enumeration")[0].type == analyse("path-traversal")[0].type


def test_recon_covers_both_scanners():
    campaign = analyse("recon")[0]

    assert len(campaign.ips) == 2, "recon should carry the enumeration and traversal hosts"
    assert campaign.event_count > len(SCENARIOS["enumeration"]())


def test_mixed_scenarios_stay_separate():
    """Run together, the campaigns must not collapse into one."""
    events = (
        SCENARIOS["credential-stuffing"]()
        + SCENARIOS["flood"]()
        + SCENARIOS["sqli"]()
    )
    campaigns = CorrelationAgent().analyse(events)

    types = {c.type for c in campaigns}
    assert {"Credential Stuffing", "Distributed Flood", "SQL Injection Probing"} <= types


def test_scenarios_carry_the_fields_the_correlator_reads():
    for name in sorted(SCENARIOS):
        for e in SCENARIOS[name]():
            assert e.ip, f"{name}: evidence with no ip"
            assert e.detector, f"{name}: evidence with no detector"
            assert e.severity in ("low", "medium", "high"), f"{name}: bad severity"
            assert e.timestamp.tzinfo is not None, f"{name}: naive timestamp"
