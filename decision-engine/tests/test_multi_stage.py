"""
Four attacks from one actor are one attack in four phases.

Naming a campaign after its dominant detector reports the loudest phase and
silently drops the rest: an actor that hunted for secrets, attacked the login
it found and then probed the database was filed as "Brute Force", described as
"22 events from bruteforce on /api/login" when only 12 of those events were
bruteforce across three endpoints, and throttled.

Phases are coarser than detectors, because guessing filenames and climbing out
of a directory are both someone looking around. Only genuinely different
phases count as progression.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone

from iasg.campaigns.repository import CampaignRepository
from iasg.config import Settings
from iasg.correlation.agent import CorrelationAgent
from iasg.models import (
    ACTION_ESCALATE,
    CAMPAIGN_MULTI_STAGE,
    Evidence,
)
from iasg.runner import Runner
from iasg.store.memory import MemoryStore
from tools.seed_evidence import SCENARIOS

BASE = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
IP = "203.0.113.77"


def ev(offset, endpoint, detector, ip=IP, severity="high"):
    return Evidence(
        timestamp=BASE + timedelta(seconds=offset), ip=ip, endpoint=endpoint,
        method="GET", detector=detector, severity=severity,
        user_agent="curl/8.4.0", details={},
    )


def kill_chain(ip=IP, recon=4, creds=12, sqli=6):
    """Look around, attack the login, then probe the data layer."""
    events = []
    for n in range(recon):
        events.append(ev(n * 5, f"/secret{n}", "enumeration", ip))
    for n in range(creds):
        events.append(ev(300 + n * 5, "/api/login", "bruteforce", ip))
    for n in range(sqli):
        events.append(ev(900 + n * 5, "/api/search", "sqli", ip))
    return events


def analyse(events):
    return CorrelationAgent().analyse(events)


# --- recognising the phases ---

def test_a_kill_chain_is_one_campaign_not_three():
    campaigns = analyse(kill_chain())
    assert len(campaigns) == 1


def test_the_phases_are_named_in_the_order_they_happened():
    (campaign,) = analyse(kill_chain())
    assert campaign.stages == ["reconnaissance", "credential attack", "injection"]


def test_phases_are_ordered_by_observation_not_by_textbook():
    """A real attacker need not follow the expected sequence."""
    backwards = (
        [ev(n * 5, "/api/search", "sqli") for n in range(6)]
        + [ev(600 + n * 5, f"/secret{n}", "enumeration") for n in range(4)]
    )
    (campaign,) = analyse(backwards)

    assert campaign.stages == ["injection", "reconnaissance"]


def test_it_is_no_longer_named_after_its_loudest_phase():
    (campaign,) = analyse(kill_chain())

    assert campaign.type == CAMPAIGN_MULTI_STAGE
    assert campaign.type != "Brute Force"


def test_the_reason_stops_dropping_two_thirds_of_the_attack():
    (campaign,) = analyse(kill_chain())

    assert "reconnaissance -> credential attack -> injection" in campaign.reason
    assert "22 events" in campaign.reason
    # The old text claimed every event came from one detector on one path.
    assert "on /api/login" not in campaign.reason


# --- the rails: what must NOT count as progression ---

def test_one_stray_detection_does_not_stage_a_campaign():
    """Otherwise a single misfire promotes enforcement on an ordinary attack."""
    mostly_login = [ev(n * 5, "/api/login", "bruteforce") for n in range(20)]
    mostly_login.append(ev(500, "/admin", "enumeration"))

    (campaign,) = analyse(mostly_login)

    assert campaign.stages == ["credential attack"]
    assert campaign.type == "Brute Force"


def test_detectors_describing_the_same_phase_are_one_phase():
    """Guessing filenames and climbing out of a directory are both looking around."""
    (campaign,) = analyse(SCENARIOS["recon"]())

    assert campaign.stages == ["reconnaissance"]
    assert campaign.type == "Reconnaissance", "recon was reclassified as staged"


def test_single_phase_scenarios_are_untouched():
    for name, expected in (
        ("credential-stuffing", "Credential Stuffing"),
        ("brute-force", "Brute Force"),
        ("flood", "Distributed Flood"),
        ("sqli", "SQL Injection Probing"),
        ("recon", "Reconnaissance"),
    ):
        (campaign, *_) = analyse(SCENARIOS[name]())
        assert campaign.type == expected, f"{name} became {campaign.type}"
        assert len(campaign.stages) == 1


# --- phases arriving across separate cycles ---

def test_phases_accumulate_between_cycles():
    """A real intrusion is slower than one 30-second window."""
    repo = CampaignRepository(MemoryStore())

    (first,) = repo.merge(analyse([ev(n * 5, f"/secret{n}", "enumeration")
                                   for n in range(4)]))
    assert first.stages == ["reconnaissance"]
    assert first.type == "Reconnaissance"

    (second,) = repo.merge(analyse([ev(300 + n * 5, "/api/login", "bruteforce")
                                    for n in range(12)]))

    assert second.campaign_id == first.campaign_id
    assert second.stages == ["reconnaissance", "credential attack"]
    assert second.type == CAMPAIGN_MULTI_STAGE


def test_accumulated_stages_survive_storage():
    store = MemoryStore()
    repo = CampaignRepository(store)
    repo.merge(analyse([ev(n * 5, f"/secret{n}", "enumeration") for n in range(4)]))
    repo.merge(analyse([ev(300 + n * 5, "/api/login", "bruteforce")
                        for n in range(12)]))

    (reloaded,) = CampaignRepository(store).all()
    assert reloaded.stages == ["reconnaissance", "credential attack"]


def test_the_runner_escalates_an_actor_that_progresses():
    store = MemoryStore()
    runner = Runner(dataclasses.replace(Settings()), store)

    for e in [ev(n * 5, f"/secret{n}", "enumeration") for n in range(4)]:
        store.append("iasg:events", e.to_stream_fields())
    first = runner.cycle()
    assert first.campaigns[0].last_action != ACTION_ESCALATE

    for e in ([ev(300 + n * 5, "/api/login", "bruteforce") for n in range(12)]
              + [ev(900 + n * 5, "/api/search", "sqli") for n in range(6)]):
        store.append("iasg:events", e.to_stream_fields())
    second = runner.cycle()

    (campaign,) = second.campaigns
    assert campaign.stages == ["reconnaissance", "credential attack", "injection"]
    assert campaign.last_action == ACTION_ESCALATE
    assert store.read_group("iasg_alerts", "t", "c", 10), "no human was told"
