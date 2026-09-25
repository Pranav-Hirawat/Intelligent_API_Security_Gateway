"""
Closing the loop: an action that demonstrably failed is not simply repeated.

The control plane already recorded what it did and what became of it. Nothing
read any of it back -- the policy ladder saw confidence, severity and address
count and nothing else, so a campaign that shrugged off three blocks was
offered a fourth identical one.

The honest signal is narrow. A campaign going quiet after a block proves very
little, because a blocked address never reaches the detectors in the first
place. A campaign still running *through* a block proves the block was not
enough, and there are exactly two ways to observe that: it outlasted the policy
and came back, or it moved to addresses the policy did not cover.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone

from iasg.campaigns.repository import CampaignRepository
from iasg.config import Settings
from iasg.models import (
    ACTION_ESCALATE,
    ACTION_MONITOR,
    ACTION_TEMP_BLOCK,
    Campaign,
    Evidence,
)
from iasg.runner import Runner
from iasg.store.memory import MemoryStore

NOW = datetime.now(timezone.utc)

SIGNATURE = {
    "endpoint": "/api/login",
    "user_agent": "curl/8.4.0",
    "detector": "bruteforce",
    "subnet": "203.0.113",
}


def campaign(ips=("203.0.113.5",), confidence=0.8, severity="high", **overrides):
    fields = dict(
        campaign_id="",
        type="Credential Stuffing",
        confidence=confidence,
        ips=list(ips),
        reason="test",
        severity=severity,
        first_seen=NOW,
        last_seen=NOW,
        event_count=10,
        signature=dict(SIGNATURE),
    )
    fields.update(overrides)
    return Campaign(**fields)


def repo():
    return CampaignRepository(MemoryStore())


def contain(r: CampaignRepository, c: Campaign, action=ACTION_TEMP_BLOCK):
    """Act on a campaign, then let it go quiet until it is marked contained."""
    c.last_action = action
    r.save(c)
    for _ in range(4):
        r.review(seen_ids=set())
    assert r.all()[0].status == "contained"


# --- observing that enforcement failed ---

def test_waiting_out_a_block_counts_against_it():
    r = repo()
    (first,) = r.merge([campaign()])
    contain(r, first)

    (resumed,) = r.merge([campaign()])

    assert resumed.persistence == 1


def test_moving_to_new_addresses_counts_against_it():
    r = repo()
    (first,) = r.merge([campaign(["203.0.113.5"])])
    first.last_action = ACTION_TEMP_BLOCK
    r.save(first)

    (resumed,) = r.merge([campaign(["198.51.100.60"])])

    assert resumed.persistence == 1
    assert resumed.rotations == 1


def test_a_campaign_we_only_watched_is_not_held_against_us():
    """
    Nothing was enforced, so its carrying on says nothing about enforcement.

    Rising confidence is what escalates a monitored campaign, and that already
    happens on every merge.
    """
    r = repo()
    (first,) = r.merge([campaign()])
    contain(r, first, action=ACTION_MONITOR)

    (resumed,) = r.merge([campaign()])

    assert resumed.persistence == 0


def test_an_unacted_campaign_is_not_held_against_us():
    r = repo()
    (first,) = r.merge([campaign()])
    contain(r, first, action="")

    (resumed,) = r.merge([campaign()])

    assert resumed.persistence == 0


def test_ordinary_continuing_evidence_is_not_counted():
    """
    Evidence generated just before a block landed must not read as failure.

    Only a genuine gap or genuinely new infrastructure counts, which is why
    this needs neither a containment nor a rotation to have happened.
    """
    r = repo()
    (first,) = r.merge([campaign(["203.0.113.5", "203.0.113.9"])])
    first.last_action = ACTION_TEMP_BLOCK
    r.save(first)

    (again,) = r.merge([campaign(["203.0.113.5", "203.0.113.9"])])

    assert again.persistence == 0


def test_persistence_accumulates():
    r = repo()
    (first,) = r.merge([campaign(["203.0.113.5"])])
    first.last_action = ACTION_TEMP_BLOCK
    r.save(first)

    (second,) = r.merge([campaign(["198.51.100.60"])])
    second.last_action = ACTION_TEMP_BLOCK
    r.save(second)

    (third,) = r.merge([campaign(["192.0.2.70"])])

    assert third.persistence == 2


def test_persistence_survives_storage():
    store = MemoryStore()
    r = CampaignRepository(store)
    (first,) = r.merge([campaign(["203.0.113.5"])])
    first.last_action = ACTION_TEMP_BLOCK
    r.save(first)
    r.merge([campaign(["198.51.100.60"])])

    (reloaded,) = CampaignRepository(store).all()
    assert reloaded.persistence == 1


# --- the whole loop, through the runner ---

def seed(store, prefix="203.0.113", octets=(5, 9, 14, 21, 33, 40), offset=0):
    for i, last in enumerate(octets):
        for n in range(6):
            store.append("iasg:events", Evidence(
                timestamp=NOW + timedelta(seconds=offset + i * 7 + n),
                ip=f"{prefix}.{last}", endpoint="/api/login", detector="bruteforce",
                severity="high", user_agent="curl/8.4.0",
                details={"failedLogins": 9, "distinctUsers": 5},
            ).to_stream_fields())


def test_the_agent_reacts_to_its_own_enforcement_failing():
    store = MemoryStore()
    r = Runner(dataclasses.replace(Settings()), store)

    seed(store)
    first = r.cycle()
    assert first.campaigns[0].persistence == 0

    # Blocked, so the attacker moves to a network we never covered.
    seed(store, prefix="198.51.100", octets=(60, 61, 62, 63, 64, 65), offset=600)
    second = r.cycle()

    (campaign_now,) = second.campaigns
    assert campaign_now.campaign_id == first.campaigns[0].campaign_id
    assert campaign_now.persistence == 1, "the rotation was not read as failure"
    assert campaign_now.last_action == ACTION_ESCALATE
