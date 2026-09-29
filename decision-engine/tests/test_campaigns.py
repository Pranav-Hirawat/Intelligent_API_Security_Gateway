"""Campaign memory: continuing an investigation rather than restarting it."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from iasg.campaigns.repository import CONTAINED_AFTER, CampaignRepository
from iasg.models import Campaign
from iasg.store.memory import MemoryStore

NOW = datetime.now(timezone.utc)


def campaign(ips, confidence=0.8, ctype="Credential Stuffing"):
    return Campaign(
        campaign_id="",
        type=ctype,
        confidence=confidence,
        ips=list(ips),
        reason="test",
        severity="high",
        first_seen=NOW,
        last_seen=NOW,
        event_count=10,
    )


def test_new_campaign_gets_an_id():
    repo = CampaignRepository(MemoryStore())
    (saved,) = repo.merge([campaign(["203.0.113.5"])])
    assert saved.campaign_id == "1"


def test_ids_increment():
    repo = CampaignRepository(MemoryStore())
    repo.merge([campaign(["203.0.113.5"])])
    (second,) = repo.merge([campaign(["198.51.100.9"])])
    assert second.campaign_id == "2"


def test_overlapping_ips_merge_into_the_same_campaign():
    repo = CampaignRepository(MemoryStore())
    (first,) = repo.merge([campaign(["203.0.113.5", "203.0.113.9"])])
    (again,) = repo.merge([campaign(["203.0.113.5", "203.0.113.9", "203.0.113.14"])])

    assert again.campaign_id == first.campaign_id
    assert len(repo.all()) == 1
    assert "203.0.113.14" in again.ips


def test_merging_accumulates_evidence():
    repo = CampaignRepository(MemoryStore())
    repo.merge([campaign(["203.0.113.5", "203.0.113.9"])])
    (again,) = repo.merge([campaign(["203.0.113.5", "203.0.113.9"])])
    assert again.event_count == 20


def test_repeated_sightings_raise_confidence():
    repo = CampaignRepository(MemoryStore())
    (first,) = repo.merge([campaign(["203.0.113.5", "203.0.113.9"], confidence=0.7)])
    (again,) = repo.merge([campaign(["203.0.113.5", "203.0.113.9"], confidence=0.7)])
    assert again.confidence > first.confidence


def test_confidence_never_exceeds_one():
    repo = CampaignRepository(MemoryStore())
    ips = ["203.0.113.5", "203.0.113.9"]
    for _ in range(10):
        (c,) = repo.merge([campaign(ips, confidence=1.0)])
    assert c.confidence == 1.0


def test_unrelated_ips_create_a_separate_campaign():
    repo = CampaignRepository(MemoryStore())
    repo.merge([campaign(["203.0.113.5"])])
    repo.merge([campaign(["198.51.100.9"])])
    assert len(repo.all()) == 2


def test_campaign_survives_a_save_and_load():
    store = MemoryStore()
    (saved,) = CampaignRepository(store).merge([campaign(["203.0.113.5"])])
    saved.explanation = "a paragraph"
    CampaignRepository(store).save(saved)

    (loaded,) = CampaignRepository(store).all()
    assert loaded.type == "Credential Stuffing"
    assert loaded.explanation == "a paragraph"
    assert loaded.ips == ["203.0.113.5"]


def test_last_seen_moves_forward_on_merge():
    repo = CampaignRepository(MemoryStore())
    repo.merge([campaign(["203.0.113.5", "203.0.113.9"])])

    later = campaign(["203.0.113.5", "203.0.113.9"])
    later.last_seen = NOW + timedelta(minutes=5)
    (again,) = repo.merge([later])

    assert again.last_seen > NOW


# --- the feedback loop: did acting on a campaign change anything? ---

def test_a_campaign_seen_this_cycle_stays_active():
    repo = CampaignRepository(MemoryStore())
    (stored,) = repo.merge([campaign(["203.0.113.5"])])

    repo.review({stored.campaign_id})

    assert repo.all()[0].status == "active"
    assert repo.all()[0].quiet_cycles == 0


def test_quiet_cycles_accumulate():
    repo = CampaignRepository(MemoryStore())
    repo.merge([campaign(["203.0.113.5"])])

    for expected in (1, 2):
        repo.review(set())
        assert repo.all()[0].quiet_cycles == expected
        assert repo.all()[0].status == "active"


def test_campaign_is_contained_after_enough_quiet_cycles():
    repo = CampaignRepository(MemoryStore())
    (stored,) = repo.merge([campaign(["203.0.113.5"])])
    stored.last_action = "temp_block"
    repo.save(stored)

    for _ in range(CONTAINED_AFTER):
        repo.review(set())

    done = repo.all()[0]
    assert done.status == "contained"
    assert "temp_block" in done.outcome


def test_evidence_resets_the_quiet_counter():
    repo = CampaignRepository(MemoryStore())
    (stored,) = repo.merge([campaign(["203.0.113.5"])])

    repo.review(set())
    repo.merge([campaign(["203.0.113.5"])])

    assert repo.all()[0].quiet_cycles == 0


# A block expires and the attacker comes back: reopen what we know, do not
# start a second campaign about the same machines.
def test_a_contained_campaign_reopens_rather_than_duplicating():
    repo = CampaignRepository(MemoryStore())
    (stored,) = repo.merge([campaign(["203.0.113.5", "203.0.113.9"])])
    stored.last_action = "temp_block"
    repo.save(stored)

    for _ in range(CONTAINED_AFTER):
        repo.review(set())
    assert repo.all()[0].status == "contained"

    repo.merge([campaign(["203.0.113.5", "203.0.113.9"])])

    reopened = repo.all()
    assert len(reopened) == 1, "a duplicate campaign was created"
    assert reopened[0].status == "active"
    assert "resumed" in reopened[0].outcome


def test_contained_campaigns_are_not_reviewed_again():
    repo = CampaignRepository(MemoryStore())
    repo.merge([campaign(["203.0.113.5"])])

    for _ in range(CONTAINED_AFTER):
        repo.review(set())

    before = repo.all()[0].quiet_cycles
    repo.review(set())

    assert repo.all()[0].quiet_cycles == before, "a closed campaign kept ticking"


def test_review_survives_a_round_trip_through_storage():
    store = MemoryStore()
    repo = CampaignRepository(store)
    (stored,) = repo.merge([campaign(["203.0.113.5"])])
    stored.last_action = "throttle"
    repo.save(stored)
    repo.review(set())

    # A fresh repository reading the same store must see the same state.
    reloaded = CampaignRepository(store).all()[0]
    assert reloaded.quiet_cycles == 1
    assert reloaded.last_action == "throttle"
