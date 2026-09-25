"""
Tracking a campaign after the attacker changes every address.

Blocking works, which is precisely why an attacker who can afford to will move.
Matching on addresses alone means each rotation looks like a brand new campaign
and the investigation restarts from nothing. What they cannot cheaply change is
the behaviour, so that is the fallback.

The risk in that fallback is over-merging: hiding one attacker inside another's
campaign is worse than carrying a duplicate. Most of these tests are the rails.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from iasg.adaptive.config import AdaptiveConfig, GuardrailConfig
from iasg.campaigns.repository import CONTINUATION_WINDOW, CampaignRepository
from iasg.models import Campaign
from iasg.store.memory import MemoryStore

NOW = datetime.now(timezone.utc)

SIGNATURE = {
    "endpoint": "/api/login",
    "user_agent": "curl/8.4.0",
    "detector": "bruteforce",
    "subnet": "203.0.113",
}


def campaign(ips, signature=None, last_seen=NOW, **overrides):
    fields = dict(
        campaign_id="",
        type="Credential Stuffing",
        confidence=0.8,
        ips=list(ips),
        reason="test",
        severity="high",
        first_seen=last_seen,
        last_seen=last_seen,
        event_count=10,
        signature=dict(SIGNATURE if signature is None else signature),
    )
    fields.update(overrides)
    return Campaign(**fields)


def repo():
    return CampaignRepository(MemoryStore())


# --- the case this exists for ---

def test_a_rotated_campaign_is_recognised_not_renumbered():
    r = repo()
    (first,) = r.merge([campaign(["203.0.113.5", "203.0.113.9"])])

    # Same operation, not one address in common.
    (again,) = r.merge([campaign(["198.51.100.60", "198.51.100.61"])])

    assert again.campaign_id == first.campaign_id, "rotation started a new campaign"
    assert len(r.all()) == 1, "the same attacker is stored twice"


def test_the_rotated_addresses_join_the_campaign():
    r = repo()
    r.merge([campaign(["203.0.113.5", "203.0.113.9"])])
    (again,) = r.merge([campaign(["198.51.100.60", "198.51.100.61"])])

    assert set(again.ips) == {
        "203.0.113.5", "203.0.113.9", "198.51.100.60", "198.51.100.61",
    }


def test_rotations_are_counted():
    r = repo()
    r.merge([campaign(["203.0.113.5"])])
    r.merge([campaign(["198.51.100.60"])])
    (third,) = r.merge([campaign(["192.0.2.70"])])

    assert third.rotations == 2


def test_a_rotation_says_so_in_the_outcome():
    r = repo()
    r.merge([campaign(["203.0.113.5"])])
    (again,) = r.merge([campaign(["198.51.100.60", "198.51.100.61"])])

    assert "2 previously unseen addresses" in again.outcome
    assert "behaviour" in again.outcome


def test_overlapping_ips_are_not_counted_as_a_rotation():
    r = repo()
    r.merge([campaign(["203.0.113.5", "203.0.113.9"])])
    (again,) = r.merge([campaign(["203.0.113.5", "203.0.113.9", "203.0.113.14"])])

    assert again.rotations == 0, "a campaign that never moved was called a rotation"


def test_rotations_survive_storage():
    store = MemoryStore()
    r = CampaignRepository(store)
    r.merge([campaign(["203.0.113.5"])])
    r.merge([campaign(["198.51.100.60"])])

    # A fresh repository over the same store, as after a restart.
    (reloaded,) = CampaignRepository(store).all()
    assert reloaded.rotations == 1


# --- the rails: what must NOT merge ---

def test_a_different_detector_is_a_different_campaign():
    r = repo()
    r.merge([campaign(["203.0.113.5"])])

    sqli = dict(SIGNATURE, detector="sqli")
    (other,) = r.merge([campaign(["198.51.100.60"], signature=sqli)])

    assert other.campaign_id == "2", "a SQLi probe absorbed into a brute force campaign"


def test_a_different_endpoint_is_a_different_campaign():
    r = repo()
    r.merge([campaign(["203.0.113.5"])])

    elsewhere = dict(SIGNATURE, endpoint="/api/search")
    (other,) = r.merge([campaign(["198.51.100.60"], signature=elsewhere)])

    assert other.campaign_id == "2"


def test_a_different_user_agent_is_a_different_campaign():
    """Endpoint plus subnet alone must sit under the threshold."""
    r = repo()
    r.merge([campaign(["203.0.113.5"])])

    other_tool = dict(SIGNATURE, user_agent="python-requests/2.32")
    (other,) = r.merge([campaign(["198.51.100.60"], signature=other_tool)])

    assert other.campaign_id == "2"


def test_an_empty_signature_matches_nothing():
    """Older stored campaigns have no signature; they must not swallow the next one."""
    r = repo()
    r.merge([campaign(["203.0.113.5"], signature={})])
    (other,) = r.merge([campaign(["198.51.100.60"], signature={})])

    assert other.campaign_id == "2"
    assert len(r.all()) == 2


def test_a_partial_signature_matches_nothing():
    r = repo()
    r.merge([campaign(["203.0.113.5"])])

    partial = {"endpoint": "/api/login"}
    (other,) = r.merge([campaign(["198.51.100.60"], signature=partial)])

    assert other.campaign_id == "2"


def test_the_same_behaviour_much_later_is_a_new_campaign():
    """A scanner returning next month is not this campaign resuming."""
    r = repo()
    r.merge([campaign(["203.0.113.5"])])

    later = NOW + CONTINUATION_WINDOW + timedelta(minutes=5)
    (other,) = r.merge([campaign(["198.51.100.60"], last_seen=later)])

    assert other.campaign_id == "2"


def test_a_block_expiring_still_counts_as_the_same_campaign():
    """The window has to outlast the longest policy TTL or rotation never matches."""
    assert CONTINUATION_WINDOW.total_seconds() > GuardrailConfig().maximum_policy_duration_seconds


def test_raising_the_policy_ceiling_widens_the_continuation_window():
    """
    CONTINUATION_WINDOW's own stated invariant is "longer than the longest
    policy TTL". maximum_policy_duration_seconds can be configured up to 24h,
    well past the fixed 2h default -- apply_config is what keeps the promise
    true instead of letting a raised ceiling silently outlast the window.
    """
    r = repo()
    config = AdaptiveConfig.from_mapping(
        {"guardrails": {"maximum_policy_duration_seconds": 21_600}}  # 6h
    )
    r.apply_config(config)
    r.merge([campaign(["203.0.113.5"])])

    # 8h later: past the fixed 2h default, inside the derived 24h window.
    later = NOW + timedelta(hours=8)
    (other,) = r.merge([campaign(["198.51.100.60"], last_seen=later)])

    assert other.campaign_id == "1", "the 6h ceiling should have widened the window to 24h"


# --- shared addresses still win ---

def test_shared_addresses_match_even_when_behaviour_differs():
    r = repo()
    (first,) = r.merge([campaign(["203.0.113.5", "203.0.113.9"])])

    moved_on = dict(SIGNATURE, endpoint="/api/admin", user_agent="sqlmap/1.8")
    (again,) = r.merge([
        campaign(["203.0.113.5", "203.0.113.9"], signature=moved_on)
    ])

    assert again.campaign_id == first.campaign_id
    assert again.rotations == 0


def test_a_contained_campaign_reopens_on_rotation():
    """The usual shape: blocked, goes quiet, returns on fresh addresses."""
    r = repo()
    (first,) = r.merge([campaign(["203.0.113.5"])])
    first.last_action = "temp_block"
    r.save(first)

    for _ in range(4):
        r.review(seen_ids=set())
    assert r.all()[0].status == "contained"

    (resumed,) = r.merge([campaign(["198.51.100.60"])])

    assert resumed.campaign_id == first.campaign_id
    assert resumed.status == "active"
    assert resumed.rotations == 1
    assert "temp_block" in resumed.outcome
    assert "behaviour" in resumed.outcome
