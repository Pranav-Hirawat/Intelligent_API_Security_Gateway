"""
The durable path, exercised against a real Postgres.

Skipped unless IASG_TEST_POSTGRES_URL points at a database the test may write
to -- these tests create and truncate tables, so they must never be aimed at
anything that matters. Everything else in the suite runs without a database,
which is the point of the store abstraction.

    createdb iasg_test
    IASG_TEST_POSTGRES_URL=postgresql://iasg_user:changeme@localhost:5432/iasg_test \
        .venv/bin/python -m pytest tests/test_postgres.py
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from iasg.adaptive.baseline import BaselineSummary, EndpointKey
from iasg.adaptive.config import AdaptiveConfig
from iasg.adaptive.lifecycle import STATUS_APPROVED, Recommendation
from iasg.campaigns.repository import CampaignRepository
from iasg.config import Settings
from iasg.feedback.memory import FeedbackMemory
from iasg.models import ACTION_TEMP_BLOCK, ACTION_THROTTLE, Campaign, PolicyDecision
from iasg.store.memory import MemoryStore

DSN = os.getenv("IASG_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not DSN, reason="set IASG_TEST_POSTGRES_URL to run the Postgres tests"
)


@pytest.fixture
def db():
    from iasg.store.postgres import Database

    database = Database(DSN)
    with database._conn.cursor() as cur:
        cur.execute(
            "TRUNCATE policy_audit, policy_recommendations, endpoint_baselines,"
            " adaptive_settings, campaigns, feedback"
        )
        cur.execute("SELECT setval('campaign_id_seq', 1, false)")
    database.adaptive.ensure_config(AdaptiveConfig())
    yield database
    database.close()


def _campaign(**kw) -> Campaign:
    now = datetime.now(timezone.utc)
    fields = dict(
        campaign_id="1",
        type="Credential Stuffing",
        confidence=0.9,
        ips=["203.0.113.5", "203.0.113.9"],
        reason="2 IPs sharing same endpoint",
        severity="high",
        first_seen=now - timedelta(minutes=5),
        last_seen=now,
        event_count=20,
        signature={"endpoint": "/api/login", "user_agent": "curl/8.4.0"},
    )
    fields.update(kw)
    return Campaign(**fields)


def test_a_campaign_survives_being_written_and_read_back(db):
    db.campaigns.save(_campaign())
    (loaded,) = db.campaigns.all()

    assert loaded.campaign_id == "1"
    assert loaded.type == "Credential Stuffing"
    assert loaded.ips == ["203.0.113.5", "203.0.113.9"]
    assert loaded.signature["endpoint"] == "/api/login"


def test_timestamps_come_back_in_utc(db):
    """
    Postgres returns TIMESTAMPTZ in the session's zone. The rest of the project
    formats times without converting, so a campaign whose start printed as
    local and end as UTC read as ending before it began.
    """
    db.campaigns.save(_campaign())
    (loaded,) = db.campaigns.all()

    assert loaded.first_seen.utcoffset() == timedelta(0)
    assert loaded.last_seen.utcoffset() == timedelta(0)
    assert loaded.first_seen <= loaded.last_seen


def test_saving_the_same_campaign_twice_updates_rather_than_duplicates(db):
    db.campaigns.save(_campaign())
    db.campaigns.save(_campaign(event_count=99, status="contained"))

    campaigns = db.campaigns.all()
    assert len(campaigns) == 1
    assert campaigns[0].event_count == 99
    assert campaigns[0].status == "contained"


def test_ids_keep_climbing_across_reconnects(db):
    first = db.campaigns.next_id()
    db.campaigns.save(_campaign(campaign_id=first))

    from iasg.store.postgres import Database

    reconnected = Database(DSN)
    try:
        assert int(reconnected.campaigns.next_id()) > int(first)
    finally:
        reconnected.close()


def test_campaigns_outside_the_working_set_are_not_offered_to_the_correlator(db):
    old = datetime.now(timezone.utc) - timedelta(hours=30)
    db.campaigns.save(_campaign(first_seen=old, last_seen=old))

    # Gone from the working set, but never deleted -- history is the reason
    # this store exists.
    assert db.campaigns.all() == []
    with db._conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM campaigns")
        assert cur.fetchone()[0] == 1


def test_the_repository_uses_the_database_when_given_one(db):
    repo = CampaignRepository(MemoryStore(), persistence=db.campaigns)
    repo.save(_campaign())

    # Straight out of Postgres, with nothing in the key-value store.
    (loaded,) = repo.all()
    assert loaded.campaign_id == "1"


def test_a_wiped_key_value_store_does_not_lose_the_investigation(db):
    """The whole point: Redis restarting must not restart the investigation."""
    store = MemoryStore()
    repo = CampaignRepository(store, persistence=db.campaigns)
    fresh = _campaign(campaign_id=repo._next_id())
    repo.save(fresh)

    # The restart.
    wiped = MemoryStore()
    after = CampaignRepository(wiped, persistence=db.campaigns)

    (survivor,) = after.all()
    assert survivor.campaign_id == fresh.campaign_id
    assert survivor.event_count == 20


def test_corrections_accumulate_in_the_database(db):
    memory = FeedbackMemory(MemoryStore(), Settings(), persistence=db.feedback)

    memory.record("Brute Force", "throttle", "temp_block")
    memory.record("Brute Force", "throttle", "temp_block")

    assert memory.bias_for("Brute Force") == 1
    assert db.feedback.all()["Brute Force"] == {"up": 2, "down": 0}


def test_opposite_corrections_cancel(db):
    memory = FeedbackMemory(MemoryStore(), Settings(), persistence=db.feedback)

    memory.record("Reconnaissance", "throttle", "temp_block")
    memory.record("Reconnaissance", "temp_block", "throttle")

    assert memory.bias_for("Reconnaissance") == 0


def test_campaigns_reach_the_key_value_store_too(db):
    """
    Postgres is the record; Redis stays the read path.

    The dashboard, like the gateway, reads Redis. When campaigns moved to
    Postgres they stopped being written there at all, and the console's
    campaign and feedback panels silently went blank while policy kept
    working -- the failure looked like "no attacks" rather than an outage.
    """
    store = MemoryStore()
    repo = CampaignRepository(store, persistence=db.campaigns)
    repo.save(_campaign())

    assert store.get("campaign:1"), "campaign missing from the read path"
    assert db.campaigns.all(), "campaign missing from the record"


def test_warming_rebuilds_the_read_path_after_a_wipe(db):
    """A restart empties Redis but not Postgres, and readers must not care."""
    db.campaigns.save(_campaign())

    wiped = MemoryStore()
    repo = CampaignRepository(wiped, persistence=db.campaigns)
    assert wiped.get("campaign:1") is None

    assert repo.warm() == 1
    assert wiped.get("campaign:1")


def test_corrections_reach_the_key_value_store_too(db):
    store = MemoryStore()
    memory = FeedbackMemory(store, Settings(), persistence=db.feedback)

    memory.record("Brute Force", "throttle", "temp_block")

    assert json.loads(store.get("feedback:Brute Force")) == {"up": 1, "down": 0}


def test_warming_rebuilds_the_feedback_read_path(db):
    db.feedback.bump("Brute Force", "up")

    wiped = MemoryStore()
    memory = FeedbackMemory(wiped, Settings(), persistence=db.feedback)

    assert memory.warm() == 1
    assert json.loads(wiped.get("feedback:Brute Force")) == {"up": 1, "down": 0}


def test_adaptive_configuration_and_baseline_survive_a_restart(db):
    configured = AdaptiveConfig.from_mapping({"mode": "manual", "version": 7})
    with db._conn.cursor() as cur:
        cur.execute(
            "UPDATE adaptive_settings SET version=%s,mode=%s,config=%s::jsonb"
            " WHERE singleton_id=1",
            (configured.version, configured.mode, json.dumps(configured.to_dict())),
        )
    baseline = BaselineSummary(
        method="POST", route_template="/api/login", sample_count=8,
        statistic=4.0, mad=1.0, derived_threshold=7, observed_rate=6,
        last_update=datetime.now(timezone.utc), version=2, ready=True,
        samples=[3, 4, 4, 5],
    )
    db.adaptive.save_baseline(baseline)

    assert db.adaptive.load_config(AdaptiveConfig()).mode == "manual"
    loaded = db.adaptive.get_baseline(EndpointKey.of("POST", "/api/login"))
    assert loaded.ready and loaded.derived_threshold == 7
    assert loaded.samples == [3.0, 4.0, 4.0, 5.0]


def test_loading_a_legacy_config_repairs_the_dashboard_document(db):
    """A retired field cannot keep returning through the dashboard form."""
    stale = AdaptiveConfig().to_dict()
    stale["mode"] = "manual"
    stale["risk"]["ml_weight"] = 0.05
    with db._conn.cursor() as cur:
        cur.execute(
            "UPDATE adaptive_settings SET version=%s,mode=%s,config=%s::jsonb"
            " WHERE singleton_id=1",
            (7, stale["mode"], json.dumps(stale)),
        )

    loaded = db.adaptive.load_config(AdaptiveConfig())

    with db._conn.cursor() as cur:
        cur.execute("SELECT version,mode,config FROM adaptive_settings WHERE singleton_id=1")
        version, mode, persisted = cur.fetchone()
    persisted = persisted if isinstance(persisted, dict) else json.loads(persisted)

    assert loaded.version == version == 7
    assert mode == "manual"
    assert "ml_weight" not in persisted["risk"]
    assert persisted == json.loads(json.dumps(loaded.to_dict()))


def test_policy_lifecycle_and_audit_are_durable(db):
    now = datetime.now(timezone.utc)
    decision = PolicyDecision(
        ip="203.0.113.5", action=ACTION_THROTTLE, campaign_id="c1",
        confidence=0.9, ttl_seconds=300, requests_per_minute=20,
        source="approved", issued_by="analyst", issued_at=now,
    )
    db.adaptive.save_recommendation(
        Recommendation(decision, STATUS_APPROVED, now, now)
    )
    db.adaptive.mark_status(decision.policy_id, "active", "control-plane")

    assert db.adaptive.approved_recommendations() == []
    with db._conn.cursor() as cur:
        cur.execute(
            "SELECT status FROM policy_recommendations WHERE policy_id=%s",
            (decision.policy_id,),
        )
        assert cur.fetchone()[0] == "active"
        cur.execute(
            "SELECT event,actor FROM policy_audit WHERE policy_id=%s ORDER BY audit_id",
            (decision.policy_id,),
        )
        assert cur.fetchall() == [("approved", "analyst"), ("active", "control-plane")]


def test_stored_recommendation_payload_keeps_the_canonical_action(db):
    # decision.to_json() rewrites temp_block to "temporary_block" for an
    # adaptive-sourced decision -- that spelling is the Redis wire contract,
    # required only at the moment a decision is actually written to
    # policy:<ip>. The dashboard reads this payload back and validates an
    # approval against its own ["monitor", "throttle", "temp_block"]
    # vocabulary; storing the wire spelling here made an unedited approval
    # of a pending temp_block recommendation fail as "invalid action".
    now = datetime.now(timezone.utc)
    decision = PolicyDecision(
        ip="203.0.113.9", action=ACTION_TEMP_BLOCK, campaign_id="c2",
        confidence=0.9, ttl_seconds=900, source="adaptive",
        issued_by="control-plane", issued_at=now,
    )
    db.adaptive.save_recommendation(
        Recommendation(decision, STATUS_APPROVED, now, now)
    )

    with db._conn.cursor() as cur:
        cur.execute(
            "SELECT payload FROM policy_recommendations WHERE policy_id=%s",
            (decision.policy_id,),
        )
        payload = cur.fetchone()[0]

    assert payload["action"] == ACTION_TEMP_BLOCK
    # The Redis wire format is unaffected -- it still rewrites the action for
    # exactly this combination of action and source.
    assert json.loads(decision.to_json())["action"] == "temporary_block"
