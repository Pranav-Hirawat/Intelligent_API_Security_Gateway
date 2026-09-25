"""
The recommendation lifecycle has an in-memory repository for tests and a
Postgres one for production. The runner relies on both answering the same
way, so each property runs against both; the Postgres half needs
IASG_TEST_POSTGRES_URL.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from iasg.adaptive.config import AdaptiveConfig
from iasg.adaptive.lifecycle import (
    STATUS_ACTIVE,
    STATUS_APPROVED,
    STATUS_PENDING,
    MemoryLifecycleRepository,
    Recommendation,
)
from iasg.config import Settings
from iasg.models import ACTION_THROTTLE, PolicyDecision
from iasg.store.postgres import open_database

DSN = os.getenv("IASG_TEST_POSTGRES_URL")
NOW = datetime.now(timezone.utc)


@pytest.fixture(params=["memory", "postgres"])
def repo(request):
    if request.param == "memory":
        yield MemoryLifecycleRepository()
        return
    if not DSN:
        pytest.skip("set IASG_TEST_POSTGRES_URL to run the Postgres half")
    from iasg.store.postgres import Database

    db = Database(DSN)
    with db._conn.cursor() as cur:
        cur.execute("TRUNCATE policy_audit, policy_recommendations, adaptive_settings")
    db.adaptive.ensure_config(AdaptiveConfig())
    yield db.adaptive
    db.close()


def decision(ip="203.0.113.5", route="/api/login", issued_at=NOW, ttl=900):
    return PolicyDecision(
        ip=ip, action=ACTION_THROTTLE, campaign_id="c1", confidence=0.9,
        ttl_seconds=ttl, requests_per_minute=20, method="POST",
        route_template=route, issued_at=issued_at,
    )


def save(repo, d, status, at=NOW):
    repo.save_recommendation(Recommendation(d, status, at, at))


def test_only_approved_rows_are_offered_for_activation(repo):
    approved, pending = decision(), decision(ip="203.0.113.6")
    save(repo, approved, STATUS_APPROVED)
    save(repo, pending, STATUS_PENDING)

    assert [d.policy_id for d in (r.decision for r in repo.approved_recommendations())] == [approved.policy_id]

    repo.mark_status(approved.policy_id, STATUS_ACTIVE, "control-plane")
    assert repo.approved_recommendations() == []


def test_last_for_scope_is_the_newest_row_for_that_endpoint(repo):
    older = decision()
    newer = decision()
    other_route = decision(route="/api/orders")
    save(repo, older, STATUS_ACTIVE, NOW - timedelta(minutes=5))
    save(repo, newer, STATUS_PENDING, NOW)
    save(repo, other_route, STATUS_ACTIVE, NOW + timedelta(minutes=1))

    found = repo.last_for_scope(decision())
    assert found is not None and found.decision.policy_id == newer.policy_id
    assert repo.last_for_scope(decision(ip="198.51.100.1")) is None


# Enforcement expires on its own; the record of it must follow.
def test_only_active_policies_past_their_expiry_are_expired(repo):
    lapsed = decision(issued_at=NOW - timedelta(hours=1), ttl=60)
    live = decision(ip="203.0.113.6")
    approved_but_lapsed = decision(ip="203.0.113.7", issued_at=NOW - timedelta(hours=1), ttl=60)
    save(repo, lapsed, STATUS_ACTIVE)
    save(repo, live, STATUS_ACTIVE)
    save(repo, approved_but_lapsed, STATUS_APPROVED)

    assert repo.expire_due(NOW) == 1
    assert repo.expire_due(NOW) == 0, "an expired policy was expired twice"
    # An approval that was never activated is left for the runner to handle.
    assert [r.decision.policy_id for r in repo.approved_recommendations()] == [approved_but_lapsed.policy_id]


# Durability is an upgrade: no URL, or an unreachable database, means Redis only.
def test_no_database_is_not_an_error(capsys):
    assert open_database(Settings()) is None
    assert open_database(Settings(postgres_url="postgresql://nobody@127.0.0.1:1/x")) is None
    assert "campaigns stay in Redis" in capsys.readouterr().out
