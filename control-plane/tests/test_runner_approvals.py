"""
The durable approval queue: what an analyst approved in Manual mode reaches
the gateway on the next cycle, and only for the time the approval has left.
"""

from __future__ import annotations

import dataclasses
import json
import sys
from datetime import datetime, timedelta, timezone

import pytest

from iasg.adaptive.config import AdaptiveConfig
from iasg.adaptive.lifecycle import STATUS_APPROVED, Recommendation
from iasg.config import Settings
from iasg.models import ACTION_MONITOR, ACTION_THROTTLE, PolicyDecision
from iasg.runner import Runner
from iasg.store.memory import MemoryStore


def runner(mode="manual") -> tuple[Runner, MemoryStore]:
    store = MemoryStore()
    adaptive = dataclasses.replace(AdaptiveConfig(), mode=mode)
    return Runner(dataclasses.replace(Settings(), adaptive=adaptive), store), store


def approve(r: Runner, *, ip="203.0.113.5", action=ACTION_THROTTLE, age=0, ttl=900, source="approved", evidence=3):
    issued = datetime.now(timezone.utc) - timedelta(seconds=age)
    d = PolicyDecision(
        ip=ip, action=action, campaign_id="c1", confidence=0.95, ttl_seconds=ttl,
        requests_per_minute=30, source=source, issued_by="analyst", issued_at=issued,
        risk_score=90, explanation={"deterministic_evidence_count": evidence},
    )
    r.adaptive.lifecycle.repository.save_recommendation(Recommendation(d, STATUS_APPROVED, issued, issued))
    return d


def status(r: Runner, d: PolicyDecision) -> str:
    return r.adaptive.lifecycle.repository.rows[d.policy_id].status


def remaining(store: MemoryStore, key: str) -> float:
    _value, expires_at = store._keys[key]
    return expires_at - __import__("time").time()


def test_an_approval_reaches_the_gateway_on_the_next_cycle():
    r, store = runner()
    d = approve(r)
    r.cycle()

    written = json.loads(store.get("policy:203.0.113.5"))
    assert written["action"] == ACTION_THROTTLE
    assert status(r, d) == "active"


# Approval starts a window at the analyst's click. A slow cycle uses some of it
# up; it must not hand the address a fresh full TTL.
def test_scheduling_delay_is_taken_out_of_the_approved_window():
    r, store = runner()
    approve(r, age=600, ttl=900)
    r.cycle()
    assert remaining(store, "policy:203.0.113.5") <= 300 + 2


# An analyst's click does not bypass the rails at the only boundary that
# reaches Redis: an approval the evidence cannot support is still refused.
def test_an_approval_without_evidence_is_still_refused_by_the_writer():
    r, store = runner()
    approve(r, evidence=0)
    result = r.cycle()
    assert store.keys("policy:*") == []
    assert any("deterministic evidence" in n for n in result.notes)


def test_a_lapsed_approval_is_expired_not_enforced():
    r, store = runner()
    d = approve(r, age=1000, ttl=900)
    r.cycle()
    assert store.get("policy:203.0.113.5") is None
    assert status(r, d) == "expired"


def test_an_approved_monitor_writes_no_policy():
    r, store = runner()
    d = approve(r, action=ACTION_MONITOR)
    r.cycle()
    assert store.keys("policy:*") == []
    assert status(r, d) == "expired"


# Switching to Monitor is a safety stop: approvals stay durable but inert.
def test_monitor_mode_holds_approvals_without_enforcing_them():
    r, store = runner(mode="monitor")
    d = approve(r)
    r.cycle()
    assert store.keys("policy:*") == []
    assert status(r, d) == STATUS_APPROVED


def test_only_analyst_approvals_use_the_queue():
    r, store = runner()
    approve(r, source="adaptive")
    r.cycle()
    assert store.keys("policy:*") == []


# One bad cycle must not end the agent, and Ctrl-C must.
def test_run_forever_survives_a_failed_cycle(monkeypatch, capsys):
    r, _ = runner()
    calls = iter([RuntimeError("boom"), None, KeyboardInterrupt()])

    def cycle():
        outcome = next(calls)
        if isinstance(outcome, BaseException):
            raise outcome
        return __import__("iasg.runner", fromlist=["CycleResult"]).CycleResult()

    monkeypatch.setattr(r, "cycle", cycle)
    monkeypatch.setattr("iasg.runner.time.sleep", lambda _s: None)
    r.run_forever()
    out = capsys.readouterr().out
    assert "cycle failed: boom" in out
    assert "[iasg] stopped" in out


def test_the_command_line_runs_one_dry_cycle(monkeypatch, capsys):
    from iasg import __main__ as cli

    monkeypatch.setenv("IASG_REDIS_URL", "redis://127.0.0.1:1/0")
    monkeypatch.delenv("IASG_POSTGRES_URL", raising=False)
    monkeypatch.setattr(sys, "argv", ["iasg", "--once", "--dry-run", "--interval", "7"])
    seen = {}
    real = cli.Runner

    def spy(settings):
        seen["settings"] = settings
        return real(settings)

    monkeypatch.setattr(cli, "Runner", spy)
    cli.main()
    assert seen["settings"].dry_run is True
    assert seen["settings"].interval_seconds == 7
    assert "[cycle] read 0 events" in capsys.readouterr().out
