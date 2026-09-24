"""Escalation is the one action that asks for a person."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone

from iasg.alerts import AlertSink
from iasg.config import Settings
from iasg.models import ACTION_ESCALATE, Campaign, PolicyDecision
from iasg.runner import Runner
from iasg.store.memory import MemoryStore

BASE = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def campaign(**overrides) -> Campaign:
    defaults = dict(
        campaign_id="1", type="Credential Stuffing", confidence=0.95,
        ips=[f"203.0.113.{n}" for n in (5, 9, 14, 21, 33)],
        reason="5 IPs sharing everything", severity="high",
        first_seen=BASE, last_seen=BASE, event_count=60,
        explanation="A credential stuffing campaign was detected.",
    )
    defaults.update(overrides)
    return Campaign(**defaults)


def decision(action=ACTION_ESCALATE) -> PolicyDecision:
    return PolicyDecision(ip="203.0.113.5", action=action, campaign_id="1",
                          confidence=0.95, ttl_seconds=3600)


def test_alert_is_written_to_its_own_stream():
    store = MemoryStore()
    entry_id = AlertSink(store).raise_for(campaign(), [decision()])

    assert entry_id
    written = store.read_group("iasg_alerts", "test", "c", 10)
    assert len(written) == 1

    _, fields = written[0]
    assert fields["campaign_id"] == "1"
    assert fields["ip_count"] == "5"
    assert fields["action"] == ACTION_ESCALATE


def test_alert_carries_the_readable_explanation():
    store = MemoryStore()
    AlertSink(store).raise_for(campaign(), [decision()])

    _, fields = store.read_group("iasg_alerts", "t", "c", 10)[0]
    assert "credential stuffing" in fields["explanation"].lower()


# Re-alerting every 30 seconds trains a reader to ignore alerts.
def test_a_campaign_is_only_alerted_once():
    store = MemoryStore()
    sink = AlertSink(store)
    c = campaign()

    first = sink.raise_for(c, [decision()])
    second = sink.raise_for(c, [decision()])

    assert first is not None
    assert second is None, "the same campaign alerted twice"
    assert len(store.read_group("iasg_alerts", "t", "c", 10)) == 1


def test_alerting_marks_the_campaign():
    c = campaign()
    assert c.alerted is False
    AlertSink(MemoryStore()).raise_for(c, [decision()])
    assert c.alerted is True


# --- through the whole loop ---

def seed(store: MemoryStore, ips=(5, 9, 14, 21, 33, 40), events=6, offset=0):
    from iasg.models import Evidence
    for last in ips:
        for n in range(events):
            e = Evidence(
                timestamp=BASE + timedelta(seconds=offset + n),
                ip=f"203.0.113.{last}", endpoint="/api/login", detector="bruteforce",
                severity="high", user_agent="curl/8.4.0",
                details={"failedLogins": 9, "distinctUsers": 5},
            )
            store.append("iasg:events", e.to_stream_fields())


def test_runner_escalates_a_large_confident_campaign():
    store = MemoryStore()
    seed(store)

    result = Runner(dataclasses.replace(Settings()), store).cycle()

    assert result.campaigns[0].last_action == ACTION_ESCALATE
    assert len(result.escalated) == 1
    assert store.read_group("iasg_alerts", "t", "c", 10), "no alert stream entry"


def test_runner_does_not_re_alert_on_the_next_cycle():
    store = MemoryStore()
    r = Runner(dataclasses.replace(Settings()), store)

    seed(store)
    first = r.cycle()
    seed(store, offset=60)
    second = r.cycle()

    assert len(first.escalated) == 1
    assert len(second.escalated) == 0, "alerted again for a campaign already raised"
    assert len(store.read_group("iasg_alerts", "t", "c", 10)) == 1


# A block expires, the attacker returns: that is worth telling someone again.
def test_a_resumed_campaign_alerts_again():
    store = MemoryStore()
    r = Runner(dataclasses.replace(Settings()), store)

    seed(store)
    r.cycle()

    for _ in range(3):
        r.cycle()
    assert r.campaigns.all()[0].status == "contained"

    seed(store, offset=7200)
    resumed = r.cycle()

    assert len(resumed.escalated) == 1, "a resumed campaign should alert again"
    assert len(store.read_group("iasg_alerts", "t", "c", 10)) == 2


def test_a_small_campaign_is_not_escalated():
    store = MemoryStore()
    seed(store, ips=(5, 9), events=6)

    result = Runner(dataclasses.replace(Settings()), store).cycle()

    assert result.campaigns[0].last_action != ACTION_ESCALATE
    assert result.escalated == []
    assert store.read_group("iasg_alerts", "t", "c", 10) == []


def test_dry_run_still_reports_but_writes_no_policy():
    store = MemoryStore()
    seed(store)

    result = Runner(dataclasses.replace(Settings(), dry_run=True), store).cycle()

    assert result.policies_written == 0
    assert result.campaigns, "dry run should still correlate"
