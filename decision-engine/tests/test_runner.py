"""The agent loop: observe -> correlate -> remember -> decide -> explain."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone

import pytest

from iasg.config import Settings
from iasg.models import Evidence
from iasg.runner import CycleResult, Runner, report
from iasg.store.memory import MemoryStore

BASE = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def settings(**overrides) -> Settings:
    return dataclasses.replace(Settings(), **overrides)


def seed_campaign(store: MemoryStore, ips=(5, 9, 14, 21, 33, 40), events=6):
    """A coordinated set that clusters into one high-confidence campaign."""
    for last in ips:
        for n in range(events):
            e = Evidence(
                timestamp=BASE + timedelta(seconds=n),
                ip=f"203.0.113.{last}",
                endpoint="/api/login",
                detector="bruteforce",
                severity="high",
                user_agent="curl/8.4.0",
                details={"failedLogins": 9, "distinctUsers": 5},
            )
            store.append("iasg:events", e.to_stream_fields())


def runner(store: MemoryStore, **overrides) -> Runner:
    return Runner(settings(**overrides), store)


def test_empty_cycle_does_nothing():
    store = MemoryStore()
    result = runner(store).cycle()

    assert result.evidence_count == 0
    assert result.campaigns == []
    assert result.policies_written == 0


def test_cycle_runs_the_whole_pipeline():
    store = MemoryStore()
    seed_campaign(store)

    result = runner(store).cycle()

    assert result.evidence_count == 36
    assert len(result.campaigns) == 1

    campaign = result.campaigns[0]
    assert campaign.type == "Credential Stuffing"
    assert len(campaign.ips) == 6
    assert campaign.confidence >= 0.9
    assert result.policies_written == 6


def test_policy_keys_land_in_the_store():
    store = MemoryStore()
    seed_campaign(store)
    runner(store).cycle()

    raw = store.get("policy:203.0.113.5")
    assert raw is not None, "no policy written for a campaign member"

    decision = json.loads(raw)
    assert decision["action"] in ("temporary_block", "escalate")
    assert decision["campaign_id"]


def test_campaign_is_persisted():
    store = MemoryStore()
    seed_campaign(store)
    runner(store).cycle()

    assert store.get("campaign:1") is not None


# Memory, not a fresh guess every 30 seconds.
def test_second_cycle_merges_instead_of_duplicating():
    store = MemoryStore()
    r = runner(store)

    seed_campaign(store)
    first = r.cycle()

    seed_campaign(store)
    second = r.cycle()

    assert len(second.campaigns) == 1
    assert second.campaigns[0].campaign_id == first.campaigns[0].campaign_id
    assert second.campaigns[0].event_count > first.campaigns[0].event_count
    assert len([k for k in store.keys("campaign:*") if k[9:].isdigit()]) == 1


def test_dry_run_writes_no_policy():
    store = MemoryStore()
    seed_campaign(store)

    result = runner(store, dry_run=True).cycle()

    assert result.policies_written == 0
    assert store.get("policy:203.0.113.5") is None
    assert any("dry-run" in note for note in result.notes)
    assert result.campaigns, "dry run should still correlate and report"


def test_max_ips_per_cycle_is_respected():
    store = MemoryStore()
    seed_campaign(store)

    result = runner(store, max_ips_per_cycle=2).cycle()

    assert result.policies_written == 2
    assert any("cycle cap" in note for note in result.notes)


def test_explanation_is_attached_without_an_llm():
    store = MemoryStore()
    seed_campaign(store)

    campaign = runner(store).cycle().campaigns[0]

    assert campaign.explanation, "template explanation missing"
    # The action is the sentence an admin needs; it must survive every path.
    assert any(w in campaign.explanation for w in ("block", "escalate", "throttle"))


def test_assessment_is_empty_without_an_llm():
    store = MemoryStore()
    seed_campaign(store)

    assert runner(store).cycle().campaigns[0].assessment == ""


def test_evidence_is_acked_after_a_successful_cycle():
    store = MemoryStore()
    seed_campaign(store)
    r = runner(store)
    r.cycle()

    # A fresh runner reclaims unacked entries; there should be none.
    assert runner(store).cycle().evidence_count == 0


# The reason ack comes last: a crash mid-cycle must replay, not lose.
def test_evidence_is_not_acked_when_a_cycle_fails():
    store = MemoryStore()
    seed_campaign(store)
    r = runner(store)

    def explode(_decisions):
        raise RuntimeError("redis fell over mid-write")

    r.writer.write = explode

    with pytest.raises(RuntimeError):
        r.cycle()

    replayed = runner(store).cycle()
    assert replayed.evidence_count == 36, "evidence was lost by a failed cycle"


def test_a_raising_provider_does_not_break_the_cycle():
    """Narration is advisory and runs after policy is written."""
    store = MemoryStore()
    seed_campaign(store)
    r = runner(store)

    class Exploding:
        def generate(self, system, prompt):
            raise RuntimeError("model not loaded")

    r.explanation._provider = Exploding()
    r.assessment._provider = Exploding()

    result = r.cycle()

    assert result.policies_written == 6, "policy must survive a failed narration"
    assert result.campaigns[0].explanation, "should have fallen back to the template"
    assert result.campaigns[0].assessment == ""

    # And the evidence still gets acked, because the cycle completed.
    assert runner(store).cycle().evidence_count == 0


def test_noise_produces_no_campaign_and_no_policy():
    store = MemoryStore()
    lone = Evidence(
        timestamp=BASE, ip="203.0.113.5", endpoint="/api/x",
        detector="flood", severity="low", user_agent="curl/8.4",
    )
    store.append("iasg:events", lone.to_stream_fields())

    result = runner(store).cycle()

    assert result.evidence_count == 1
    assert result.campaigns == []
    assert result.policies_written == 0


def test_cycle_result_defaults_are_independent():
    a, b = CycleResult(), CycleResult()
    a.campaigns.append("x")
    a.notes.append("y")

    assert b.campaigns == [] and b.notes == [], "mutable default shared between results"


def test_report_prints_without_crashing(capsys):
    store = MemoryStore()
    seed_campaign(store)
    report(runner(store).cycle())

    out = capsys.readouterr().out
    assert "Campaign #1" in out
    assert "Credential Stuffing" in out
    assert "6 IPs" in out


def test_report_handles_an_empty_cycle(capsys):
    report(CycleResult())
    assert "read 0 events" in capsys.readouterr().out


def test_report_uses_singular_for_one_ip(capsys):
    store = MemoryStore()
    seed_campaign(store, ips=(5,), events=8)
    report(runner(store).cycle())

    out = capsys.readouterr().out
    assert "1 IP," in out and "1 IPs" not in out
