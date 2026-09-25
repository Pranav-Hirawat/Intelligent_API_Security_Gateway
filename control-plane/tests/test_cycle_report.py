"""
What an operator reads after each cycle, and how the cycle treats its own
bookkeeping failing.

The report is the agent's only voice on a terminal. A line missing from it is
a decision nobody sees.
"""

from __future__ import annotations

from dataclasses import replace

from iasg.config import Settings
from iasg.models import Campaign, PolicyDecision
from iasg.runner import CycleResult, Runner, report
from iasg.store.memory import MemoryStore


def campaign(**changes) -> Campaign:
    fields = dict(campaign_id="3", type="Multi-Stage Intrusion", confidence=0.91,
                  ips=["203.0.113.5"], reason="one actor, several phases", severity="high")
    fields.update(changes)
    return Campaign(**fields)


def test_every_part_of_a_busy_cycle_is_reported(capsys):
    busy = campaign(
        stages=["reconnaissance", "credential_attack"], rotations=2, persistence=1,
        last_action="throttle", explanation="Seen from 203.0.113.5.", assessment="Grouping looks sound.",
    )
    result = CycleResult(
        evidence_count=40, campaigns=[busy], policies_written=1, narration_skipped=2,
        notes=["skipped 10.0.0.5 (not a public address)"],
        escalated=[busy],
        reviewed=[campaign(campaign_id="1", status="contained", outcome="no activity after block"),
                  campaign(campaign_id="2", status="active", quiet_cycles=3, last_action="")],
    )
    report(result)
    out = capsys.readouterr().out

    for line in (
        "[cycle] read 40 events",
        "Campaign #3 -- Multi-Stage Intrusion",
        "1 IP, confidence 0.91, high",
        "reconnaissance -> credential_attack (2 phases, not 2 separate attacks)",
        "through 2 address changes",
        "survived 1 enforcement round -- responding with throttle",
        "[explain]     Seen from 203.0.113.5.",
        "[assess]      Grouping looks sound.",
        "[policy]      wrote 1 policy keys",
        "2 call(s) fell back to templates",
        "skipped 10.0.0.5 (not a public address)",
        "Campaign #3 raised for human review",
        "Campaign #1 contained -- no activity after block",
        "Campaign #2 quiet for 3 cycle(s) after no action",
    ):
        assert line in out, line


def test_a_human_instruction_on_a_quiet_cycle_is_still_reported(capsys):
    manual = PolicyDecision(ip="203.0.113.9", action="temp_block", campaign_id="", confidence=1.0,
                            ttl_seconds=600, reason="confirmed attack", source="human")
    report(CycleResult(evidence_count=3, manual=[manual], policies_written=1))
    out = capsys.readouterr().out
    assert "[human]       203.0.113.9 -> temp_block (confirmed attack)" in out
    assert "no campaigns formed" in out
    assert "wrote 1 policy keys" in out


class HeartbeatFails(MemoryStore):
    def set(self, key, value, ttl_seconds=None):
        if key == "iasg:heartbeat":
            raise ConnectionError("redis went away")
        super().set(key, value, ttl_seconds)


def test_a_failed_heartbeat_does_not_fail_the_cycle(capsys):
    """Liveness is reporting, not work: losing it must not lose the cycle."""
    Runner(replace(Settings(), dry_run=False), HeartbeatFails()).cycle()
    assert "[heartbeat] could not record this cycle (redis went away)" in capsys.readouterr().out
