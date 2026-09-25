"""
The agent loop (section 12).

    observe -> correlate -> remember -> decide -> explain

Runs every interval_seconds. Evidence is acked only once a cycle completes,
so a crash mid-cycle replays rather than loses it.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone

from iasg.alerts import AlertSink
from iasg.adaptive.baseline import MemoryBaselineRepository
from iasg.adaptive.controller import AdaptiveController
from iasg.adaptive.lifecycle import (
    STATUS_APPROVED,
    STATUS_REJECTED,
    MemoryLifecycleRepository,
    Recommendation,
)
from iasg.adaptive.windows import WindowConsumer
from iasg.assessment.agent import AssessmentAgent
from iasg.campaigns.repository import CampaignRepository
from iasg.config import Settings
from iasg.correlation.agent import CorrelationAgent
from iasg.evidence.consumer import EvidenceConsumer
from iasg.explanation.agent import ExplanationAgent
from iasg.feedback import overrides as human
from iasg.feedback.memory import FeedbackMemory
from iasg.feedback.overrides import OverrideChannel
from iasg.models import ACTION_ESCALATE, ACTION_MONITOR, Campaign, PolicyDecision
from iasg.policy.agent import PolicyAgent
from iasg.policy.simulation import Simulator
from iasg.policy.writer import PolicyWriter
from iasg.reasoning import open_provider
from iasg.store import open_store
from iasg.store.base import Store
from iasg.store.postgres import open_database


@dataclass
class CycleResult:
    evidence_count: int = 0
    campaigns: list[Campaign] = field(default_factory=list)
    policies_written: int = 0
    notes: list[str] = field(default_factory=list)
    # Older campaigns whose status changed this cycle.
    reviewed: list[Campaign] = field(default_factory=list)
    # Campaigns escalated to a human this cycle.
    escalated: list[Campaign] = field(default_factory=list)
    # Campaigns a human overruled this cycle.
    overridden: list[Campaign] = field(default_factory=list)
    # Policy written purely on a human's instruction, about addresses no
    # campaign mentioned.
    manual: list[PolicyDecision] = field(default_factory=list)
    # What the agent has learned from past overrides and applied this cycle.
    learned: list[str] = field(default_factory=list)
    # Narration calls the cycle refused because its budget was spent. Reported
    # so a campaign reading as a bare template is explained rather than
    # looking like the LLM silently broke.
    narration_skipped: int = 0

class Runner:
    def __init__(self, settings: Settings, store: Store | None = None) -> None:
        self.settings = settings
        self.store = store or open_store(settings)

        provider = open_provider(settings)
        # Optional and non-fatal: without it campaigns stay in Redis under a
        # TTL, which is the behaviour every test and the default deployment use.
        self.database = open_database(settings)

        self.consumer = EvidenceConsumer(self.store, settings)
        self.correlation = CorrelationAgent()
        self.campaigns = CampaignRepository(
            self.store,
            persistence=self.database.campaigns if self.database else None,
        )
        self.simulator = Simulator(self.store, settings)
        # Kept as the compatibility surface for embedders and historical
        # feedback tests. Production decisions below use AdaptiveController.
        self.policy = PolicyAgent()
        self.overrides = OverrideChannel(self.store, settings)
        self.feedback = FeedbackMemory(
            self.store,
            settings,
            persistence=self.database.feedback if self.database else None,
        )
        if self.database:
            restored = self.campaigns.warm() + self.feedback.warm()
            if restored:
                print(f"[postgres] restored {restored} records into Redis")

        self.writer = PolicyWriter(self.store, settings)
        baseline_repository = self.database.adaptive if self.database else MemoryBaselineRepository()
        lifecycle_repository = self.database.adaptive if self.database else MemoryLifecycleRepository()
        self.windows = WindowConsumer(self.store, settings)
        self.adaptive = AdaptiveController(
            baseline_repository,
            lifecycle_repository,
            settings.adaptive,
        )
        self.provider = provider
        self.explanation = ExplanationAgent(provider)
        self.assessment = AssessmentAgent(provider)
        self.alerts = AlertSink(self.store)

    def cycle(self) -> CycleResult:
        result = CycleResult()

        config = (
            self.database.adaptive.load_config(self.settings.adaptive)
            if self.database else self.settings.adaptive
        )
        self.adaptive.apply_config(config)
        self.writer.apply_config(config)
        self.simulator.apply_config(config)
        self.campaigns.apply_config(config)
        self.writer.begin_cycle()
        self.adaptive.lifecycle.repository.expire_due(datetime.now(timezone.utc))
        for decision, enforce, _ in self.adaptive.observe(self.windows.completed()):
            if enforce:
                self._write_active(decision, result, actor=decision.issued_by)
        self._activate_approved(config, result)

        # Narration is capped per cycle, not per call, so the allowance has to
        # be restored before any campaign spends it. Providers without a
        # budget -- NullProvider -- have nothing to reset.
        begin = getattr(self.provider, "begin_cycle", None)
        if begin:
            begin()

        # Read before anything is decided, and applied whether or not there was
        # an attack this cycle: an admin blocking an address should not have to
        # wait for the agent to notice a campaign first.
        pending = {o.ip: o for o in self.overrides.pending()}

        # 1. observe
        evidence = self.consumer.fetch()
        result.evidence_count = len(evidence)

        # 2. correlate, then 3. remember
        campaigns = (
            self.campaigns.merge(self.correlation.analyse(evidence))
            if evidence
            else []
        )
        result.campaigns = campaigns

        covered: set[str] = set()
        for campaign in campaigns:
            self._respond(campaign, evidence, pending, result, config)
            covered.update(campaign.ips)

        # Instructions about addresses no campaign mentioned. Blocking an
        # address the agent has never seen is the plainest use of an override.
        loose = human.standalone(pending, covered, config)
        if loose:
            # Through the same gate, so an allowlisted range is protected from
            # a mistyped instruction exactly as it is from the agent.
            result.manual, notes = self.simulator.review(loose, evidence)
            result.notes.extend(notes)
            for decision in result.manual:
                now = datetime.now(timezone.utc)
                self.adaptive.lifecycle.repository.save_recommendation(
                    Recommendation(decision, STATUS_APPROVED, now, now)
                )
                self._write_active(decision, result, actor=decision.issued_by)

        # 6. review -- did acting on the older campaigns change anything? A
        # cycle with no evidence is not a wasted one: silence is the signal.
        result.reviewed = self.campaigns.review({c.campaign_id for c in campaigns})

        self._beat(result)

        result.narration_skipped = getattr(self.provider, "skipped", 0)

        # Ack last: everything above succeeded, so this cycle is truly done.
        # Unconditional, because a cycle that produced no evidence still read
        # entries -- clean requests are the common case, and skipping the ack
        # for them is what left them pending forever.
        self.consumer.ack(evidence)
        return result

    def _beat(self, result: CycleResult) -> None:
        """
        Say the agent is alive, and when it last thought.

        Given a TTL of a few intervals, the key's *absence* is the signal: a
        console reading it cannot tell a stopped agent from a quiet network
        otherwise, and those two look identical while meaning opposite things.
        Best effort -- failing to announce a cycle must not fail the cycle.
        """
        try:
            self.store.set(
                self.settings.heartbeat_key,
                json.dumps(
                    {
                        "at": datetime.now(timezone.utc).isoformat(),
                        "interval_seconds": self.settings.interval_seconds,
                        "evidence": result.evidence_count,
                        "campaigns": len(result.campaigns),
                        "policies_written": result.policies_written,
                        "durable": bool(self.database),
                        "dry_run": self.settings.dry_run,
                        "mode": self.adaptive.config.mode,
                        "config_version": self.adaptive.config.version,
                        # "null" when narration is off, "ollama" when a model
                        # is configured -- reachability isn't tracked here, so
                        # this says what's configured, not what's answering.
                        "narration_provider": self.provider.name,
                    }
                ),
                ttl_seconds=max(self.settings.interval_seconds * 3, 90),
            )
        except Exception as err:  # noqa: BLE001 - liveness is not worth a cycle
            print(f"[heartbeat] could not record this cycle ({err})")

    def _respond(self, campaign, evidence, pending, result: CycleResult, config) -> None:
        """Decide, check the decision is safe, let a human overrule it, write."""
        # 4. decide -- validated numeric configuration and completed-window
        # facts only. The gateway never waits for this control-plane work.
        staged = self.adaptive.decisions(campaign, evidence)
        decisions = [decision for decision, _, _ in staged]
        eligible = {decision.policy_id: enforce for decision, enforce, _ in staged}
        standing = [
            replace(
                decision,
                action=(decision.explanation.get("final") or {}).get(
                    "standing_action", decision.action
                ),
            )
            for decision, _, why in staged
            if "not renewed" in why or "change cooldown" in why
        ]
        standing_ids = {decision.policy_id for decision in standing}

        # 4b. a person outranks the agent, and disagreeing with us is the only
        # thing here worth learning from.
        decisions, lessons, notes = human.apply(decisions, pending, config)
        result.notes.extend(notes)
        for agent_action, human_action in lessons:
            self.feedback.record(campaign.type, agent_action, human_action)
            result.overridden.append(campaign)

        # 4c. simulate -- last, so nothing reaches the gateway without passing
        # the safety checks, whoever asked for it.
        proposed_ids = {decision.policy_id for decision in decisions}
        decisions, notes = self.simulator.review(decisions, evidence)
        result.notes.extend(notes)
        reviewed_ids = {decision.policy_id for decision in decisions}
        for policy_id in proposed_ids - reviewed_ids - standing_ids:
            self.adaptive.lifecycle.repository.mark_status(
                policy_id,
                STATUS_REJECTED,
                "control-plane",
                {"reason": "final collateral review rejected the recommendation"},
            )

        active: list[PolicyDecision] = []
        for decision in decisions:
            human_override = decision.source == "human"
            automatic = eligible.get(decision.policy_id, False)
            should_activate = human_override or automatic
            if should_activate:
                now = datetime.now(timezone.utc)
                self.adaptive.lifecycle.repository.save_recommendation(
                    Recommendation(decision, STATUS_APPROVED, now, now)
                )
            if should_activate:
                if self._write_active(decision, result, actor=decision.issued_by):
                    active.append(decision)

        # What was actually applied, not what was first proposed -- the next
        # cycle judges whether this worked.
        effective = active or standing
        campaign.last_action = effective[0].action if effective else ACTION_MONITOR
        guard = self.adaptive.config.guardrails
        if effective and (
            (
                campaign.confidence >= guard.analyst_escalation_confidence
                and len(campaign.ips) >= guard.analyst_escalation_min_clients
            )
            or len(campaign.stages) >= guard.analyst_escalation_min_stages
        ):
            # Escalation is an alert, not a fourth automatic enforcement action.
            # The Redis policy remains the bounded throttle/block selected by
            # guardrails while a person is asked to inspect the campaign.
            campaign.last_action = ACTION_ESCALATE

        # 5. explain -- advisory text, after the decision is already made
        campaign.explanation = self.explanation.explain(campaign, decisions)
        campaign.assessment = self.assessment.review(campaign)

        # Escalation is the one action that asks for a person. Raised
        # after the explanation so the alert carries something readable.
        if campaign.last_action == ACTION_ESCALATE:
            if self.alerts.raise_for(campaign, decisions):
                result.escalated.append(campaign)

        self.campaigns.save(campaign)

    def _activate_approved(self, config, result: CycleResult) -> None:
        # An analyst may approve in Manual mode.  Switching back to Monitor
        # before the next cycle is a safety stop and leaves approval durable
        # without turning it into a live Redis key.
        if config.mode == "monitor":
            return
        for decision in self.adaptive.lifecycle.approved():
            # Automatic proposals are approved and activated in the same
            # cycle after final review. Only an analyst-approved Manual row is
            # eligible for this durable queue.
            if decision.source != "approved":
                continue
            if decision.action == ACTION_MONITOR:
                self.adaptive.lifecycle.repository.mark_status(
                    decision.policy_id,
                    "expired",
                    decision.issued_by,
                    {"reason": "approved monitor recommendation has no active Redis policy"},
                )
                continue
            now = datetime.now(timezone.utc)
            remaining = int((decision.expires_at - now).total_seconds())
            if remaining <= 0:
                self.adaptive.lifecycle.repository.mark_status(
                    decision.policy_id, "expired", "control-plane"
                )
                continue
            # Approval starts a bounded window at the analyst's click. Agent
            # scheduling delay consumes that window; it must not silently
            # grant a fresh full TTL when Redis is finally written.
            approved = replace(
                decision,
                source="approved",
                issued_at=now,
                ttl_seconds=remaining,
            )
            self._write_active(approved, result, actor=approved.issued_by)

    def _write_active(
        self, decision: PolicyDecision, result: CycleResult, *, actor: str
    ) -> bool:
        written, notes = self.writer.write([decision])
        result.policies_written += written
        result.notes.extend(notes)
        if written:
            self.adaptive.lifecycle.activated(decision, actor=actor)
            return True
        return False

    def run_forever(self) -> None:
        print(
            f"[iasg] control plane started "
            f"(every {self.settings.interval_seconds}s, "
            f"dry_run={self.settings.dry_run})"
        )
        while True:
            try:
                report(self.cycle())
            except KeyboardInterrupt:
                print("\n[iasg] stopped")
                return
            except Exception as err:
                # One bad cycle must not end the agent.
                print(f"[iasg] cycle failed: {err}")
            time.sleep(self.settings.interval_seconds)


def report(result: CycleResult) -> None:
    """Print one cycle in the shape the proposal's demo output describes."""
    print(f"\n[cycle] read {result.evidence_count} events")

    for line in result.learned:
        print(f"[learned]     {line}")

    for decision in result.manual:
        print(f"[human]       {decision.ip} -> {decision.action} ({decision.reason})")

    if not result.campaigns:
        if result.evidence_count:
            print("        no campaigns formed")
        if result.manual:
            print(f"[policy]      wrote {result.policies_written} policy keys")
        # A quiet cycle is when the review has something to say, so it must
        # be printed before returning.
        _report_review(result)
        return

    for c in result.campaigns:
        plural = "IP" if len(c.ips) == 1 else "IPs"
        print(f"[correlation] Campaign #{c.campaign_id} -- {c.type}")
        print(
            f"              {len(c.ips)} {plural}, "
            f"confidence {c.confidence:.2f}, {c.severity}"
        )
        print(f"              {c.reason}")
        if len(c.stages) > 1:
            print(
                f"[stages]      {' -> '.join(c.stages)} "
                f"({len(c.stages)} phases, not {len(c.stages)} separate attacks)"
            )
        if c.rotations:
            changes = "change" if c.rotations == 1 else "changes"
            print(
                f"[continuity]  re-identified by behaviour through "
                f"{c.rotations} address {changes}"
            )
        if c.persistence:
            rounds = "round" if c.persistence == 1 else "rounds"
            print(
                f"[adapt]       survived {c.persistence} enforcement {rounds} "
                f"-- responding with {c.last_action or 'no action'}"
            )
        if c.explanation:
            print(f"[explain]     {c.explanation}")
        if c.assessment:
            print(f"[assess]      {c.assessment}")

    print(f"[policy]      wrote {result.policies_written} policy keys")
    if result.narration_skipped:
        print(
            f"[llm]         narration budget spent -- "
            f"{result.narration_skipped} call(s) fell back to templates"
        )
    for note in result.notes:
        print(f"              {note}")

    _report_review(result)


def _report_review(result: CycleResult) -> None:
    """Anything raised for a human, and what became of older campaigns."""
    for c in result.escalated:
        print(
            f"[escalate]    Campaign #{c.campaign_id} raised for human review "
            f"-- {len(c.ips)} IPs, confidence {c.confidence:.2f}"
        )

    for c in result.reviewed:
        if c.status == "contained":
            print(f"[review]      Campaign #{c.campaign_id} contained -- {c.outcome}")
        else:
            print(
                f"[review]      Campaign #{c.campaign_id} quiet for "
                f"{c.quiet_cycles} cycle(s) after {c.last_action or 'no action'}"
            )
