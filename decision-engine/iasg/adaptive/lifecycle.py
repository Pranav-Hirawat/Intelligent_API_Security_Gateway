"""Durable recommendation lifecycle around the one Redis policy writer."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol

from iasg.adaptive.config import AdaptiveConfig
from iasg.models import ACTION_MONITOR, PolicyDecision


STATUS_RECOMMENDED = "recommended"
STATUS_PENDING = "pending_approval"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_ACTIVE = "active"
STATUS_EXPIRED = "expired"
STATUS_SUPERSEDED = "superseded"


@dataclass
class Recommendation:
    decision: PolicyDecision
    status: str
    created_at: datetime
    updated_at: datetime


class LifecycleRepository(Protocol):
    def save_recommendation(self, recommendation: Recommendation) -> None: ...
    def approved_recommendations(self) -> list[Recommendation]: ...
    def mark_status(self, policy_id: str, status: str, actor: str, details: dict | None = None) -> None: ...
    def last_for_scope(self, decision: PolicyDecision) -> Recommendation | None: ...
    def expire_due(self, now: datetime) -> int: ...


class MemoryLifecycleRepository:
    def __init__(self) -> None:
        self.rows: dict[str, Recommendation] = {}
        self.audit: list[dict] = []

    def save_recommendation(self, recommendation: Recommendation) -> None:
        self.rows[recommendation.decision.policy_id] = recommendation
        self.audit.append({
            "policy_id": recommendation.decision.policy_id,
            "event": recommendation.status,
            "actor": recommendation.decision.issued_by,
            "at": recommendation.updated_at,
            "details": {},
        })

    def approved_recommendations(self) -> list[Recommendation]:
        return [row for row in self.rows.values() if row.status == STATUS_APPROVED]

    def mark_status(self, policy_id: str, status: str, actor: str, details: dict | None = None) -> None:
        row = self.rows.get(policy_id)
        if row:
            row.status = status
            row.updated_at = datetime.now(timezone.utc)
        self.audit.append({
            "policy_id": policy_id, "event": status, "actor": actor,
            "at": datetime.now(timezone.utc), "details": details or {},
        })

    def last_for_scope(self, decision: PolicyDecision) -> Recommendation | None:
        matching = [row for row in self.rows.values() if _same_scope(row.decision, decision)]
        return max(matching, key=lambda row: row.updated_at) if matching else None

    def expire_due(self, now: datetime) -> int:
        due = [row for row in self.rows.values()
               if row.status == STATUS_ACTIVE and row.decision.expires_at <= now]
        for row in due:
            self.mark_status(row.decision.policy_id, STATUS_EXPIRED, "decision-engine")
        return len(due)


class Lifecycle:
    def __init__(self, repository: LifecycleRepository) -> None:
        self.repository = repository

    def stage(
        self, decision: PolicyDecision, config: AdaptiveConfig, now: datetime | None = None
    ) -> tuple[Recommendation, bool, str]:
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        status = STATUS_RECOMMENDED
        enforce = False
        why = "monitor mode records recommendations without enforcement"
        if decision.mode == "manual_override" or decision.source == "human":
            status = STATUS_APPROVED
            enforce = decision.action != ACTION_MONITOR
            why = "explicit operator override"
        elif config.mode == "manual":
            status = STATUS_PENDING
            why = "manual mode requires analyst approval"
        elif config.mode == "automatic" and decision.action != ACTION_MONITOR:
            enforce = True
            # Approval is recorded only after the final collateral review in
            # Runner. Staging an approval here would let a rejected proposal
            # look eligible for later activation.
            status = STATUS_RECOMMENDED
            why = "automatic guardrails were satisfied; final review remains"

        previous = self.repository.last_for_scope(decision)
        same_mode_open = previous and (
            (previous.status == STATUS_RECOMMENDED and config.mode == "monitor")
            or (previous.status == STATUS_PENDING and config.mode == "manual")
        )
        if (
            previous
            and previous.decision.action == decision.action
            and (previous.status == STATUS_ACTIVE or same_mode_open)
            and previous.decision.expires_at > now
        ):
            # Redis expiry, rather than recurring evidence, ends enforcement.
            # Return the current proposal so a human can still disagree with
            # it, but carry the standing action separately for outcome review.
            # The transient proposal is not persisted and cannot renew Redis.
            why = "same-scope policy is still current and is not renewed"
            final = decision.explanation.setdefault("final", {})
            final["lifecycle"] = why
            final["standing_action"] = previous.decision.action
            final["standing_policy_id"] = previous.decision.policy_id
            final["policy_expiry"] = previous.decision.expires_at.astimezone(
                timezone.utc
            ).isoformat()
            return Recommendation(decision, previous.status, now, now), False, why
        # A recommendation to monitor has no Redis key and therefore cannot
        # protect anyone from a later, evidence-backed action. Applying the
        # change cooldown to it would create a blind spot for the first real
        # attack on that scope.
        if (
            previous
            and previous.status == STATUS_ACTIVE
            and previous.decision.action != decision.action
        ):
            age = now - previous.updated_at
            emergency = decision.mode == "manual_override" or decision.source == "human"
            if not emergency and age < timedelta(seconds=config.guardrails.policy_cooldown_seconds):
                enforce = False
                status = STATUS_RECOMMENDED if config.mode != "manual" else STATUS_PENDING
                why = "same-scope policy is inside the configured change cooldown"
                final = decision.explanation.setdefault("final", {})
                final["lifecycle"] = why
                final["standing_action"] = previous.decision.action
                final["standing_policy_id"] = previous.decision.policy_id
                final["policy_expiry"] = previous.decision.expires_at.astimezone(
                    timezone.utc
                ).isoformat()
                return Recommendation(decision, previous.status, now, now), False, why
            else:
                decision.supersedes_policy_id = previous.decision.policy_id

        final = decision.explanation.setdefault("final", {})
        final["lifecycle"] = why
        final["policy_expiry"] = decision.expires_at.astimezone(timezone.utc).isoformat()

        recommendation = Recommendation(
            decision=decision, status=status, created_at=now, updated_at=now
        )
        self.repository.save_recommendation(recommendation)
        return recommendation, enforce, why

    def approved(self) -> list[PolicyDecision]:
        return [row.decision for row in self.repository.approved_recommendations()]

    def activated(self, decision: PolicyDecision, actor: str = "decision-engine") -> None:
        if decision.supersedes_policy_id:
            self.repository.mark_status(
                decision.supersedes_policy_id,
                STATUS_SUPERSEDED,
                actor,
                {"superseded_by": decision.policy_id},
            )
        self.repository.mark_status(decision.policy_id, STATUS_ACTIVE, actor)


def _same_scope(left: PolicyDecision, right: PolicyDecision) -> bool:
    return (
        left.ip == right.ip
        and left.method == right.method
        and left.route_template == right.route_template
    )
