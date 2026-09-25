"""
Policy simulation: what would this actually hit, besides the attacker?

The Policy Agent asks "is this malicious?". This asks the separate question
"is this response safe?", and it runs after the decision is made and before it
is written, so a proposal can be softened or dropped without the ladder having
to know about collateral damage.

An honest limit, stated up front: the gateway reports attacks, never ordinary
traffic. There is no way from here to measure how many real users sit behind
an address, so this does not pretend to compute a percentage of legitimate
traffic affected. It works with what is actually observable -- ranges an
operator declared, and how many distinct clients an address appears to speak
for -- and says so when it is guessing.
"""

from __future__ import annotations

import json
from dataclasses import replace

from iasg.config import Settings
from iasg.models import (
    ACTION_ALLOW,
    ACTION_LADDER,
    ACTION_MONITOR,
    ACTION_THROTTLE,
    Evidence,
    PolicyDecision,
)
from iasg.policy.writer import parse_networks, within
from iasg.store.base import Store


class Simulator:
    def __init__(self, store: Store, settings: Settings) -> None:
        self._store = store
        self._settings = settings
        self._allowlist = parse_networks(settings.allowlist)
        self._shared = parse_networks(settings.shared_ranges)
        self._adaptive = settings.adaptive

    def apply_config(self, config) -> None:
        self._adaptive = config.validate()

    def review(
        self, decisions: list[PolicyDecision], evidence: list[Evidence]
    ) -> tuple[list[PolicyDecision], list[str]]:
        """
        Return the decisions as they should actually be applied, plus notes.

        Runs last, so it is the final say on everything written -- but whose
        judgement it defers to depends on what kind of check it is.

        Declared configuration binds everyone, including a human at a console:
        an operator who listed a range as theirs has already answered, and an
        instruction typed in a hurry should not quietly undo it. Change the
        config if you mean it.

        The guesses below -- an address that looks shared, a standing policy
        worth keeping -- bind only the agent. A person who says block anyway
        has seen something this cannot, and overruling them with a heuristic
        would make the override feature a suggestion box.
        """
        clients = _clients_per_address(evidence)
        approved: list[PolicyDecision] = []
        notes: list[str] = []

        for decision in decisions:
            # 1. Declared ours. Not negotiable, and not overridable either --
            # an operator who listed a range here has already answered.
            if decision.action != ACTION_ALLOW and within(decision.ip, self._allowlist):
                notes.append(f"[sim] {decision.ip} allowlisted, no policy written")
                continue

            # 2. Declared shared. Real people are behind this address, so it
            # can be slowed but never cut off.
            if within(decision.ip, self._shared):
                decision, note = _soften(
                    decision,
                    ACTION_THROTTLE,
                    "declared a shared range",
                    self._adaptive,
                )
                if note:
                    notes.append(note)

            # Everything from here down is inference, so a human's instruction
            # passes through it untouched.
            if decision.source == "human":
                approved.append(decision)
                continue

            # 3. Suspected shared, which is a guess and treated like one.
            if clients.get(decision.ip, 0) >= self._settings.shared_address_agents:
                seen = clients[decision.ip]
                if decision.confidence >= 0.9:
                    # Softening here would be an evasion route: rotate the
                    # user agent enough and the block turns into a throttle.
                    # A confident campaign is answered in full and the doubt
                    # is reported instead.
                    notes.append(
                        f"[sim] {decision.ip} looks shared ({seen} distinct "
                        f"clients) but evidence is confident -- applying "
                        f"{decision.action} anyway"
                    )
                else:
                    decision, note = _soften(
                        decision,
                        ACTION_THROTTLE,
                        f"{seen} distinct clients suggest a shared address",
                        self._adaptive,
                    )
                    if note:
                        notes.append(note)

            # 4. Never trade a live policy for a weaker one. Campaigns are
            # re-decided every cycle, so without this a quiet cycle could
            # downgrade a block that is the very reason things went quiet.
            standing = self._standing_action(decision.ip)
            if standing and _rung(standing) > _rung(decision.action):
                notes.append(
                    f"[sim] {decision.ip} keeps standing {standing} "
                    f"(proposed {decision.action} is weaker)"
                )
                continue

            approved.append(decision)

        return approved, notes

    def _standing_action(self, ip: str) -> str:
        """The action already in force for this address, if any."""
        raw = self._store.get(f"{self._settings.policy_prefix}{ip}")
        if not raw:
            return ""
        try:
            return json.loads(raw).get("action", "")
        except (ValueError, AttributeError):
            return ""


def _soften(
    decision: PolicyDecision, ceiling: str, why: str, config
) -> tuple[PolicyDecision, str]:
    """Cap a decision at `ceiling`, leaving anything gentler alone."""
    if _rung(decision.action) <= _rung(ceiling):
        return decision, ""

    guard = config.guardrails
    ttl = {
        ACTION_THROTTLE: guard.throttle_duration_seconds,
        ACTION_MONITOR: guard.monitor_duration_seconds,
    }.get(ceiling, decision.ttl_seconds)
    rpm = decision.requests_per_minute
    if ceiling == ACTION_THROTTLE and rpm <= 0:
        rpm = guard.default_throttle_rpm
    softened = replace(
        decision,
        action=ceiling,
        ttl_seconds=min(ttl, guard.maximum_policy_duration_seconds),
        requests_per_minute=rpm,
        reason=f"{decision.reason}; reduced from {decision.action} ({why})",
    )
    return softened, (
        f"[sim] {decision.ip} {decision.action} -> {ceiling} ({why})"
    )


def _clients_per_address(evidence: list[Evidence]) -> dict[str, int]:
    """How many distinct user agents each address spoke with."""
    agents: dict[str, set[str]] = {}
    for e in evidence:
        if e.ip and e.user_agent:
            agents.setdefault(e.ip, set()).add(e.user_agent)
    return {ip: len(seen) for ip, seen in agents.items()}


def _rung(action: str) -> int:
    try:
        return ACTION_LADDER.index(action)
    except ValueError:
        return -1
