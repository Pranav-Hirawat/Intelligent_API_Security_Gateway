"""
Writes policy:<ip> keys into Redis.

Everything that could do damage is guarded here rather than in the agent, so
there is one place to audit before trusting this with real traffic.
"""

from __future__ import annotations

import hashlib
import ipaddress

from iasg.adaptive.config import AUTO_ACTIONS
from iasg.config import Settings
from iasg.models import ACTION_ALLOW, ACTION_MONITOR, ACTION_TEMP_BLOCK, ACTION_THROTTLE, PolicyDecision
from iasg.store.base import Store


class PolicyWriter:
    def __init__(self, store: Store, settings: Settings) -> None:
        self._store = store
        self._settings = settings
        self._adaptive = settings.adaptive
        self._allowlist = parse_networks((*settings.allowlist, *self._adaptive.guardrails.allowlist))

    def apply_config(self, config) -> None:
        self._adaptive = config.validate()
        self._allowlist = parse_networks(
            (*self._settings.allowlist, *self._adaptive.guardrails.allowlist)
        )

    def begin_cycle(self) -> None:
        self._cycle_budget = self._settings.max_ips_per_cycle

    def write(self, decisions: list[PolicyDecision]) -> tuple[int, list[str]]:
        """
        Apply decisions. Returns (written, skipped_notes).

        Rails, in order:
          - never touch loopback, private or reserved addresses
          - never write a bare "monitor", which would be a no-op key
          - never write a decision that has no expiry
          - cap how many IPs one cycle may action
          - dry_run writes nothing at all
        """
        written = 0
        notes: list[str] = []
        budget = getattr(self, "_cycle_budget", self._settings.max_ips_per_cycle)

        for decision in decisions:
            if decision.action == ACTION_MONITOR:
                continue

            if not _is_public(decision.ip):
                notes.append(f"skipped {decision.ip} (not a public address)")
                continue

            if decision.action != ACTION_ALLOW and within(decision.ip, self._allowlist):
                notes.append(f"skipped {decision.ip} (emergency allowlist)")
                continue

            problem = self._adaptive_guardrail_problem(decision)
            if problem:
                notes.append(f"skipped {decision.ip} ({problem})")
                continue

            # Enforcement has to release itself. Redis is what ends a block --
            # nothing in the design renews or clears one -- so a decision with
            # no expiry would refuse an address until a human noticed and
            # deleted the key by hand. The store treats a falsy ttl as "keep
            # forever", which turns a missing number into a permanent sentence,
            # so the number is checked here rather than trusted downstream.
            if not decision.ttl_seconds or decision.ttl_seconds <= 0:
                notes.append(
                    f"skipped {decision.ip} ({decision.action} with no expiry)"
                )
                continue

            if budget <= 0:
                notes.append(f"skipped {decision.ip} (cycle cap reached)")
                continue

            key = self._policy_key(decision)
            if self._settings.dry_run:
                notes.append(f"[dry-run] would set {key} -> {decision.action}")
            else:
                self._store.set(key, decision.to_json(), decision.ttl_seconds)
                written += 1

            budget -= 1

        if hasattr(self, "_cycle_budget"):
            self._cycle_budget = budget

        return written, notes

    def _policy_key(self, decision: PolicyDecision) -> str:
        if not decision.method and not decision.route_template:
            return f"{self._settings.policy_prefix}{decision.ip}"
        scope = f"{decision.method.upper()}\x00{decision.route_template}".encode()
        digest = hashlib.sha256(scope).hexdigest()[:16]
        return f"{self._settings.policy_prefix}{decision.ip}:{digest}"

    def _adaptive_guardrail_problem(self, decision: PolicyDecision) -> str:
        """Re-check the rails at the only boundary that can reach Redis."""
        if decision.source not in ("adaptive", "approved"):
            return ""
        config = self._adaptive
        guard = config.guardrails
        if decision.source == "adaptive" and config.mode != "automatic":
            return f"{config.mode} mode cannot auto-enforce"
        if (
            decision.source == "adaptive"
            and decision.action in AUTO_ACTIONS
            and AUTO_ACTIONS.index(decision.action)
            > AUTO_ACTIONS.index(guard.maximum_automatic_action)
        ):
            return f"{decision.action} exceeds the automatic action ceiling"
        if decision.ttl_seconds > guard.maximum_policy_duration_seconds:
            return "duration exceeds the configured maximum"
        evidence_count = int(
            (decision.explanation or {}).get("deterministic_evidence_count") or 0
        )
        final = (decision.explanation or {}).get("final") or {}
        behavioural_throttle = bool(final.get("behavioural_throttle_authorized"))
        if decision.action == ACTION_THROTTLE:
            if behavioural_throttle:
                baseline = (decision.explanation or {}).get("baseline") or {}
                if not guard.behavioural_throttle_enabled:
                    return "behavioural throttles are disabled"
                if not baseline.get("baseline_ready"):
                    return "behavioural throttle requires a ready baseline"
                if float(baseline.get("deviation") or 0) < guard.behavioural_throttle_minimum_deviation:
                    return "behavioural deviation is below the throttle minimum"
                if not decision.method or not decision.route_template:
                    return "behavioural throttle must be endpoint scoped"
            else:
                if decision.confidence < guard.minimum_confidence_throttle:
                    return "confidence is below the throttle minimum"
                if evidence_count < guard.minimum_deterministic_evidence_throttle:
                    return "deterministic evidence is below the throttle minimum"
            if not guard.minimum_throttle_rpm <= decision.requests_per_minute <= guard.maximum_throttle_rpm:
                return "throttle rate is outside configured bounds"
        if decision.action == ACTION_TEMP_BLOCK:
            if decision.confidence < guard.minimum_confidence_temporary_block:
                return "confidence is below the temporary-block minimum"
            if evidence_count < guard.minimum_deterministic_evidence_temporary_block:
                return "deterministic evidence is below the temporary-block minimum"
        return ""


# RFC 5737 ranges reserved for documentation and examples. Python's
# is_private returns True for these, but they can never belong to a real host,
# so blocking them would only break demos and tests.
DOC_RANGES = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


def _is_public(ip: str) -> bool:
    """Refuse to write policy for anything that isn't safely actionable."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if any(addr in net for net in DOC_RANGES):
        return True

    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def parse_networks(entries: tuple[str, ...]) -> list:
    """Parse config entries into networks, ignoring anything unparseable."""
    networks = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
    return networks


def within(ip: str, networks: list) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in networks)
