"""
The Correlation Agent.

Answers "what is actually happening?" -- never "should this be blocked?".
Turns scattered per-IP evidence into named campaigns with a confidence score.
Entirely deterministic: no LLM is involved in any of this.
"""

from __future__ import annotations

from iasg.correlation.cluster import cluster
from iasg.correlation.features import IPProfile, build_profiles, common_traits
from iasg.models import (
    CAMPAIGN_MULTI_STAGE,
    DETECTOR_BRUTE_FORCE,
    DETECTOR_ENUMERATION,
    DETECTOR_FLOOD,
    DETECTOR_OBJECT_ENUMERATION,
    DETECTOR_OWNERSHIP,
    DETECTOR_REPUTATION,
    DETECTOR_SQLI,
    DETECTOR_TRAVERSAL,
    DETECTOR_UNKNOWN_ROUTE_SCAN,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    STAGE_OF,
    Campaign,
    Evidence,
)

# Below this, a single IP acting alone is filed as noise rather than a campaign.
MIN_SOLO_EVENTS = 3

# The consumer hands correlation only the evidence newly received in one
# decision-engine cycle. A signature-confirmed injection or traversal probe must
# not vanish merely because a gateway reflex stops the next request before it
# can add a third event. Other single-IP detectors still need volume before
# they are called campaigns; these exceptions apply only when the gateway
# already rated their evidence high.
IMMEDIATE_SOLO_CAMPAIGN_DETECTORS = frozenset({DETECTOR_SQLI, DETECTOR_TRAVERSAL})

# Events a phase needs before it counts as a phase. One stray detection from
# another detector should not turn a single-purpose attack into a staged
# intrusion, because staging raises enforcement.
MIN_STAGE_EVENTS = 3

# How much each shared trait contributes to confidence.
TRAIT_WEIGHTS = {
    "user_agent": 0.25,
    "endpoint": 0.20,
    "attack_type": 0.15,
    "subnet": 0.20,
    "timing": 0.10,
}

# A lone attacker shares traits with nobody, so the weights above can never
# score one. Its own volume is the evidence instead: how many times a detector
# fired on this single address, coarsely banded rather than curve-fitted.
SOLO_VOLUME = (
    (100, 0.80),
    (50, 0.72),
    (25, 0.62),
    (10, 0.50),
    (5, 0.40),
    (3, 0.30),
)

# What a detector already thought of the traffic, worth a nudge either way.
SOLO_SEVERITY_BONUS = {SEVERITY_HIGH: 0.07, SEVERITY_MEDIUM: 0.03}

# Kept under 0.9 so volume alone can get a single address blocked but never
# escalated: escalation on the evidence path means "wake a human about a
# coordinated campaign", and one machine repeating itself is not that.
#
# One machine that moves through phases is, though, and the policy ladder can
# still promote it there -- a lone actor who scanned for secrets, attacked the
# login it found and then probed the database is a likelier real intrusion than
# any amount of the same request repeated.
SOLO_CEILING = 0.87


class CorrelationAgent:
    def __init__(self, min_shared: int = 2, window_seconds: int = 300) -> None:
        self._min_shared = min_shared
        self._window_seconds = window_seconds

    def analyse(self, evidence: list[Evidence]) -> list[Campaign]:
        """Build campaigns from a batch of evidence."""
        if not evidence:
            return []

        profiles = build_profiles(evidence)
        clusters = cluster(profiles, self._min_shared, self._window_seconds)

        campaigns = []
        for ips, _pairwise in clusters:
            members = [profiles[ip] for ip in ips]

            # A lone IP with a couple of events is an incident, not a campaign.
            # Without this the agent files a campaign for every stray detection
            # and its memory fills with noise.
            if (
                len(members) == 1
                and members[0].event_count < MIN_SOLO_EVENTS
                and not _is_immediate_solo_campaign(members[0])
            ):
                continue

            # Report and score on what the whole group shares, not on what some
            # pair happened to share.
            traits = common_traits(members, self._window_seconds)
            campaigns.append(self._build(members, traits))

        # Most confident first, so the policy agent sees the clearest cases first.
        campaigns.sort(key=lambda c: c.confidence, reverse=True)
        return campaigns

    def _build(self, members: list[IPProfile], traits: list[str]) -> Campaign:
        ips = [m.ip for m in members]
        events = sum(m.event_count for m in members)
        confidence = self._confidence(members, traits)
        stages = _stages(members)

        return Campaign(
            campaign_id="",  # assigned by the repository when it is stored
            type=self._classify(members, stages),
            confidence=confidence,
            ips=ips,
            reason=self._reason(members, traits, stages),
            severity=self._severity(members, confidence),
            stages=stages,
            first_seen=min(m.first_seen for m in members if m.first_seen),
            last_seen=max(m.last_seen for m in members if m.last_seen),
            event_count=events,
            signature={
                "traits": traits,
                "endpoint": members[0].top_endpoint,
                "user_agent": members[0].top_user_agent,
                "detector": _dominant_detector(members),
                "subnet": members[0].subnet,
            },
        )

    def _confidence(self, members: list[IPProfile], traits: list[str]) -> float:
        """
        Weighted sum of shared traits, plus a nudge for scale.

        Coordination is the strongest signal available, but it needs at least
        two addresses to exist. A lone attacker is scored on its own volume
        instead -- see _solo_confidence.
        """
        if len(members) == 1:
            return self._solo_confidence(members[0])

        score = sum(TRAIT_WEIGHTS.get(t, 0.0) for t in traits)

        # More coordinated machines is stronger evidence of a campaign.
        if len(members) >= 5:
            score += 0.15
        elif len(members) >= 3:
            score += 0.10

        # Sustained volume matters even without coordination.
        events = sum(m.event_count for m in members)
        if events >= 50:
            score += 0.15
        elif events >= 10:
            score += 0.08

        return round(min(score, 1.0), 3)

    def _solo_confidence(self, member: IPProfile) -> float:
        """
        Score one address on the evidence it actually produces.

        Before this existed a single IP could never exceed 0.15 and so could
        never be throttled or blocked, no matter how many times a detector
        fired on it -- which left the most ordinary attack of all, one machine
        grinding away at a login form, permanently unactionable.
        """
        score = 0.0
        for threshold, banded in SOLO_VOLUME:
            if member.event_count >= threshold:
                score = banded
                break

        score += SOLO_SEVERITY_BONUS.get(member.worst_severity, 0.0)
        return round(min(score, SOLO_CEILING), 3)

    def _classify(self, members: list[IPProfile], stages: list[str]) -> str:
        """Name the campaign from its dominant detector and its shape."""
        # An actor that moved from one phase to another is doing something the
        # dominant detector cannot describe on its own. Naming it after that
        # detector would report the loudest phase and hide the rest.
        if len(stages) > 1:
            return CAMPAIGN_MULTI_STAGE

        detector = _dominant_detector(members)
        multi_ip = len(members) >= 3
        sprayed = any(m.distinct_users > 3 for m in members)

        if detector == DETECTOR_BRUTE_FORCE:
            if multi_ip and sprayed:
                return "Credential Stuffing"
            if sprayed:
                return "Password Spraying"
            return "Brute Force"
        if detector == DETECTOR_FLOOD:
            return "Distributed Flood" if multi_ip else "API Flooding"
        if detector == DETECTOR_SQLI:
            return "SQL Injection Probing"
        if detector in (DETECTOR_TRAVERSAL, DETECTOR_ENUMERATION, DETECTOR_UNKNOWN_ROUTE_SCAN):
            return "Reconnaissance"
        if detector == DETECTOR_OBJECT_ENUMERATION:
            return "Object ID Enumeration (BOLA)"
        if detector == DETECTOR_OWNERSHIP:
            return "Unauthorized Object Access (BOLA)"
        if detector == DETECTOR_REPUTATION:
            return "Known Bad Address"
        return "Unclassified Activity"

    def _severity(self, members: list[IPProfile], confidence: float) -> str:
        worst = "low"
        for m in members:
            if m.worst_severity == SEVERITY_HIGH:
                worst = SEVERITY_HIGH
                break
            if m.worst_severity == SEVERITY_MEDIUM:
                worst = SEVERITY_MEDIUM

        # A wide, confident campaign is serious even if each detector shrugged.
        if worst != SEVERITY_HIGH and len(members) >= 5 and confidence >= 0.8:
            return SEVERITY_HIGH
        return worst or SEVERITY_LOW

    def _reason(
        self, members: list[IPProfile], traits: list[str], stages: list[str]
    ) -> str:
        events = sum(m.event_count for m in members)

        # Said first, because naming only the dominant detector here would
        # describe one phase of the attack and silently drop the others.
        if len(stages) > 1:
            who = "single IP" if len(members) == 1 else f"{len(members)} IPs"
            return (
                f"{who}, {events} events progressing through "
                f"{' -> '.join(stages)}"
            )

        if len(members) == 1:
            m = members[0]
            return (
                f"single IP, {m.event_count} events from "
                f"{m.top_detector or 'detector'} on {m.top_endpoint or 'unknown path'}"
            )

        readable = {
            "user_agent": f"same User-Agent ({members[0].top_user_agent or 'n/a'})",
            "endpoint": f"same endpoint ({members[0].top_endpoint or 'n/a'})",
            "attack_type": f"same attack type ({_dominant_detector(members)})",
            "subnet": f"same subnet ({members[0].subnet or 'n/a'})",
            "timing": "overlapping timing",
        }
        shared = ", ".join(readable[t] for t in traits if t in readable)
        return f"{len(members)} IPs sharing {shared}"


def _is_immediate_solo_campaign(member: IPProfile) -> bool:
    """Allow a confirmed injection or traversal probe through the noise gate."""
    return (
        member.worst_severity == SEVERITY_HIGH
        and any(
            detector in IMMEDIATE_SOLO_CAMPAIGN_DETECTORS
            for detector in member.detectors
        )
    )


def _stages(members: list[IPProfile]) -> list[str]:
    """
    The intrusion phases this group went through, earliest first.

    Ordered by when each phase was actually first observed rather than by any
    textbook sequence, because real attackers do not read the textbook and a
    claim of progression should be something we saw.
    """
    counts: dict[str, int] = {}
    started: dict[str, object] = {}

    for m in members:
        for detector, count in m.detectors.items():
            stage = STAGE_OF.get(detector)
            if not stage:
                continue
            counts[stage] = counts.get(stage, 0) + count

            at = m.detector_first_seen.get(detector)
            if at is not None and (stage not in started or at < started[stage]):
                started[stage] = at

    seen = [s for s, n in counts.items() if n >= MIN_STAGE_EVENTS and s in started]
    seen.sort(key=lambda s: started[s])
    return seen


def _dominant_detector(members: list[IPProfile]) -> str:
    totals: dict[str, int] = {}
    for m in members:
        for detector, count in m.detectors.items():
            totals[detector] = totals.get(detector, 0) + count
    if not totals:
        return ""

    # Reputation describes who an address is, not what it did, so it never
    # out-votes a detector that actually watched behaviour -- otherwise a
    # listed attacker running a brute force would produce a campaign named
    # after the list it appears on. It can still name a campaign when it is
    # genuinely all we have.
    behavioural = {d: c for d, c in totals.items() if d != DETECTOR_REPUTATION}
    if behavioural:
        return max(behavioural, key=lambda k: behavioural[k])
    return max(totals, key=lambda k: totals[k])
