"""
Per-IP profiles built from raw evidence.

The correlation agent never compares individual events. It compares IPs, so
each IP's events are first folded into one profile of what that IP did.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from iasg.models import Evidence


@dataclass
class IPProfile:
    """Everything one IP did in this batch."""

    ip: str
    endpoints: Counter = field(default_factory=Counter)
    user_agents: Counter = field(default_factory=Counter)
    detectors: Counter = field(default_factory=Counter)
    severities: Counter = field(default_factory=Counter)
    # When each detector first fired on this address. Lets a campaign say which
    # phase came first rather than assuming attacks arrive in textbook order.
    detector_first_seen: dict = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    event_count: int = 0
    distinct_users: int = 0

    def add(self, ev: Evidence) -> None:
        self.event_count += 1
        if ev.endpoint:
            self.endpoints[ev.endpoint] += 1
        if ev.user_agent:
            self.user_agents[ev.user_agent] += 1
        if ev.detector:
            self.detectors[ev.detector] += 1
            earliest = self.detector_first_seen.get(ev.detector)
            if earliest is None or ev.timestamp < earliest:
                self.detector_first_seen[ev.detector] = ev.timestamp
        if ev.severity:
            self.severities[ev.severity] += 1

        if self.first_seen is None or ev.timestamp < self.first_seen:
            self.first_seen = ev.timestamp
        if self.last_seen is None or ev.timestamp > self.last_seen:
            self.last_seen = ev.timestamp

        # Detector-specific numbers. Keep the highest seen, since detectors
        # report a running total rather than a delta.
        d = ev.details or {}
        self.distinct_users = max(self.distinct_users, _as_int(d.get("distinctUsers")))

    @property
    def top_endpoint(self) -> str:
        return _top(self.endpoints)

    @property
    def top_user_agent(self) -> str:
        return _top(self.user_agents)

    @property
    def top_detector(self) -> str:
        return _top(self.detectors)

    @property
    def subnet(self) -> str:
        """The /24 the IP sits in. Machines in one botnet often share it."""
        try:
            net = ipaddress.ip_network(f"{self.ip}/24", strict=False)
            return str(net)
        except ValueError:
            return ""

    @property
    def worst_severity(self) -> str:
        for level in ("high", "medium", "low"):
            if self.severities.get(level):
                return level
        return "low"


def build_profiles(evidence: list[Evidence]) -> dict[str, IPProfile]:
    """Fold a batch of evidence into one profile per IP."""
    profiles: dict[str, IPProfile] = {}
    for ev in evidence:
        if not ev.ip:
            continue
        profile = profiles.get(ev.ip)
        if profile is None:
            profile = IPProfile(ip=ev.ip)
            profiles[ev.ip] = profile
        profile.add(ev)
    return profiles


def shared_traits(a: IPProfile, b: IPProfile, window_seconds: int) -> list[str]:
    """Which of the section 13.1 attributes these two IPs have in common."""
    traits: list[str] = []

    if a.top_endpoint and a.top_endpoint == b.top_endpoint:
        traits.append("endpoint")
    if a.top_user_agent and a.top_user_agent == b.top_user_agent:
        traits.append("user_agent")
    if a.top_detector and a.top_detector == b.top_detector:
        traits.append("attack_type")
    if a.subnet and a.subnet == b.subnet:
        traits.append("subnet")
    if _overlap(a, b, window_seconds):
        traits.append("timing")

    return traits


def common_traits(members: list[IPProfile], window_seconds: int) -> list[str]:
    """
    Traits shared by EVERY member, not merely by some pair.

    Pairwise links are what form a group, but reporting their union would
    claim a shared User-Agent when only two of six members shared one. This
    is what the campaign's reason and confidence are built from.
    """
    if len(members) == 1:
        return []

    traits = []
    first = members[0]

    if first.top_endpoint and all(m.top_endpoint == first.top_endpoint for m in members):
        traits.append("endpoint")
    if first.top_user_agent and all(m.top_user_agent == first.top_user_agent for m in members):
        traits.append("user_agent")
    if first.top_detector and all(m.top_detector == first.top_detector for m in members):
        traits.append("attack_type")
    if first.subnet and all(m.subnet == first.subnet for m in members):
        traits.append("subnet")

    starts = [m.first_seen for m in members if m.first_seen]
    ends = [m.last_seen for m in members if m.last_seen]
    if starts and ends and (max(ends) - min(starts)).total_seconds() <= window_seconds * 4:
        traits.append("timing")

    return traits


def _overlap(a: IPProfile, b: IPProfile, window_seconds: int) -> bool:
    """True when the two IPs were active at roughly the same time."""
    if not (a.first_seen and a.last_seen and b.first_seen and b.last_seen):
        return False
    gap = max(
        (b.first_seen - a.last_seen).total_seconds(),
        (a.first_seen - b.last_seen).total_seconds(),
    )
    return gap <= window_seconds


def _top(counter: Counter) -> str:
    if not counter:
        return ""
    return counter.most_common(1)[0][0]


def _as_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
