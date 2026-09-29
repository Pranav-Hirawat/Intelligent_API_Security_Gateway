"""
Campaign memory (section 11 of the proposal).

Campaigns survive between cycles. A cluster that overlaps an existing campaign
is merged into it rather than stored as a new one, so confidence and evidence
accumulate over time. That merge is what makes this an agent continuing an
investigation instead of a script starting over every 30 seconds.
"""

from __future__ import annotations

import json
from dataclasses import asdict, fields
from datetime import timedelta

from iasg.adaptive.config import AdaptiveConfig
from iasg.models import CAMPAIGN_MULTI_STAGE, ENFORCEMENT_ACTIONS, Campaign, parse_timestamp
from iasg.store.base import Store

# How much IP overlap counts as "the same campaign".
MERGE_OVERLAP = 0.4

# Quiet cycles before a campaign is considered contained. Three keeps a short
# lull from being mistaken for success.
CONTAINED_AFTER = 3

# What the behavioural fingerprint is worth when no addresses are shared.
# Endpoint and user agent carry most of it: together they clear the threshold,
# and neither alone can. The subnet is a bonus rather than a requirement --
# rotating out of it is exactly the move this is meant to survive.
SIGNATURE_WEIGHTS = {"endpoint": 0.4, "user_agent": 0.4, "subnet": 0.2}
SIGNATURE_MATCH = 0.7

# Fields without which there is nothing worth comparing.
_SIGNATURE_REQUIRED = ("endpoint", "user_agent", "detector")

# How long an attacker can be quiet and still be the same campaign returning.
# Comfortably longer than the longest policy TTL, so a block expiring and the
# attacker coming back on fresh addresses is recognised rather than renumbered.
#
# Derived from guardrails.maximum_policy_duration_seconds (see apply_config)
# rather than fixed outright: that ceiling is itself configurable up to 24h,
# and a bare constant here could not keep its own stated promise once an
# operator raised it. The floor below is what every test and default
# deployment sees, since the default ceiling (1800s) times the multiple
# already lands exactly on it.
CONTINUATION_WINDOW = timedelta(hours=2)
CONTINUATION_WINDOW_MULTIPLE = 4


class CampaignRepository:
    def __init__(
        self,
        store: Store,
        prefix: str = "campaign:",
        persistence=None,
    ) -> None:
        """
        `persistence` is an optional durable backend -- see store/postgres.py.
        Given one, campaigns live there and survive a restart. Given None, they
        stay in the key-value store under a 24-hour TTL, which is what every
        test and every Redis-only deployment uses.
        """
        self._store = store
        self._prefix = prefix
        self._counter_key = f"{prefix}next_id"
        self._db = persistence
        self._continuation_window = CONTINUATION_WINDOW

    def apply_config(self, config: AdaptiveConfig) -> None:
        """
        Keep the continuation window's own stated invariant true: comfortably
        longer than the longest policy TTL, even after that ceiling is raised.
        """
        self._continuation_window = max(
            CONTINUATION_WINDOW,
            CONTINUATION_WINDOW_MULTIPLE
            * timedelta(seconds=config.guardrails.maximum_policy_duration_seconds),
        )

    def all(self) -> list[Campaign]:
        if self._db:
            return self._db.all()

        campaigns = []
        for key in self._store.keys(f"{self._prefix}*"):
            if key == self._counter_key:
                continue
            raw = self._store.get(key)
            if raw:
                campaigns.append(_from_json(raw))
        return campaigns

    def save(self, campaign: Campaign, ttl_seconds: int = 86_400) -> None:
        if self._db:
            self._db.save(campaign, ttl_seconds)
            # Deliberately falls through. Postgres is the record, but the
            # dashboard and anything else that wants a fast look reads Redis,
            # exactly as the gateway does -- so the key-value copy is kept as a
            # projection. It may expire; the database is what must not.

        self._store.set(
            f"{self._prefix}{campaign.campaign_id}",
            _to_json(campaign),
            ttl_seconds=ttl_seconds,
        )

    def merge(self, fresh: list[Campaign]) -> list[Campaign]:
        """
        Fold this cycle's clusters into what we already knew.

        Returns the campaigns as they now stand, whether new or updated.
        """
        known = self.all()
        result = []

        for candidate in fresh:
            match, matched_on = _best_match(candidate, known, self._continuation_window)
            if match is None:
                candidate.campaign_id = self._next_id()
                known.append(candidate)
                result.append(candidate)
            else:
                # Counted before absorbing, while the address sets are still
                # distinguishable.
                rotated = len(set(candidate.ips) - set(match.ips))
                if matched_on == "behaviour":
                    match.rotations += 1

                # We restrained this campaign and it is back regardless, either
                # by outlasting the policy or by moving to new addresses. Either
                # way the action we chose did not end it, which is the one
                # signal here that is not circular: a campaign going quiet after
                # a block proves little, but one continuing through a block
                # proves the block was not enough.
                if match.last_action in ENFORCEMENT_ACTIONS and (
                    match.status == "contained" or matched_on == "behaviour"
                ):
                    match.persistence += 1

                _absorb(match, candidate)

                if match.status == "contained":
                    # We thought this was over and it started again. Almost
                    # always means the block expired and the attacker resumed.
                    match.status = "active"
                    match.alerted = False
                    match.outcome = (
                        f"resumed after {match.quiet_cycles} quiet cycles "
                        f"following {match.last_action or 'no action'}"
                    )
                    if matched_on == "behaviour":
                        match.outcome += (
                            f", on {rotated} previously unseen "
                            f"addresses -- recognised by behaviour"
                        )
                elif matched_on == "behaviour":
                    match.outcome = (
                        f"still active on {rotated} previously unseen "
                        f"addresses -- recognised by behaviour"
                    )

                match.quiet_cycles = 0
                result.append(match)

        for campaign in result:
            self.save(campaign)
        return result

    def review(self, seen_ids: set[str]) -> list[Campaign]:
        """
        Close the loop: notice whether acting on a campaign changed anything.

        A campaign that stops producing evidence after we acted is marked
        contained; one that keeps producing it is not. Called once per cycle
        with the ids that saw fresh evidence.

        What "contained" honestly means: no further evidence reached us. When
        the action was a block that is largely circular, because a blocked
        address never reaches the detectors in the first place -- so this
        confirms enforcement is holding rather than that the attacker gave up.
        For monitor and throttle, where traffic still flows, it is a real
        signal that the campaign stopped.
        """
        changed = []

        for campaign in self.all():
            if campaign.campaign_id in seen_ids or campaign.status != "active":
                continue

            campaign.quiet_cycles += 1
            if campaign.quiet_cycles >= CONTAINED_AFTER:
                campaign.status = "contained"
                campaign.outcome = (
                    f"no further evidence for {campaign.quiet_cycles} cycles "
                    f"after {campaign.last_action or 'no action'}"
                )
            changed.append(campaign)

        for campaign in changed:
            self.save(campaign)
        return changed

    def warm(self) -> int:
        """
        Rebuild the key-value projection from the database.

        After a restart Redis is empty while Postgres is not, and without this
        the dashboard would show nothing until the next cycle happened to write
        a campaign. Returns how many were restored.
        """
        if not self._db:
            return 0

        campaigns = self._db.all()
        for campaign in campaigns:
            self._store.set(
                f"{self._prefix}{campaign.campaign_id}",
                _to_json(campaign),
                ttl_seconds=86_400,
            )
        return len(campaigns)

    def _next_id(self) -> str:
        if self._db:
            return self._db.next_id()

        current = self._store.get(self._counter_key)
        nxt = int(current) + 1 if current else 1
        # No TTL: the counter must outlive the campaigns it numbers.
        self._store.set(self._counter_key, str(nxt))
        return str(nxt)


def _best_match(
    candidate: Campaign, known: list[Campaign], continuation_window: timedelta
) -> tuple[Campaign | None, str]:
    """
    The stored campaign this cluster most likely continues, and how we decided.

    Two ways in, tried in that order. Shared addresses are the strongest
    evidence available, so they are checked first and behaviour is only
    consulted when there are none in common.
    """
    best, best_score = None, 0.0
    for existing in known:
        # Contained campaigns stay matchable so a resumed attack reopens the
        # one we already know about instead of starting a duplicate.
        score = _overlap(set(candidate.ips), set(existing.ips))
        if score > best_score:
            best, best_score = existing, score
    if best_score >= MERGE_OVERLAP:
        return best, "ips"

    # Not one address in common. Blocking works, so an attacker who can afford
    # to will simply move -- and matching on addresses alone means every
    # rotation looks like a brand new campaign and the investigation restarts.
    # What they cannot cheaply change is the behaviour: same endpoint, same
    # tooling, same attack. That is what we fall back to.
    best, best_score = None, 0.0
    for existing in known:
        score = _behaviour_match(candidate, existing, continuation_window)
        if score > best_score:
            best, best_score = existing, score
    if best_score >= SIGNATURE_MATCH:
        return best, "behaviour"

    return None, ""


def _behaviour_match(
    candidate: Campaign, existing: Campaign, continuation_window: timedelta
) -> float:
    """
    How strongly two campaigns look like the same operation on new hardware.

    Deliberately strict. Wrongly merging two unrelated attackers hides one of
    them behind the other's campaign, which is worse than carrying a duplicate.
    """
    a, b = candidate.signature or {}, existing.signature or {}

    # An empty or partial signature must not match everything it meets.
    if not all(a.get(k) and b.get(k) for k in _SIGNATURE_REQUIRED):
        return 0.0

    # A SQL injection probe is not the continuation of a flood, however much
    # the rest of the fingerprint agrees.
    if a["detector"] != b["detector"]:
        return 0.0

    # The same tooling pointed at the same endpoint next month is a new
    # campaign, not this one resuming. The window is wide enough that a block
    # expiring and the attacker returning still counts as a continuation.
    if abs(candidate.last_seen - existing.last_seen) > continuation_window:
        return 0.0

    return sum(
        weight
        for field, weight in SIGNATURE_WEIGHTS.items()
        if a.get(field) and a.get(field) == b.get(field)
    )


def _overlap(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _absorb(existing: Campaign, fresh: Campaign) -> None:
    """Update a known campaign with a new sighting."""
    existing.ips = sorted(set(existing.ips) | set(fresh.ips))
    existing.event_count += fresh.event_count
    existing.last_seen = max(existing.last_seen, fresh.last_seen)
    existing.severity = _worst(existing.severity, fresh.severity)

    # Phases accumulate. An actor that scanned in one cycle and attacked the
    # login in the next is staged even though neither cycle looked it alone,
    # and that is the case worth catching -- a real intrusion is slower than
    # one 30-second window. Merged before the reason is written, since whether
    # the campaign has outgrown this sighting depends on the result.
    for stage in fresh.stages:
        if stage not in existing.stages:
            existing.stages.append(stage)

    # The fresh reason describes this sighting, not the campaign. Once the
    # campaign covers more addresses or more phases than the sighting does,
    # the sentence would otherwise appear to contradict the figures printed
    # beside it, so it says which of the two it is talking about.
    outgrown = (
        len(existing.ips) > len(fresh.ips)
        or len(existing.stages) > len(fresh.stages)
    )
    existing.reason = (
        f"latest sighting: {fresh.reason}" if outgrown else fresh.reason
    )
    existing.signature = fresh.signature or existing.signature

    # Repeated sightings raise confidence, but never past certainty.
    existing.confidence = round(
        min(1.0, max(existing.confidence, fresh.confidence) + 0.05), 3
    )

    if len(existing.stages) > 1:
        existing.type = CAMPAIGN_MULTI_STAGE
    elif fresh.type != "Unclassified Activity":
        existing.type = fresh.type


def _worst(a: str, b: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    return a if order.get(a, 0) >= order.get(b, 0) else b


_REQUIRED = ("campaign_id", "type", "confidence", "ips", "reason", "severity")


def _to_json(c: Campaign) -> str:
    d = asdict(c)
    d["first_seen"], d["last_seen"] = c.first_seen.isoformat(), c.last_seen.isoformat()
    return json.dumps(d)


def _from_json(raw: str) -> Campaign:
    d = json.loads(raw)
    known = {f.name for f in fields(Campaign)}
    # A missing required key raises, as it always has; every other field falls
    # back to the dataclass default, so campaigns stored before a field existed
    # still load.
    data = {k: v for k, v in d.items() if k in known}
    data.update({k: d[k] for k in _REQUIRED})
    data["first_seen"] = parse_timestamp(d.get("first_seen") or "")
    data["last_seen"] = parse_timestamp(d.get("last_seen") or "")
    return Campaign(**data)
