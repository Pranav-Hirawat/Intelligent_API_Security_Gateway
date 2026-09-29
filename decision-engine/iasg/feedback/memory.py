"""
What the agent learned from being overruled.

Every time a human changes a recommendation, the direction of that change is
recorded against the campaign type. Once the same correction has been made
often enough, the agent starts making it itself.

Deliberately small and deliberately bounded:

  * it shifts a recommendation by at most one rung, ever, so a run of unusual
    calls cannot walk the agent from monitor to escalate
  * it needs several consistent corrections before it moves at all, so one
    disagreement is not treated as a rule
  * corrections in opposite directions cancel, so a type people genuinely
    disagree about stays where the evidence put it
  * it changes only the starting recommendation. The collateral checks and the
    address rails run afterwards and are not learnable, because a system that
    could learn its way past its own safety rails would eventually do so

There is no model here and nothing is trained. It is a tally.
"""

from __future__ import annotations

import json

from iasg.config import Settings
from iasg.models import ACTION_LADDER
from iasg.store.base import Store


class FeedbackMemory:
    def __init__(self, store: Store, settings: Settings, persistence=None) -> None:
        """`persistence` is the optional durable backend -- see store/postgres.py."""
        self._store = store
        self._settings = settings
        self._db = persistence

    def record(self, campaign_type: str, agent_action: str, human_action: str) -> None:
        """Note that a human moved this kind of campaign up or down."""
        direction = _direction(agent_action, human_action)
        if not direction or not campaign_type:
            return

        key = "up" if direction > 0 else "down"
        if self._db:
            # Incremented in the database rather than read-modify-written here,
            # so two agents correcting the same type cannot lose a correction.
            self._db.bump(campaign_type, key)
            # Read back rather than assumed, then mirrored to the key-value
            # store for fast readers -- see CampaignRepository.save.
            self._store.set(
                self._key(campaign_type), json.dumps(self._db.tally(campaign_type))
            )
            return

        tally = self._tally(campaign_type)
        tally[key] = tally.get(key, 0) + 1
        # No TTL: this is the agent's experience, not a cached value.
        self._store.set(self._key(campaign_type), json.dumps(tally))

    def bias_for(self, campaign_type: str) -> int:
        """-1, 0 or +1 rungs, from the corrections seen so far."""
        tally = self._tally(campaign_type)
        net = tally.get("up", 0) - tally.get("down", 0)

        if net >= self._settings.feedback_min_samples:
            return 1
        if -net >= self._settings.feedback_min_samples:
            return -1
        return 0

    def explain(self, campaign_type: str) -> str:
        """One line an admin can read, or empty if nothing has been learned."""
        tally = self._tally(campaign_type)
        up, down = tally.get("up", 0), tally.get("down", 0)
        bias = self.bias_for(campaign_type)
        if not bias:
            return ""

        stronger = "stronger" if bias > 0 else "weaker"
        return (
            f"{campaign_type}: humans chose {stronger} action "
            f"{max(up, down)} times (+{up}/-{down}) -- "
            f"recommending one rung {stronger}"
        )

    def all(self) -> dict[str, dict]:
        """Everything learned, for reporting."""
        if self._db:
            return self._db.all()

        learned = {}
        for key in self._store.keys(f"{self._settings.feedback_prefix}*"):
            raw = self._store.get(key)
            if raw:
                learned[key[len(self._settings.feedback_prefix):]] = json.loads(raw)
        return learned

    def warm(self) -> int:
        """Rebuild the key-value projection from the database. See the repository."""
        if not self._db:
            return 0

        learned = self._db.all()
        for campaign_type, tally in learned.items():
            self._store.set(self._key(campaign_type), json.dumps(tally))
        return len(learned)

    def _tally(self, campaign_type: str) -> dict:
        if self._db:
            return self._db.tally(campaign_type)

        raw = self._store.get(self._key(campaign_type))
        if not raw:
            return {}
        try:
            value = json.loads(raw)
            return value if isinstance(value, dict) else {}
        except ValueError:
            return {}

    def _key(self, campaign_type: str) -> str:
        return f"{self._settings.feedback_prefix}{campaign_type}"


def _direction(agent_action: str, human_action: str) -> int:
    """+1 if the human went harder, -1 if softer, 0 if it tells us nothing."""
    try:
        agent = ACTION_LADDER.index(agent_action)
        human = ACTION_LADDER.index(human_action)
    except ValueError:
        return 0
    if human > agent:
        return 1
    if human < agent:
        return -1
    return 0
