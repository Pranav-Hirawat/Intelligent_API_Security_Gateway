"""
Escalation: the one action that asks for a human.

monitor, throttle and temp_block are things the system does by itself.
Escalation means the campaign is big and confident enough that somebody
should look at it, so it writes a durable record to its own Redis stream
rather than only a log line that scrolls away.

A stream, not an email, because the project has no mail or chat integration
and inventing one would be a dependency for a demo. Anything can read this:
the dashboard, redis-cli, or a later notifier that does send mail.
"""

from __future__ import annotations

from iasg.models import Campaign, PolicyDecision
from iasg.store.base import Store


class AlertSink:
    def __init__(self, store: Store, stream: str = "iasg_alerts") -> None:
        self._store = store
        self._stream = stream

    def raise_for(self, campaign: Campaign, decisions: list[PolicyDecision]) -> str | None:
        """
        Record one alert for an escalated campaign.

        Returns the entry id, or None when nothing was written. Alerting once
        per campaign rather than once per cycle matters: an escalated campaign
        stays escalated for as long as it is active, and re-alerting every 30
        seconds would train whoever reads this to ignore it.
        """
        if campaign.alerted:
            return None

        entry = {
            "campaign_id": campaign.campaign_id,
            "type": campaign.type,
            "severity": campaign.severity,
            "confidence": f"{campaign.confidence:.3f}",
            "ip_count": str(len(campaign.ips)),
            "ips": ",".join(campaign.ips),
            "event_count": str(campaign.event_count),
            "action": decisions[0].action if decisions else "",
            "reason": campaign.reason,
            "first_seen": campaign.first_seen.isoformat(),
            "last_seen": campaign.last_seen.isoformat(),
            # The admin-facing paragraph, so a reader needs nothing else.
            "explanation": campaign.explanation,
        }

        entry_id = self._store.append(self._stream, entry)
        campaign.alerted = True
        return entry_id
