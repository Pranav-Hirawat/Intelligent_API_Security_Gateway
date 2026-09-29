"""
IP reputation: the one signal that comes from outside this gateway.

The properties worth protecting are all about restraint. Reputation says who an
address is, not what it did, so it must firm up a response without inventing
one, and it must never take credit for a campaign it merely witnessed.
"""

from __future__ import annotations

from datetime import datetime, timezone

from iasg.correlation.agent import CorrelationAgent
from iasg.models import (
    DETECTOR_BRUTE_FORCE,
    DETECTOR_FLOOD,
    DETECTOR_REPUTATION,
    SIGNAL_TO_DETECTOR,
    STAGE_OF,
    Evidence,
)

NOW = datetime.now(timezone.utc)


def evidence(ip, detector, severity="medium", endpoint="/api/login"):
    return Evidence(
        timestamp=NOW, ip=ip, endpoint=endpoint,
        detector=detector, severity=severity,
    )


# --- staging ---

def test_reputation_is_not_an_intrusion_phase():
    """
    Being on a list is not something the attacker did, so it must not count as
    a stage -- the number of stages is read as evidence of intent, and every
    listed address would look like a multi-phase attacker.
    """
    assert DETECTOR_REPUTATION not in STAGE_OF


def test_reputation_evidence_does_not_add_a_stage():
    ip = "203.0.113.66"
    only_flood = CorrelationAgent().analyse([evidence(ip, DETECTOR_FLOOD)] * 3)
    with_listing = CorrelationAgent().analyse(
        [evidence(ip, DETECTOR_FLOOD)] * 3 + [evidence(ip, DETECTOR_REPUTATION)]
    )
    assert len(only_flood[0].stages) == len(with_listing[0].stages)


# --- naming ---

def test_reputation_does_not_rename_a_behavioural_campaign():
    """
    A listed address running a brute force is a brute force. Reputation fires
    on a cooldown so it should not out-count anything, but the classifier does
    not rely on that.
    """
    ip = "203.0.113.66"
    campaigns = CorrelationAgent().analyse(
        [evidence(ip, DETECTOR_BRUTE_FORCE)] * 2 + [evidence(ip, DETECTOR_REPUTATION)] * 20
    )
    assert campaigns[0].type != "Known Bad Address"
    assert "Brute Force" in campaigns[0].type or "Spraying" in campaigns[0].type


def test_reputation_can_name_a_campaign_when_it_is_all_there_is():
    # A lone address needs MIN_SOLO_EVENTS before it counts as a campaign, and
    # reputation fires once per cooldown -- so this is a listed address that
    # kept calling for a quarter of an hour without tripping anything else.
    campaigns = CorrelationAgent().analyse(
        [evidence("203.0.113.66", DETECTOR_REPUTATION, endpoint="/products")] * 3
    )
    assert campaigns[0].type == "Known Bad Address"


# --- the wire ---

def test_the_gateway_signal_name_maps_to_this_detector():
    assert SIGNAL_TO_DETECTOR["ip_reputation"] == DETECTOR_REPUTATION


def test_telemetry_carrying_a_reputation_hit_becomes_evidence():
    import json

    event = {
        "ts": NOW.isoformat(),
        "ip": "203.0.113.66",
        "path": "/products",
        "fired": ["ip_reputation"],
        "signals": [
            {
                "signal": "ip_reputation",
                "score": 80,
                "thresholdCross": True,
                "attackType": "known_bad_address",
                "details": {"listed": True},
            }
        ],
    }
    found = Evidence.from_stream_entry("1-1", {"event": json.dumps(event)})

    assert len(found) == 1
    assert found[0].detector == DETECTOR_REPUTATION
    assert found[0].ip == "203.0.113.66"
