"""
Evidence and policy as they cross process boundaries.

Everything here is read from something another program wrote -- the gateway,
the seeder, an older control plane, the dashboard. A malformed record must be
skipped or defaulted, never crash the cycle that happens to read it.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from iasg.models import (
    ACTION_TEMP_BLOCK,
    DETECTOR_ENUMERATION,
    DETECTOR_REPUTATION,
    DETECTOR_TRAVERSAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    Evidence,
    PolicyDecision,
)

WHEN = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)


def evidence(detector, severity=SEVERITY_HIGH, **details):
    return Evidence(
        timestamp=WHEN, ip="203.0.113.5", endpoint="/api/../etc/passwd", method="GET",
        detector=detector, severity=severity, user_agent="curl/8", details=details, stream_id="1-0",
    )


@pytest.mark.parametrize("detector", [DETECTOR_TRAVERSAL, DETECTOR_ENUMERATION, DETECTOR_REPUTATION])
@pytest.mark.parametrize("severity", [SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW])
def test_evidence_survives_the_trip_through_gateway_telemetry(detector, severity):
    """The seeder writes evidence in the gateway's format; the agent must read
    back exactly the detector and severity it was given."""
    (back,) = Evidence.from_stream_entry("1-0", evidence(detector, severity).to_telemetry_fields())
    assert (back.detector, back.severity, back.ip) == (detector, severity, "203.0.113.5")


def test_one_request_that_both_traverses_and_enumerates_is_two_pieces_of_evidence():
    event = {
        "ip": "203.0.113.5", "path": "/x", "fired": ["enumeration_path_traversal"],
        "signals": [{"signal": "enumeration_path_traversal", "score": 80,
                     "attackType": "path_traversal+enumeration", "details": {}}],
    }
    found = Evidence.from_stream_entry("1-0", {"event": json.dumps(event)})
    assert sorted(e.detector for e in found) == sorted([DETECTOR_TRAVERSAL, DETECTOR_ENUMERATION])


def test_a_combined_signal_that_names_neither_part_still_counts():
    event = {"ip": "203.0.113.5", "fired": ["enumeration_path_traversal"], "signals": []}
    (found,) = Evidence.from_stream_entry("1-0", {"event": json.dumps(event)})
    assert found.detector == DETECTOR_TRAVERSAL


def test_a_signal_this_agent_does_not_know_is_ignored():
    event = {"ip": "203.0.113.5", "fired": ["future_detector"], "signals": []}
    assert Evidence.from_stream_entry("1-0", {"event": json.dumps(event)}) == []


def test_an_unreadable_score_counts_as_medium():
    event = {"ip": "203.0.113.5", "fired": ["sql_injection"],
             "signals": [{"signal": "sql_injection", "score": "high"}]}
    (found,) = Evidence.from_stream_entry("1-0", {"event": json.dumps(event)})
    assert found.severity == SEVERITY_MEDIUM


@pytest.mark.parametrize("fields", [
    {"event": "{not json"},
    {"event": "[1, 2]"},
    {"ip": "203.0.113.5"},
    {},
])
def test_a_malformed_stream_entry_yields_no_evidence(fields):
    assert Evidence.from_stream_entry("1-0", fields) == []


def test_flat_fields_with_unreadable_details_keep_the_evidence():
    fields = evidence(DETECTOR_TRAVERSAL).to_stream_fields()
    fields["details"] = "{broken"
    (found,) = Evidence.from_stream_entry("1-0", fields)
    assert found.details == {}
    assert found.detector == DETECTOR_TRAVERSAL


def decision(**changes):
    fields = dict(ip="203.0.113.5", action=ACTION_TEMP_BLOCK, campaign_id="7", confidence=0.8,
                  ttl_seconds=600, method="POST", route_template="/api/login", issued_at=WHEN)
    fields.update(changes)
    return PolicyDecision(**fields)


def test_a_decision_read_back_is_the_decision_that_was_stored():
    original = decision()
    back = PolicyDecision.from_dict(original.to_dict())
    for name in ("ip", "action", "campaign_id", "ttl_seconds", "method", "route_template",
                 "policy_id", "issued_at", "source"):
        assert getattr(back, name) == getattr(original, name), name


@pytest.mark.parametrize("spelling", ["temporary_block", "block"])
def test_older_block_spellings_read_as_a_temporary_block(spelling):
    assert PolicyDecision.from_dict({"ip": "203.0.113.5", "action": spelling}).action == ACTION_TEMP_BLOCK


def test_a_stored_expiry_time_becomes_the_remaining_lifetime():
    stored = {"ip": "203.0.113.5", "action": "throttle", "issued_at": WHEN.isoformat(),
              "expires_at": (WHEN + timedelta(minutes=15)).isoformat()}
    assert PolicyDecision.from_dict(stored).ttl_seconds == 900


def test_a_record_with_nothing_in_it_becomes_a_harmless_monitor():
    empty = PolicyDecision.from_dict({})
    assert empty.action == "monitor"
    assert empty.ttl_seconds == 0
