"""Gateway iasg:events JSON must become typed Evidence, including split traversal/enum."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from iasg.models import (
    DETECTOR_BRUTE_FORCE,
    DETECTOR_ENUMERATION,
    DETECTOR_FLOOD,
    DETECTOR_OBJECT_ENUMERATION,
    DETECTOR_OWNERSHIP,
    DETECTOR_TRAVERSAL,
    DETECTOR_UNKNOWN_ROUTE_SCAN,
    Evidence,
)


def test_clean_telemetry_is_ignored():
    event = {
        "ts": "2026-08-14T10:00:00Z",
        "ip": "203.0.113.5",
        "method": "GET",
        "path": "/api/products",
        "fired": [],
        "signals": [],
        "riskScore": 0,
    }
    assert Evidence.from_stream_entry("1-0", {"event": json.dumps(event)}) == []


def test_flood_signal_maps_to_flood_detector():
    event = {
        "ts": "2026-08-14T10:00:00+00:00",
        "ip": "198.51.100.7",
        "method": "GET",
        "path": "/api/products",
        "userAgent": "curl/8.4",
        "fired": ["api_flooding"],
        "riskScore": 80,
        "signals": [
            {
                "signal": "api_flooding",
                "score": 80,
                "thresholdCross": True,
                "attackType": "api_flooding",
                "details": {"requestRate": 120, "threshold": 100},
            }
        ],
    }

    got = Evidence.from_stream_entry("9-0", {"event": json.dumps(event)})

    assert len(got) == 1
    assert got[0].detector == DETECTOR_FLOOD
    assert got[0].ip == "198.51.100.7"
    assert got[0].endpoint == "/api/products"
    assert got[0].details["requestRate"] == 120
    assert got[0].stream_id == "9-0"
    assert got[0].timestamp == datetime(2026, 8, 14, 10, 0, tzinfo=timezone.utc)


def test_enumeration_path_traversal_splits_both_phases():
    event = {
        "ts": "2026-08-14T10:00:00Z",
        "ip": "203.0.113.9",
        "path": "/.git",
        "fired": ["enumeration_path_traversal"],
        "signals": [
            {
                "signal": "enumeration_path_traversal",
                "score": 100,
                "attackType": "path_traversal+enumeration",
                "details": {
                    "pathTraversalDetected": True,
                    "enumerationDetected": True,
                },
            }
        ],
    }

    got = Evidence.from_stream_entry("2-0", {"event": json.dumps(event)})
    assert {e.detector for e in got} == {DETECTOR_TRAVERSAL, DETECTOR_ENUMERATION}
    assert all(e.stream_id == "2-0" for e in got)


def test_seeder_telemetry_round_trips():
    original = Evidence(
        timestamp=datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc),
        ip="203.0.113.5",
        endpoint="/api/login",
        detector=DETECTOR_BRUTE_FORCE,
        severity="high",
        method="POST",
        user_agent="curl/8.4.0",
        details={"failedLogins": 9},
    )

    got = Evidence.from_stream_entry("3-0", original.to_telemetry_fields())
    assert len(got) == 1
    assert got[0].detector == DETECTOR_BRUTE_FORCE
    assert got[0].details["failedLogins"] == 9


def test_unknown_route_scan_maps_to_reconnaissance_evidence():
    event = {
        "ts": "2026-08-14T10:00:00Z",
        "ip": "203.0.113.6",
        "method": "GET",
        "path": "/admin",
        "fired": ["unknown_route_scanning"],
        "signals": [{
            "signal": "unknown_route_scanning",
            "score": 60,
            "thresholdCross": True,
            "attackType": "unknown_route_scanning",
            "details": {"distinctPaths": 8, "window": "5m0s"},
        }],
    }

    got = Evidence.from_stream_entry("4-0", {"event": json.dumps(event)})
    assert len(got) == 1
    assert got[0].detector == DETECTOR_UNKNOWN_ROUTE_SCAN
    assert got[0].details["distinctPaths"] == 8


def test_flat_fields_still_parse():
    got = Evidence.from_stream_entry(
        "4-0",
        {
            "timestamp": "2026-08-14T10:00:00+00:00",
            "ip": "203.0.113.1",
            "endpoint": "/api/login",
            "detector": "bruteforce",
            "severity": "high",
            "method": "POST",
            "userAgent": "curl/8.4",
            "details": '{"failedLogins": 9}',
        },
    )
    assert len(got) == 1
    assert got[0].detector == "bruteforce"
    assert got[0].details["failedLogins"] == 9


def test_object_enumeration_evidence_is_keyed_on_the_template():
    # /api/orders/1..N are one endpoint being harvested. Keyed on the raw path,
    # no two requests would share an endpoint and correlation could not see it.
    def event(ip, order_id):
        return {
            "ts": "2026-08-14T10:00:00Z",
            "ip": ip,
            "method": "GET",
            "path": f"/api/orders/{order_id}",
            "fired": ["object_enumeration"],
            "signals": [{
                "signal": "object_enumeration",
                "score": 90,
                "thresholdCross": True,
                "attackType": "object_enumeration",
                "details": {
                    "template": "GET /api/orders/{id}",
                    "distinctIds": 24,
                    "deniedShare": 0.9,
                    "sequentialRun": 24,
                },
            }],
        }

    first = Evidence.from_stream_entry("5-0", {"event": json.dumps(event("203.0.113.81", 7))})
    second = Evidence.from_stream_entry("5-1", {"event": json.dumps(event("203.0.113.81", 8))})

    assert [e.detector for e in first] == [DETECTOR_OBJECT_ENUMERATION]
    assert first[0].endpoint == second[0].endpoint == "/api/orders/{id}"
    assert first[0].severity == "high"
    assert first[0].details["distinctIds"] == 24


def test_ownership_violation_maps_to_the_template_endpoint():
    event = {
        "ts": "2026-09-17T10:00:00Z",
        "ip": "203.0.113.90",
        "method": "GET",
        "path": "/api/orders/12",
        "status": 404,
        "fired": ["ownership_violation"],
        "signals": [{
            "signal": "ownership_violation",
            "score": 80,
            "thresholdCross": True,
            "attackType": "owner_mismatch",
            "details": {
                "template": "GET /api/orders/{id}",
                "reason": "owner_mismatch",
                "caller": "2",
                "owner": "4",
                "recentViolations": 1,
            },
        }],
    }

    got = Evidence.from_stream_entry("6-0", {"event": json.dumps(event)})

    assert [e.detector for e in got] == [DETECTOR_OWNERSHIP]
    assert got[0].endpoint == "/api/orders/{id}"
    assert got[0].severity == "high"
    assert got[0].details["owner"] == "4"
