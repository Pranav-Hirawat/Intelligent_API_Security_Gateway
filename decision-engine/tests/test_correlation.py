"""The Correlation Agent groups related IPs and leaves unrelated ones alone."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from iasg.adaptive.config import AdaptiveConfig
from iasg.adaptive.risk import calculate_risk
from iasg.correlation.agent import CorrelationAgent
from iasg.correlation.cluster import UnionFind
from iasg.models import ACTION_THROTTLE, Evidence

BASE = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def evidence(ip, *, endpoint="/api/login", ua="curl/8.4", detector="bruteforce",
             offset=0, severity="high", **details):
    return Evidence(
        timestamp=BASE + timedelta(seconds=offset),
        ip=ip,
        endpoint=endpoint,
        detector=detector,
        severity=severity,
        user_agent=ua,
        details=details,
    )


def test_union_find_merges_transitively():
    uf = UnionFind(["a", "b", "c", "d"])
    uf.union("a", "b")
    uf.union("b", "c")
    groups = {tuple(g) for g in uf.groups()}
    assert ("a", "b", "c") in groups
    assert ("d",) in groups


def test_coordinated_ips_become_one_campaign():
    events = [
        evidence(f"203.0.113.{n}", offset=n, distinctUsers=5, failedLogins=9)
        for n in (5, 9, 14, 21, 33, 40)
    ]
    campaigns = CorrelationAgent().analyse(events)

    assert len(campaigns) == 1
    assert len(campaigns[0].ips) == 6
    assert campaigns[0].type == "Credential Stuffing"
    assert campaigns[0].confidence >= 0.8


def test_unrelated_ips_stay_separate():
    events = [
        *[evidence("203.0.113.5", endpoint="/api/login", ua="curl/8.4", offset=n)
          for n in range(4)],
        *[evidence("198.51.100.9", endpoint="/api/products", ua="Mozilla/5.0",
                   detector="flood", offset=9_000 + n) for n in range(4)],
    ]
    campaigns = CorrelationAgent().analyse(events)
    assert len(campaigns) == 2


def test_lone_ip_with_one_event_is_noise_not_a_campaign():
    assert CorrelationAgent().analyse([evidence("203.0.113.5")]) == []


def test_one_high_severity_sqli_probe_becomes_a_campaign():
    """A confirmed injection probe must survive a cycle by itself."""
    row = evidence("203.0.113.61", detector="sqli", severity="high")
    campaigns = CorrelationAgent().analyse([row])

    assert len(campaigns) == 1
    assert campaigns[0].type == "SQL Injection Probing"
    assert campaigns[0].ips == ["203.0.113.61"]

    result = calculate_risk(AdaptiveConfig(), campaigns[0], [row])
    assert result.action == ACTION_THROTTLE
    assert result.score == 52.1
    assert result.confidence == 0.582


def test_traversal_with_enumeration_becomes_a_campaign_before_reflex_blocks_more():
    """The gateway may stop the third probe, so these first two must suffice."""
    rows = [
        evidence("203.0.113.81", endpoint="/.env-demo", detector="enumeration",
                 severity="medium"),
        evidence("203.0.113.81", endpoint="/api/demo-files", detector="traversal",
                 severity="high", offset=1),
    ]

    (campaign,) = CorrelationAgent().analyse(rows)

    assert campaign.type == "Reconnaissance"
    assert campaign.ips == ["203.0.113.81"]
    result = calculate_risk(AdaptiveConfig(), campaign, rows)
    assert result.action == ACTION_THROTTLE
    assert result.explanation["deterministic_evidence_count"] == 2


def test_same_time_same_detector_alone_does_not_group():
    """Different networks, endpoints and agents must not become one campaign."""
    events = [
        *[evidence("203.0.113.5", endpoint="/api/cart", ua="Mozilla/5.0 (a)",
                   detector="flood", offset=n) for n in range(4)],
        *[evidence("198.51.100.9", endpoint="/api/orders", ua="Mozilla/5.0 (b)",
                   detector="flood", offset=n) for n in range(4)],
    ]
    campaigns = CorrelationAgent().analyse(events)
    assert len(campaigns) == 2


def test_reason_only_lists_traits_the_whole_group_shares():
    """Two of three sharing a User-Agent must not be reported as all three."""
    events = [
        *[evidence(f"203.0.113.{n}", ua="curl/8.4", offset=n) for n in (5, 9)],
        *[evidence("203.0.113.14", ua="wget/1.21", offset=3)],
        *[evidence("203.0.113.14", ua="wget/1.21", offset=n) for n in (4, 5)],
    ]
    (campaign,) = CorrelationAgent().analyse(events)
    assert len(campaign.ips) == 3
    assert "User-Agent" not in campaign.reason


def test_single_ip_many_failures_is_brute_force_not_stuffing():
    events = [
        evidence("203.0.113.5", offset=n, failedLogins=20, distinctUsers=1)
        for n in range(12)
    ]
    campaigns = CorrelationAgent().analyse(events)

    assert len(campaigns) == 1
    assert campaigns[0].type == "Brute Force"
    assert campaigns[0].ips == ["203.0.113.5"]


def test_spraying_detected_from_distinct_users():
    events = [
        evidence("203.0.113.5", offset=n, failedLogins=8, distinctUsers=9)
        for n in range(4)
    ]
    campaigns = CorrelationAgent().analyse(events)
    assert campaigns[0].type == "Password Spraying"


def test_distributed_flood_named_by_shape():
    events = [
        evidence(f"198.51.100.{n}", endpoint="/api/products", ua="python-requests/2.32",
                 detector="flood", offset=n, requestCount=500)
        for n in (7, 8, 9)
    ]
    campaigns = CorrelationAgent().analyse(events)
    assert campaigns[0].type == "Distributed Flood"


def test_empty_evidence_produces_no_campaigns():
    assert CorrelationAgent().analyse([]) == []


def test_timing_gap_prevents_grouping():
    """Same fingerprint, but a day apart, so timing must not link them."""
    events = [
        *[evidence("203.0.113.5", offset=n) for n in range(4)],
        *[evidence("203.0.113.9", offset=86_400 + n) for n in range(4)],
    ]
    campaigns = CorrelationAgent().analyse(events)
    assert len(campaigns) == 2


# A lone attacker shares traits with nobody, so coordination cannot score it.
# Before the solo path existed this capped at 0.15 and could never be actioned.
def test_single_ip_confidence_rises_with_volume():
    def confidence(n):
        events = [evidence("203.0.113.5", offset=i) for i in range(n)]
        return CorrelationAgent().analyse(events)[0].confidence

    low, mid, high = confidence(5), confidence(25), confidence(100)

    assert low < mid < high, "volume must move the score"
    assert high >= 0.75, "a machine with 100 detections must be blockable"


def test_single_ip_is_capped_below_escalation():
    events = [evidence("203.0.113.5", offset=i) for i in range(500)]
    (campaign,) = CorrelationAgent().analyse(events)

    assert campaign.confidence < 0.9, "one machine must never reach escalation"


def test_single_ip_severity_shifts_the_score():
    def confidence(severity):
        events = [evidence("203.0.113.5", offset=i, severity=severity)
                  for i in range(25)]
        return CorrelationAgent().analyse(events)[0].confidence

    assert confidence("high") > confidence("low")


# Coordination should still outrank a lone machine at the same volume.
def test_a_coordinated_group_outscores_one_ip():
    solo = [evidence("203.0.113.5", offset=i) for i in range(30)]
    group = [
        evidence(f"203.0.113.{n}", offset=i, distinctUsers=5)
        for n in (5, 9, 14, 21, 33)
        for i in range(6)
    ]

    solo_score = CorrelationAgent().analyse(solo)[0].confidence
    group_score = CorrelationAgent().analyse(group)[0].confidence

    assert group_score > solo_score


def test_coordinated_object_harvesting_is_named_bola():
    events = [
        evidence(f"203.0.113.{n}", endpoint="/api/orders/{id}", ua="python-requests/2.32",
                 detector="object_enumeration", offset=n + i, distinctIds=25)
        for n in (81, 82, 83)
        for i in range(4)
    ]
    campaigns = CorrelationAgent().analyse(events)

    assert len(campaigns) == 1
    campaign = campaigns[0]
    assert campaign.type == "Object ID Enumeration (BOLA)"
    assert sorted(campaign.ips) == ["203.0.113.81", "203.0.113.82", "203.0.113.83"]
    assert campaign.signature["endpoint"] == "/api/orders/{id}"
    assert campaign.stages == ["abuse"]


def test_refused_reads_of_other_peoples_objects_are_named_bola():
    events = [
        evidence("203.0.113.90", endpoint="/api/orders/{id}", ua="curl/8.7",
                 detector="ownership_violation", offset=i, reason="owner_mismatch")
        for i in range(5)
    ]
    campaigns = CorrelationAgent().analyse(events)

    assert len(campaigns) == 1
    assert campaigns[0].type == "Unauthorized Object Access (BOLA)"
    assert campaigns[0].stages == ["abuse"]
