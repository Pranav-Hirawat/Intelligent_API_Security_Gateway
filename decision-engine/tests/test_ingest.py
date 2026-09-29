"""Parsing the gateway's printed SECURITY ALERT blocks."""

from __future__ import annotations

from iasg.evidence.ingest import parse

BRUTE_FORCE = """
------ Incoming Request ------
Method: POST

			========================================
			SECURITY ALERT: BRUTE FORCE DETECTED
			----------------------------------------
			IP Address     : 203.0.113.5
			Endpoint       : /api/login
			Failed Logins  : 12
			Distinct Users : 5
			Attack Type    : PASSWORD SPRAYING (multiple accounts)
			Time Window    : 1m0s
			User-Agent     : curl/8.4.0
			Severity       : HIGH
			Timestamp      : 2026-08-11T12:31:00+05:30
			ACTION         : DETECTED (ALLOWING REQUEST)
			========================================
""".splitlines()

FLOOD = """
			========================================
			SECURITY ALERT: API FLOOD DETECTED
			----------------------------------------
			IP Address     : 198.51.100.7
			Endpoint       : /api/products
			Requests       : 480
			Time Window    : 1m0s
			User-Agent     : python-requests/2.32
			Severity       : HIGH
			Timestamp      : 2026-08-11T12:35:00+05:30
			ACTION         : DETECTED (ALLOWING REQUEST)
			========================================
""".splitlines()


def test_parses_brute_force_alert():
    (ev,) = parse(BRUTE_FORCE)
    assert ev.ip == "203.0.113.5"
    assert ev.detector == "bruteforce"
    assert ev.endpoint == "/api/login"
    assert ev.severity == "high"
    assert ev.user_agent == "curl/8.4.0"
    assert ev.details["failedLogins"] == 12
    assert ev.details["distinctUsers"] == 5


def test_parses_flood_alert():
    (ev,) = parse(FLOOD)
    assert ev.detector == "flood"
    assert ev.details["requestCount"] == 480


def test_parses_multiple_blocks_in_one_stream():
    assert len(parse(BRUTE_FORCE + FLOOD)) == 2


def test_ordinary_log_lines_are_ignored():
    noise = [
        "------ Incoming Request ------",
        "Method: GET",
        "Path: /api/products",
        "IP: 10.0.0.1",
    ]
    assert parse(noise) == []


def test_unknown_alert_type_is_skipped():
    block = [
        "SECURITY ALERT: SOMETHING NEW DETECTED",
        "----------------------------------------",
        "IP Address     : 203.0.113.5",
        "========================================",
    ]
    assert parse(block) == []


def test_alert_without_ip_is_skipped():
    block = [
        "SECURITY ALERT: BRUTE FORCE DETECTED",
        "----------------------------------------",
        "Endpoint       : /api/login",
        "========================================",
    ]
    assert parse(block) == []


def test_round_trips_through_stream_fields():
    """Parsed evidence must survive the trip through Redis."""
    from iasg.models import Evidence

    (ev,) = parse(BRUTE_FORCE)
    back = Evidence.from_stream_fields("1-1", ev.to_stream_fields())
    assert back.ip == ev.ip
    assert back.details["failedLogins"] == 12


def block(headline, **fields):
    rows = "\n".join(f"\t\t\t{name.replace('_', ' '):<15}: {value}" for name, value in fields.items())
    return f"""
\t\t\t========================================
\t\t\tSECURITY ALERT: {headline}
\t\t\t----------------------------------------
{rows}
\t\t\t========================================
""".splitlines()


def test_an_unknown_severity_is_read_as_medium():
    (ev,) = parse(block("SQL INJECTION DETECTED", IP_Address="203.0.113.5", Severity="CATASTROPHIC"))
    assert ev.severity == "medium"


def test_an_unreadable_count_is_dropped_not_fatal():
    (ev,) = parse(block("API FLOOD DETECTED", IP_Address="203.0.113.5", Requests="lots"))
    assert "requestCount" not in ev.details


def test_an_alert_without_an_address_or_known_detector_is_skipped():
    """An address is what a policy would be written for; without one there is
    nothing to act on, and an unknown headline has no detector to credit."""
    assert parse(block("SQL INJECTION DETECTED", Severity="HIGH")) == []
    assert parse(block("SOMETHING NEW DETECTED", IP_Address="203.0.113.5")) == []


def test_the_pipe_writes_each_alert_to_the_evidence_stream(monkeypatch, capsys):
    import io

    from iasg.evidence import ingest
    from iasg.store.memory import MemoryStore

    store = MemoryStore()
    monkeypatch.setattr(ingest, "open_store", lambda settings: store)
    monkeypatch.setattr("sys.stdin", io.StringIO("\n".join(BRUTE_FORCE + FLOOD) + "\n"))

    ingest.main()

    out = capsys.readouterr().out
    assert "SECURITY ALERT: BRUTE FORCE DETECTED" in out, "the gateway's own output must stay visible"
    assert "[ingest] -> flood 198.51.100.7 (2 total)" in out
    store.ensure_group("iasg:events", "check")
    entries = store.read_group("iasg:events", "check", "c", 10)
    assert [fields["detector"] for _, fields in entries] == ["bruteforce", "flood"]
