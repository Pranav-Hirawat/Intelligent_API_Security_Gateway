"""
Timestamps and request records as the gateway writes them.

An unreadable timestamp does not raise -- the record is dropped, and the
window it belonged to quietly looks emptier than it was. So every shape the
gateway and its older releases write must parse: Go's nanoseconds, a bare Z,
an offset, no zone at all.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from iasg.anomaly.health import health_by_window
from iasg.anomaly.records import arrival_from_json, parse_ts, record_from_event
from iasg.anomaly.spec import UNMATCHED_ROUTE
from iasg.models import parse_timestamp

UTC = timezone.utc


def test_a_go_nanosecond_timestamp_is_kept_to_the_microsecond():
    assert parse_ts("2026-09-25T10:00:00.123456789Z") == datetime(2026, 9, 25, 10, 0, 0, 123456, UTC)


def test_an_offset_survives_parsing():
    parsed = parse_ts("2026-09-25T15:30:00.5+05:30")
    assert parsed.utcoffset() == timedelta(hours=5, minutes=30)
    assert parsed.microsecond == 500000


def test_a_time_without_a_zone_is_read_as_utc():
    assert parse_ts("2026-09-25T10:00:00").tzinfo == UTC
    assert parse_ts(datetime(2026, 9, 25, 10)).tzinfo == UTC
    aware = datetime(2026, 9, 25, 10, tzinfo=timezone(timedelta(hours=2)))
    assert parse_ts(aware) is aware


def test_a_dangling_fraction_is_tolerated():
    assert parse_ts("2026-09-25T10:00:00.Z") == datetime(2026, 9, 25, 10, tzinfo=UTC)


def test_an_unreadable_timestamp_is_missing_not_an_error():
    for value in ("", None, "yesterday", "2026-13-45T99:00:00Z"):
        assert parse_ts(value) is None


def test_evidence_with_an_unreadable_time_is_dated_now_rather_than_dropped():
    before = datetime.now(UTC)
    assert parse_timestamp("garbage") >= before


def test_an_arrival_needs_both_an_id_and_a_time():
    assert arrival_from_json({"requestId": "r1"}) is None
    assert arrival_from_json({"arrivalTs": "2026-09-25T10:00:00Z"}) is None


def test_an_arrival_without_a_route_counts_as_unmatched():
    record = arrival_from_json({"requestId": "r1", "arrivalTs": "2026-09-25T10:00:00Z", "ip": "203.0.113.5"})
    assert record.route_template == UNMATCHED_ROUTE
    assert record.completed_ts is None


def test_a_completed_event_carries_both_times():
    record = record_from_event({
        "requestId": "r1", "arrivalTs": "2026-09-25T10:00:00Z", "ts": "2026-09-25T10:00:01Z",
        "method": "GET", "path": "/api/products", "routeTemplate": "/api/products",
    })
    assert record.completed_ts - record.arrival_ts == timedelta(seconds=1)
    assert record_from_event({"ts": "2026-09-25T10:00:01Z"}) is None


def beats(start, count, **fields):
    return [
        {"at": (start + timedelta(seconds=i)).isoformat(), "seq": i, **fields}
        for i in range(count)
    ]


def test_a_minute_is_trusted_only_with_sixty_contiguous_heartbeats_and_no_drops():
    start = datetime(2026, 9, 25, 10, 0, tzinfo=UTC)
    assert health_by_window(beats(start, 60))[start].fully_observed

    assert not health_by_window(beats(start, 59))[start].fully_observed
    gap = beats(start, 60)
    gap[30]["seq"] = 99
    assert not health_by_window(gap)[start].fully_observed
    assert not health_by_window(beats(start, 60), trim_losses=True)[start].fully_observed


def test_dropped_events_within_a_minute_are_counted_and_distrusted():
    start = datetime(2026, 9, 25, 10, 0, tzinfo=UTC)
    entries = beats(start, 60, droppedTotal=4)
    entries[-1]["droppedTotal"] = 7
    entries[-1]["arrivalsDroppedTotal"] = "2"
    health = health_by_window(entries)[start]
    assert health.dropped == 5
    assert not health.fully_observed


def test_unreadable_heartbeats_are_ignored():
    start = datetime(2026, 9, 25, 10, 0, tzinfo=UTC)
    entries = beats(start, 60) + [{"at": "nonsense", "seq": 1}]
    entries[0]["droppedTotal"] = "n/a"
    assert health_by_window(entries)[start].fully_observed
