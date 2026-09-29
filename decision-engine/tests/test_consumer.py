"""The evidence consumer must never lose an event, even across a crash."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone

from iasg.config import Settings
from iasg.evidence.consumer import EvidenceConsumer
from iasg.models import Evidence
from iasg.store.memory import MemoryStore

BASE = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def settings(**overrides) -> Settings:
    return dataclasses.replace(Settings(), **overrides)


def seed(store: MemoryStore, count: int, stream: str = "iasg:events") -> None:
    for n in range(count):
        e = Evidence(
            timestamp=BASE + timedelta(seconds=n),
            ip=f"203.0.113.{n + 1}",
            endpoint="/api/login",
            detector="bruteforce",
            severity="high",
            user_agent="curl/8.4",
            details={"failedLogins": 9},
        )
        store.append(stream, e.to_stream_fields())


def consumer(store: MemoryStore, **overrides) -> EvidenceConsumer:
    return EvidenceConsumer(store, settings(**overrides))


def test_empty_stream_yields_nothing():
    store = MemoryStore()
    assert consumer(store).fetch() == []


def test_fetch_returns_typed_evidence_oldest_first():
    store = MemoryStore()
    seed(store, 3)

    got = consumer(store).fetch()

    assert [e.ip for e in got] == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
    assert all(isinstance(e, Evidence) for e in got)
    assert got[0].detector == "bruteforce"
    # Redis hands everything back as text; the model converts it.
    assert got[0].details["failedLogins"] == 9


def test_batch_size_caps_one_cycle():
    store = MemoryStore()
    seed(store, 10)

    assert len(consumer(store, batch_size=4).fetch()) == 4


def test_second_fetch_does_not_replay_read_entries():
    store = MemoryStore()
    seed(store, 3)
    c = consumer(store)

    first = c.fetch()
    second = c.fetch()

    assert len(first) == 3
    assert second == [], "already-read entries were handed out twice"


def test_new_events_arrive_on_the_next_fetch():
    store = MemoryStore()
    seed(store, 2)
    c = consumer(store)
    c.fetch()

    seed(store, 1)
    assert len(c.fetch()) == 1


def test_ack_marks_entries_processed():
    store = MemoryStore()
    seed(store, 3)
    c = consumer(store)

    evidence = c.fetch()
    assert c.ack(evidence) == 3


def test_ack_of_nothing_is_harmless():
    store = MemoryStore()
    assert consumer(store).ack([]) == 0


def test_ack_ignores_evidence_with_no_stream_id():
    store = MemoryStore()
    handmade = Evidence(
        timestamp=BASE, ip="203.0.113.5", endpoint="/x",
        detector="flood", severity="low", user_agent="",
    )
    assert consumer(store).ack([handmade]) == 0


# The point of the consumer group: a crash before ack must replay, not lose.
def test_unacked_evidence_is_recovered_by_a_new_consumer():
    store = MemoryStore()
    seed(store, 3)

    crashed = consumer(store)
    crashed.fetch()  # read, then "crash" without acking

    restarted = consumer(store)
    recovered = restarted.fetch()

    assert len(recovered) == 3, "evidence was lost when the agent restarted"
    assert {e.ip for e in recovered} == {
        "203.0.113.1", "203.0.113.2", "203.0.113.3",
    }


def test_acked_evidence_is_not_recovered_after_restart():
    store = MemoryStore()
    seed(store, 3)

    first = consumer(store)
    first.ack(first.fetch())

    assert consumer(store).fetch() == [], "acked evidence was replayed"


# Recovery is a startup step, not something that repeats every cycle.
def test_pending_is_only_reclaimed_once():
    store = MemoryStore()
    seed(store, 2)

    stale = consumer(store)
    stale.fetch()

    restarted = consumer(store)
    assert len(restarted.fetch()) == 2
    assert restarted.fetch() == []


# The gateway writes one entry per request and most requests are clean, so the
# majority of entries produce no Evidence at all. Acking only what became
# Evidence left those pending forever.
def clean_request(store: MemoryStore, path: str = "/api/products") -> None:
    store.append("iasg:events", {
        "event": json.dumps({
            "requestId": "abc123",
            "ts": BASE.isoformat(),
            "ip": "203.0.113.50",
            "method": "GET",
            "path": path,
            "status": 200,
            "decision": "allow",
            "fired": [],
            "signals": [],
        }),
        "ip": "203.0.113.50",
        "path": path,
    })


def test_clean_request_produces_no_evidence():
    store = MemoryStore()
    clean_request(store)

    assert consumer(store).fetch() == []


def test_an_entry_that_produced_no_evidence_is_still_acked():
    store = MemoryStore()
    clean_request(store)
    c = consumer(store)

    assert c.fetch() == []
    assert c.ack([]) == 1, "a clean request stayed pending forever"


def test_clean_requests_do_not_replay_after_restart():
    store = MemoryStore()
    for _ in range(3):
        clean_request(store)

    first = consumer(store)
    first.ack(first.fetch())

    restarted = consumer(store)
    assert restarted.fetch() == []
    # Nothing was recovered, so nothing was left pending.
    assert restarted.ack([]) == 0


def test_a_crash_before_ack_still_replays_clean_requests():
    store = MemoryStore()
    clean_request(store)

    crashed = consumer(store)
    crashed.fetch()  # read, then "crash" without acking

    # It yields no Evidence either way, so the observable proof that it was
    # recovered is that the restarted consumer can still ack it.
    restarted = consumer(store)
    restarted.fetch()
    assert restarted.ack([]) == 1, "an unacked clean request was lost"


def test_mixed_batch_acks_every_entry_not_just_the_firing_ones():
    store = MemoryStore()
    seed(store, 2)
    clean_request(store)
    c = consumer(store)

    evidence = c.fetch()

    assert len(evidence) == 2, "only the firing entries become Evidence"
    assert c.ack(evidence) == 3, "the clean entry was not acked"


def test_ack_twice_does_not_double_count():
    store = MemoryStore()
    seed(store, 2)
    c = consumer(store)

    evidence = c.fetch()
    assert c.ack(evidence) == 2
    assert c.ack(evidence) == 0, "already-acked entries were acked again"


# A "clear campaigns" reset writes a watermark rather than trimming the
# stream -- raw evidence is kept, but nothing older than the reset may ever
# become Evidence again, or clearing would immediately be undone by whatever
# was still sitting in the stream.
def test_evidence_before_the_reset_watermark_is_acked_but_not_correlated():
    store = MemoryStore()
    e = Evidence(
        timestamp=BASE, ip="203.0.113.9", endpoint="/api/login",
        detector="bruteforce", severity="high", user_agent="curl/8.4",
    )
    pre_reset_id = store.append("iasg:events", e.to_stream_fields())
    watermark_ms = int(pre_reset_id.split("-", 1)[0]) + 1
    store.set(settings().reset_watermark_key, str(watermark_ms))

    c = consumer(store)
    evidence = c.fetch()

    assert evidence == [], "evidence older than the reset watermark was correlated"
    # Read and ackable like any other entry -- a reset must not leave it
    # pending forever, or read_pending would keep re-delivering it.
    assert c.ack([]) == 1, "pre-reset entry was left pending instead of acked"


def test_evidence_at_or_after_the_reset_watermark_is_still_correlated():
    store = MemoryStore()
    store.set(settings().reset_watermark_key, "0")
    seed(store, 1)

    evidence = consumer(store).fetch()

    assert len(evidence) == 1, "evidence at/after the watermark was wrongly dropped"


def test_a_malformed_watermark_value_filters_nothing():
    store = MemoryStore()
    store.set(settings().reset_watermark_key, "not-a-number")
    seed(store, 1)

    evidence = consumer(store).fetch()

    assert len(evidence) == 1, "a broken watermark should fail open, not swallow evidence"


def test_group_is_created_on_construction():
    store = MemoryStore()
    consumer(store, evidence_stream="brand_new_stream")

    # Appending and reading works immediately, so the group exists.
    seed(store, 1, stream="brand_new_stream")
    got = consumer(store, evidence_stream="brand_new_stream").fetch()
    assert len(got) == 1
