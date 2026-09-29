"""MemoryStore behaviour. Ported from the Go memory_test.go."""

from __future__ import annotations

import time

from iasg.store.memory import MemoryStore


def test_get_missing_key_returns_none():
    assert MemoryStore().get("nope") is None


def test_set_then_get():
    store = MemoryStore()
    store.set("policy:1.2.3.4", "throttle")
    assert store.get("policy:1.2.3.4") == "throttle"


def test_key_expires_on_read():
    store = MemoryStore()
    store.set("temp", "x", ttl_seconds=0.05)
    assert store.get("temp") == "x"
    time.sleep(0.1)
    assert store.get("temp") is None


def test_no_ttl_never_expires():
    store = MemoryStore()
    store.set("forever", "x")
    time.sleep(0.05)
    assert store.get("forever") == "x"


def test_keys_matches_pattern_and_hides_expired():
    store = MemoryStore()
    store.set("policy:a", "1")
    store.set("policy:b", "2")
    store.set("campaign:a", "3")
    store.set("policy:gone", "4", ttl_seconds=0.05)
    time.sleep(0.1)
    assert sorted(store.keys("policy:*")) == ["policy:a", "policy:b"]


def test_append_returns_unique_ids():
    store = MemoryStore()
    first = store.append("s", {"a": "1"})
    second = store.append("s", {"a": "2"})
    assert first != second


def test_append_copies_caller_dict():
    """Mutating the dict after appending must not rewrite stored history."""
    store = MemoryStore()
    fields = {"ip": "1.1.1.1"}
    store.append("s", fields)
    fields["ip"] = "9.9.9.9"

    store.ensure_group("s", "g")
    (_id, stored), = store.read_group("s", "g", "c", 10)
    assert stored["ip"] == "1.1.1.1"


def test_cursor_advances_so_events_are_not_replayed():
    store = MemoryStore()
    store.ensure_group("s", "g")
    store.append("s", {"n": "1"})
    store.append("s", {"n": "2"})

    assert len(store.read_group("s", "g", "c", 10)) == 2
    assert store.read_group("s", "g", "c", 10) == []


def test_read_group_respects_count():
    store = MemoryStore()
    store.ensure_group("s", "g")
    for n in range(5):
        store.append("s", {"n": str(n)})
    assert len(store.read_group("s", "g", "c", 2)) == 2


def test_unacked_entries_are_replayed_by_read_pending():
    store = MemoryStore()
    store.ensure_group("s", "g")
    store.append("s", {"n": "1"})
    batch = store.read_group("s", "g", "c", 10)

    # Simulates a crash: read but never acked.
    assert len(store.read_pending("s", "g", "c", 10)) == 1

    store.ack("s", "g", *[i for i, _ in batch])
    assert store.read_pending("s", "g", "c", 10) == []


def test_ack_counts_only_pending_ids():
    store = MemoryStore()
    store.ensure_group("s", "g")
    store.append("s", {"n": "1"})
    batch = store.read_group("s", "g", "c", 10)
    ids = [i for i, _ in batch]

    assert store.ack("s", "g", *ids) == 1
    assert store.ack("s", "g", *ids) == 0


def test_ensure_group_is_repeatable():
    store = MemoryStore()
    store.ensure_group("s", "g")
    store.append("s", {"n": "1"})
    store.read_group("s", "g", "c", 10)

    # Calling it again must not rewind the cursor.
    store.ensure_group("s", "g")
    assert store.read_group("s", "g", "c", 10) == []
