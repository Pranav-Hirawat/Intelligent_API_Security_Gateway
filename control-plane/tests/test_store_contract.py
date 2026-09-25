"""
MemoryStore stands in for Redis in almost every other test, so it is only
worth trusting if it behaves the way RedisStore does. Every property here runs
against both; the Redis half runs when IASG_TEST_REDIS_URL points at a Redis
the test may flush.
"""

from __future__ import annotations

import os
import time

import pytest

from iasg.config import Settings
from iasg.store import MemoryStore, RedisStore, open_store

REDIS_URL = os.getenv("IASG_TEST_REDIS_URL")


@pytest.fixture(params=["memory", "redis"])
def store(request):
    if request.param == "memory":
        yield MemoryStore()
        return
    if not REDIS_URL:
        pytest.skip("set IASG_TEST_REDIS_URL to run the store contract against Redis")
    s = RedisStore(REDIS_URL)
    s._client.flushdb()
    yield s
    s._client.flushdb()
    s.close()


def test_a_group_reads_each_entry_once(store):
    store.ensure_group("s", "g")
    store.ensure_group("s", "g")  # repeated creation is the normal case
    first = store.append("s", {"n": "1"})
    store.append("s", {"n": "2"})

    batch = store.read_group("s", "g", "c", 10)
    assert [fields["n"] for _, fields in batch] == ["1", "2"]
    assert batch[0][0] == first
    assert store.read_group("s", "g", "c", 10) == []


def test_a_group_created_after_events_still_sees_them(store):
    store.append("s", {"n": "1"})
    store.ensure_group("s", "late")
    assert len(store.read_group("s", "late", "c", 10)) == 1


# Crash recovery: what was read but not acked comes back, until it is acked.
def test_unacked_entries_are_redelivered_and_acked_ones_are_not(store):
    store.ensure_group("s", "g")
    ids = [store.append("s", {"n": str(n)}) for n in range(3)]
    store.read_group("s", "g", "c", 10)

    assert [i for i, _ in store.read_pending("s", "g", "c", 10)] == ids
    assert store.ack("s", "g", ids[0], ids[1]) == 2
    assert store.ack("s", "g") == 0
    assert [i for i, _ in store.read_pending("s", "g", "c", 10)] == [ids[2]]


# The dashboard's reset relies on this: trimming empties the stream but the
# control plane's consumer group survives, so the next cycle is not NOGROUP.
def test_trimming_keeps_the_consumer_group(store):
    store.ensure_group("s", "g")
    for n in range(5):
        store.append("s", {"n": str(n)})
    store.read_group("s", "g", "c", 10)
    store.trim("s", 0)

    store.append("s", {"n": "after"})
    assert [f["n"] for _, f in store.read_group("s", "g", "c", 10)] == ["after"]


def test_keys_expire_by_themselves(store):
    store.set("policy:a", "x", ttl_seconds=1)
    store.set("keep", "y")
    assert store.get("policy:a") == "x"
    time.sleep(1.2)
    assert store.get("policy:a") is None
    assert store.get("keep") == "y"


def test_keys_match_their_pattern(store):
    for key in ("policy:1", "policy:2", "campaign:1"):
        store.set(key, "v")
    assert sorted(store.keys("policy:*")) == ["policy:1", "policy:2"]
    assert store.get("missing") is None


# A dead Redis must never stop the agent starting.
def test_unreachable_redis_falls_back_to_memory(capsys):
    fallback = open_store(Settings(redis_url="redis://127.0.0.1:1/0"))
    assert isinstance(fallback, MemoryStore)
    assert "in-memory store" in capsys.readouterr().out
