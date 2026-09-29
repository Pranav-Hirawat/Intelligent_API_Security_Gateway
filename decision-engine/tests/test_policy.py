"""The rails that stop a policy doing damage, whatever decided on it."""

from __future__ import annotations

import json
from dataclasses import replace

from iasg.config import Settings
from iasg.models import ACTION_MONITOR, ACTION_TEMP_BLOCK, ACTION_THROTTLE, PolicyDecision
from iasg.policy.writer import PolicyWriter
from iasg.store.memory import MemoryStore


def decisions(ips=("203.0.113.5",), action=ACTION_TEMP_BLOCK, ttl=1800, **kw):
    return [
        PolicyDecision(ip=ip, action=action, campaign_id="7", confidence=0.8,
                       ttl_seconds=ttl, reason="test", **kw)
        for ip in ips
    ]


# --- the rails ---

def settings(**kwargs):
    return replace(Settings(), **kwargs)


def test_writes_policy_for_public_ip():
    store = MemoryStore()
    written, _ = PolicyWriter(store, settings()).write(decisions())

    assert written == 1
    stored = json.loads(store.get("policy:203.0.113.5"))
    assert stored["action"] == ACTION_TEMP_BLOCK


def test_never_writes_policy_for_private_or_loopback():
    store = MemoryStore()
    for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.1.1"):
        written, notes = PolicyWriter(store, settings()).write(decisions([ip]))
        assert written == 0, f"wrote policy for {ip}"
        assert notes


def test_never_writes_a_decision_without_an_expiry():
    """
    A block ends because Redis drops the key. Nothing renews or clears one, so
    a decision with no expiry would refuse an address until a human deleted the
    key by hand -- and the store reads a falsy ttl as "keep forever", which
    turns a missing number into a permanent sentence.
    """
    store = MemoryStore()
    (decision,) = decisions()

    for ttl in (0, None, -1):
        written, notes = PolicyWriter(store, settings()).write(
            [replace(decision, ttl_seconds=ttl)]
        )
        assert written == 0, f"wrote an unexpiring policy for ttl={ttl!r}"
        assert any("no expiry" in note for note in notes), notes
        assert store.keys("policy:*") == []


def test_an_unexpiring_decision_does_not_consume_the_cycle_budget():
    """A refused decision must not cost a slot a real one could have used."""
    store = MemoryStore()
    (good,) = decisions(["203.0.113.5"])
    (bad,) = decisions(["203.0.113.9"], ttl=0)

    written, _ = PolicyWriter(store, settings(max_ips_per_cycle=1)).write([bad, good])

    assert written == 1
    assert store.get("policy:203.0.113.5") is not None


def test_monitor_writes_nothing():
    store = MemoryStore()
    written, _ = PolicyWriter(store, settings()).write(decisions(action=ACTION_MONITOR, ttl=300))
    assert written == 0
    assert store.keys("policy:*") == []


def test_dry_run_writes_nothing_but_reports():
    store = MemoryStore()
    written, notes = PolicyWriter(store, settings(dry_run=True)).write(decisions())

    assert written == 0
    assert store.keys("policy:*") == []
    assert any("dry-run" in n for n in notes)


def test_cycle_cap_limits_how_many_ips_are_actioned():
    store = MemoryStore()
    ips = [f"203.0.113.{n}" for n in range(1, 11)]
    written, notes = PolicyWriter(store, settings(max_ips_per_cycle=3)).write(decisions(ips))

    assert written == 3
    assert any("cap reached" in n for n in notes)


def test_malformed_ip_is_skipped():
    store = MemoryStore()
    written, _ = PolicyWriter(store, settings()).write(decisions(["not-an-ip"]))
    assert written == 0


def test_written_policy_carries_a_ttl():
    store = MemoryStore()
    PolicyWriter(store, settings()).write(decisions())

    _value, expires_at = store._keys["policy:203.0.113.5"]
    assert expires_at is not None


# --- the rate a throttle carries -------------------------------------------

def test_the_rate_reaches_the_gateway_contract():
    # The JSON at policy:<ip> is the whole contract with the Go gateway, so the
    # rate is only real if it survives serialisation under that exact name.
    (decision,) = decisions(action=ACTION_THROTTLE, ttl=900, requests_per_minute=20)
    written = json.loads(decision.to_json())
    assert written["requests_per_minute"] == 20
    assert written["action"] == ACTION_THROTTLE
