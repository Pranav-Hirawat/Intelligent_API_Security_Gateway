"""
What the agent learns from being overruled, and where that learning stops.

Human overrides are tallied per campaign type (feedback/memory.py). Once the
same correction has been made often enough, the agent's own next
recommendation for that type moves one rung that way. It moves the proposal
only: every guardrail still runs afterwards, because a system that could learn
its way past its own rails eventually would.
"""

from __future__ import annotations

import contextlib
import io
import json
from dataclasses import replace

import pytest

from iasg.adaptive.config import AUTO_ACTIONS, AdaptiveConfig
from iasg.adaptive.risk import _learned, calculate_risk
from iasg.config import Settings
from iasg.models import ACTION_MONITOR, ACTION_TEMP_BLOCK, ACTION_THROTTLE
from iasg.runner import Runner, report
from iasg.store.memory import MemoryStore
from tests.test_feedback import instruct, seed
from tools.seed_evidence import SCENARIOS


def actions_for(scenario: str, tally: dict | None = None, settings: Settings | None = None):
    """The policy the agent writes for a seeded scenario, given what it has learned."""
    store = MemoryStore()
    for e in SCENARIOS[scenario]():
        store.append("iasg:events", e.to_stream_fields())
    if tally is not None:
        store.set("feedback:Brute Force", json.dumps(tally))
    with contextlib.redirect_stdout(io.StringIO()):
        result = Runner(settings or Settings(), store).cycle()
    written = {json.loads(store.get(key))["action"] for key in store.keys("policy:*")}
    return written, result


def test_consistent_firmer_corrections_make_the_next_recommendation_firmer():
    before, _ = actions_for("brute-force")
    after, result = actions_for("brute-force", {"up": 2})
    assert before == {"throttle"}
    assert after == {"temporary_block"}
    assert result.learned == [
        "Brute Force: humans chose stronger action 2 times (+2/-0) -- recommending one rung stronger"
    ]


def test_consistent_softer_corrections_make_it_softer():
    after, result = actions_for("brute-force", {"down": 2})
    assert after == set(), "throttle softened one rung is monitor, which writes nothing"
    assert result.campaigns, "softening the response must not hide the campaign"


@pytest.mark.parametrize("tally", [{"up": 1}, {"up": 2, "down": 2}, {}])
def test_one_correction_or_disagreement_teaches_nothing(tally):
    assert actions_for("brute-force", tally)[0] == {"throttle"}


def test_learning_is_one_rung_ever():
    assert _learned(ACTION_MONITOR, 50) == (ACTION_THROTTLE, 1)
    assert _learned(ACTION_TEMP_BLOCK, -50) == (ACTION_THROTTLE, -1)
    assert _learned(ACTION_TEMP_BLOCK, 1) == (ACTION_TEMP_BLOCK, 0), "there is no rung above the ceiling"
    assert _learned(ACTION_MONITOR, -1) == (ACTION_MONITOR, 0)
    for action in AUTO_ACTIONS:
        assert _learned(action, 0) == (action, 0)


def test_learning_cannot_authorize_enforcement_without_gateway_evidence():
    result = calculate_risk(AdaptiveConfig(), None, [], learned_bias=1)
    assert result.action == ACTION_MONITOR
    assert result.explanation["final"]["learned_rungs"] == 1, "the push was proposed and refused"


def test_learning_cannot_pass_the_operators_action_ceiling():
    base = AdaptiveConfig()
    capped = replace(base, guardrails=replace(base.guardrails, maximum_automatic_action="throttle"))
    written, _ = actions_for("brute-force", {"up": 2}, replace(Settings(), adaptive=capped))
    assert written == {"throttle"}


def test_learning_cannot_pass_the_block_minimums():
    base = AdaptiveConfig()
    strict = replace(base, guardrails=replace(base.guardrails, minimum_confidence_temporary_block=0.99))
    written, _ = actions_for("brute-force", {"up": 2}, replace(Settings(), adaptive=strict))
    assert written == {"throttle"}


def test_the_whole_loop_overrides_teach_the_next_campaign(capsys):
    """Two operators block brute force the agent only throttled. The next brute
    force, from an address nobody has touched, is blocked by the agent itself."""
    store = MemoryStore()
    runner = Runner(Settings(), store)
    for n in range(2):
        seed(store, offset=n * 600)
        instruct(store, action="temp_block")
        runner.cycle()
    capsys.readouterr()

    seed(store, ip="203.0.113.77", offset=1800)
    result = runner.cycle()

    written = json.loads(store.get("policy:203.0.113.77"))
    assert written["action"] == "temporary_block"
    assert written["source"] == "adaptive", "the agent decided this, not a human"
    assert written["explanation"]["final"]["learned_rungs"] == 1

    report(result)
    assert "[learned]     Brute Force: humans chose stronger action 2 times" in capsys.readouterr().out
