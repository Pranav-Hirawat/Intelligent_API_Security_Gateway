"""
The guardrails between a risk score and the action it proposes.

A score only nominates an action. These checks decide whether the evidence
behind it is strong enough, and they may only ever move the action down.
"""

from __future__ import annotations

import itertools
from dataclasses import replace

from iasg.adaptive.config import AUTO_ACTIONS, AdaptiveConfig
from iasg.adaptive.risk import _guard
from iasg.models import ACTION_MONITOR, ACTION_TEMP_BLOCK, ACTION_THROTTLE


def config(**guardrails) -> AdaptiveConfig:
    base = AdaptiveConfig()
    return replace(base, guardrails=replace(base.guardrails, **guardrails))


def guard(candidate, confidence=0.9, score=80.0, count=3, behavioural=False, cfg=None):
    return _guard(candidate, confidence, score, count, behavioural, cfg or AdaptiveConfig())


def test_well_supported_actions_stand():
    assert guard(ACTION_TEMP_BLOCK)[0] == ACTION_TEMP_BLOCK
    assert guard(ACTION_THROTTLE)[0] == ACTION_THROTTLE


def test_a_block_without_enough_confidence_becomes_a_throttle():
    action, reasons = guard(ACTION_TEMP_BLOCK, confidence=0.6)
    assert action == ACTION_THROTTLE
    assert "temporary-block confidence minimum was not met" in reasons


def test_a_block_without_enough_evidence_becomes_a_throttle():
    action, reasons = guard(ACTION_TEMP_BLOCK, count=1)
    assert action == ACTION_THROTTLE
    assert "temporary-block evidence minimum was not met" in reasons


def test_a_throttle_without_enough_confidence_becomes_monitoring():
    action, reasons = guard(ACTION_THROTTLE, confidence=0.3)
    assert action == ACTION_MONITOR
    assert "throttle confidence minimum was not met" in reasons


def test_a_throttle_without_enough_evidence_becomes_monitoring():
    action, reasons = guard(ACTION_THROTTLE, count=1, cfg=config(minimum_deterministic_evidence_throttle=2,
                                                                 minimum_deterministic_evidence_temporary_block=2))
    assert action == ACTION_MONITOR
    assert "throttle evidence minimum was not met" in reasons


def test_evidence_an_operator_weighted_to_zero_cannot_enforce():
    action, reasons = guard(ACTION_TEMP_BLOCK, score=0.0)
    assert action == ACTION_MONITOR
    assert "configured deterministic evidence carried no weight" in reasons


def test_a_behavioural_throttle_respects_a_monitor_only_ceiling():
    action, reasons = guard(ACTION_THROTTLE, count=0, behavioural=True,
                            cfg=config(maximum_automatic_action="monitor"))
    assert action == ACTION_MONITOR
    assert "behavioural throttle exceeds the automatic-action ceiling" in reasons


def test_a_behavioural_surprise_can_throttle_but_never_block():
    action, _ = guard(ACTION_TEMP_BLOCK, count=0, behavioural=True)
    assert action == ACTION_THROTTLE


def test_guardrails_only_ever_lower_an_action():
    """Swept across every combination: no check may turn a weaker nomination
    into a stronger response."""
    rank = {action: i for i, action in enumerate(AUTO_ACTIONS)}
    ceilings = [config(maximum_automatic_action=a) for a in AUTO_ACTIONS]
    for candidate, confidence, score, count, behavioural, cfg in itertools.product(
        AUTO_ACTIONS, (0.0, 0.4, 0.6, 0.9), (0.0, 50.0), (0, 1, 3), (False, True), ceilings,
    ):
        action, reasons = _guard(candidate, confidence, score, count, behavioural, cfg)
        assert reasons, "every outcome must say why"
        if not behavioural or count:
            assert rank[action] <= rank[candidate], (candidate, confidence, score, count, action)
        assert rank[action] <= rank[cfg.guardrails.maximum_automatic_action]
