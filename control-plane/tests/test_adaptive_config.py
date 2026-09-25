"""
The adaptive configuration is edited by operators from the console, so every
number in it is checked before it can move a decision. A value that slipped
through would not fail loudly -- it would quietly change who gets blocked.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from iasg.adaptive.config import AdaptiveConfig, load_adaptive_config


def changed(section: str, **values) -> AdaptiveConfig:
    base = AdaptiveConfig()
    if not section:
        return replace(base, **values)
    return replace(base, **{section: replace(getattr(base, section), **values)})


def test_the_shipped_defaults_are_valid():
    assert AdaptiveConfig().validate() == AdaptiveConfig()


# One row per rule: an operator typing any of these gets a refusal that names
# the setting, rather than a controller running on a nonsensical number.
REFUSED = [
    ("", {"mode": "yolo"}, "mode must be one of"),
    ("baseline", {"method": "mean"}, "baseline.method"),
    ("baseline", {"window_seconds": 30}, "baseline.window_seconds"),
    ("baseline", {"rolling_windows": 2}, "baseline.rolling_windows"),
    ("baseline", {"warmup_windows": 500}, "baseline.warmup_windows"),
    ("baseline", {"mad_multiplier": 0.05}, "baseline.mad_multiplier"),
    ("baseline", {"minimum_mad": -1}, "baseline.minimum_mad"),
    ("baseline", {"minimum_threshold_rpm": 700}, "threshold limits"),
    ("baseline", {"hysteresis_ratio": 0.6}, "baseline.hysteresis_ratio"),
    ("baseline", {"cooldown_seconds": 90_000}, "baseline.cooldown_seconds"),
    ("risk", {"deterministic_weight": 0.9}, "risk weights"),
    ("risk", {"throttle_score": 80.0}, "risk action scores"),
    ("risk", {"detector_points": {"sqli": 150.0}}, "risk.detector_points"),
    ("risk", {"repeated_evidence_increment": 101.0}, "risk.repeated_evidence_increment"),
    ("risk", {"severity_multipliers": {"high": 1.5}}, "risk.severity_multipliers"),
    ("risk", {"confidence_deterministic_weight": 0.9}, "confidence weights"),
    ("guardrails", {"maximum_automatic_action": "escalate"}, "maximum_automatic_action"),
    ("guardrails", {"minimum_confidence_throttle": 1.5}, "minimum_confidence_throttle"),
    ("guardrails", {"minimum_confidence_temporary_block": -0.1}, "minimum_confidence_temporary_block"),
    ("guardrails", {"minimum_confidence_temporary_block": 0.4}, "cannot be below throttle confidence"),
    ("guardrails", {"maximum_policy_duration_seconds": 10}, "maximum_policy_duration_seconds"),
    ("guardrails", {"throttle_duration_seconds": 0}, "action durations"),
    ("guardrails", {"default_throttle_rpm": 500}, "throttle rates"),
    ("guardrails", {"throttle_baseline_fraction": 0}, "throttle_baseline_fraction"),
    ("guardrails", {"behavioural_throttle_enabled": "yes"}, "must be boolean"),
    ("guardrails", {"behavioural_throttle_minimum_deviation": 0}, "behavioural_throttle_minimum_deviation"),
    ("guardrails", {"policy_cooldown_seconds": -1}, "policy_cooldown_seconds"),
    ("guardrails", {"minimum_deterministic_evidence_throttle": 0}, "for throttle must be at least 1"),
    ("guardrails", {"minimum_deterministic_evidence_temporary_block": 0}, "temporary block evidence minimum"),
    ("guardrails", {"analyst_escalation_confidence": 2}, "analyst_escalation_confidence"),
    ("guardrails", {"analyst_escalation_min_stages": 1}, "analyst escalation"),
    ("guardrails", {"allowlist": ("not-a-network",)}, "allowlist contains an invalid"),
    ("guardrails", {"blocklist": ("300.1.1.1",)}, "blocklist contains an invalid"),
]


@pytest.mark.parametrize("section,values,message", REFUSED, ids=[m for *_, m in REFUSED])
def test_an_out_of_range_setting_is_refused_by_name(section, values, message):
    with pytest.raises(ValueError) as refused:
        changed(section, **values).validate()
    assert message in str(refused.value)


def test_every_problem_is_reported_at_once():
    """An operator fixing a form should not discover the errors one save at a time."""
    config = replace(
        changed("baseline", mad_multiplier=0.05),
        mode="yolo",
    )
    with pytest.raises(ValueError) as refused:
        config.validate()
    assert "mode must be one of" in str(refused.value)
    assert "baseline.mad_multiplier" in str(refused.value)


def test_a_typo_in_a_field_name_is_refused_not_ignored():
    """A misspelt key silently ignored would leave the old value in force while
    the operator believes it changed."""
    with pytest.raises(ValueError, match="unknown GuardrailConfig fields: minimum_confidense"):
        AdaptiveConfig.from_mapping({"guardrails": {"minimum_confidense": 0.9}})


def test_lenient_loading_skips_unknown_fields_but_keeps_known_ones():
    config = AdaptiveConfig.from_mapping(
        {"guardrails": {"retired_setting": 1, "minimum_confidence_throttle": 0.6}}, strict=False
    )
    assert config.guardrails.minimum_confidence_throttle == 0.6


def test_a_mapping_only_changes_what_it_names():
    base = changed("guardrails", default_throttle_rpm=90)
    config = AdaptiveConfig.from_mapping({"mode": "MANUAL"}, base)
    assert config.mode == "manual"
    assert config.guardrails.default_throttle_rpm == 90


def test_an_empty_mapping_keeps_the_base():
    assert AdaptiveConfig.from_mapping({}) == AdaptiveConfig()


@pytest.mark.parametrize("value", [{"guardrails": {"allowlist": "10.0.0.0/8"}}, {"baseline": []}])
def test_a_wrongly_shaped_section_is_refused(value):
    with pytest.raises(ValueError):
        AdaptiveConfig.from_mapping(value)


def test_address_lists_arrive_as_tuples():
    config = AdaptiveConfig.from_mapping({"guardrails": {"allowlist": ["203.0.113.0/24"]}})
    assert config.guardrails.allowlist == ("203.0.113.0/24",)


def test_config_loads_from_inline_json_a_file_or_nothing(tmp_path):
    assert load_adaptive_config(None) == AdaptiveConfig()
    assert load_adaptive_config('{"mode": "monitor"}').mode == "monitor"

    path = tmp_path / "adaptive.json"
    path.write_text(json.dumps({"mode": "manual"}))
    assert load_adaptive_config(str(path)).mode == "manual"


def test_config_that_is_not_an_object_is_refused():
    with pytest.raises(ValueError, match="must be a JSON object"):
        load_adaptive_config("[1, 2]")


def test_a_missing_file_is_not_mistaken_for_defaults(tmp_path):
    """A mistyped path must fail loudly, not start the controller on defaults."""
    with pytest.raises(ValueError):
        load_adaptive_config(str(tmp_path / "missing.json"))


def test_an_invalid_config_from_the_environment_is_refused():
    with pytest.raises(ValueError, match="mode must be one of"):
        load_adaptive_config('{"mode": "yolo"}')
