"""Validated configuration for adaptive decisions.

Every number that can move a behavioural decision lives here.  The defaults
are intentionally conservative, but they are data: Postgres/dashboard values
or ``IASG_ADAPTIVE_CONFIG`` can replace them without changing source code.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any


MODES = ("monitor", "manual", "automatic")
AUTO_ACTIONS = ("monitor", "throttle", "temp_block")


@dataclass(frozen=True)
class BaselineConfig:
    method: str = "median_mad"
    window_seconds: int = 60
    rolling_windows: int = 120
    warmup_windows: int = 8
    mad_multiplier: float = 3.0
    minimum_mad: float = 1.0
    minimum_threshold_rpm: int = 5
    maximum_threshold_rpm: int = 600
    hysteresis_ratio: float = 0.10
    cooldown_seconds: int = 300


@dataclass(frozen=True)
class RiskConfig:
    deterministic_weight: float = 0.50
    behavioural_weight: float = 0.20
    campaign_weight: float = 0.30
    detector_points: dict[str, float] = field(default_factory=lambda: {
        "sqli": 100.0,
        "traversal": 100.0,
        "bruteforce": 80.0,
        "flood": 70.0,
        "enumeration": 55.0,
        "unknown_route_scanning": 60.0,
        "object_enumeration": 80.0,
        # Each hit is a refused read of someone else's object: proof, not a
        # pattern, so it outweighs the enumeration detector's inference.
        "ownership_violation": 90.0,
        "reputation": 20.0,
    })
    repeated_evidence_increment: float = 5.0
    severity_multipliers: dict[str, float] = field(default_factory=lambda: {
        "low": 0.50,
        "medium": 0.75,
        "high": 1.0,
    })
    throttle_score: float = 45.0
    temporary_block_score: float = 75.0
    confidence_deterministic_weight: float = 0.55
    confidence_campaign_weight: float = 0.45


@dataclass(frozen=True)
class GuardrailConfig:
    maximum_automatic_action: str = "temp_block"
    minimum_confidence_throttle: float = 0.50
    minimum_confidence_temporary_block: float = 0.75
    maximum_policy_duration_seconds: int = 1800
    monitor_duration_seconds: int = 300
    throttle_duration_seconds: int = 900
    temporary_block_duration_seconds: int = 1800
    minimum_throttle_rpm: int = 10
    maximum_throttle_rpm: int = 300
    default_throttle_rpm: int = 60
    throttle_baseline_fraction: float = 0.50
    # Disabled by default: a valid-traffic burst is ambiguous unless an
    # operator explicitly opts in to this narrower, endpoint-only response.
    behavioural_throttle_enabled: bool = False
    behavioural_throttle_minimum_deviation: float = 2.0
    policy_cooldown_seconds: int = 300
    minimum_deterministic_evidence_throttle: int = 1
    minimum_deterministic_evidence_temporary_block: int = 2
    analyst_escalation_confidence: float = 0.75
    analyst_escalation_min_clients: int = 5
    analyst_escalation_min_stages: int = 2
    allowlist: tuple[str, ...] = ()
    blocklist: tuple[str, ...] = ()


@dataclass(frozen=True)
class AdaptiveConfig:
    version: int = 1
    mode: str = "automatic"
    baseline: BaselineConfig = field(default_factory=BaselineConfig)
    risk: RiskConfig = field(default_factory=RiskConfig)
    guardrails: GuardrailConfig = field(default_factory=GuardrailConfig)

    def validate(self) -> "AdaptiveConfig":
        errors: list[str] = []
        b, r, g = self.baseline, self.risk, self.guardrails

        if self.mode not in MODES:
            errors.append(f"mode must be one of {', '.join(MODES)}")
        if b.method != "median_mad":
            errors.append("baseline.method must be median_mad")
        if b.window_seconds != 60:
            errors.append("baseline.window_seconds must be 60")
        if not 3 <= b.rolling_windows <= 1440:
            errors.append("baseline.rolling_windows must be between 3 and 1440")
        if not 3 <= b.warmup_windows <= b.rolling_windows:
            errors.append("baseline.warmup_windows must be between 3 and rolling_windows")
        if not 0.1 <= b.mad_multiplier <= 20:
            errors.append("baseline.mad_multiplier must be between 0.1 and 20")
        if not 0 <= b.minimum_mad <= 1000:
            errors.append("baseline.minimum_mad must be between 0 and 1000")
        if not 1 <= b.minimum_threshold_rpm <= b.maximum_threshold_rpm <= 100_000:
            errors.append("baseline threshold limits must be ordered within 1..100000")
        if not 0 <= b.hysteresis_ratio <= 0.5:
            errors.append("baseline.hysteresis_ratio must be between 0 and 0.5")
        if not 0 <= b.cooldown_seconds <= 86_400:
            errors.append("baseline.cooldown_seconds must be between 0 and 86400")

        weights = (
            r.deterministic_weight,
            r.behavioural_weight,
            r.campaign_weight,
        )
        if any(value < 0 or value > 1 for value in weights) or not 0.99 <= sum(weights) <= 1.01:
            errors.append("risk weights must each be 0..1 and total 1")
        if not 0 <= r.throttle_score < r.temporary_block_score <= 100:
            errors.append("risk action scores must be ordered within 0..100")
        if any(not 0 <= value <= 100 for value in r.detector_points.values()):
            errors.append("risk.detector_points values must be within 0..100")
        if not 0 <= r.repeated_evidence_increment <= 100:
            errors.append("risk.repeated_evidence_increment must be within 0..100")
        if any(not 0 <= value <= 1 for value in r.severity_multipliers.values()):
            errors.append("risk.severity_multipliers values must be within 0..1")
        confidence_weights = r.confidence_deterministic_weight + r.confidence_campaign_weight
        if (
            not 0 <= r.confidence_deterministic_weight <= 1
            or not 0 <= r.confidence_campaign_weight <= 1
            or not 0.99 <= confidence_weights <= 1.01
        ):
            errors.append("confidence weights must each be 0..1 and total 1")

        if g.maximum_automatic_action not in AUTO_ACTIONS:
            errors.append(f"guardrails.maximum_automatic_action must be one of {', '.join(AUTO_ACTIONS)}")
        if not 0 <= g.minimum_confidence_throttle <= 1:
            errors.append("minimum_confidence_throttle must be within 0..1")
        if not 0 <= g.minimum_confidence_temporary_block <= 1:
            errors.append("minimum_confidence_temporary_block must be within 0..1")
        if g.minimum_confidence_temporary_block < g.minimum_confidence_throttle:
            errors.append("temporary-block confidence cannot be below throttle confidence")
        if not 30 <= g.maximum_policy_duration_seconds <= 86_400:
            errors.append("maximum_policy_duration_seconds must be between 30 and 86400")
        durations = (
            g.monitor_duration_seconds,
            g.throttle_duration_seconds,
            g.temporary_block_duration_seconds,
        )
        if any(value <= 0 or value > g.maximum_policy_duration_seconds for value in durations):
            errors.append("action durations must be positive and no greater than the maximum")
        if not 1 <= g.minimum_throttle_rpm <= g.default_throttle_rpm <= g.maximum_throttle_rpm <= 100_000:
            errors.append("throttle rates must be ordered within 1..100000")
        if not 0.01 <= g.throttle_baseline_fraction <= 1:
            errors.append("throttle_baseline_fraction must be between 0.01 and 1")
        if not isinstance(g.behavioural_throttle_enabled, bool):
            errors.append("behavioural_throttle_enabled must be boolean")
        if not 0.1 <= g.behavioural_throttle_minimum_deviation <= 100:
            errors.append("behavioural_throttle_minimum_deviation must be between 0.1 and 100")
        if not 0 <= g.policy_cooldown_seconds <= 86_400:
            errors.append("policy_cooldown_seconds must be between 0 and 86400")
        if g.minimum_deterministic_evidence_throttle < 1:
            errors.append("minimum deterministic evidence for throttle must be at least 1")
        if g.minimum_deterministic_evidence_temporary_block < g.minimum_deterministic_evidence_throttle:
            errors.append("temporary block evidence minimum cannot be below throttle")
        if not 0 <= g.analyst_escalation_confidence <= 1:
            errors.append("analyst_escalation_confidence must be within 0..1")
        if g.analyst_escalation_min_clients < 1 or g.analyst_escalation_min_stages < 2:
            errors.append("analyst escalation size/stage minimums are invalid")
        for name, entries in (("allowlist", g.allowlist), ("blocklist", g.blocklist)):
            for entry in entries:
                try:
                    ipaddress.ip_network(entry, strict=False)
                except (TypeError, ValueError):
                    errors.append(f"guardrails.{name} contains an invalid address or CIDR: {entry}")

        if errors:
            raise ValueError("; ".join(errors))
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_mapping(
        cls,
        value: dict[str, Any] | None,
        base: "AdaptiveConfig | None" = None,
        *,
        strict: bool = True,
    ) -> "AdaptiveConfig":
        base = base or cls()
        if not value:
            return base.validate()
        baseline = replace(base.baseline, **_known(BaselineConfig, value.get("baseline", {}), strict=strict))
        risk_values = _known(RiskConfig, value.get("risk", {}), strict=strict)
        risk = replace(base.risk, **risk_values)
        guard_values = _known(GuardrailConfig, value.get("guardrails", {}), strict=strict)
        for name in ("allowlist", "blocklist"):
            if name in guard_values:
                if not isinstance(guard_values[name], (list, tuple)):
                    raise ValueError(f"guardrails.{name} must be an array")
                guard_values[name] = tuple(guard_values[name] or ())
        guardrails = replace(base.guardrails, **guard_values)
        config = cls(
            version=int(value.get("version", base.version)),
            mode=str(value.get("mode", base.mode)).lower(),
            baseline=baseline,
            risk=risk,
            guardrails=guardrails,
        )
        return config.validate()


def load_adaptive_config(raw_or_path: str | None) -> AdaptiveConfig:
    if not raw_or_path:
        return AdaptiveConfig().validate()
    # JSON is the common container form. Trying a large JSON document as a
    # Windows pathname can raise before exists() gets a chance to return
    # false, so only path-probe values that do not already look like JSON.
    stripped = raw_or_path.lstrip()
    if stripped.startswith("{"):
        raw = raw_or_path
    else:
        candidate = Path(raw_or_path)
        try:
            raw = candidate.read_text() if candidate.exists() else raw_or_path
        except OSError:
            raw = raw_or_path
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("adaptive configuration must be a JSON object")
    return AdaptiveConfig.from_mapping(parsed)


def _known(cls, values: Any, *, strict: bool = True) -> dict[str, Any]:
    if not isinstance(values, dict):
        raise ValueError(f"{cls.__name__} must be an object")
    names = set(cls.__dataclass_fields__)
    unknown = set(values) - names
    if unknown and strict:
        raise ValueError(f"unknown {cls.__name__} fields: {', '.join(sorted(unknown))}")
    return {key: value for key, value in values.items() if key in names}
