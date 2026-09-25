"""Explainable 0-100 scoring and guardrail-bounded action selection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from iasg.adaptive.baseline import BaselineLearner, BaselineSummary, EndpointKey
from iasg.adaptive.config import AdaptiveConfig, AUTO_ACTIONS
from iasg.models import (
    ACTION_MONITOR,
    ACTION_TEMP_BLOCK,
    ACTION_THROTTLE,
    DETECTOR_REPUTATION,
    Campaign,
    Evidence,
)


@dataclass(frozen=True)
class RiskResult:
    score: float
    confidence: float
    action: str
    requests_per_minute: int
    explanation: dict


def calculate_risk(
    config: AdaptiveConfig,
    campaign: Campaign | None,
    evidence: Iterable[Evidence],
    *,
    endpoint: EndpointKey | None = None,
    baseline: BaselineSummary | None = None,
    observed_rate: int = 0,
    learned_bias: int = 0,
) -> RiskResult:
    evidence = list(evidence)
    risk = config.risk
    guard = config.guardrails

    deterministic = [row for row in evidence if row.detector != DETECTOR_REPUTATION]
    deterministic_count = len({
        row.stream_id if row.stream_id else f"unidentified-{index}"
        for index, row in enumerate(deterministic)
    })
    signal_rows = []
    strongest = 0.0
    for row in deterministic:
        base = float(risk.detector_points.get(row.detector, 0.0))
        severity = float(risk.severity_multipliers.get(row.severity, 0.0))
        value = _clamp(base * severity, 0.0, 100.0)
        strongest = max(strongest, value)
        signal_rows.append({
            "detector": row.detector,
            "severity": row.severity,
            "points": round(value, 2),
            "endpoint": row.endpoint,
        })
    deterministic_score = _clamp(
        strongest + max(0, deterministic_count - 1) * risk.repeated_evidence_increment,
        0.0,
        100.0,
    )

    deviation = BaselineLearner.deviation(baseline, observed_rate)
    behavioural_score = _clamp(deviation * 100.0, 0.0, 100.0)
    behavioural_throttle = (
        guard.behavioural_throttle_enabled
        and baseline is not None
        and baseline.ready
        and baseline.derived_threshold > 0
        and deviation >= guard.behavioural_throttle_minimum_deviation
    )

    campaign_confidence = _clamp(campaign.confidence if campaign else 0.0, 0.0, 1.0)
    campaign_severity = risk.severity_multipliers.get(
        campaign.severity if campaign else "low", 0.0
    )
    campaign_score = _clamp(campaign_confidence * campaign_severity * 100.0, 0.0, 100.0)

    contributions = {
        "deterministic": deterministic_score * risk.deterministic_weight,
        "behavioural": behavioural_score * risk.behavioural_weight,
        "campaign": campaign_score * risk.campaign_weight,
    }
    total = _clamp(sum(contributions.values()), 0.0, 100.0)

    confidence = _clamp(
        (deterministic_score / 100.0) * risk.confidence_deterministic_weight
        + campaign_confidence * risk.confidence_campaign_weight,
        0.0,
        1.0,
    )
    # A ready baseline represents a completed set of trusted observations, not
    # a detector hit. Its confidence is therefore used only for the explicit,
    # throttle-only behavioural path below; it can never justify a block.
    behavioural_confidence = min(
        1.0, baseline.sample_count / max(config.baseline.warmup_windows, 1)
    ) if behavioural_throttle else 0.0
    confidence = max(confidence, behavioural_confidence)
    candidate = ACTION_THROTTLE if behavioural_throttle else _candidate(total, config)
    # What humans keep doing to this kind of campaign moves the proposal, never
    # the checks: _guard runs after it, so a learned push still needs the
    # evidence, the confidence and the ceiling any other proposal needs. The
    # behavioural path is the operator's explicit opt-in and is not learnable.
    learned_rungs = 0
    if not behavioural_throttle:
        candidate, learned_rungs = _learned(candidate, learned_bias)
    action, guardrail_reasons = _guard(
        candidate,
        confidence,
        deterministic_score,
        deterministic_count,
        behavioural_throttle,
        config,
    )
    rpm = _throttle_rate(action, baseline, config)

    explanation = {
        "deterministic_evidence": signal_rows,
        "deterministic_evidence_count": deterministic_count,
        "baseline": {
            "method": endpoint.method if endpoint else "",
            "route_template": endpoint.route_template if endpoint else "",
            "value": baseline.statistic if baseline else None,
            "threshold": baseline.derived_threshold if baseline else None,
            "observed": observed_rate,
            "deviation": round(deviation, 4),
            "baseline_ready": bool(baseline and baseline.ready),
            "sample_count": baseline.sample_count if baseline else 0,
            "version": baseline.version if baseline else 0,
        },
        "campaign": {
            "campaign_id": campaign.campaign_id if campaign else "",
            "severity": campaign.severity if campaign else "",
            "confidence": campaign_confidence,
            "facts": campaign.reason if campaign else "",
            "stages": list(campaign.stages) if campaign else [],
        },
        "components": {
            name: {
                "weighted_points": round(value, 2),
                "weight": getattr(risk, f"{name}_weight"),
            }
            for name, value in contributions.items()
        },
        "final": {
            "risk_score": round(total, 2),
            "confidence": round(confidence, 3),
            "candidate_action": candidate,
            "learned_rungs": learned_rungs,
            "selected_action": action,
            "behavioural_throttle_authorized": behavioural_throttle,
            "behavioural_throttle_minimum_deviation": guard.behavioural_throttle_minimum_deviation,
            "guardrails": guardrail_reasons,
            "configuration_version": config.version,
        },
    }
    return RiskResult(
        score=round(total, 2), confidence=round(confidence, 3), action=action,
        requests_per_minute=rpm, explanation=explanation,
    )


def _candidate(score: float, config: AdaptiveConfig) -> str:
    if score >= config.risk.temporary_block_score:
        return ACTION_TEMP_BLOCK
    if score >= config.risk.throttle_score:
        return ACTION_THROTTLE
    return ACTION_MONITOR


def _learned(candidate: str, bias: int) -> tuple[str, int]:
    """Move a proposal by the learned bias, one rung at most, ever.

    Clamped rather than trusted: the bias comes from stored state, and a run of
    unusual corrections must not walk a campaign from monitor to block.
    """
    step = max(-1, min(1, int(bias or 0)))
    start = AUTO_ACTIONS.index(candidate)
    moved = max(0, min(len(AUTO_ACTIONS) - 1, start + step))
    return AUTO_ACTIONS[moved], moved - start


def _guard(
    candidate: str,
    confidence: float,
    deterministic_score: float,
    deterministic_count: int,
    behavioural_throttle: bool,
    config: AdaptiveConfig,
) -> tuple[str, list[str]]:
    guard = config.guardrails
    reasons: list[str] = []
    action = candidate

    # A statistical surprise remains monitor-only unless an operator opted in
    # to a ready-baseline throttle. That exception cannot produce a block.
    if deterministic_count == 0:
        if not behavioural_throttle:
            return ACTION_MONITOR, ["no deterministic gateway evidence; monitor only"]
        if AUTO_ACTIONS.index(guard.maximum_automatic_action) < AUTO_ACTIONS.index(ACTION_THROTTLE):
            return ACTION_MONITOR, ["behavioural throttle exceeds the automatic-action ceiling"]
        return ACTION_THROTTLE, [
            "ready endpoint baseline exceeded the behavioural throttle deviation guardrail"
        ]

    ceiling = AUTO_ACTIONS.index(guard.maximum_automatic_action)
    if AUTO_ACTIONS.index(action) > ceiling:
        action = AUTO_ACTIONS[ceiling]
        reasons.append(f"automatic action capped at {guard.maximum_automatic_action}")

    if action == ACTION_TEMP_BLOCK:
        if deterministic_count < guard.minimum_deterministic_evidence_temporary_block:
            action = ACTION_THROTTLE
            reasons.append("temporary-block evidence minimum was not met")
        elif confidence < guard.minimum_confidence_temporary_block:
            action = ACTION_THROTTLE
            reasons.append("temporary-block confidence minimum was not met")

    if action == ACTION_THROTTLE:
        if deterministic_count < guard.minimum_deterministic_evidence_throttle:
            action = ACTION_MONITOR
            reasons.append("throttle evidence minimum was not met")
        elif confidence < guard.minimum_confidence_throttle:
            action = ACTION_MONITOR
            reasons.append("throttle confidence minimum was not met")

    if deterministic_score <= 0:
        action = ACTION_MONITOR
        reasons.append("configured deterministic evidence carried no weight")
    if not reasons:
        reasons.append("configured score, confidence, and evidence guardrails were met")
    return action, reasons


def _throttle_rate(
    action: str, baseline: BaselineSummary | None, config: AdaptiveConfig
) -> int:
    if action != ACTION_THROTTLE:
        return 0
    guard = config.guardrails
    proposed = guard.default_throttle_rpm
    if baseline is not None and baseline.ready and baseline.derived_threshold > 0:
        proposed = round(
            baseline.derived_threshold * guard.throttle_baseline_fraction
        )
    return max(guard.minimum_throttle_rpm, min(guard.maximum_throttle_rpm, proposed))


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))
