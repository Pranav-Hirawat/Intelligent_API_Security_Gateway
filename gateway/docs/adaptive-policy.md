# Adaptive Policy Module

Adaptive policy helps the decision engine distinguish ordinary traffic changes
from suspicious deviation. It is not a synchronous gateway feature.

## Baselines

The decision engine groups clean completed traffic into one-minute endpoint
windows. For each method and normalized route it learns a bounded baseline from
recent trusted windows using median and median absolute deviation (MAD).

Incomplete or unhealthy windows are excluded so a telemetry outage does not
become a new normal. The baseline changes only after warm-up and configured
cooldown rules.

## Risk and actions

Risk combines deterministic evidence, behavioral deviation, campaign severity,
and confidence. Guardrails reduce the action when evidence or confidence is
weak. Reputation remains supporting evidence and cannot originate enforcement.

| Mode | Effect |
| --- | --- |
| Monitor | Store recommendation; write no active policy. |
| Manual | Hold action for operator approval. |
| Automatic | Write a guardrail-compliant expiring policy. |

The dashboard exposes adaptive settings and recommendations. Its updates are
read by the decision engine on a later cycle, so a dashboard action is never an
immediate direct block.

## Operator feedback

Overrides arrive on `iasg_overrides`. Declared allowlists and shared ranges
still apply. Repeated, consistent corrections can move an initial
recommendation by at most one action rung; they cannot bypass evidence,
confidence, address eligibility, or expiry rules.
