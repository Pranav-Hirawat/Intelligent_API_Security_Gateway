# Adaptive policy and analyst control

The adaptive system runs in the Python decision engine after a completed
60-second window. The Go gateway never waits for this work: it refreshes an
expiring policy snapshot in the background and performs an in-memory lookup on
the request path.

## Baselines

The decision engine learns a separate normal request rate for every normalized
HTTP method and route template. It uses a bounded rolling sample and derives a
threshold with `median + mad_multiplier * max(MAD, minimum_mad)`. Warm-up,
hard limits, hysteresis, and cooldown prevent one unusual minute from changing
the learned normal rate.

Only complete, detector-clean, allowed windows with uninterrupted telemetry
health are admitted to a baseline. A deviation from a ready baseline is an
explainable behavioural input; it is never sufficient by itself to create an
active policy.

## Risk and confidence

The decision engine combines three configured, bounded components:

1. deterministic gateway evidence;
2. endpoint-baseline deviation; and
3. campaign facts from correlation.

Risk is a 0-100 value and confidence is an independent 0-1 value. The
decision explanation records raw inputs, configured weights, weighted points,
the selected action, and every guardrail that applied.

No deterministic evidence normally results in `monitor`. Reputation does not
count as deterministic evidence. An operator may explicitly enable the
ready-baseline behavioural-throttle path: it is endpoint-scoped, can produce
only an expiring throttle, requires a configured deviation beyond a completed
trusted baseline, and never authorizes a block. This keeps the exception
bounded while preserving observed gateway evidence as the default basis for
automatic enforcement.

## Modes and safety rails

| Mode | Behaviour |
| --- | --- |
| Monitor | Store recommendations only; never write an active gateway policy. |
| Manual | Store pending recommendations for analyst approval, edit, or rejection. |
| Automatic | Write only a throttle or temporary-block recommendation that passes every guardrail. |

The writer is the sole path that can change gateway policy. It rejects unsafe
addresses, policies without a TTL, decisions over the action/duration ceiling,
and changes over the per-cycle budget. Allowlist rules have precedence;
shared-address checks soften collateral-risky actions; a policy naturally
expires instead of being renewed by repeated evidence.

All tunable risk weights, score thresholds, baseline controls, policy TTLs,
and throttle bounds are validated by `AdaptiveConfig` and may be supplied by
the dashboard-backed configuration or `IASG_ADAPTIVE_CONFIG`.
