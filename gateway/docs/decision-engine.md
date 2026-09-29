# Decision Engine Module

The decision engine is a Python process in `decision-engine/`. It runs off the
request path, normally every 30 seconds. It reads gateway evidence and writes
only time-limited policy keys.

```bash
cd decision-engine
PYTHONPATH=. .venv/bin/python -m iasg --once
PYTHONPATH=. .venv/bin/python -m iasg --dry-run
```

## One cycle

```mermaid
flowchart LR
  A[Read new events] --> B[Build trusted traffic windows]
  B --> C[Correlate evidence into campaigns]
  C --> D[Load campaign history and feedback]
  D --> E[Score risk and choose action]
  E --> F[Apply overrides and safety simulation]
  F --> G[Write expiring policy]
  G --> H[Create explanation and assessment]
```

The model, when configured, is used only in the final explanatory step. A
template is the default. Model output cannot influence policy.

## Decision inputs

- Gateway detector evidence and completion events.
- Complete, trusted traffic windows from the arrival stream.
- Endpoint baselines based on median and median absolute deviation.
- Campaign traits: endpoint, user agent, detector type, subnet, timing, and
  previous campaign history.
- Operator overrides and bounded feedback learning.

## Actions and rails

The engine proposes `monitor`, `throttle`, `temp_block`, or `escalate`. It
cannot create enforcement without deterministic evidence. The policy writer is
the only module that writes gateway policy and enforces address eligibility,
TTL, cycle caps, allowlists, and dry-run mode.

Campaigns can continue across cycles and cautious IP rotation. A quiet campaign
is eventually marked contained. An escalation also writes an `iasg_alerts`
event for the dashboard.

## Stores

Redis is the transport and active-policy store. With Postgres configured,
campaigns, adaptive state, settings, feedback, and audit history survive a
restart. Redis policy keys still expire independently.
