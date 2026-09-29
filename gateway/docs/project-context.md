# Project Context

This repository demonstrates a practical API-security architecture, not an inline AI filter. The fast Go gateway and background Python **decision engine** have intentionally separate jobs.

## What it demonstrates

- Reverse-proxy protection for an existing HTTP API.
- Deterministic detection and campaign correlation.
- Expiring throttles and blocks.
- BOLA/IDOR protection for configured read endpoints.
- A dashboard for evidence, campaigns, settings, and operator input.

## Deliberate limits

- A detector is not proof that a request should be blocked.
- IP reputation alone is not enforcement authority.
- The gateway never asks a model to approve a request.
- The ownership guard complements application authorization and cannot protect writes after they occur.
- The dashboard is open for this demo; do not expose it publicly.

Read [System Architecture](system-architecture.md), [Request Lifecycle](request-lifecycle.md), [Detection Signals](detection-signals.md), [Policy Enforcement](policy-enforcement.md), then [Decision Engine](decision-engine.md).
