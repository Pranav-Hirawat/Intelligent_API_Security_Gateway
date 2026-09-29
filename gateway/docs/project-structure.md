# Project Structure

```text
gateway/                  Go request gateway
  cmd/server/             startup and environment overrides
  configs/                example configuration
  internal/netutil/       CIDR utilities and client-IP resolution
  internal/policy/        policy snapshot, quota, and enforcer
  internal/enforcement/   short-lived gateway reflex
  internal/signals/       deterministic detectors and evidence
  internal/ownership/     BOLA response guard
  internal/telemetry/     routes, events, arrivals, redaction, async writers
decision-engine/          Python background decision engine
  iasg/adaptive/          baselines, risk, lifecycle
  iasg/correlation/       campaign clustering
  iasg/policy/            simulation and policy writer
  iasg/feedback/          overrides and bounded learning
gateway-dashboard/        Next.js operations console
vulnerable-app/           intentionally weak demo backend
infra/                    Compose definitions and environment example
testing/                  shell scripts and JMeter plans
```

Nothing in `decision-engine/` is imported into the gateway request path.
