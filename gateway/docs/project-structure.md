# Project structure

| Directory | Purpose |
| --- | --- |
| `gateway/` | Go reverse proxy, detectors, cached-policy enforcement, telemetry, and documentation. |
| `decision-engine/` | Python correlation, adaptive baseline/risk decisions, lifecycle, policy writer, and durable storage. |
| `gateway-dashboard/` | Next.js operator console for traffic, campaigns, policies, settings, and adaptive controls. |
| `vulnerable-app/` | Deliberately vulnerable demonstration API protected by the gateway. |
| `infra/` | Docker Compose deployment definitions. |
| `testing/` | Shell signal checks and JMeter verification plans. |

The request path is only `gateway/`. The decision engine reads evidence and writes
expiring policy keys asynchronously; the dashboard displays and configures that
state without joining the request path.
