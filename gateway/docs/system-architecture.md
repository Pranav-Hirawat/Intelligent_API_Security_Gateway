# System Architecture

## Runtime modules

| Module | Runs | Reads | Writes |
| --- | --- | --- | --- |
| Gateway | Every request, `:8082` | Local policy snapshot; bounded Redis quota | Backend requests; arrivals and events |
| Decision engine | Normally every 30 seconds | Redis streams; optional Postgres history | Policies, campaigns, heartbeat, alerts |
| Dashboard | On demand, `:5177` | Redis and optional Postgres | Settings and override streams |
| Backend | Behind the gateway, `:5002` | Admitted requests | API responses |

The split is deliberate: an unavailable decision engine cannot make the API
unavailable.

## Shared state

- `iasg:arrivals` records request arrival time for traffic windows.
- `iasg:events` records completed requests, responses, and evidence.
- `iasg:telemetry:health` records publisher health.
- `policy:<ip>` holds an expiring decision, optionally limited to a route and method.
- `iasg_overrides` holds dashboard/operator instructions for the decision engine.

Postgres is optional durable storage for campaign history, feedback, and
adaptive configuration; it is never on the gateway request path.

## Safety boundaries

1. Detectors observe and emit evidence; they do not reject the request they inspect.
2. The decision engine normally decides policy; its policy writer is the only decision-engine code that can influence the gateway.
3. The gateway reflex is a small, local stopgap that affects only a later request after configured high-confidence evidence.
4. Policies always carry a TTL and are not renewed.
5. Narration is produced after policy selection and cannot change enforcement.

See [Policy Enforcement](policy-enforcement.md) and [Decision Engine](decision-engine.md).
