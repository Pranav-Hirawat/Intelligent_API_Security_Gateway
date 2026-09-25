# Testing — attacking your own gateway

Everything here is a *client*. It sends real traffic to a running gateway over HTTP and
watches what the system does about it. None of it is compiled into the gateway or imported
by the control plane, and none of it is a substitute for the unit tests
(`cd gateway && go test ./...`, `cd control-plane && .venv/bin/python -m pytest`).

```text
testing/
  signals/     shell scripts, one per detector
  jmeter/      maintained JMeter verification plans
```

## Prerequisites

A gateway on `:8082` with somewhere to send traffic:

```bash
docker compose -f infra/docker-compose.yml up -d
```

## Shell scripts

```bash
bash testing/signals/run_all.sh        # every detector in sequence
bash testing/signals/brute_force.sh    # or one at a time
bash testing/signals/flood.sh
bash testing/signals/sqli.sh
bash testing/signals/traversal.sh

bash testing/signals/redis_inspect.sh  # what landed in Redis
```

See [`signals/README.md`](signals/README.md) for what each one sends and what it should
trigger.

## JMeter

The maintained plans live directly in `testing/jmeter/`. They use RFC 5737
documentation addresses where a control-plane policy must be eligible for
enforcement. Open a plan in the JMeter GUI or run it headlessly, for example:

```bash
jmeter -n -t "testing/jmeter/4-SQL-Injection-Detection.jmx"
```

### Functional-requirements traceability

| Requirement | JMeter plans that cover it | Coverage |
|---|---|---|
| FR1 — Intercept and validate requests | `1-Gateway forwarding, response capture, and telemetry.jmx`; `2- Request-size protection.jmx` | Forwarding, trusted `X-Forwarded-For`, normal requests, and the `413` body-size rejection. |
| FR2 — Detect suspicious behaviour | `3A-Brute-force detection.jmx`; `3B-Password Spraying detection.jmx`; `4-SQL-Injection-Detection.jmx`; `5-Enumeration and path-traversal detection.jmx`; `6-Unknown-route scanning.jmx`; `7-Immediate gateway reflex for API flooding.jmx`; `14-BOLA ownership and object-enumeration protection.jmx` | Covers the required attack types; BOLA is additional object-enumeration coverage. |
| FR3 — Risk assessment and campaign correlation | `4-SQL-Injection-Detection.jmx`; `9-Control-plane campaign correlation.jmx`; `10-Monitor manual and automatic modes.jmx`; `11-Policy enforcement monitor throttle temporary block escalate.jmx`; `14-BOLA ownership and object-enumeration protection.jmx` | Exercises multi-IP campaign correlation and resulting actions. Verify dashboard explanations manually. |
| FR4 — Adaptive, expiring policies | `3A-Brute-force detection.jmx`; `4-SQL-Injection-Detection.jmx`; `10-Monitor manual and automatic modes.jmx`; `11-Policy enforcement monitor throttle temporary block escalate.jmx`; `12-Adaptive rate limiting without attack signature.jmx`; `14-BOLA ownership and object-enumeration protection.jmx` | Exercises policy generation and outcomes. Redis policy fields and TTL are inspected manually. |
| FR5 — Enforcement and adaptive rate limits | `3A-Brute-force detection.jmx`; `4-SQL-Injection-Detection.jmx`; `5-Enumeration and path-traversal detection.jmx`; `7-Immediate gateway reflex for API flooding.jmx`; `8-Gateway reflex allowlist and exemption settings.jmx`; `10-Monitor manual and automatic modes.jmx`; `11-Policy enforcement monitor throttle temporary block escalate.jmx`; `12-Adaptive rate limiting without attack signature.jmx`; `13-Global baseline limiter test.jmx`; `14-BOLA ownership and object-enumeration protection.jmx` | Covers `403` blocks, `429` throttles with `Retry-After`, reflexes, exemptions, operation modes, escalation, and the configured static limiter. |
| FR6 — Forward permitted requests and capture responses | `1-Gateway forwarding, response capture, and telemetry.jmx`; `2- Request-size protection.jmx`; permitted-response phases in plans `4`, `5`, `6`, `7`, and `14` | Plan 1 is the direct forwarding and response-telemetry check. |
| FR7 — Logging, monitoring, and visualization | `1-Gateway forwarding, response capture, and telemetry.jmx`; `4-SQL-Injection-Detection.jmx`; `9-Control-plane campaign correlation.jmx`; `10-Monitor manual and automatic modes.jmx`; `11-Policy enforcement monitor throttle temporary block escalate.jmx` | Events, campaigns, policies, and dashboard outcomes are inspected during runs; dashboard and audit-history coverage is manual. |
| FR8 — Administrative configuration and overrides | `8-Gateway reflex allowlist and exemption settings.jmx`; `10-Monitor manual and automatic modes.jmx`; `11-Policy enforcement monitor throttle temporary block escalate.jmx`; `13-Global baseline limiter test.jmx` | Settings, exemptions, mode changes, manual approvals, policy actions, and static-limiter configuration are deliberate operator steps. Authentication and audit-record assertions are not automated. |

`12-Adaptive rate limiting without attack signature.jmx` is the focused proof
that valid traffic alone can lead to a dynamic throttle. Its optional TTL
recovery check is disabled by default.

## Seeding instead of attacking

If you only need the *control plane* to have something to reason about, the seeder writes
realistic evidence straight into Redis and skips the traffic entirely:

```bash
cd control-plane
.venv/bin/python -m tools.seed_evidence --scenario credential-stuffing
.venv/bin/python -m iasg --once
```

That is the faster path for demonstrating correlation, policy and the console. These
scripts are the slower, more honest one: they prove the *detectors* fire, which seeding
assumes.

Scenarios: `credential-stuffing`, `brute-force`, `flood`, `enumeration`, `path-traversal`,
`recon`, `sqli`, `mixed`, and `noise` — which must **not** form a campaign, and is the
most useful one to run when you want to know the correlator is not simply agreeing with
everything.

## What to watch while they run

| Where | Shows |
|---|---|
| Gateway logs | Detectors firing, in real time |
| `http://localhost:5177` | The console — events, then campaigns, then policy |
| `redis-cli KEYS 'policy:*'` | What the agent decided to enforce |
| Control plane logs | The correlation and the reasoning behind each action |

The interesting gap is the one between a detector firing and a campaign forming: the
gateway reacts within a request, and the agent takes up to a cycle. Watching both at once
is the clearest way to see why the system is split in two.
