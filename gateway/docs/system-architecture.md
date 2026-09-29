# System Architecture

## Overview

The gateway is a Go HTTP server wrapped around `httputil.ReverseProxy`, with a
middleware chain in front of it. Alongside it run a Python decision
engine, a Next.js dashboard, Redis, and Postgres.

## Startup

`cmd/server/main.go` loads YAML configuration and starts a `proxy.Server`.
Three environment variables override the file, which is what lets the same
config work locally and under Compose:

| Variable | Overrides |
| --- | --- |
| `IASG_CONFIG` | Path to the config file (default `configs/config.yaml`) |
| `IASG_BACKEND_URL` | `proxy.backend_url` |
| `IASG_REDIS_HOST` | `storage.redis.host` |

`Server.Start` in `internal/proxy/server.go` then constructs the six
detectors, a `signals.Collector` over them, the Redis telemetry writer, the
client-IP resolver, reflex, and policy enforcer. It assembles them with
`ChainMiddleware` and serves.

## The middleware chain

`ChainMiddleware` applies its arguments so that **index 0 is outermost** — the
first to see a request and the last to see the response.

| # | Middleware | Package | Role |
| --- | --- | --- | --- |
| 1 | `resolver.Middleware` | `netutil` | Decides which IP the request is attributed to |
| 2 | `telemetry.Middleware` | `telemetry` | Assigns request context; enqueues the completed event without reading the body |
| 3 | `LoggingMiddleware` | `proxy` | Prints request metadata to stdout |
| 4 | `enforcer.Middleware` | `policy` | Applies cached policy/reflex decisions; checks shared Redis quota only when a rate applies |
| 5 | `BodyLimitMiddleware` | `proxy` | Caps admitted request bodies |
| 6 | `telemetry.CaptureBody` | `telemetry` | Captures a body snippet after admission and the size cap |
| 7 | `enforcement.Middleware` | `enforcement` | Observes detector evidence after the response; records reflex blocks for subsequent requests |
| 8 | `reputationDetector.Middleware` | `signals` | Known-bad address lookup |
| 9 | `floodDetector.Middleware` | `signals` | Request-rate flooding |
| 10 | `unknownRouteScanDetector.Middleware` | `signals` | Bounded distinct unmatched-path scanning |
| 11 | `sqliDetector.Middleware` | `signals` | SQL injection patterns |
| 12 | `traversalEnumDetector.Middleware` | `signals` | Path traversal and forced browsing |
| 13 | `bruteForceDetector.Middleware` | `signals` | Repeated failed logins |

Then `NewReverseProxy` sets `X-Gateway: IASG` and forwards upstream.

Two orderings in that list carry real weight, and both are explained in
[Request Lifecycle](request-lifecycle.md): the resolver must precede telemetry,
and body reads and detectors sit *inside* enforcement, so a refused request
never reaches them.

## Runtime structure

```mermaid
flowchart TD
    subgraph DataPlane["Data plane -- per request"]
        Listener[HTTP listener] --> Chain[Middleware chain]
        Chain --> RP[Reverse proxy]
        RP --> Backend[Backend API]
    end

    subgraph State["Shared state"]
        Redis[(Redis)]
        PG[(Postgres)]
    end

    subgraph DecisionEngine["Decision engine -- every 30s"]
        Runner[Runner cycle]
        Windows[Completed 60-second windows]
        Baselines[Endpoint median/MAD baselines]
    end

    Chain -->|background event publication| Redis
    Redis -->|background policy snapshot| Chain
    Chain -->|bounded atomic quota check when a rate applies| Redis
    Redis --> Runner
    Runner --> Windows --> Baselines
    Baselines --> Runner
    Runner --> Redis
    Runner --> PG
    PG --> Dashboard[Next.js dashboard]
    Redis --> Dashboard
```

## Bounded Redis work and local policy lookup

`policy.Store` copies `policy:<ip>` values and their actual remaining TTLs into
a background snapshot. Requests read it through an `atomic.Pointer` and check
local absolute expiry, so a policy lookup never touches the network. New
policies can take `enforcement.policy.refresh_interval` (5s by default) to
appear. A failed refresh clears the snapshot; `cache_max_age` (10s by default)
also bounds its lifetime if refresh stalls.

When a throttle policy or opt-in baseline applies, a Redis Lua script checks
and consumes a shared token for the client IP, exact path, and HTTP method.
This synchronous quota operation has a configurable 25ms timeout by default,
fails open on error, and backs off after failure. It returns `429` with
`Retry-After` on exhaustion; requests never wait for token refill. Background
snapshot refresh has its own `policy_refresh_timeout` (2s by default).

Telemetry publication runs in a bounded background queue and reconnects after
an outage, including one present at startup. Queue overflow drops telemetry
rather than holding a request. Python, PostgreSQL, and models remain entirely
off the request path. See [Policy enforcement](policy-enforcement.md) for
action mapping, policy schema, expiry details, and configuration.

## Components outside the gateway

| Component | Location | Notes |
| --- | --- | --- |
| Decision engine | `decision-engine/` | Python agent, `python -m iasg`. See [Decision Engine](decision-engine.md) |
| Dashboard | `gateway-dashboard/` | Next.js 15, port 5177. See [Command Center Dashboard](modules/dashboard.md) |
| Vulnerable app | `vulnerable-app/` | Deliberately weak API used as the protected backend |
| Compose stack | `infra/docker-compose.yml` | See [Running with Docker](running-with-docker.md) |

## Code references

| Path | Role |
| --- | --- |
| `cmd/server/main.go` | Entrypoint; loads config and applies env overrides |
| `internal/config/config.go` | YAML schema and defaults |
| `internal/proxy/server.go` | Builds the detectors, resolver, enforcer, and the chain |
| `internal/proxy/middleware.go` | `ChainMiddleware`, logging, request inspection |
| `internal/proxy/reverse_proxy.go` | Reverse proxy and the `X-Gateway` header |
| `internal/netutil/ip.go` | Client IP resolution |
| `internal/telemetry/` | Event shape, redaction, recording middleware |
| `internal/policy/` | Policy snapshot store and the enforcing middleware |
| `internal/signals/` | The six detectors, evidence, and the collector |
