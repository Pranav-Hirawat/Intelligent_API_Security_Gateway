# Gateway — the data plane

A Go reverse proxy that sits in front of the backend API. It enforces cached decisions,
records detection evidence, and forwards admitted requests with minimal overhead.

It never calls the control plane, PostgreSQL, or a model on the request path. Policy
lookup is local; active rate limits use a short, bounded Redis quota check shared by
all gateway replicas.

## What it does, in order

1. Resolve the real client IP — from `X-Forwarded-For`, but only when the immediate peer
   is a configured trusted proxy, so the header cannot be spoofed to frame another address
2. Start telemetry and look up active policy/reflex decisions before reading the body;
   forward, return `403`, or check the applicable quota and return `429` when exhausted
3. Cap the admitted request body, capture a redacted telemetry snippet, and run detectors
4. Proxy to the backend; let the reflex observe the completed detector evidence
5. Enqueue what happened for background publication to `iasg:events`

Steps 2 and 5 are the two halves of the split: the gateway *reads* a decision it did not
make, and *writes* evidence it does not interpret.

## Layout

| Path | What it is |
|---|---|
| `cmd/server/` | Entry point |
| `internal/config/` | YAML + env configuration |
| `internal/proxy/` | Reverse proxy, middleware chain, server |
| `internal/signals/` | The detectors, and the evidence they emit |
| `internal/policy/` | Reads `policy:<ip>`, caches it, enforces the action |
| `internal/netutil/` | Client IP resolution, and shared CIDR parsing |
| `internal/reputation/` | The known-bad list: loading, refreshing, lookup |
| `internal/storage/redis/` | Stream and key access |
| `internal/telemetry/` | Per-request records for the dashboard |

## Detectors

| File | Catches |
|---|---|
| `brute_force.go` | Repeated failed logins against one account (`consecutive_failed_logins`) |
| `api_flooding.go` | Request volume from one address |
| `sqli_injection.go` | Injection patterns in path, decoded query values and body |
| `enumeration_path_traversal.go` | Directory walking and resource enumeration |
| `unknown_route_scanning.go` | A client walking several paths the route table does not recognise |
| `object_enumeration.go` | A client walking many object IDs on a protected endpoint (BOLA / IDOR) |
| `ip_reputation.go` | Addresses already known to be malicious |

Reputation is the odd one out, and deliberately so. The other five are behavioural and
windowed: they count requests, failures or pattern matches, and cannot say anything until
the attacker has repeated themselves -- a flood needs a hundred requests before it exists.
Reputation is a standing fact about an address, so it is the only one that *knows* on the
first request, and the only evidence the control plane can receive about an address that
has done nothing yet. Enforcement still lands on the request after, because the reflex
observes after the handler rather than deciding in front of it -- see
`internal/enforcement/middleware.go`. It pays for its head start by firing on a
cooldown -- a listed address is listed on *every* request, and raising a signal each time
would drown the real attack in the event stream. Inside the cooldown it still scores; it
just does not fire again.

Each one emits `Evidence` onto `iasg:events`. They score and report; they do not decide
what to do about it. That is the control plane's job, and keeping it there is what lets
the detectors stay fast.

## Running it

```bash
cp configs/config.yaml.example configs/config.yaml
go mod download
go run ./cmd/server
```

Listens on `:8082` and proxies to `proxy.backend_url` (`http://localhost:5002` by default,
which is the deliberately vulnerable app).

Environment overrides, used by Compose:

| Variable | Overrides |
|---|---|
| `IASG_CONFIG` | Path to the config file |
| `IASG_BACKEND_URL` | `proxy.backend_url` |
| `IASG_REDIS_HOST` | `storage.redis.host` |

## Enforcement

The control plane writes `policy:<ip>` keys with a TTL. Background snapshots preserve
the actual Redis expiry and expire locally on every lookup. Rate limits use atomic
Redis token buckets per client IP, exact URL path, and HTTP method. A quota check fails
open on Redis errors, with a configurable timeout and failure backoff.

`allow` and `monitor` forward normally. `throttle` uses the policy's
`requests_per_minute` and returns `429` with `Retry-After` when exhausted, without
sleeping. `block`, `temp_block`, and `escalate` return `403`. Independent reflex blocks
still apply. See [Policy enforcement and adaptive rate limiting](docs/policy-enforcement.md)
for the compatible Python JSON contract, configuration, Redis keys, tests, and Compose
verification commands.

## Testing

```bash
go build ./...
go vet ./...
go test ./...
go test ./internal/signals/ -race
```

For traffic that exercises the detectors end to end, the shell scripts in
[`../testing/`](../testing/) hit a running gateway over HTTP.

## No separate trust engine

There is no central trust-scoring component, and no `trust_engine` block in
`configs/config.yaml` any more. It was parsed into structs that nothing read, so it has
been removed rather than left advertising a component that does not exist.

Every decision is made by the parts that already hold the evidence: each detector scores
what it sees, [`internal/enforcement`](internal/enforcement/) acts on a threshold cross
immediately, and the control plane re-decides off-path with the wider view.

## Documentation

- [Client IP resolution](docs/client-ip.md)
- [Reverse proxy logic](docs/reverse-proxy-logic.md)
- [Request lifecycle](docs/request-lifecycle.md)
- [System architecture](docs/system-architecture.md)
- [Project structure](docs/project-structure.md)
- [Running locally](docs/running-locally.md)
