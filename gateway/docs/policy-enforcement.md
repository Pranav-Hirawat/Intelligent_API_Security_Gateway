# Policy enforcement and adaptive rate limiting

The Go gateway enforces decisions already made by the Python decision engine or
its own reflex. Policy lookup uses a background-refreshed local snapshot; the
gateway never calls Python, PostgreSQL, or a model while handling a request.
Distributed rate accounting is the one synchronous Redis operation: a bounded
atomic token-bucket check, only when a policy or opt-in baseline names a rate.
Requests are forwarded immediately, refused with `403`, or refused with `429`
and `Retry-After`. Throttling never sleeps or queues a request.

## Policy contract

The existing Python `PolicyDecision.to_json()` format remains accepted. Store
this JSON as `policy:203.0.113.55` for address-wide policy or
`policy:<ip>:<scope-digest>` for endpoint scope, always with a Redis expiry:

```json
{
  "action": "throttle",
  "policy_id": "a5484d97-0791-4eb4-b1cb-6a7518f94b22",
  "scope": "client_endpoint",
  "target_identity": "203.0.113.55",
  "endpoint_scope": {"method": "POST", "route_template": "/api/login"},
  "campaign_id": "demo-adaptive",
  "confidence": 0.95,
  "risk_score": 81.5,
  "reason": "Repeated login attempts",
  "source": "agent",
  "issued_at": "2026-09-05T12:00:00+00:00",
  "expires_in": 60,
  "requests_per_minute": 20
}
```

| Field | Meaning |
| --- | --- |
| `action` | One of the action labels below |
| `policy_id`, `scope`, `target_identity`, `endpoint_scope` | Lifecycle identity and optional normalized method/route scope |
| `campaign_id`, `risk_score`, `confidence`, `reason`, `issued_at` | Explainable decision metadata |
| `source` | Existing origin, usually `agent` or `human`; defaults to `agent` when absent |
| `expires_in` | Declared lifetime in seconds; **Redis `PTTL` is authoritative** |
| `requests_per_minute` | Positive sustained rate for `throttle`; absent or zero uses the configured fallback |
| `route`, `method` | Legacy exact selectors, still accepted |

New adaptive policies use the same configured route-template table as
telemetry, so resource IDs do not create high-cardinality scopes. The client
identity is resolved with the trusted-proxy rules. A manual address-wide
override outranks an adaptive endpoint policy; among policies at the same
priority, the endpoint scope wins.

| Action | Behaviour |
| --- | --- |
| `allow`, `monitor` | Forward normally; do not apply the optional baseline to this match |
| `throttle` | Consume one token at the policy's rate; return `429` when none is available |
| `block`, `temp_block`, `temporary_block` | Return `403` without forwarding |
| `escalate` | Preserve the existing `403` behaviour described below |
| Unknown | Forward normally; an unrecognised label cannot create enforcement through a fallback |

The Python writer does not create `monitor` keys because they perform no
enforcement. The gateway accepts them for compatibility with existing policy
producers. The first applicable source wins: decision-engine policies outrank
gateway reflex decisions, including a less restrictive `allow` or `monitor`.
A scoped policy only takes precedence on requests matching its selectors.

### What `escalate` already means

`internal/policy/middleware.go` already treated `escalate` like `temp_block` and
returned `403`. This remains unchanged. Separately, the Python runner writes
the policy, produces its advisory explanation/assessment, then calls
`AlertSink.raise_for()` to append one human-review alert per campaign to the
`iasg_alerts` Redis stream. That stream is the existing alert mechanism; the
gateway does not send notifications or call the decision engine. Directly
inserting an `escalate` key tests `403` but does not run Python's alert workflow.

## Configuration

This is the Go gateway's own configurable-limits surface — rate limits,
timeouts, and the Redis policy lookup. It never reads `AdaptiveConfig` or
Postgres directly; `adaptive-policy.md`'s "Configurable policy limits" is the
decision-engine side of that same category, on the other side of the `policy:`
Redis keys.

Merge these settings into the existing configuration; preserve local tuning.

```yaml
enforcement:
  policy:
    enabled: true
    key_prefix: "policy:"
    refresh_interval: 5s
  adaptive_rate_limit:
    fallback_requests_per_minute: 60
    burst: 20
    redis_timeout: 25ms
    policy_refresh_timeout: 2s
    failure_backoff: 1s
    cache_max_age: 10s
    bucket_key_prefix: "iasg:rate:"
  rate_limit:
    enabled: true
    requests_per_minute: 100
    burst: 20
    enforce: false
```

`storage.redis` supplies the shared Redis address, credentials, database, and
pool size. Enable `storage.redis.enabled` for distributed enforcement. Policy
enforcement is opt-in in the example configuration. Replicas must use the same
Redis database, key prefixes, and rate configuration.

| Setting | Effect |
| --- | --- |
| `fallback_requests_per_minute` | Rate for a legacy throttle policy with no positive rate; replaces the previous artificial delay |
| `adaptive_rate_limit.burst` | Maximum immediate token grant for policy and baseline quotas, capped at the applicable RPM |
| `redis_timeout` | Bounded quota operation/connect/pool wait; there are no command retries |
| `policy_refresh_timeout` | Total budget for a background scan across all pages; separate from the per-operation Redis timeout |
| `failure_backoff` | After Redis failure, temporarily bypass quota checks instead of repeatedly paying an outage timeout |
| `cache_max_age` | Maximum age of a successful policy snapshot before lookup fails open |
| `bucket_key_prefix` | Namespace for disposable distributed token-bucket state |
| `policy.refresh_interval` | Background polling cadence; new policies become visible at the next successful refresh |
| `rate_limit.enforce` | Opt-in baseline when no applicable policy supplies a different action |
| `rate_limit.requests_per_minute` | Baseline sustained rate; exemptions reuse `block.exempt_cidrs` |

`rate_limit.enabled` still controls the independent per-IP flooding detector.
It records evidence; it does not refuse requests. `enforce` controls the
baseline. A throttle policy replaces the baseline in either direction.
`enforcement.throttle.delay_ms` remains readable for configuration
compatibility, but policy enforcement no longer delays requests.
`rate_limit.burst` is a legacy field; distributed enforcement uses
`adaptive_rate_limit.burst`. Adaptive settings require a gateway restart and
are displayed, but cannot be changed, through the live settings wire.

## Distributed quota and expiry

Each bucket belongs to the resolved **client IP + normalized route template + HTTP
method + policy identity**. Query parameters do not create new buckets.
`/api/login` and `/api/products` are independent, as are `GET /api/login` and
`POST /api/login`. Paths such as `/api/products/1` and `/api/products/2` share
the configured `/api/products/{id}` bucket.

Redis Lua performs refill, admission, decrement, and expiry atomically using
Redis server time. A bucket starts with `min(burst, requests_per_minute)` tokens
and refills at `requests_per_minute / 60` tokens per second. Thus a rate of
20/minute with burst 5 admits five immediate requests and then roughly one
every three seconds. This is a sustained-rate token bucket, not a hard
20-request cap over every rolling minute. Replicas do not cache token grants,
so their concurrent requests share the same allowance.

An exhausted bucket returns `429` immediately. `Retry-After` is a positive
integer number of seconds, rounded upward until another token can be granted.
No goroutine sleeps waiting for refill.

| Redis key | Value and lifetime |
| --- | --- |
| `policy:<ip>` | Existing JSON string, set by Python with a positive Redis TTL; never renewed by the gateway |
| `iasg:rate:<digest>` | Hash containing fractional `tokens` and `updated_ms`; digest is lowercase SHA-256 of JSON `[ip, path, method, policyKey, rawPolicyJSON]` |
| `iasg:events` | Existing request event stream, now including policy details |
| `iasg_alerts` | Existing Python human-review alert stream for escalation |

The bucket prefix is configurable. Baseline buckets use empty policy key and
raw JSON in their identity. Bucket expiry is the full-refill duration
`ceil(capacity * 60000 / RPM)` milliseconds, capped by the policy's remaining
`PTTL`. Changing the policy JSON creates a new policy identity. The Lua script
also compares the current raw policy and checks `PTTL` atomically before
charging: a deleted, replaced, or unexpiring policy cannot consume quota.
This requires a shared Redis server; the existing `policy:<ip>` schema and
multi-key Lua script are not Redis Cluster hash-slot compatible.

`policy.Store` loads values and millisecond TTLs together, then stores an
absolute local expiry with each decision. Lookup checks that expiry on every
request, even between refreshes. Expired, malformed, or unexpiring keys are
not enforced. `expires_in` cannot extend an actual Redis TTL. A stale snapshot
also stops enforcing after `cache_max_age`; a failed refresh clears it.
Early block-policy deletion/replacement becomes visible on the next successful
refresh, while natural expiry is checked locally on every request.

When a policy expires, its bucket is no longer consulted. Normal forwarding
resumes unless an independent reflex block or the opt-in baseline still
applies. A failed quota check fails open; a cached block can remain effective
until its actual expiry, snapshot-age bound, or the next failed refresh.
Redis failure does not crash the gateway, wait for reconnection, or introduce
an unbounded wait.

## Structured telemetry

Policy matches, including admitted throttled requests, add this optional
object to the normal `iasg:events` record:

```json
{
  "policy": {
    "action": "throttle",
    "source": "agent",
    "client_ip": "203.0.113.55",
    "route": "/api/login",
    "method": "POST",
    "requests_per_minute": 20,
    "reason": "Repeated login attempts; quota_exhausted",
    "outcome": "throttled"
  }
}
```

The existing top-level `decision` is retained (`rate_limited` for a 429).
Policy outcomes are `allowed`, `throttled`, `blocked`, `matched` (unknown
actions), or `fail_open` with a reason such as `redis_unavailable` or
`policy_inactive`. Structured `policy_match` logs
include `request_id`, `action`, `policy_source`, `client_ip`, `route`, `method`,
`requests_per_minute`, `reason`, `outcome`, and `status`. Events are enqueued
without waiting for Redis; a bounded telemetry queue drops events when full.
Configure its capacity and background write timeout with
`storage.redis.telemetry_queue_size` and
`storage.redis.telemetry_write_timeout`.

```yaml
storage:
  redis:
    telemetry_queue_size: 1024
    telemetry_write_timeout: 100ms
```

The middleware order is client-IP resolver, telemetry event recorder, request
logging, policy/reflex enforcer, request-body cap, telemetry snippet capture,
reflex observer and detectors, then reverse proxy. A refused request is
recorded without reading or inspecting its body. `X-Forwarded-For` is used only
when the immediate TCP peer is trusted; the resolver walks the chain from the
right to the first untrusted address.

## Tests

From `gateway/`:

```bash
go build ./...
go vet ./...
go test ./...
go test ./internal/signals/ -race
```

Run the real-Redis integration tests from the repository root:

```bash
docker compose -f infra/docker-compose.yml up -d redis
docker compose -f infra/docker-compose.yml run --rm --no-deps \
  -e IASG_TEST_REDIS_ADDR=redis:6379 gateway \
  sh -c 'go test ./internal/policy/ -count=1'
```

For a native PowerShell test run, set
`$env:IASG_TEST_REDIS_ADDR = 'localhost:6379'` before `go test`. Integration
tests skip when the environment variable is absent. The Go race detector
requires CGO and a C compiler; use a toolchain with those installed.

## Verify with Docker Compose

These **Bash** commands start an isolated demo gateway on port 8083 using an
unused Redis database 15. Reserve that database for the demo or choose another
unused database everywhere below. They leave the normal gateway configuration,
decision-engine policies, dashboard settings, and event stream alone. Run from
the repository root.

```bash
dc() { docker compose -f infra/docker-compose.yml "$@"; }
dc up -d redis vulnerable_api
docker pull curlimages/curl:latest
cat > gateway/configs/adaptive-demo.yaml <<'YAML'
server:
  host: 0.0.0.0
  port: 8082
  trusted_proxies: ["127.0.0.1/32"]
proxy:
  backend_url: http://vulnerable_api:5002
storage:
  redis:
    enabled: true
    host: redis
    port: 6379
    db: 15
enforcement:
  policy:
    enabled: true
    key_prefix: "policy:"
    refresh_interval: 100ms
  adaptive_rate_limit:
    fallback_requests_per_minute: 2
    burst: 2
    redis_timeout: 25ms
    failure_backoff: 1s
    cache_max_age: 1s
    bucket_key_prefix: "iasg:adaptive-demo:rate:"
  rate_limit:
    enabled: false
    enforce: false
  block:
    enabled: false
YAML
dc run --rm -d --no-deps --name iasg-adaptive-demo -p 8083:8082 \
  -e IASG_CONFIG=configs/adaptive-demo.yaml gateway
docker logs -f iasg-adaptive-demo
# Once it is listening, Ctrl-C leaves the demo gateway running.
```

The curl container shares the demo gateway's network namespace. Connecting to
its loopback interface makes the immediate peer the single explicitly trusted
proxy address. This avoids Docker Desktop rewriting the host IP and does not
require trusting arbitrary forwarded-IP headers.

```bash
demo_curl() {
  docker run --rm --network container:iasg-adaptive-demo \
    curlimages/curl:latest -sS \
    -H 'X-Forwarded-For: 203.0.113.55' "$@"
}

# No policy: backend health returns 200.
demo_curl -i http://127.0.0.1:8082/api/health

# Existing Python JSON, with no route/method selectors. EX is essential.
dc exec -T redis redis-cli -n 15 SET policy:203.0.113.55 \
  '{"action":"throttle","campaign_id":"demo-adaptive","confidence":0.95,"reason":"Adaptive rate demo","source":"agent","issued_at":"2026-09-05T12:00:00+00:00","expires_in":60,"requests_per_minute":2}' EX 60
sleep 1

# Two immediate 200 responses, then 429 with Retry-After.
for i in 1 2 3; do
  demo_curl -i http://127.0.0.1:8082/api/health
done

# Different method and endpoint retain their own quotas.
demo_curl -I http://127.0.0.1:8082/api/health
demo_curl -i http://127.0.0.1:8082/api/products

# A new temporary block replaces the throttle. Expect 403.
dc exec -T redis redis-cli -n 15 SET policy:203.0.113.55 \
  '{"action":"temp_block","campaign_id":"demo-block","confidence":1,"reason":"Temporary block demo","source":"human","expires_in":3,"requests_per_minute":0}' EX 3
sleep 1
demo_curl -i http://127.0.0.1:8082/api/health

# Redis expiry releases the block, including between snapshot refreshes.
sleep 3
demo_curl -i http://127.0.0.1:8082/api/health
dc exec -T redis redis-cli -n 15 PTTL policy:203.0.113.55
# Expected: HTTP 200 and PTTL -2 (key no longer exists).

# Inspect evidence and disposable bucket keys.
dc exec -T redis redis-cli -n 15 XREVRANGE iasg:events + - COUNT 3
dc exec -T redis redis-cli -n 15 --scan --pattern 'iasg:adaptive-demo:rate:*'
```

Cleanup stops only the demo container and removes its temporary configuration
and known demo telemetry keys. Bucket keys expire automatically.

```bash
docker stop iasg-adaptive-demo
rm gateway/configs/adaptive-demo.yaml
dc exec -T redis redis-cli -n 15 DEL policy:203.0.113.55 \
  iasg:ip:203.0.113.55:latest iasg:stats iasg:attackers
dc exec -T redis redis-cli -n 15 XTRIM iasg:events MAXLEN 0
dc exec -T redis redis-cli -n 15 XINFO GROUPS iasg:events
```

The isolated demo has no decision-engine consumer. If exercising the main stack
instead, clean its test history through `POST /api/admin/reset` with
`{"confirm":"reset"}` and verify `XINFO GROUPS iasg:events` still contains the
consumer groups. Never `DEL` the main event stream: that also deletes its
consumer groups. Resetting history deliberately does not remove `policy:*`.

## Code references

| Path | Role |
| --- | --- |
| `internal/policy/store.go` | Policy snapshot, absolute expiry, stale-cache bound |
| `internal/policy/middleware.go` | Action mapping, selectors, quota outcomes |
| `internal/policy/` | Redis Lua limiter and policy tests |
| `internal/netutil/ip.go` | Trusted client-IP resolution |
| `internal/telemetry/` | Structured request events and background publication |
| `decision-engine/iasg/models.py` | Existing serialized policy contract |
| `decision-engine/iasg/policy/writer.py` | Public-address, positive-TTL, cycle-cap, and dry-run rails |
| `decision-engine/iasg/alerts.py` | Existing escalation alerts |
