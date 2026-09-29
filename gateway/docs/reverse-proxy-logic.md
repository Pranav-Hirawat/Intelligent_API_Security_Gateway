# Reverse Proxy Logic

This document explains how the gateway reverse proxy works, how configuration is loaded, and what happened to the old `internal/context` package.

## What The Gateway Is Doing

The gateway is an HTTP reverse proxy. That means it accepts a request on the gateway port, inspects it with middleware, and then forwards it to a backend API if the request is allowed to continue.

In this project, the gateway runs on `0.0.0.0:8082` inside the container and is published on host port `8082` through Docker Compose.

The backend API in your Docker stack runs on `vulnerable_api:5002`, so requests like `http://localhost:8082/api/health` should reach the gateway first and then be forwarded to the backend.

## Request Flow

The runtime flow starts in `gateway/cmd/server/main.go`:

1. Load YAML configuration from `configs/config.yaml`.
2. Apply `IASG_BACKEND_URL` if it is set in the environment.
3. Build the gateway server configuration.
4. Start the proxy server.

Inside `gateway/internal/proxy/server.go`, the server builds the request pipeline like this:

1. Trusted client-IP resolver
2. Telemetry recorder (assigns context and records on return; does not read the body)
3. `LoggingMiddleware`
4. Policy/reflex enforcer, including an atomic Redis quota check when a rate applies
5. `BodyLimitMiddleware`, then `telemetry.CaptureBody`
6. Reflex observer wrapping reputation, flooding, unknown-route scanning, SQLi, traversal, and brute-force detectors
7. Reverse proxy handler

The middleware order matters. The outer middleware sees the request first, and the inner proxy runs last.

## Proxy Package

The main reverse proxy implementation lives in `gateway/internal/proxy/reverse_proxy.go`.

### What it does

- Parses the configured backend URL.
- Creates a `httputil.NewSingleHostReverseProxy` for that backend.
- Configures the outbound HTTP transport with timeout and connection limits.
- Adds the `X-Gateway: IASG` header to proxied requests.
- Sends the backend its own hostname in `Host` and the client's in
  `X-Forwarded-Host`, which it always overwrites. `proxy.preserve_host: true`
  forwards the client's `Host` instead. See
  [Protecting your own API](protecting-your-own-api.md).

### Why it matters

This is the part that forwards admitted traffic to the backend API. Earlier
middleware enforces existing policies and records detection evidence; refused
requests never reach the reverse proxy.

## Middleware Layer

The middleware in `gateway/internal/proxy/middleware.go` does the first layer of request visibility.

### LoggingMiddleware

This logs:

- request method
- request path
- client IP
- user agent

### RequestInspectionMiddleware

This legacy debug helper printed headers and bodies to stdout for every
request, which put passwords and tokens in the logs. It has been deleted, not
merely left unwired -- only an explanatory comment remains at
`internal/proxy/middleware.go:37`. Admitted requests instead pass through the
body-size cap and `telemetry.CaptureBody`, which captures a redacted snippet
and restores the body for forwarding. Requests refused by policy are recorded
without reading their bodies.

## Attack Detection Layer

The gateway has six detection middlewares in `internal/signals`. None of them
refuses a request -- that is the enforcer's job, acting on a decision made
earlier -- so a false positive here costs a log line rather than a customer.

### API Flood Detection

File: `gateway/internal/signals/api_flooding.go`

This tracks request timestamps per IP address in memory.

Behavior:

- groups requests by client IP
- keeps a one minute window
- counts requests in that window
- logs a flood alert if the count goes above the configured threshold
- records evidence and allows the request; refusing is the enforcer's job

### SQL Injection Detection

File: `gateway/internal/signals/sqli_injection.go`

This reads the URL path, decoded query values, and JSON/body content for known SQLi signatures such as:

- `' OR`
- `--`
- `UNION SELECT`
- ` OR 1=1`

The comment marker `--` by itself is retained as low-confidence context but does not fire the detector. A stronger signature emits standardized evidence, logs a formatted alert, and still allows the request through. The dashboard and decision engine distinguish this detection from any later policy enforcement.

### Brute Force Detection

File: `gateway/internal/signals/brute_force.go`

Rather than a hardcoded login path and status code, this reads the top-level
`routes.auth_outcomes` list -- each entry names a method and route template,
plus which backend statuses mean `success` and which mean
`invalid_credentials`. A configured invalid-credentials response grows a
consecutive-failure streak for that client and login target; a configured
success resets it; gateway refusals never reach the detector and are never
interpreted as an authentication outcome. This is a change from an earlier,
hardcoded implementation -- a doc or comment that still lists `/api/login` and
`401`/`403` as fixed is describing that older version.

The detector tracks per-`(ip, route, target)` streaks and reports the single
strongest one via `Metrics(ip)`, which the collector and the reflex read. It
does not classify "classic brute force" versus "password spraying" -- that
distinction exists only as a decision-engine campaign classification, derived
from repeated brute-force evidence, never as its own gateway signal. It also
does not log: unlike the other detectors here, a firing streak produces
`Evidence` but no `SECURITY ALERT` line.

Config comes from `enforcement.brute_force` (`enabled`, `max_failures`,
`window`, `max_clients`, `max_targets_per_client`) plus the shared
`routes.auth_outcomes` declaration. This signal is advisory-only -- see
[Unknown-Route Scanning](#unknown-route-scanning) below for what that means.

### Unknown-Route Scanning

File: `gateway/internal/signals/unknown_route_scanning.go`

Consults the same compiled route table `telemetry` uses. A request that the
table classifies `<unmatched>` records its raw path against the requesting
client; a known route that happens to return a backend 404 is irrelevant, and
repeating one broken link stays one path. The detector needs several distinct
paths within its rolling window before it fires. `max_clients` and
`max_paths_per_client` bound retained attacker input, and inactive entries are
swept after the window elapses.

Config comes from `enforcement.unknown_route_scanning` (`enabled`,
`distinct_paths`, `window`, `max_clients`, `max_paths_per_client`).

Both this signal and brute force above are **advisory-only**: naming either one
in `block.signals` makes the gateway refuse to start with an explicit error
(`internal/enforcement/reflex.go`) rather than silently do nothing. They can
still become an expiring throttle or block, but only after decision-engine
correlation and the policy writer's safety checks -- see
[Detection Signals](detection-signals.md).

### Path Traversal and Enumeration Detection

File: `gateway/internal/signals/enumeration_path_traversal.go`

Matches traversal signatures (`../`, `%2e%2e%2f` and the encoded variants) in
the path and decoded query, and known-sensitive paths such as `/.env`, `/.git`
and `/wp-admin`. Request-scoped: it describes one request, not a window.

Config comes from `enforcement.enumeration_path_traversal`.

### IP Reputation

File: `gateway/internal/signals/ip_reputation.go`

The other five ask what an address just did. This one asks who it is, against a
list loaded from `configs/reputation.txt` plus an optional feed fetched on an
interval. Being listed is a standing fact, so this is the only detector that
knows something on a first request -- and the only source of evidence about an
address that has not yet tripped anything.

It fires on a **cooldown**, because a listed address is listed on every request
it makes. Firing each time would write one `Evidence` per request, swamping the
decision engine's detector counts and the event stream both. Inside the cooldown
the address still contributes its score; it simply does not fire again.

Config comes from `enforcement.ip_reputation` (`enabled`, `feed_path`,
`feed_url`, `refresh_interval`, `score`, `cooldown`). The list and refresh
interval are structural; `enabled`, `score` and `cooldown` can be changed on a
running gateway from the console.

## Configuration Folder

Yes, the `configs` folder is used.

It contains the runtime YAML that the gateway loads when it starts.

### `configs/config.yaml`

This is the active config used by the gateway in Docker and local runs.

### `configs/config.yaml.example`

This is the template copy you can keep for fresh setups.

### How it is used

`gateway/cmd/server/main.go` calls `config.Load(...)`, which reads the YAML into Go structs defined in `gateway/internal/config/config.go`.

Then `main.go` passes those values into the proxy server:

- listen address
- backend URL
- timeouts
- rate limit config
- attack detection config
- brute force config

So the config folder is not just documentation. It directly controls how the gateway starts and behaves.

## `config.go`

The file `gateway/internal/config/config.go` defines the shape of the YAML config.

It contains Go structs such as:

- `Config`
- `ServerConfig`
- `ProxyConfig`
- `EnforcementConfig`
- `RateLimitConfig`
- `AttackDetectionConfig`

It also contains `Load(path string)`, which:

1. reads the file from disk
2. unmarshals YAML into Go structs
3. fills some defaults
4. validates required fields

So `config.go` is definitely used. It is the bridge between your YAML files and the running gateway.

## About `internal/context`

The old `internal/context` package is not used by the current gateway code.

It contained:

- `RequestContext`
- `BuildRequestContext`
- `NewRequestContext`

But nothing in the live proxy flow imported or called it. The current runtime
uses the trusted IP resolver, telemetry, policy enforcement, bounded body
capture, detectors, and reverse proxying described above.

Because it was unused, the package has been removed.

## Current Runtime Summary

The gateway now does exactly this at runtime:

1. Accept the request on port `8082`.
2. Resolve the real client IP, believing `X-Forwarded-For` only from a
   configured trusted proxy.
3. Assign a request ID and start the telemetry record.
4. Log request metadata and consult the local policy/reflex snapshot:
   `block`, `temp_block`, and `escalate` return `403`; `allow` and `monitor`
   forward normally. An applicable rate uses a shared Redis token bucket per
   IP, path, and method, returning `429` with `Retry-After` when exhausted.
5. Cap the admitted body and capture its redacted telemetry snippet.
6. Run the six detectors, each filling in `Evidence`.
7. Forward the request to the backend API on `5002`.
8. Let the reflex observe what they found, after the response, and record a
   block if a trusted detector crossed its threshold.
9. Enqueue the telemetry record for background publication to `iasg:events`.

So it detects *and* enforces, but only ever on a decision made earlier — by the
decision engine, or by the reflex on a previous request. Nothing in the request
path calls the decision engine, PostgreSQL, or a model. Only applicable quotas
perform synchronous Redis I/O, with a short configurable timeout and fail-open
behaviour. Throttling never sleeps or queues requests. See
[Policy enforcement](policy-enforcement.md) for the JSON contract, configuration,
and Docker verification commands.

## If You Want To Extend It Later

Genuinely open, in rough order of value:

- add a gateway health endpoint — there is no mux, so every path proxies and
  liveness cannot be checked without reaching the backend
- convert alert logging into structured JSON logs
- export metrics, so throughput and latency are observable without reading
  container logs
- graceful shutdown: there is no `signal.Notify` or `Shutdown` call, so
  `docker compose stop` drops in-flight requests
