# Project Context: Intelligent API Security Gateway

> Comprehensive handoff document for contributors and other AIs.  
> Combines product intent (SRS / team decisions) with the **actual** repository state as of July 2026.

---

## 1. Overview

**Intelligent API Security Gateway (IASG)** is a capstone project: a **security-focused reverse proxy**, not a full-featured API gateway like Kong, APISIX, or NGINX.

Primary purpose: detect malicious API behavior and dynamically mitigate attacks **before** requests reach the backend. Backend services require **zero modifications**.

```text
                Client
                   │
                   ▼
        Intelligent API Security Gateway
                   │
                   ▼
              Backend API
```

Stack focus:

- **Language**: Go 1.22+
- **Module**: `github.com/Adnan-Safdari/Intelligent_API_Security_Gateway`
- **Core runtime**: `gateway/` (Go reverse proxy)
- **Demo backend**: `vulnerable-app/` (Node API + web)
- **Admin UI**: `gateway-dashboard/` (Next.js command center on :5177, reads Redis)
- **Compose stack**: `infra/docker-compose.yml`
- **Docs site**: MkDocs (`mkdocs.yml` → `gateway/docs/`)

---

## 2. Problem Statement

Modern apps expose many Internet-facing APIs, expanding the attack surface. Existing approaches have gaps:

| Limitation | Consequence |
| --- | --- |
| Security logic duplicated in each backend | Inconsistent protection, hard to maintain |
| Static rate limits | Cannot separate legitimate spikes from floods |
| Detection separated from mitigation | Alerts without adaptive response |
| Rule-heavy commercial gateways | Static signatures over behavior |
| Little behavior-based security in lightweight self-hosted proxies | Gap for this project |

**Solution direction:** a Go reverse proxy that performs behavior analysis, adaptive rate limiting, unified risk scoring, and intelligent Allow / Throttle / Block decisions.

---

## 3. Main Goal — Intended Request Lifecycle

Every request should follow:

```text
Incoming Request
        │
        ▼
Intercept Request
        │
        ▼
Behavior Analysis (detectors → metrics)
        │
        ▼
Risk Scoring
        │
        ▼
Decision Engine
        │
 ┌──────┼──────────┐
 │      │          │
 ▼      ▼          ▼
Allow Throttle   Block
 │
 ▼
Forward to Backend
```

The backend should only receive requests the decision engine marks as **Allow** (or Allow under throttle policy, depending on how throttle is enforced).

**Important team decision:** detectors must **not** block on their own. They emit metrics; one centralized engine decides.

Preferred AI role (future):

```text
Detectors → Metrics → Risk Scoring → Decision Engine → AI explanation (optional)
```

Not:

```text
AI → Allow / Block
```

---

## 4. Functional Requirements (SRS) vs Status

| ID | Requirement | Status | Reality in code |
| --- | --- | --- | --- |
| **FR1** | Intercept API requests (reverse proxy + middleware) | **Complete** | Working |
| **FR2** | Analyze request behavior (detectors → metrics) | **Complete** | Six detectors: flood, SQLi, brute force (`consecutive_failed_logins`), traversal/enumeration, unknown-route scanning, and IP reputation. Each fills the same `Evidence` shape; `signals.Collector` summarises them per request, the reflex reads that summary, and telemetry publishes it for the decision engine |
| **FR3** | Adaptive rate limiting as a **decision outcome** | **Complete** | An opt-in baseline (`rate_limit.enforce`) holds every address to `requests_per_minute`; a throttle policy carries its own rate, set from campaign severity, and replaces the baseline in both directions. `policy.Limiter` answers `429` over whichever applies. Recovery is the policy's TTL lapsing |
| **FR4** | Risk scoring + centralized decision engine | **Superseded by design** | Scoring is per-detector; decisions are split between the gateway reflex and the decision engine. No central engine, and the dead `trust_engine` config has been removed |
| **FR5** | Forward valid / reject blocked / throttle | **Complete** | `policy.Enforcer` answers `403` for `temp_block`/`escalate` and `429` for a throttled address over its rate; the gateway's own reflex blocks on a threshold cross |
| **FR6** | Logging & monitoring (Postgres + dashboard) | **Complete** | Redis hot telemetry (capped event stream + counters), durable campaign and feedback history in Postgres, and the Next.js console on :5177 |
| **FR7** | Admin configuration (thresholds, detectors, lists) | **Complete** | The console's Settings page changes the whole `enforcement` block on a running gateway, via an override in Redis. Structural settings still need a restart |

**Overall progress estimate:** the functional requirements are met, with FR4 deliberately answered a different way than the SRS imagined -- see that row. What remains is polish and evidence rather than missing subsystems.

---

## 5. What Actually Runs Today

### 5.1 Bootstrap

Entrypoint: `gateway/cmd/server/main.go`

1. Load YAML from `IASG_CONFIG` or default `configs/config.yaml`
2. Optional override: `IASG_BACKEND_URL`
3. Build `proxy.Config` from server/proxy/enforcement slices of config
4. `proxy.NewServer(...).Start()`

Docker Compose runs: `go run ./cmd/server` with backend `http://vulnerable_api:5002`, host port **8082**.

### 5.2 Live middleware chain

Order in `gateway/internal/proxy/server.go` (outer → inner):

1. `netutil.Resolver.Middleware` — resolve the real client IP, believing `X-Forwarded-For` only from a configured trusted proxy. First, so everything below keys off the same address
2. `telemetry.Middleware` — assign a request ID, and record the event on the way out
3. `LoggingMiddleware` — method, path, IP, User-Agent
4. `policy.Enforcer.Middleware` — **the branch.** `temp_block`/`escalate` answers `403`; a throttled address over its rate answers `429` with `Retry-After`; an address over the baseline rate answers `429`. Nothing below runs
5. `BodyLimitMiddleware`, then `telemetry.CaptureBody` — caps the admitted body and captures a redacted snippet. The old `RequestInspectionMiddleware` debug helper that printed full headers and bodies has been deleted, not merely left unwired — only an explanatory comment remains at `internal/proxy/middleware.go:37`
6. `enforcement.Middleware` — the reflex. Observes *after* the handler, so it never adds latency; a block it records takes effect on the next request
7. The six detectors — reputation, flood, unknown-route scanning, SQLi, traversal/enumeration, brute force (`consecutive_failed_logins`). Each **records evidence and allows**
8. `NewReverseProxy` — `httputil.NewSingleHostReverseProxy` + `X-Gateway: IASG`

**Current behavior summary:** the gateway detects *and* enforces, but never decides in the request path. Every refusal acts on a decision already made — by the decision engine, written to `policy:<ip>` and read from a background-refreshed snapshot, or by the reflex on an earlier request. The detectors themselves still only ever record and allow, which is what keeps a false positive cheap.

### 5.3 Config that is actually used at runtime

Used when building/starting the server:

- `server.*` (host, port, timeouts)
- `proxy.*` (backend_url, timeout, connection limits)
- `enforcement.rate_limit` → flood detector
- `enforcement.attack_detection` → SQLi patterns / enabled flag
- `enforcement.brute_force` → enabled / max_failures / window / login_paths
- `enforcement.enumeration_path_traversal` → traversal/enum detector
- `enforcement.unknown_route_scanning` → route-scan detector
- `enforcement.ip_reputation` → reputation feed and detector
- `enforcement.block` → the gateway's own reflex blocking
- `enforcement.policy` / `enforcement.adaptive_rate_limit` → decision-engine policy and quotas
- `routes.*` → route templates and login outcomes for telemetry and brute force
- `storage.redis` → hot telemetry (stream, stats, per-IP latest)

Accepted for compatibility but with **no effect**:

- `enforcement.throttle` — quota admission never sleeps

Retired — no longer parsed, and ignored if a config file still carries them:

- `storage.postgres`, `signals.*`, `logging.*`

### 5.4 Removed / unused pieces

- `internal/context` (`RequestContext`, builder) — **removed**; was never imported by the live proxy path. Empty `internal/context/` directory may still exist on disk.
- `proxy/security.go` — **removed entirely**, not merely superseded; the real wiring has always been in `server.go`.
- `RequestInspectionMiddleware` — **removed entirely**. It printed every header and the raw request body to stdout for every request, which put passwords and tokens in the logs; only an explanatory comment remains at `internal/proxy/middleware.go:37`.

---

## 6. Repository Structure (Accurate)

```text
Intelligent_API_Security_Gateway/
├── README.md
├── mkdocs.yml                          # docs site root → gateway/docs
├── infra/
│   └── docker-compose.yml              # full local stack
├── gateway/                            # Go module root
│   ├── cmd/server/main.go              # ONLY gateway entrypoint
│   ├── configs/
│   │   ├── config.yaml                 # active runtime config
│   │   └── config.yaml.example
│   ├── Dockerfile
│   ├── go.mod / go.sum
│   ├── docs/                           # MkDocs content — see project-structure.md for the full list
│   └── internal/
│       ├── config/config.go            # YAML → structs + Load()
│       ├── netutil/ip.go               # ClientIP helper
│       ├── proxy/
│       │   ├── server.go               # listen + middleware assembly
│       │   ├── middleware.go           # logging + ChainMiddleware
│       │   ├── reverse_proxy.go        # upstream forwarder
│       │   └── live.go                  # live reconfiguration from the console
│       ├── policy/                     # policy snapshot store, enforcing middleware, rate limiter
│       ├── enforcement/                # the gateway's own reflex — a threshold cross too fast to wait an agent cycle for
│       ├── reputation/                 # known-bad-address list loading and refresh
│       ├── settings/                   # the iasg:settings live-override channel
│       ├── storage/redis/              # the Redis adapter
│       ├── telemetry/                  # event shape, redaction, recording middleware
│       └── signals/
│           ├── api_flooding.go         # request volume, windowed
│           ├── sqli_injection.go       # injection signatures, request-scoped
│           ├── brute_force.go          # consecutive failed logins, windowed + Metrics()
│           ├── enumeration_path_traversal.go
│           ├── unknown_route_scanning.go  # distinct unmatched-path scanning, windowed
│           └── ip_reputation.go        # known-bad list, fires on a cooldown
├── decision-engine/                      # Python agent — see decision-engine.md
├── testing/
│   ├── jmeter/                         # JMeter demo plans
│   ├── signals/                        # HTTP test scripts for detectors (not in the gateway module)
├── gateway-dashboard/                  # Next.js command center (UI + /api/overview)
│   ├── app/
│   └── lib/
├── vulnerable-app/                     # intentional vulnerable demo API/UI
└── DEMO.md                             # brute force demo guide
```

**Not present, despite an even older version of this document once claiming otherwise:**

- `internal/trust/`

---

## 7. Current Modules (Detailed)

### 7.1 Reverse proxy (`internal/proxy`)

| File | Role |
| --- | --- |
| `server.go` | HTTP server, detector construction, middleware chain |
| `middleware.go` | `ChainMiddleware`, logging, body inspection |
| `reverse_proxy.go` | Single-host reverse proxy + transport limits + gateway header |
| `security.go` | Compatibility SQLi middleware (not used by `Start`) |

### 7.2 Signals (`internal/signals`)

#### Implemented now

Every detector implements `Name()` + `Metrics(ip) Evidence` (shared contract in `evidence.go`). None of them block. A `Collector` fans a lookup out across all six and summarises the result — see [Detection Signals](detection-signals.md) for the full contract.

| Attack | File | Mechanism | Metrics() | Enforcement |
| --- | --- | --- | --- | --- |
| **API Flooding** | `api_flooding.go` | Per-IP sliding window; threshold = `requests_per_minute` | Yes — `requestRate`, `threshold`, `window`; Score 0–100 | Deterministic — can arm the reflex |
| **SQL Injection** | `sqli_injection.go` | Signatures in path, query, and body | Yes — `matchCount`, `matchedPatterns`; last-request evidence per IP | Deterministic — can arm the reflex |
| **Path Traversal + Enumeration** | `enumeration_path_traversal.go` | URL/query signatures (`../`, `/.env`, …) | Yes — `pathTraversalDetected`, `enumerationDetected`, match counts | Deterministic — can arm the reflex |
| **Brute Force** (`consecutive_failed_logins`) | `brute_force.go` | Consecutive invalid-credential outcomes per client and login target, read from `routes.auth_outcomes` — no hardcoded path or status code | Yes — `consecutiveFailures`, `failedLogins`, `maxFailures` | **Advisory-only** — the reflex refuses this signal if named in `block.signals` |
| **Unknown-Route Scanning** | `unknown_route_scanning.go` | Distinct paths the route table classifies `<unmatched>`, per client, within a rolling window | Yes — distinct-path count vs. `distinct_paths` | **Advisory-only** — same refusal as brute force |
| **IP Reputation** | `ip_reputation.go` | Known-bad address lookup, fires on a cooldown | Yes | Deterministic — can arm the reflex |

Shared type (`internal/signals/evidence.go`):

```go
type Evidence struct {
    Signal         string         // api_flooding | sql_injection | enumeration_path_traversal |
                                   // consecutive_failed_logins | unknown_route_scanning | ip_reputation
    Score          int            // 0-100 contribution
    ThresholdCross bool
    AttackType     string
    Details        map[string]any
}
```

Brute force does not classify "spraying" versus "brute force" — that distinction exists only as a decision-engine campaign classification derived from repeated brute-force evidence (`correlation/agent.py`), never as its own gateway signal.

#### Considered and deprioritized

| Attack | Status | Notes |
| --- | --- | --- |
| **XSS** | Deprioritized | Too WAF-like; stay API-centric |

The centralized decision engine imagined by the original SRS was superseded by design (see FR4 above) rather than left pending — decisions are split between the gateway reflex and the decision engine's adaptive engine (`decision-engine/iasg/adaptive/`), and persistent logging exists via Postgres.

**Reference pattern:** `Metrics(ip) Evidence` + never block.

Every `internal/signals/*.go` detector has a matching `*_test.go` file beside it — the "unit tests live only in `testing/signals/`" framing this section once had is no longer accurate. HTTP-level test scripts additionally live in `testing/signals/` at the repo root, for verifying a *running* gateway rather than the Go logic in isolation. See [Signal Test Scripts](modules/signal-tests.md).

### 7.3 Config (`internal/config` + `configs/`)

Bridge from YAML to Go. Validates `server.port` and `proxy.backend_url`. Defaults host to `0.0.0.0` if empty.

### 7.4 Netutil (`internal/netutil`)

`ClientIP(remoteAddr)` strips host:port for IP-keyed detection.

---

## 8. Planned Target Architecture

### 8.1 Detection → metrics (not decisions)

Each detector should return metrics, for example:

```json
{
  "failedLogins": 8,
  "requestRate": 40,
  "enumerationScore": 25,
  "pathTraversalDetected": false,
  "sqliConfidence": 0.8
}
```

Example metric ideas per attack family:

| Family | Example metrics |
| --- | --- |
| API Flooding | request rate, burst size, window |
| Enumeration | sequential IDs, 404 ratio, endpoint discovery |
| Path Traversal | `../`, encoded traversal, depth |
| SQL Injection | keyword matches, payload patterns, confidence |

### 8.2 Centralized decision engine

Conceptual risk score:

```text
Risk Score = Flooding + Enumeration + Traversal + SQLi (+ …)
```

Decision bands (example; exact numbers belong in config):

| Score | Decision |
| --- | --- |
| 0–30 | Allow |
| 30–70 | Throttle |
| 70+ | Block |

Responses:

- **Block** → `403 Forbidden`
- **Throttle** → `429 Too Many Requests` (and/or delayed forwarding per policy)
- **Allow** → forward to backend

### 8.3 Adaptive rate limiting

ARL is **not** a pre-analysis gate and **not** a detector.

Correct:

```text
Analyze → Decision Engine → Throttle (adaptive limits by risk band)
```

Incorrect:

```text
Rate Limit → Analyze
```

Example adaptive bands:

| Risk | Limit |
| --- | --- |
| Low | 100 req/min |
| Medium | 40 req/min |
| High | 5 req/min |
| Blocked | 0 |

### 8.4 Logging (FR6)

Every request, any outcome. Suggested fields:

- Timestamp, IP, Endpoint, HTTP Method  
- Detectors triggered / metrics snapshot  
- Risk score, Decision, Response code  

Storage target: **PostgreSQL** (Compose already runs Postgres on host port **5434**). Redis is available for hot state (Compose **6379**).

Dashboard should later show: volume, allow/block/throttle counts, top attacking IPs, attack mix, risk trends, endpoint stats.

### 8.5 Admin configuration (FR7)

Without recompilation:

- Detector thresholds / enable-disable  
- Adaptive rate-limit bands  
- Risk decision thresholds  
- Whitelist / blacklist  

---

## 9. Docker / Local Ports (Compose)

From `infra/docker-compose.yml`:

| Service | Port |
| --- | --- |
| Gateway API | http://localhost:8082 |
| Vulnerable API | http://localhost:5002 |
| Vulnerable Web | http://localhost:5175 |
| Dashboard Web | http://localhost:5177 |
| MkDocs | http://localhost:8000 |
| Postgres (gateway) | localhost:5434 |
| Postgres (vuln API) | localhost:5435 |
| Redis | localhost:6379 |

Gateway env in Compose:

- `IASG_CONFIG=configs/config.yaml`
- `IASG_BACKEND_URL=http://vulnerable_api:5002`

---

## 10. Documentation Status (Important)

Documentation drifts behind the code in this project routinely enough that no
blanket "current" claim in this section should be trusted at face value --
this section itself has previously asserted accuracy it did not have (a
five-detector count, `internal/enforcement`/`internal/storage` claimed absent
while both were live, a phantom dashboard-API port). Treat any specific,
checkable claim here as something to verify against the code before relying
on it, the same way the rest of this document should be read.

Known reconciliation passes: the gateway was originally detect-and-log only;
enforcement and the adaptive decision-engine engine
path were added afterward and are documented in
[Policy Enforcement](policy-enforcement.md) and
[Adaptive Policy and Analyst Control](adaptive-policy.md). The console's login
system was later removed entirely (`gateway-dashboard/lib/auth.js` is a stub);
see [Command Center Dashboard](modules/dashboard.md).

The entrypoint is `cmd/server`. Any doc that says `cmd/gateway/main.go` is
wrong; that path has not existed for a long time.

When docs conflict with code, **trust the Go sources and `reverse-proxy-logic.md`**.

---

## 11. Design Philosophy

- Behavior-aware more than pure signature WAF  
- Detectors produce **evidence**; engine produces **policy**  
- Lightweight, modular, backend-agnostic  
- Suitable as a drop-in security layer in front of existing APIs  
- Stay API-centric (prefer abuse patterns over HTML/XSS WAF features)  
- AI assists explanation/analysis later; does not own Allow/Block  

---

## 12. Meeting Decisions (Locked-in Direction)

1. No per-attack blocking logic ownership — common decision engine only.  
2. Detectors emit metrics; engine combines them.  
3. Agentic AI is a priority research/feature area, but as **assistive explanation**, not the enforcement brain.  
4. Research each attack independently before coding.  
5. After detectors mature: logging → dashboard → risk scoring polish → adaptive rate limiting → admin config.  
6. Refactor detectors from “alert + allow” toward “metrics only,” then wire enforcement once.

---

## 13. Next Development Priorities (Recommended Order)

1. **Define a shared metrics / request-security context** (all detectors write into it; brute force `Metrics()` is the template).  
2. **Centralized risk scoring + decision engine** (consume metrics → Allow/Throttle/Block).  
3. **Wire enforcement** in the proxy (403 / 429 / forward) after the engine.  
4. **Refactor flood + SQLi** to expose `Metrics()` like brute force.  
5. **Add missing detectors** (enumeration, path traversal; optional dedicated credential stuffing) as metric producers.  
6. **Connect adaptive rate limiting** to risk bands.  
7. **Persistent structured logging** to Postgres.  
8. **Dashboard** consumption of those logs.  
9. **Admin configuration** API / UI for thresholds without rebuild.  
10. Refresh MkDocs pages so they match the live chain and entrypoint.

---

## 14. Key Implementation Facts for Coding Agents

- Work inside `gateway/` as the Go module root.  
- Do not reintroduce detector-owned hard blocks. Detectors observe and score; blocking belongs to `internal/enforcement` and the decision engine.  
- There is no trust score and no `trust_engine` config. The model in use is **risk** (higher = worse): each detector emits a 0–100 score, and thresholds are read that way throughout. Do not reintroduce a competing trust-style scale.  
- Compose and Dockerfile expect `./cmd/server`.  
- Healthcheck in Dockerfile hits `/api/health` — that path is expected from the **backend**, not implemented as a gateway-local route today.  
- Prefer extending `internal/signals` (detection) and `internal/enforcement` (action) rather than bloating middleware with one-off blocks. Do not add an `internal/trust` or `internal/decision` package; that layer was considered and deliberately not built.
- Use `brute_force.go` as the reference detector pattern (detect + metrics + never block), or `ip_reputation.go` for one that is stateless apart from its cooldown.
- Adding a section to `enforcement:` config means three places: `main.go` builds the server config, `proxy.Config.Enforcement()` reassembles the block for the settings watcher, and `internal/settings` puts it on the wire. Missing the middle one is silent -- the detector reads a zero config and switches itself off. A reflection test in `internal/proxy` guards it.

---

## 15. One-Paragraph Absolute Truth

IASG is a Go reverse proxy on port 8082 in front of a deliberately vulnerable API, paired with a Python decision engine and a Next.js console. Six detectors — API flooding, SQL injection, brute force (`consecutive_failed_logins`), path traversal/enumeration, unknown-route scanning, and IP reputation — record evidence and always allow; the request path never decides anything. Refusals act on decisions made elsewhere: the decision engine correlates evidence off-path every 30 seconds, groups addresses into campaigns, and writes `policy:<ip>` keys that the gateway reads from a background-refreshed snapshot, answering `403` for a block and `429` for an address over the rate its policy names. A faster gateway-side reflex covers the gap for signals trusted to act alone — brute force and unknown-route scanning are deliberately excluded from that trust and are advisory-only. The whole `enforcement` config block can be changed on a running gateway from the console. What the SRS called a centralized risk/decision engine was deliberately not built: scoring is per-detector and deciding is split between the reflex and the decision engine's adaptive engine, which is why the `trust_engine` config was deleted rather than implemented. The console has no authentication, and the gateway has no health endpoint and no graceful shutdown — those are the honest gaps.
