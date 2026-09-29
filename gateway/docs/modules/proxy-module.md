# Gateway Module

The gateway is a Go reverse proxy whose request work is bounded and local.

| Area | Package | Responsibility |
| --- | --- | --- |
| Startup | `cmd/server`, `internal/config` | YAML loading and environment overrides. |
| Client identity | `internal/netutil` | Trusted-proxy IP resolution and CIDR parsing. |
| Proxying | `internal/proxy` | Middleware chain, body cap, CORS, upstream transport. |
| Decisions | `internal/policy`, `internal/enforcement` | Cached policy and short-lived reflex behavior. |
| Observation | `internal/signals`, `internal/telemetry` | Evidence and asynchronous Redis publication. |
| Object protection | `internal/identity`, `internal/ownership` | JWT verification and BOLA response protection. |

The server starts a background policy snapshot refresher and asynchronous telemetry writers. Neither can block an individual request. See [Request Lifecycle](../request-lifecycle.md).
