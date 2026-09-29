# Command Center Dashboard

## Overview

The operations console is a **Next.js 15** app in `gateway-dashboard/`, served
on <http://localhost:5177>. It is a single App Router application — not a
separate Express API plus React SPA.

It reads live state from Redis and the durable record from Postgres, and it is
the one place an operator can overrule the agent.

## Pages

The pages live in the `(console)` route group, which supplies the shared shell.
The console runs open -- there is no login -- so whoever can reach the port can
use every control on it:

| Route | File | Shows |
| --- | --- | --- |
| `/` | `app/(console)/page.jsx` | Overview: live traffic, stats, attack map, and setup warnings (below) |
| `/campaigns` | `app/(console)/campaigns/page.jsx` | Campaigns the decision engine has formed |
| `/events` | `app/(console)/events/page.jsx` | The raw `iasg:events` stream |
| `/policy` | `app/(console)/policy/page.jsx` | Active `policy:<ip>` keys, and overrides |
| `/history` | `app/(console)/history/page.jsx` | Durable campaign history from Postgres |
| `/settings` | `app/(console)/settings/page.jsx` | Live enforcement settings |
| `/adaptive` | `app/(console)/adaptive/page.jsx` | Adaptive mode, guardrails and baselines; the analyst approval queue — see [Adaptive Policy and Analyst Control](../adaptive-policy.md) |
| `/signals` | `app/(console)/signals/page.jsx` | The six gateway detectors, one row per `internal/signals/*.go` file, with real alert counts, each one's configured threshold, and which four of the six can arm the reflex to block on their own — see [Detection Signals](../detection-signals.md) |
| `/ip/<address>` | `app/(console)/ip/[address]/page.jsx` | Everything known about one address in one place: its events, policy status, campaign membership and signals tripped, previously spread across four pages |

## API routes

| Route | Purpose |
| --- | --- |
| `app/api/overview/route.js` | Live stats and events for the overview, and the setup checks over the last 500 events |
| `app/api/campaigns/route.js` | Active campaigns |
| `app/api/events/route.js` | The full event stream for investigation, deeper than the live poll's slice |
| `app/api/history/route.js` | Campaign history from Postgres |
| `app/api/overrides/route.js` | Operator instructions to the agent |
| `app/api/settings/route.js` | Read, change and revert the live enforcement settings |
| `app/api/adaptive/route.js` | Adaptive config, baselines, recommendations and audit for the console |
| `app/api/adaptive/settings/route.js` | Change the durable adaptive configuration |
| `app/api/adaptive/overrides/route.js` | An analyst's manual policy instruction on the adaptive path |
| `app/api/adaptive/recommendations/[id]/route.js` | Approve, edit or reject one pending recommendation |
| `app/api/ip/[address]/route.js` | Everything known about one address, for the investigation page |
| `app/api/policies/[address]/route.js` | Delete an address's active policy immediately |
| `app/api/admin/reset/route.js` | Clear the history and live telemetry |
| `app/api/health/route.js` | Liveness |

## Shared modules

| Path | Role |
| --- | --- |
| `app/ui/chrome.jsx` | Console shell and page headers |
| `app/ui/parts.jsx` | Shared presentational pieces |
| `app/ui/icons.jsx` | Every icon the console uses (`lucide-react`), imported once |
| `app/ui/store.jsx` | Client-side polling provider |
| `app/ui/format.js` | Formatting helpers |
| `app/ui/export.js` | CSV export of whatever rows are currently on screen, filters included |
| `app/traffic-map.jsx` | Geographic plot of source addresses |
| `lib/redis.js` | Redis client |
| `lib/postgres.js` | Postgres pool |
| `lib/telemetry.js` | Reads the event stream and stats |
| `lib/plane.js` | Readers for what the decision engine concluded — campaigns, policies, feedback — shared by the campaigns feed and the per-address investigation view |
| `lib/adaptive.js` | Validates a proposed adaptive configuration and a recommendation edit against the live guardrails |
| `lib/setup-checks.mjs` | The Overview's setup warnings, computed from recent events |
| `app/ui/setup-warnings.jsx` | Renders them; dismissal is per browser |
| `lib/adaptive-mode.mjs` | The three adaptive modes' labels and behaviour copy, shared by the settings form and its confirmation dialog |
| `lib/geo.js` | Address to coordinates |
| `lib/auth.js` | A stub — see below |

Every route still calls `requireRole(...)` with the role it would need if
login were restored, but the stub grants every role unconditionally, so the
argument is currently a statement of intent rather than an enforced check.

## Setup warnings

Two deployment mistakes leave the gateway running and recording while it
protects nothing, and neither raises an error. Overview checks the last 500
events (Docker healthcheck probes excluded) for both and shows a warning
naming what it saw:

| Warning | Shown when | Usually means |
| --- | --- | --- |
| Most traffic comes from private addresses | At least 30 requests, 90% or more from private addresses | `server.trusted_proxies` does not list the proxy in front of the gateway, so every request is attributed to it. The gateway and the decision engine never block private addresses. |
| Endpoints missing from the route table | An unmatched endpoint called by at least 2 clients, at least 5 times, and at least twice per client | `routes.templates` does not describe the API, so its own clients count toward unknown-route scanning. |

Both are heuristics, so each warning says when it is expected: an API whose
clients really are on a private network, or testing from the same machine.

The route check is built to ignore attacks. A scanner requests many paths once
each, and a botnet requests one path once per address; neither repeats a path
the way a real client does. Requests flagged by the SQL injection or
path-traversal detectors are left out. Requests flagged by unknown-route
scanning are kept, because a missing route makes its own clients trip that
detector. Segments that look like identifiers are grouped, so `/users/1` and
`/users/2` count as `/users/{id}`, the template the warning suggests.

Dismissing a warning hides it in that browser until what it reports changes: a
different address, or another missing route, shows again.

## Settings

`/settings` changes what the running gateway detects and blocks, without a
restart. Two Redis keys carry it:

| Key | Written by | Holds |
| --- | --- | --- |
| `iasg:settings` | The console | The override that was asked for |
| `iasg:settings:effective` | The gateway | What it is actually enforcing |

The page reads the **effective** key, never the requested one. The gateway
validates independently and can refuse a change -- a duration that will not
parse, a CIDR that will not -- and when it does, the two keys disagree.
Building the form from the request would tell an operator their change was live
when it was not.

`Revert to file` deletes the override, and the gateway returns to exactly the
settings it booted with. The YAML file stays the source of truth: the override
is a layer on top of it, not a replacement for it.

Only the `enforcement` block travels this way. Listen address, backend URL,
timeouts and the Redis connection are structural -- changing them means
rebuilding the server -- so they stay in the file, where a restart applies them.

Both actions are typed confirmations rather than plain buttons, for the same
reason the reset is: the console is open, and these change what a security
gateway is doing to live traffic.

## Overrides

An operator's instruction is written to the `iasg_overrides` stream and read by
the decision engine **before** it decides anything, so a human does not have to
wait for the agent to notice a campaign first.

Overrides still pass through the same simulation and safety checks as the
agent's own decisions, so an allowlisted range is protected from a mistyped
instruction exactly as it is from the agent. Policy written this way is
recorded with `source: human`.

## Environment

| Variable | Purpose |
| --- | --- |
| `REDIS_HOST`, `REDIS_PORT` | Live panels |
| `IASG_POSTGRES_URL` | Campaign history |

## Running it

Under Compose it starts automatically. Standalone:

```bash
cd gateway-dashboard
npm ci
npm run dev      # next dev -H 0.0.0.0 -p 5177
npm start        # production build on the same port
```

The map plots public source addresses; private and container traffic is drawn
at the gateway site instead. On Docker Desktop, host-originated traffic all
arrives as one address — see the warning in
[Running with Docker](../running-with-docker.md).
