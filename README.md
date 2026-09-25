# Intelligent API Security Gateway

An API gateway that detects attacks in the request path and decides what to do about them
out of it — a fast Go proxy that enforces, and a Python agent that watches, correlates and
adapts.

## How it works

Two lanes, deliberately separate.

```
                    ┌──────────────────────────────────────────┐
   request ────────▶│  Go gateway (data plane)                 │────▶ backend API
                    │  detect · check policy · allow/slow/block│
                    └───────────────┬──────────────────────────┘
                                    │ evidence            ▲ policy:<ip>
                                    ▼                     │
                    ┌──────────────────────────────────────────┐
                    │  Redis                                   │
                    └───────────────┬──────────────────────────┘
                                    │                     ▲
                                    ▼                     │
                    ┌──────────────────────────────────────────┐
                    │  Python control plane (every 30s)        │
                    │  correlate · remember · decide · explain │
                    └──────────────────────────────────────────┘
```

The **gateway** handles every request and must be fast, so it only ever reads a cached
answer — never waits on Redis, never waits on the agent, never waits on a model.

The **control plane** never touches a live request. It reads what the detectors saw, groups
it into attack campaigns, decides enforcement, and writes it back as `policy:<ip>` keys
with a TTL.

Stop the control plane and the gateway keeps serving traffic exactly as before. That
independence is the point of the split.

## Five core mechanisms

The project is designed to be explained through these mechanisms, rather than
as a collection of queues, caches, and timers:

| Mechanism | Responsibility |
|---|---|
| Deterministic attack detectors | Emit evidence for known attack shapes; detectors never choose a response. |
| Adaptive endpoint baseline | Learn safe normal traffic per method and route from trusted completed windows. |
| Campaign correlation | Relate evidence across addresses and cycles into continuing attacks. |
| Risk/confidence policy engine | Choose a bounded, explainable policy from evidence, behaviour, and campaign facts. |

Body limits, detector cooldowns, Redis streams, token buckets, policy snapshots,
and TTLs support safe enforcement and reliable delivery; they are not separate
detection algorithms. IP reputation is optional supporting evidence only. The
LLM writes narration strictly after policy selection and cannot affect risk,
confidence, or enforcement. The offline template provider remains the safe
default; Ollama is an explicit, opt-in narration provider — as a container in
the Docker stack (`docker compose --profile llm up -d`, see
[`infra/README.md`](infra/README.md#narration)) or as a native install
alongside a bare-metal control plane.

See the [control-plane overview](control-plane/OVERVIEW.md) and
[adaptive-policy documentation](gateway/docs/adaptive-policy.md) for the
decision boundaries and their safeguards.

## Functional requirements

Functional requirements describe the observable jobs the system must perform.
They are separate from implementation choices: the requirements say *what* the
gateway delivers, while the Go proxy, Redis, and Python control plane explain
*how* it delivers it.

| Requirement | What it means | Algorithm used | How it is done | Why it matters |
|---|---|---|---|---|
| FR1 — Intercept and validate requests | Every protected API request passes through one safe entry point. | Reverse-proxy routing, trusted-proxy CIDR matching, and bounded body reading. | The Go reverse proxy resolves trusted client identity, caps bodies, and validates request metadata before forwarding. | Prevents unsafe or oversized traffic from reaching the backend unchecked. |
| FR2 — Detect suspicious behaviour | Recognise flooding, credential attacks, SQLi, enumeration, traversal, and related signals. | Deterministic substring/signature matching and per-client time-window counters. | Deterministic detectors emit structured evidence; they never decide to block the same request. | Keeps detection explainable and avoids false-positive enforcement in detector code. |
| FR3 — Assess risk and correlate campaigns | Identify related activity across IPs, routes, detectors, and time windows. | Union-find correlation over shared behavioural traits, with rule-based confidence scoring. | The off-path Python agent correlates Redis evidence into campaigns and records confidence and explanations. | Distinguishes isolated noise from coordinated attacks. |
| FR4 — Generate adaptive policies | Produce time-limited, explainable security decisions. | Rule-based risk/confidence ladder with policy-writer guardrails and TTLs. | The policy writer applies safety rails and stores TTL-bound `policy:<ip>` records in Redis. | Ensures controls expire automatically instead of becoming permanent accidental blocks. |
| FR5 — Enforce decisions and rate limits | Apply monitor, throttle, temporary-block, and escalation outcomes before forwarding. | Background policy snapshots, Redis token buckets, and threshold-based reflex blocking. | The gateway reads background-refreshed policy snapshots, uses bounded quotas for throttles, and can apply a local reflex for urgent flooding. | Protects the backend without making requests wait for analysis. |
| FR6 — Forward permitted requests and capture responses | Preserve normal application behaviour while observing outcomes. | Reverse proxying with response-status capture. | Admitted requests are reverse-proxied to the backend and response metadata is recorded as telemetry. | Lets the gateway protect an existing API without modifying it. |
| FR7 — Provide monitoring and visualisation | Make traffic, evidence, campaigns, policies, and health visible. | Redis-stream telemetry aggregation and dashboard polling. | Redis telemetry and durable campaign history are presented by the Next.js dashboard. | Gives operators an auditable view of why action was taken. |
| FR8 — Support configuration and human overrides | Let operators configure thresholds, modes, exemptions, and policy instructions. | Validated override processing with deterministic safety guardrails. | Dashboard actions become control-plane overrides and still pass the policy writer's safety rails. | Keeps human review available without bypassing safety controls. |

**Viva summary:** IASG is a split-plane security gateway. The gateway handles
the immediate request path; the control plane performs slower correlation and
policy generation afterward. This separation is deliberate: it keeps
enforcement fast, decisions explainable, and every policy bounded by a TTL and
safety checks.

## Layout

| Path | What it is |
|---|---|
| [`gateway/`](gateway/README.md) | Go reverse proxy, detectors, policy enforcement |
| [`control-plane/`](control-plane/README.md) | Python agent — correlation, policy, narration |
| [`vulnerable-app/`](vulnerable-app/README.md) | Deliberately insecure API to attack |
| [`gateway-dashboard/`](gateway-dashboard/README.md) | Next.js operations console |
| [`infra/`](infra/README.md) | Docker Compose for everything |
| [`testing/`](testing/README.md) | Load and attack scripts |
| [`desktop/`](desktop/README.md) | Electron app that runs the packaged stack (.dmg / .exe / .AppImage / .deb / .pacman) |

Each has its own README covering how to run it, what it talks to, and what it does not do.

## Prerequisites

- Docker and Docker Compose
- Go 1.22.2+, Python 3.11+, and Node.js 22 for local development (matching the Compose images)
- Redis and Postgres (via Compose, or `brew install redis postgresql@18`)

## Quick start

### Desktop app (no clone needed)

1. Download from the
   [latest release](https://github.com/Pranav-Hirawat/Intelligent_API_Security_Gateway/releases/latest):
   `IASG-<version>-arm64.dmg` for Apple Silicon Macs, `IASG-<version>.dmg` for
   Intel Macs, `IASG.Setup.<version>.exe` for Windows, or on Linux
   `IASG-<version>.AppImage` (x64), `IASG-<version>-arm64.AppImage`, or
   `iasg-desktop_<version>_amd64.deb` for Debian and Ubuntu, or
   `iasg-desktop-<version>.pacman` for Arch-based systems such as CachyOS
   (`sudo pacman -U iasg-desktop-<version>.pacman`). Make an AppImage executable
   first (`chmod +x IASG-*.AppImage`; Arch needs `fuse2`).
2. Open **IASG**. If Docker Desktop is missing or stopped, the app walks you
   through installing or starting it and carries on by itself once it runs.
3. The first launch downloads the images (a few GB), then the dashboard opens
   in the app window. Later launches pick up newer images automatically.
   Quitting the app stops the containers; data is kept.

Opening the app keeps the services up to date, but not the app itself. When a
newer app exists, the **IASG** menu shows **Download Launcher**; install that
to get changes to the app, such as its setup screens.

The app is not signed with an Apple or Microsoft developer certificate, so the
OS warns the first time:

- **macOS:** open IASG and choose **Done** on the "could not verify" message,
  then System Settings → Privacy & Security → **Open Anyway**. Versions 0.1.7
  and earlier may instead say the app is "damaged"; for those, run
  `xattr -cr /Applications/IASG.app`.
- **Windows:** on the SmartScreen prompt, **More info** → **Run anyway**.

See [`desktop/README.md`](desktop/README.md) for how releases are made.

### Everything at once, from source

```bash
docker compose -f infra/docker-compose.yml up -d
docker ps
```

Ports:

| Service | URL |
|---|---|
| Gateway | http://localhost:8082 |
| Vulnerable API | http://localhost:5002 |
| Vulnerable web | http://localhost:5175 |
| Dashboard | http://localhost:5177 |
| Docs | http://localhost:8000 |
| Postgres | localhost:5434 |
| Redis | localhost:6379 |

Then open the console at http://localhost:5177. There is no sign-in — see
[Reaching the console](#reaching-the-console).

## Run locally, piece by piece

Redis and Postgres first (Compose, or your own local services):

```bash
docker compose -f infra/docker-compose.yml up -d redis postgres
```

Bring the rest up in this order. Each runs in its own terminal.

**1. Vulnerable API** — the target (`memory` mode needs no database):

```bash
cd vulnerable-app/backend
npm install
PORT=5002 npm start
```

**2. Gateway** — the data plane, proxying to the target:

```bash
cd gateway
cp configs/config.yaml.example configs/config.yaml   # first time only
go mod download
go run ./cmd/server
```

**3. Control plane** — the agent. Needs Redis; Postgres is optional but recommended:

```bash
cd control-plane
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev,postgres]"

export IASG_POSTGRES_URL=postgresql://iasg_user:changeme@localhost:5432/iasg

.venv/bin/python -m iasg --once     # one cycle, then exit
.venv/bin/python -m iasg            # run forever (every 30s)
.venv/bin/python -m iasg --dry-run  # decide everything, write nothing
```

Every setting has a working default. `control-plane/.env.example` documents the `IASG_*`
variables; export the ones you want to change rather than copying the file:

```bash
IASG_INTERVAL_SECONDS=15 IASG_LLM_PROVIDER=ollama .venv/bin/python -m iasg
```

That last example needs a host-native Ollama (`brew install ollama`) already running;
the Docker stack ships its own containerised one instead — see
[`infra/README.md`](infra/README.md#narration).

**4. Dashboard** — the operations console. Needs Redis and Postgres:

```bash
cd gateway-dashboard
npm install
export IASG_POSTGRES_URL=postgresql://iasg_user:changeme@localhost:5432/iasg
REDIS_HOST=127.0.0.1 npm run dev            # development
# or a production build:
REDIS_HOST=127.0.0.1 npm run build && REDIS_HOST=127.0.0.1 npm start
```

## See it work without an attacker

The seeder writes realistic attack evidence straight into Redis, so the whole pipeline is
demonstrable in a second:

```bash
cd control-plane
.venv/bin/python -m tools.seed_evidence --scenario credential-stuffing
.venv/bin/python -m iasg --once

redis-cli KEYS 'policy:*'
redis-cli GET policy:203.0.113.5
```

Scenarios: `credential-stuffing`, `brute-force`, `flood`, `enumeration`, `path-traversal`,
`recon`, `sqli`, `mixed`, and `noise` — which must *not* form a campaign.

## See a real attack, end to end

The seeder skips the gateway. To watch the whole chain — detect → correlate → decide →
enforce — send real traffic instead.

Two things have to be true for the gateway to enforce rather than watch. Both are set in
the committed `gateway/configs/config.yaml`, so a fresh clone is already enforcing:

```yaml
server:
  trusted_proxies:        # believe X-Forwarded-For from these, so a local
    - 127.0.0.1/32        # test can present a public client IP
    - 172.16.0.0/12       # the Compose bridge
enforcement:
  policy:
    enabled: true         # act on policy:<ip>, not just observe
```

`enforcement.policy.enabled` can also be turned on and off from the console's **Settings**
page while the gateway is running, which is the easier way to show the difference between
observing and enforcing without restarting anything.

Now attack it — the `X-Forwarded-For` gives the request a public source address the control
plane will act on (loopback and private ranges are never written policy for).

The commands below assume the gateway is running **on your machine** (the "run locally"
path above), where the request arrives from `127.0.0.1` and the header is believed. Under
Compose on Docker Desktop it arrives from the port forwarder instead and the header is
ignored — run the loop inside a container there, as in
[Adaptive rate limiting](#adaptive-rate-limiting).

```bash
# 40 failed logins from one "attacker"
for i in $(seq 1 40); do
  curl -s -o /dev/null -X POST http://localhost:8082/api/login \
    -H 'Content-Type: application/json' \
    -H 'X-Forwarded-For: 203.0.113.60' \
    -H 'User-Agent: Hydra/9.5' \
    -d "{\"username\":\"admin\",\"password\":\"guess-$i\"}"
done
```

Within one control-plane cycle a campaign forms and a policy is written. Watch it happen:

```bash
redis-cli GET policy:203.0.113.60      # the agent's decision, with a TTL
redis-cli GET iasg:heartbeat           # last cycle: evidence read, campaigns, policies

# the attacker is now enforced, a clean address is not
curl -s -o /dev/null -w "attacker %{http_code}\n" \
  -X POST http://localhost:8082/api/login -H 'X-Forwarded-For: 203.0.113.60' \
  -H 'Content-Type: application/json' -d '{"username":"a","password":"b"}'
curl -s -o /dev/null -w "clean    %{http_code}\n" \
  -X POST http://localhost:8082/api/login -H 'X-Forwarded-For: 198.51.100.9' \
  -H 'Content-Type: application/json' -d '{"username":"a","password":"b"}'
```

`403` means the address was blocked outright. `429` means it was throttled and has just
gone over the rate its policy allows — see [Adaptive rate limiting](#adaptive-rate-limiting)
below. The clean address should answer normally throughout.

The scripts in [`testing/`](testing/README.md) drive every detector this way, not just
brute force:

```bash
bash testing/signals/run_all.sh
```

## Adaptive rate limiting

A throttle carries a number, not just a verdict. Every address is held to a rate, and a
policy replaces the one it would otherwise get:

| Address | Allowed |
|---|---|
| No policy | The baseline — `rate_limit.requests_per_minute`, 100/min |
| Exempt range | Everything; never counted |
| Throttled, low or medium severity | 50/min |
| Throttled, high severity | 20/min |
| Blocked | Nothing — the request is refused |

The policy wins in **both** directions: a campaign judged worse than the baseline is held
tighter, one judged better is allowed more. The control plane looked at that address
specifically, which beats the figure everyone else gets.

The baseline is **off by default**. `rate_limit.enabled` counts requests and raises a flood
signal; `rate_limit.enforce` turns that same threshold into a limit the gateway acts on.
Two flags, because noticing a flood and refusing traffic are different decisions and only
the second can turn a legitimate spike into an outage. It is one number either way — the
baseline *is* the detection threshold, so the alert and the refusal cannot disagree about
what "too fast" means. Exemptions are `block.exempt_cidrs`, the same list the reflex never
blocks.

Over the limit the gateway answers **429** with a `Retry-After`, not the **403** a block
gets. The difference is worth keeping: a block says *not you*, a rate limit says *not this
fast*. Refused requests still count toward the window, so hammering after a refusal does
not earn a way back in.

Recovery is the policy expiring. When the key goes the gateway stops finding a decision for
that address, stops counting it, and it is back to the default immediately — there is no
de-escalation ladder to walk down. Each rung already carries its own TTL: throttle 15
minutes, block 30, escalation an hour.

Watching it happen, without waiting for the agent — write a policy by hand and spend it:

```bash
docker exec infra-redis-1 redis-cli SET policy:203.0.113.50 \
  '{"action":"throttle","campaign_id":"demo","confidence":0.8,"reason":"demo","source":"agent","issued_at":"2026-01-01T00:00:00+00:00","expires_in":300,"requests_per_minute":20}' EX 300

sleep 6      # the gateway refreshes its policy snapshot every 5s

docker exec infra-gateway-1 sh -c 'for i in $(seq 1 26); do
  wget -S -q -O /dev/null --header="X-Forwarded-For: 203.0.113.50" \
    http://127.0.0.1:8082/api/products 2>&1 | grep -o "HTTP/1.1 [0-9]*" | tail -1
done | sort | uniq -c'
```

```
  20 HTTP/1.1 200
   6 HTTP/1.1 429
```

The loop runs **inside** the gateway container, and against `127.0.0.1` rather than
`localhost`, for two reasons that will otherwise waste an afternoon:

- Run from your own machine under Docker Desktop, the request reaches the gateway as
  `192.168.65.1` — the port forwarder's address, not yours. That is not a trusted proxy, so
  `X-Forwarded-For` is ignored (correctly) and every request is attributed to one address.
  See the warning in [Running with Docker](gateway/docs/running-with-docker.md).
- Inside the container, `localhost` resolves to `::1` first, and the shipped
  `trusted_proxies` lists `127.0.0.1/32` but not `::1/128` — same silent outcome.

Only addresses under a throttle policy are ever counted — everyone else never touches the
limiter — so this costs nothing for ordinary traffic.

## Changing what it enforces, while it runs

The console's **Settings** page edits the whole `enforcement` block of a running gateway:
detector thresholds, which detectors may block on their own, the score floor, block
duration, exempt ranges, and whether the agent's decisions are acted on at all. Changes
apply within a few seconds, without a restart.

The YAML file stays the source of truth at boot. The console writes an override into Redis
on top of it, and **Revert to file** drops the override and returns the gateway to exactly
what it started with. The page always shows what the gateway reports it is *actually*
enforcing, not what it was last asked for, so a change the gateway refused — an unparseable
duration, a malformed CIDR — shows as refused rather than appearing to have worked.

Listen address, backend URL, timeouts and the Redis connection stay in the file. Changing
those means rebuilding the server, which a live apply cannot do.

## What each side does

**Gateway (Go)**

- Reverse proxy to the backend
- Detectors: brute force, API flooding, SQL injection, enumeration and path traversal
- Resolves the real client IP from `X-Forwarded-For`, but only from proxies configured as
  trusted, so the header cannot be spoofed to frame another address
- Reads `policy:<ip>` from a background-refreshed snapshot, so the request path does no
  Redis I/O. A dead Redis means "no policy", never added latency. Unknown actions fail open
- Enforces what it finds: `403` for a block, `429` for a throttled address over the rate its
  policy names
- Has a reflex of its own for the cases too fast to wait 30s for: a detector crossing its
  threshold with a high enough score blocks the address immediately, for a short fixed
  period, and only for detectors named in the config

**Control plane (Python)**

- Groups IPs into campaigns by shared behaviour — subnet, user agent, endpoint, detector,
  timing
- Remembers campaigns between cycles, and keeps tracking one after the attacker moves to
  addresses never seen before
- Notices whether acting worked, and answers an action that failed with a stronger one
- Reads several attack phases from one actor as one intrusion rather than separate attacks
- Writes `monitor` / `throttle` / `temp_block` / `escalate`, always by rule, and puts a
  per-minute allowance on a throttle so the limit fits the campaign
- Checks the response is safe before writing it — allowlisted and shared ranges are
  protected, and a standing policy is never traded for a weaker one
- Takes instructions from a human, and learns from being overruled

An LLM writes the human-readable incident note and nothing else. It runs *after* the
decision is made and written, so a hallucinated or prompt-injected note can mislead a
reader but cannot change enforcement. It is optional — the default provider is an offline
template.

## Durable memory

Without Postgres, campaigns live in Redis under a 24-hour TTL, so restarting the machine
loses every investigation in progress. With it, they survive:

```bash
cd control-plane
.venv/bin/python -m pip install -e ".[postgres]"

export IASG_POSTGRES_URL=postgresql://iasg_user:changeme@localhost:5432/iasg
.venv/bin/python -m iasg --once      # prints: [postgres] campaigns and feedback are durable
```

Compose already passes this, so `docker compose up` needs no extra step.

What moves and what does not:

| | Where | Why |
|---|---|---|
| Campaigns, feedback tallies | Postgres, mirrored to Redis | Postgres is the record. Redis keeps a copy because the dashboard reads it, exactly as the gateway does |
| `policy:<ip>` | Redis | The gateway reads it on the hot path, and it is *meant* to expire |
| Evidence, alerts, overrides | Redis streams | Transport. Once correlated, it is done |

The mirror is a projection, not a second source of truth: it may expire, and the agent
rebuilds it from Postgres on startup, so a wiped Redis costs a cycle rather than an
investigation.

Campaigns are never deleted, but only the last 24 hours are offered to the correlator, so
switching stores does not change which campaigns a cycle can merge into. The rest is
history you can query:

```sql
SELECT type, count(*), round(avg(confidence)::numeric, 2) AS avg_confidence
  FROM campaigns GROUP BY type ORDER BY count DESC;
```

Everything degrades: no driver, no database, or a database that is down means the agent
says so once and carries on with Redis.

## Reaching the console

The console runs open. There is no login, no accounts and no roles: whoever can reach
http://localhost:5177 can use every control on it, including the ones that change what the
gateway enforces and the one that wipes the history.

That is a deliberate trade for a project that runs on one machine, and it is the only thing
protecting it. **Do not expose port 5177 to a network you do not trust.** Bind it to
loopback, or put it behind something that does authenticate, before it leaves your laptop.

The login system that used to be here — accounts, sessions, scrypt hashing, viewer /
operator / admin roles — was removed because it was one more thing to keep working during
a demo. It is in the git history if it is ever wanted back; `gateway-dashboard/lib/auth.js`
says what to restore.

## Testing

```bash
cd gateway && go build ./... && go vet ./... && go test ./...
cd gateway && go test ./internal/signals/ -race
cd control-plane && PYTHONPATH=. .venv/bin/python -m pytest -q
cd gateway-dashboard && npm test
cd vulnerable-app/backend && npm test
```

Use `.venv/bin/python -m pytest` (not `.venv/bin/pytest`) — the module form does not depend
on the shebang, which can break if the virtualenv was created under a different path.

The Postgres tests are skipped unless you point them at a database they may write to —
they truncate tables, so never aim this at anything that matters:

```bash
createdb iasg_test    # once -- the tests truncate, so never the live database

IASG_TEST_POSTGRES_URL=postgresql://iasg_user:changeme@localhost:5432/iasg_test \
    .venv/bin/python -m pytest tests/test_postgres.py
```

## Deliberately not built

- **A central trust engine.** There is no separate scoring service, and the `trust_engine`
  config block that used to imply one has been deleted rather than left in the file — it
  was parsed into Go structs that nothing ever read. Scoring already happens where the
  evidence is: each detector scores what it sees, the gateway's reflex acts on a threshold
  cross in nanoseconds, and the control plane re-decides every 30s with the wider view. An
  engine in between would only re-derive what both already have.

Postgres was a real gap on this list until campaigns and feedback were moved into it. See
**Durable memory** above.

## Documentation

The full site builds with MkDocs and is served at http://localhost:8000 by the Compose
stack. The pages worth starting from:

**How a request is handled**

- [System architecture](gateway/docs/system-architecture.md)
- [Request lifecycle](gateway/docs/request-lifecycle.md)
- [Reverse proxy logic](gateway/docs/reverse-proxy-logic.md)
- [Client IP resolution](gateway/docs/client-ip.md) — why `X-Forwarded-For` is only
  believed from configured proxies

**Security pipeline**

- [Detection signals](gateway/docs/detection-signals.md) — what each detector looks for
- [Policy enforcement](gateway/docs/policy-enforcement.md) — the decision contract, the
  adaptive rate limit, and why every action must be able to expire
- [Control plane](gateway/docs/control-plane.md)

**Running and operating it**

- [Running with Docker](gateway/docs/running-with-docker.md),
  [running locally](gateway/docs/running-locally.md)
- [Operations console](gateway/docs/modules/dashboard.md) — pages, API routes, and the
  live Settings page
- [Redis telemetry](gateway/docs/modules/redis-telemetry.md),
  [project structure](gateway/docs/project-structure.md)

**Per-component READMEs**

- [Gateway](gateway/README.md), [control plane](control-plane/README.md),
  [dashboard](gateway-dashboard/README.md), [infra](infra/README.md),
  [testing](testing/README.md)
- [Control-plane algorithm summary](control-plane/OVERVIEW.md) and
  [full algorithm pseudocode](control-plane/README.md#algorithms-and-pseudocode)
- [Demo walkthrough](DEMO.md) and [command reference](commands.md)

## Stopping

```bash
docker compose -f infra/docker-compose.yml down
```
