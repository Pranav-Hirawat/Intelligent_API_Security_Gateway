# AGENTS.md

Working notes for AI agents in this repository. Read this before changing code.

## What this is

An API security gateway in two lanes, and the split is the whole design:

- **`gateway/`** — Go reverse proxy on `:8082`, in the path of every request.
  Detects, enforces a decision it *already has*, forwards. Budget: microseconds.
- **`decision-engine/`** — Python agent, off the request path, every 30 seconds.
  Reads evidence, correlates it into campaigns, decides, writes `policy:<ip>`
  keys back to Redis.
- **`gateway-dashboard/`** — Next.js console on `:5177`.
- **`vulnerable-app/`** — the deliberately vulnerable API being protected.
- **`infra/docker-compose.yml`** — runs all of it. Docs site on `:8000`.

The one sentence to preserve: **the gateway never waits on thinking.** No change
should put Redis, the decision engine, or a model on the synchronous request path.

## Commands

```bash
# Everything
docker compose -f infra/docker-compose.yml up -d

# Go — always all three before claiming done
cd gateway && go build ./... && go vet ./... && go test ./...
cd gateway && go test ./internal/signals/ -race      # detectors hold live state

# Python — the venv already exists; PYTHONPATH is required
cd decision-engine && PYTHONPATH=. .venv/bin/python -m pytest -q
cd decision-engine && PYTHONPATH=. .venv/bin/python -m iasg --once

```

Go 1.22 in `go.mod` (containers run 1.23), Python ≥3.11. There are no linters
configured — run `gofmt -l` on anything you touch.

## Invariants

Breaking any of these breaks the architecture, not just a test.

1. **Detectors never refuse a request.** They fill in `Evidence` and allow. Only
   `internal/policy` (decision-engine decisions) and `internal/enforcement` (the
   gateway's own reflex) may refuse, and both act on decisions made *earlier*.
2. **Nothing on the request path blocks on I/O it can avoid.** Policy is read
   from a background-refreshed snapshot. A dead Redis means "no policy", never
   added latency.
3. **The LLM never influences enforcement.** It writes the incident note and an
   assessment, after policy is written. Nothing reads its output back. Keep it
   that way — a prompt-injected assessment must not be able to unblock anyone.
4. **`policy/writer.py` is the only code that can influence the gateway.** All
   the rails live there together (no private/reserved addresses, no policy
   without a TTL, per-cycle cap, dry-run). Add new guards there, not scattered.
5. **Enforcement expires on its own.** Every policy key carries a TTL and
   nothing renews it. Don't add renewal.
6. **Nothing reads the request body without a cap above it.**
   `BodyLimitMiddleware` sits above every stage that buffers a body —
   `telemetry.CaptureBody` and all the detectors — and below the enforcer, so
   a blocked address is refused before its body is read at all. Config
   (`MaxBodyBytes`) may raise or lower the cap, never remove it. Adding a new
   body reader means checking it is below this line, not above it.

## House style

**Comments say *why*, not *what*.** This codebase is unusually consistent about
it, and matching that matters more than any formatting rule. Prefer explaining
the failure a piece of code prevents:

```go
// Charged in a finally block so a call that raised still costs what it burned.
// Otherwise a provider that reliably times out would be free, and would be
// retried for every campaign in the cycle.
```

Do not write `// increment the counter`. If a line needs no explanation, leave
it bare.

**Tests assert properties, not paths** — "reputation cannot invent enforcement",
"bias cannot compound past one rung", "a narration failure never fails a cycle".
When you fix a bug, add the property that was violated.

**Commit messages are prose** explaining the reasoning and what was verified.
Look at `git log` before writing one. **No `Co-Authored-By` trailer.**

## Git

Branch off `main`, push the branch, open a PR — **never commit directly to
`main`**. Pranav merges.

Note the local checkout has flipped to `main` unexpectedly more than once
mid-session. Check `git branch --show-current` before assuming your work is
where you left it.

## Traps that have actually cost time

Each of these was hit for real. They fail silently, which is why they are here.

**`gateway/configs/config.yaml` is tracked and *not* ignored**, despite
`.gitignore` carrying a `configs/config.yaml` line. That pattern has a slash in
the middle, so git anchors it to the repository root and it never reaches the
`gateway/` directory. Local demo tuning therefore shows up as a real repo
change and will be committed if you stage it blindly. Stage selectively.

**Telemetry writes to three streams, not one.** `iasg:events` on completion,
`iasg:arrivals` before the request runs, and `iasg:telemetry:health` once a
second. Adaptive baseline windows key on arrival time; the console and the
`iasg:attackers` counters read only `iasg:events` and must keep doing so.

**Adding a section to `enforcement:` config needs three places** — `main.go`
building the server config, `proxy.Config.Enforcement()` reassembling the block
for the settings watcher, and `internal/settings` putting it on the wire. Miss
the middle one and the detector reads a zero config, switches itself off, and
*nothing fails*. `internal/proxy/enforcement_config_test.go` guards this by
reflection; if it fails, that is what it is telling you.

**`DEL` on a Redis stream deletes its consumer groups.** The decision engine
creates groups once at startup, so a reset that deletes `iasg:events` leaves
every later cycle failing `NOGROUP` until a restart. Use `XTRIM MAXLEN 0`, as
`app/api/admin/reset/route.js` does. That endpoint also deliberately spares
`policy:*` — clearing history and lifting live blocks are different actions.

**Docker Desktop rewrites source IPs.** Requests from the host arrive as
`192.168.65.1`. Drive attack traffic from *inside* a container on the compose
network, and set `X-Forwarded-For` — the gateway only believes that header from
a configured trusted proxy.

**Demo traffic must come from `203.0.113.x`.** `policy/writer.py` refuses to
police private, loopback and reserved addresses, so an attack from localhost
correctly produces no policy at all and looks broken. The RFC 5737
documentation ranges are explicitly allowed for exactly this.

**`open_store` falls back to an in-memory store when Redis is unreachable**, and
only prints a warning. The seeder then writes somewhere the agent cannot see,
and the cycle reads zero events with nothing visibly wrong.

**Python block-buffers stdout under Compose.** `PYTHONUNBUFFERED=1` is already
set; without it the agent looks hung while working normally.

**Never run a dev server inside the bind-mounted `gateway-dashboard/`.** Two
Next servers sharing `.next` corrupts it and the console starts returning 500s.

**Clean up test traffic.** `POST /api/admin/reset` with `{"confirm":"reset"}`.
Then check the consumer groups survived.

## Known gaps — do not "discover" these as new

- The console has no authentication (`gateway-dashboard/lib/auth.js` is a stub
  that always authorises). Deliberate, but it now fronts settings and reset.
- No graceful shutdown, no health endpoint, no metrics. `go run` does not
  forward SIGTERM either.
- Detection is substring matching; `UNION/**/SELECT` walks past the SQLi
  detector.
