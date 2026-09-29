# Dashboard — the operations console

A Next.js app that reads what the gateway saw, shows what the agent concluded, and lets a
person argue with it. UI and API routes in one process.

Runs on **http://localhost:5177**.

## Pages

| Page | Answers |
|---|---|
| `/` | What does the traffic look like right now |
| `/campaigns` | What did the agent correlate, and what did it decide |
| `/policy` | What is being enforced, and how do I change it |
| `/events` | What actually happened, request by request |
| `/history` | What keeps happening to us, across restarts |
| `/adaptive` | What the adaptive engine would do, and the approval queue for it |
| `/signals` | What each detector is configured to catch, and its real alert counts |
| `/ip/<address>` | Everything known about one address, in one place |

They are linked rather than merely separate: an address anywhere opens its own events, a
signal opens the events that fired it, and a metric tile opens the page behind it.

## Where the data comes from

| Source | Written by | Shows as |
|---|---|---|
| `iasg:stats`, `iasg:events`, `iasg:attackers` | Go gateway | Metrics, map, signals, event stream |
| `campaign:*`, `policy:*`, `feedback:*`, `iasg_alerts` | Decision engine | Campaigns, policy, escalations, learning |
| `iasg:heartbeat` | Decision engine | Whether the agent is alive |
| `campaigns` table (Postgres) | Decision engine | History that survives a restart |
| `iasg_overrides` | **This console** | Instructions to the agent |

The gateway's counters only exist while the gateway is running. When they are absent —
seeded evidence, a replay — the metrics fall back to the visible event window and say so,
rather than reporting zero above a screen full of attacks.

## Accounts

There are none. The console runs open — no login, no accounts, no roles.
Whoever can reach http://localhost:5177 can use every control on it. See the
root [README](../README.md#reaching-the-console) for why, and for the warning
about not exposing this port to a network you don't trust.

`lib/auth.js` is a stub: `require()` always authorises, as a full admin, with
no session, regardless of the role a route handler asks for — routes still
call `requireRole("operator")` and similar, but the argument is currently a
statement of intent rather than an enforced check. The login system this
replaced (accounts, sessions, scrypt hashing, `viewer`/`operator`/`admin`
roles, `/login` and `/setup` pages) is in git history if it's ever wanted
back; the comment at the top of `lib/auth.js` says what to restore.

## Writing is instructing, not enforcing

Nothing here writes a policy key. Every action appends to `iasg_overrides`, and the
decision engine applies it on its next cycle **after** the same allowlist and collateral
checks its own decisions face. Two consequences worth knowing:

- The toast says *"applies next cycle"* because that is true, and the UI should not imply
  an address is already blocked.
- `monitor` stops future enforcement rather than clearing a block that is already
  standing; that expires on its own TTL. There is no release button, because the decision
  engine has no release operation.

The actor recorded against an override comes from the session, never from the request
body — an actor the caller can choose is not an audit trail.

## Running it

```bash
cd gateway-dashboard
npm install

export IASG_POSTGRES_URL=postgresql://iasg_user:changeme@localhost:5432/iasg
REDIS_HOST=127.0.0.1 npm run dev
```

| Variable | Default | For |
|---|---|---|
| `REDIS_HOST` / `REDIS_PORT` | `127.0.0.1` / `6379` | Everything live |
| `IASG_POSTGRES_URL` | — | Durable campaign and feedback history, and the adaptive-policy settings |

**Postgres is optional.** Without it (`lib/postgres.js`), the console simply
has no history to show — every live panel keeps working from Redis.

Under Compose both are set for you:

```bash
docker compose -f infra/docker-compose.yml up -d gateway_dashboard
```

For traffic to look at: `bash testing/signals/run_all.sh`, or seed the decision engine
directly with `python -m tools.seed_evidence --scenario mixed`.

## Layout

```text
app/
  (console)/        every page; layout.js used to be the login gate, now removed
    page.jsx        overview, adaptive/, campaigns/, events/, history/,
                     ip/[address]/, policy/, settings/, signals/
  api/               overview, adaptive/, campaigns/, events/, history/,
                     health, ip/[address], overrides, policies/[address], settings
  ui/
    store.jsx       one poller for the whole console, above the router
    chrome.jsx      header, nav, status line, toasts
    parts.jsx       cards, tables and action rows shared between pages
    icons.jsx       every icon the console uses, imported once
    format.js       pure helpers: labels, tones, filters
    export.js       CSV export of whatever's on screen
lib/
  redis.js  postgres.js  plane.js  adaptive.js  adaptive-mode.mjs
  telemetry.js  geo.js  auth.js (a stub -- see "Accounts" above)
```

Polling lives in `LiveProvider`, above the router, so moving between pages neither
restarts the clock nor blanks the screen, and Pause stops every page at once.

## One thing that leaves the machine

`lib/geo.js` calls `ip-api.com` over plain HTTP to place public addresses on the map. It
is cached, has a short timeout, and degrades to no marker — but it does send attacker IP
addresses to a third party, and looks up this host's own public IP for the "gateway site"
marker. With no internet the rest of the console is unaffected.
