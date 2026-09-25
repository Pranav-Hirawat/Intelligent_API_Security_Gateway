# Infra — everything at once

One Compose file brings up the whole system: the gateway, the agent, the target it
protects, the console, and the two stores they share.

```bash
docker compose -f infra/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml logs -f control_plane
```

## Services

| Service | Port | What it is |
|---|---|---|
| `gateway` | 8082 | Go reverse proxy — the data plane |
| `control_plane` | — | Python agent, no HTTP port. Correlates and decides |
| `vulnerable_api` | 5002 | The deliberately insecure API being protected |
| `vulnerable_web` | 5175 | Its front end |
| `gateway_dashboard` | 5177 | Next.js operations console |
| `postgres` | 5434 | Durable campaign memory, feedback, and dashboard settings |
| `vulnerable_postgres` | 5435 | The vulnerable app's own database, kept separate |
| `redis` | 6379 | Evidence stream, policy keys, telemetry |
| `docs` | 8000 | MkDocs site |
| `ports_info` | — | Prints the port map and exits |
| `ollama` | — | Local LLM for narration. Opt-in (`--profile llm`), internal-only, CPU-only in Docker |
| `ollama_pull` | — | One-shot: makes sure the narration model is downloaded, then exits |

`ports_info` runs once and stops. Compose reporting it as exited is expected.
So does `ollama_pull`, once the model is in place.

## The two databases

They are deliberately separate. `postgres` holds what the security system knows;
`vulnerable_postgres` holds the target application's data. An SQL injection demo that
reached the security system's own campaign history would be a very different demo from the
one intended.

## Persistence

Both databases and Redis use named volumes, and Redis runs with `--appendonly yes`, so a
`docker compose down` and back up keeps campaigns, accounts and evidence.

`docker compose down -v` removes the volumes and everything in them, including campaign
history, feedback, adaptive settings, and database-backed dashboard state.

## Narration

The control plane can write incident prose with a local LLM. It's off by default — a
plain `docker compose up` downloads and runs nothing extra. To turn it on:

```bash
docker compose -f infra/docker-compose.yml --profile llm up -d
```

That starts `ollama` and runs `ollama_pull`, which downloads `llama3.2` (~2GB) the
first time and is a fast no-op after. Then set `IASG_LLM_PROVIDER=ollama` in
`infra/.env` (see [`.env.example`](.env.example)) and recreate `control_plane`.

It's CPU-only here — Docker Desktop can't pass an Apple Silicon GPU to a Linux
container — so it's noticeably slower than a native `brew install ollama`. Either way,
narration is advisory: a slow or unreachable model degrades to an offline template,
never blocks a decision.

## Configuration

Every service has a working default. Override by putting an `.env` beside the Compose file:

```bash
POSTGRES_USER=iasg_user
POSTGRES_PASSWORD=change-me-before-anyone-else-uses-this
POSTGRES_DB=iasg

VULN_POSTGRES_USER=vuln_user
VULN_POSTGRES_PASSWORD=vuln_changeme
VULN_POSTGRES_DB=vuln_app

IASG_JWT_SECRET=change-me-before-anyone-else-uses-this
```

Compose passes the security-system database credentials to `control_plane`
and `gateway_dashboard` as `IASG_POSTGRES_URL`. The vulnerable database
values go only to `vulnerable_api`; `IASG_JWT_SECRET` is shared by that API
and `gateway` for the ownership demonstration.

The control plane's own settings are documented in
[`../control-plane/.env.example`](../control-plane/.env.example) and read from the
environment, so add them to the `control_plane` service rather than copying that file.

## Ordering

`gateway` and `control_plane` wait for Redis and Postgres to pass their health checks
before starting, so a cold `up` does not race the stores. The gateway does not wait for
the control plane, and never should — that independence is the point of the split, and
Compose is where it would be easiest to accidentally undo.

## Stopping

```bash
docker compose -f infra/docker-compose.yml down      # keeps the data
docker compose -f infra/docker-compose.yml down -v   # deletes it
```
