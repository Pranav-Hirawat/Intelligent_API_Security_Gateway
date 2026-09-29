# Running with Docker

## Overview

`infra/docker-compose.yml` runs the whole system — both lanes, both databases,
the protected backend, the dashboard, and this documentation site.

```bash
docker compose -f infra/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml ps
docker compose -f infra/docker-compose.yml logs -f gateway
```

The first start is slow: it pulls roughly 1.5 GB of images and then runs
`npm ci` three times, `pip install` twice, and a Go module download inside the
containers. Several minutes of apparent silence is normal.

## Ports

| Service | URL | Notes |
| --- | --- | --- |
| Gateway API | <http://localhost:8082> | The proxy itself |
| Vulnerable API | <http://localhost:5002> | The protected backend |
| Gateway Dashboard | <http://localhost:5177> | Next.js console |
| Vulnerable Web | <http://localhost:5175> | Demo front end |
| Documentation | <http://localhost:8000> | This site |
| Postgres (gateway) | `localhost:5434` | Campaigns, feedback, dashboard users |
| Postgres (vuln API) | `localhost:5435` | Backend's own data |
| Redis | `localhost:6379` | Evidence, policy, overrides |
| Decision engine | — | No HTTP port; it is a worker |

The `ports_info` service prints this map on every `up`.

## Credentials

`infra/.env` is optional. Without it the defaults apply
(`iasg_user` / `changeme`, `vuln_user` / `vuln_changeme`). Create the file to
override them; Compose reads it automatically.

## Schema and first run

Nothing needs migrating. `campaigns` and `feedback` are created with `CREATE
TABLE IF NOT EXISTS` at startup by the decision engine. A fresh volume is a
working system.

The console has no accounts and no login. Whoever can reach port 5177 is
treated as an operator, which is worth knowing before exposing it: that page
can disable enforcement and clear the record. See `gateway-dashboard/lib/auth.js`.

## Port conflicts

The most common failure is a port already held by something running natively:

```
Error response from daemon: ports are not available:
exposing port TCP 0.0.0.0:5002 -> ...: bind: address already in use
```

Because `gateway` → `gateway_dashboard` → `vulnerable_web` all depend on
`vulnerable_api`, a single conflict on 5002 leaves four services stuck in
`Created` while the rest of the stack comes up — a half-running system that is
easy to mistake for a working one. Check with:

```bash
docker compose -f infra/docker-compose.yml ps -a
lsof -nP -iTCP:5002 -sTCP:LISTEN
```

A locally installed Redis (for example `brew services start redis`) will
conflict on 6379 in the same way.

!!! warning "Client IPs on Docker Desktop"
    Docker Desktop's port forwarder does not preserve the source address of
    traffic that arrives from the host. Every request from your machine reaches
    the gateway as a single, and frequently nonsensical, address.

    Container-to-container traffic is unaffected and reports the real peer.

    This matters because per-IP detection, campaign correlation, and policy all
    key on the client address — driven from the host, every attacker collapses
    into one IP and the multi-address demo cannot reproduce. Drive attack
    traffic from inside the Compose network instead:

    ```bash
    docker run --rm --network infra_default curlimages/curl:latest \
      curl -s -o /dev/null -w '%{http_code}\n' \
      -X POST http://gateway:8082/api/login \
      -H 'Content-Type: application/json' \
      -d '{"email":"admin","password":"wrong"}'
    ```

    Alternatively, add the Compose subnet to `server.trusted_proxies` and send
    `X-Forwarded-For` — see [Identifying the Client](client-ip.md) for why the
    header is only believed from a listed proxy.

## Verifying the stack end to end

```bash
# 1. Detection -- expect 401s from the backend, never a 429 from the gateway
docker run --rm --network infra_default curlimages/curl:latest sh -c \
  'for i in $(seq 1 12); do curl -s -o /dev/null -w "%{http_code} " \
   -X POST http://gateway:8082/api/login -H "Content-Type: application/json" \
   -d "{\"email\":\"admin\",\"password\":\"wrong$i\"}"; done'

# 2. The gateway saw it
docker compose -f infra/docker-compose.yml logs gateway | grep "BRUTE FORCE"

# 3. Telemetry landed
redis-cli HGETALL iasg:stats
redis-cli XLEN iasg:events

# 4. The decision engine turned it into a campaign
docker compose -f infra/docker-compose.yml logs decision_engine | tail
docker compose -f infra/docker-compose.yml exec postgres \
  psql -U iasg_user -d iasg -c 'SELECT campaign_id, type, severity, event_count FROM campaigns;'
```

## Rebuilding and resetting

```bash
# Restart one service after a config change
docker compose -f infra/docker-compose.yml up -d --force-recreate decision_engine

# Throw away all state, including databases
docker compose -f infra/docker-compose.yml down -v
```

`down -v` deletes the named volumes, which means campaigns, agent feedback and
backend data all go. The next `up` starts from an empty system.

## Code references

| Path | Role |
| --- | --- |
| `infra/docker-compose.yml` | Service definitions, ports, environment |
| `infra/README.md` | Port table and service notes |
| `gateway/configs/config.yaml` | Gateway configuration, mounted into the container |
| `gateway/docs/requirements.txt` | Documentation toolchain installed by the `docs` service |
