# IASG command reference

Commands below are for the local demo stack and assume PowerShell at the
repository root. Use `curl.exe` rather than PowerShell's `curl` alias when a
real curl invocation is needed. Do not point the attack plans at an external
or production API.

## Start and stop

```powershell
docker compose -f infra/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml ps
docker compose -f infra/docker-compose.yml logs -f gateway
docker compose -f infra/docker-compose.yml logs -f control_plane
docker compose -f infra/docker-compose.yml down
```

`down` keeps named volumes. `down -v` deletes Redis and both Postgres volumes,
including evidence, campaigns, policies, and demo data.

| Service | Address |
|---|---|
| Gateway | http://localhost:8082 |
| Vulnerable API | http://localhost:5002 |
| Vulnerable web | http://localhost:5175 |
| Dashboard | http://localhost:5177 |
| Docs | http://localhost:8000 |

The dashboard has no authentication. Keep port 5177 on a trusted local network.

## Inspect evidence and policy

```powershell
docker compose -f infra/docker-compose.yml exec redis redis-cli XLEN iasg:events
docker compose -f infra/docker-compose.yml exec redis redis-cli XREVRANGE iasg:events + - COUNT 20
docker compose -f infra/docker-compose.yml exec redis redis-cli KEYS 'policy:*'
docker compose -f infra/docker-compose.yml exec redis redis-cli GET policy:203.0.113.71
docker compose -f infra/docker-compose.yml exec redis redis-cli TTL policy:203.0.113.71
```

Resetting console history does not lift live policies. Use the dashboard's
**Policy** page to delete a single policy only when a fresh demo requires it.

## JMeter plans

The maintained plans are in `testing/jmeter/`; see
[testing/README.md](testing/README.md) for their functional-requirements map
and each plan's comments for its settings and reset prerequisites.

Run a plan from inside the Compose network when it must demonstrate policy
enforcement with its RFC 5737 `X-Forwarded-For` address:

```powershell
docker run --rm --network infra_default -v "${PWD}\testing\jmeter:/plans" -w /plans justb4/jmeter:5.6.3 `
  -n -t "4-SQL-Injection-Detection.jmx" -JHOST=gateway -JPORT=8082
```

Replace `infra_default` if `docker network ls` shows a different
`<project>_default` network. Useful entry points are:

- `4-SQL-Injection-Detection.jmx` — end-to-end evidence, correlation, policy, and `403` verification.
- `9-Control-plane campaign correlation.jmx` — coordinated three-IP reconnaissance.
- `11-Policy enforcement monitor throttle temporary block escalate.jmx` — operator-selected policy outcomes.
- `12-Adaptive rate limiting without attack signature.jmx` — valid-traffic adaptive throttling.
- `14-BOLA ownership and object-enumeration protection.jmx` — ownership protection and object enumeration.

For lightweight detector checks, use a Bash-capable shell:

```bash
bash testing/signals/run_all.sh
bash testing/signals/sqli.sh
bash testing/signals/traversal.sh
```

## Developer checks

```powershell
Push-Location gateway
go build ./...
go vet ./...
go test ./...
go test ./internal/signals/ -race
Pop-Location

Push-Location control-plane
$env:PYTHONPATH='.'
.venv\Scripts\python.exe -m pytest -q
Pop-Location

Push-Location gateway-dashboard
npm test
npm run build
Pop-Location

Push-Location vulnerable-app\backend
npm test
Pop-Location
```

The control-plane tests can write to a test Postgres database only when
`IASG_TEST_POSTGRES_URL` is configured; never point it at the live demo
database. See the component READMEs for local, non-Compose development and
environment configuration.
