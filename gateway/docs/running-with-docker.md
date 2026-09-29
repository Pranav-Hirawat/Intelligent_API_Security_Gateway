# Running with Docker

```bash
docker compose -f infra/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml logs -f gateway decision_engine
```

| Service | Host port | Purpose |
| --- | --- | --- |
| `gateway` | 8082 | Protected API entry point. |
| `vulnerable_api` | 5002 | Demo backend. |
| `vulnerable_web` | 5175 | Demo frontend. |
| `gateway_dashboard` | 5177 | Operations console. |
| `redis` | 6379 | Live hand-off and policy store. |
| `postgres` | 5434 | Security-system history. |
| `docs` | 8000 | MkDocs site. |

The decision engine has no HTTP port. The gateway does not wait for it.

## Optional narration

```bash
docker compose -f infra/docker-compose.yml --profile llm up -d
```

Set `IASG_LLM_PROVIDER=ollama` in `infra/.env` and recreate `decision_engine`. Model failures fall back to templates and cannot change policy.

`docker compose -f infra/docker-compose.yml down` keeps volumes. `down -v` deletes Redis and database data. To clear demo traffic while preserving consumer groups, use the dashboard reset endpoint rather than deleting `iasg:events`.
