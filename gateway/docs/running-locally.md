# Running Locally

Start dependencies, then run the Go gateway:

```bash
docker compose -f infra/docker-compose.yml up -d redis postgres vulnerable_api
cd gateway
go run ./cmd/server
```

The default configuration is `configs/config.yaml`; the default listener is `:8082` and demo backend is `http://localhost:5002`.

| Variable | Purpose |
| --- | --- |
| `IASG_CONFIG` | Gateway YAML path. |
| `IASG_BACKEND_URL` | Backend URL. |
| `IASG_REDIS_HOST` | Redis host. |
| `IASG_JWT_SECRET` | JWT secret for ownership rules. |

Run the decision engine separately:

```bash
cd decision-engine
PYTHONPATH=. .venv/bin/python -m iasg --once
```

Before handing off Go changes, run `go build ./...`, `go vet ./...`, `go test ./...`, and `go test ./internal/signals/ -race`.
