# Contributing

This is a university project built by a small team. These notes exist so that
work lands the same way each time, not to add ceremony.

## The shape of the repository

Four things run, and they are deliberately independent:

| Directory | What it is | Language |
|---|---|---|
| `gateway/` | The data plane. Handles every request, must stay fast. | Go |
| `decision-engine/` | The agent. Correlates evidence, decides policy. Never touches a live request. | Python |
| `gateway-dashboard/` | The operations console. | Next.js |
| `desktop/` | Electron launcher that runs the packaged stack. | JavaScript |

`vulnerable-app/` is the target used for demonstrations. It is insecure **on
purpose** — see [SECURITY.md](SECURITY.md) before reporting anything about it.

## Running it

```bash
docker compose -f infra/docker-compose.yml up -d
```

The dashboard is then at http://localhost:5177. `gateway/docs/running-locally.md`
covers running each piece outside Compose.

## Before opening a pull request

Run whatever covers the part you touched. All of it, if you are unsure:

```bash
# Go gateway
cd gateway && go test ./...

# Python decision engine  (16 tests skip without Postgres, which is expected)
cd decision-engine && .venv/bin/python -m pytest

# Dashboard
cd gateway-dashboard && npm test

# Documentation — catches broken cross-references
mkdocs build --strict
```

## How changes land

Everything goes through a pull request against `main`, including small fixes.
Branch names follow `fix/…`, `feat/…` or `docs/…`.

Two things are worth knowing because they have caught people out:

- **Documentation is treated as code.** A count, a command or a claim that no
  longer matches the source is a defect, not cosmetic. If your change makes a
  doc wrong, fix the doc in the same pull request.
- **Configuration is validated, not clamped.** `AdaptiveConfig` rejects unknown
  keys and out-of-range values rather than quietly correcting them, and the
  dashboard mirrors those bounds. Adding a field means changing both.

## Writing commit messages

Say why the change is needed, not only what it does. The reason a value moved
or a guard exists is the part that cannot be recovered from the diff later.

## Cutting a release

Pushing a `v*` tag builds five Docker images, both desktop installers, and
attaches `infra/docker-compose.release.yml` to a GitHub release:

```bash
git tag v0.1.3 main
git push origin v0.1.3
```

The release stays a draft until every job succeeds, because the desktop app
reads `releases/latest` and that ignores drafts — so it can never see half of a
release. Use a **new** version each time; re-pushing an existing tag does not
trigger the workflow. `desktop/README.md` has the details.
