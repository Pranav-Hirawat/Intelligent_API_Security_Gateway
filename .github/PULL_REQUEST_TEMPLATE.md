## Summary

<!-- What changes, and why it is needed. The reason is the part that cannot be
     recovered from the diff in six months. -->

## Test plan

<!-- What you actually ran, and what it said. Tick only what you did. -->

- [ ] `cd gateway && go test ./...`
- [ ] `cd decision-engine && .venv/bin/python -m pytest` (16 skip without Postgres)
- [ ] `cd gateway-dashboard && npm test`
- [ ] `mkdocs build --strict`
- [ ] Exercised the change in the running stack

## Documentation

- [ ] No documentation claims a count, command or behaviour this change makes wrong
- [ ] Or: the affected docs are updated in this pull request
