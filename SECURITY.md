# Security policy

## `vulnerable-app/` is insecure on purpose

Before reporting anything, check whether it concerns `vulnerable-app/`.

That directory is a deliberately vulnerable target. It exists so the gateway
has something real to defend, and so the detectors can be demonstrated against
genuine attacks rather than simulated ones. Among other things it stores
passwords in plain text, interpolates them straight into SQL, applies no rate
limiting, and serves endpoints that leak files.

**None of that is a vulnerability to report. It is the exhibit.** The same goes
for the demo routes referenced in `commands.md` and `testing/`.

## The console has no authentication

`gateway-dashboard` runs open — no login, no accounts, no roles. `lib/auth.js`
is a stub that authorises every caller as an admin; the route handlers still
call `requireRole(...)`, but the argument is a statement of intent rather than
an enforced check.

This is known and deliberate for a local demonstration. It is also why the
packaged stack publishes its ports on `127.0.0.1` only. Do not expose port 5177
to a network you do not trust.

## What is worth reporting

Anything where the gateway itself fails to do what it claims:

- A detector that can be bypassed by a request it should catch.
- A way past the enforcement rails — the deterministic-evidence requirement,
  the policy TTL ceiling, the allowlist, the per-cycle write cap.
- A path where the decision engine can write a policy the gateway should refuse.
- Anything in `gateway/`, `decision-engine/`, `gateway-dashboard/` or `desktop/`
  that leaks data or grants access beyond what the documentation describes.
- Something in the release pipeline that would ship a compromised artifact.

## How to report

This is a private university project, so raise it with the team directly rather
than opening a public advisory: open an issue on this repository, or contact a
maintainer listed in the repository's contributor list.

Include what you did, what happened, and what you expected. A failing request —
the method, path, headers and body — is worth more than a description of one.

## Scope

Only this repository. The dependencies it pulls (Next.js, Go modules, Python
packages, the Docker base images) should be reported upstream to their own
maintainers.

One thing that genuinely leaves the machine, so it is not a surprise if you
find it: `gateway-dashboard/lib/geo.js` sends public IP addresses to `ip-api.com`
over plain HTTP to place markers on the map. It is cached, times out quickly,
and degrades to no marker — but it does send attacker addresses to a third
party, and looks up this host's own public address.
