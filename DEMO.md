# Live demo: JMeter and the Gateway Dashboard

Use only the local, deliberately vulnerable demo stack. The JMeter plans create
real traffic; the dashboard is where to inspect evidence, campaigns, policies,
and enforcement.

## Before the demo

Start the stack from the repository root and open the dashboard:

```powershell
docker compose -f infra/docker-compose.yml up -d
```

Open http://localhost:5177. Use **Settings → Reset console** to clear old
evidence and campaigns. Reset deliberately preserves `policy:*`; remove a
reused policy on **Policy**, or use the documentation addresses already assigned
to a fresh plan run.

For policy enforcement on Docker Desktop, run JMeter inside the Compose network.
The gateway then receives traffic from its configured trusted bridge and can
honour each plan's `X-Forwarded-For` address.

```powershell
docker run --rm --network infra_default -v "${PWD}\testing\jmeter:/plans" -w /plans justb4/jmeter:5.6.3 `
  -n -t "4-SQL-Injection-Detection.jmx" -JHOST=gateway -JPORT=8082
```

If the Compose project uses a different network name, replace `infra_default`
with the `<project>_default` network shown by `docker network ls`.

## A complete incident in five minutes

Run `4-SQL-Injection-Detection.jmx` with the command above. It compares the
unsafe and parameterized product-search routes, has three documentation IPs
generate SQLi evidence, waits for correlation and policy refresh, then asserts
that each affected address receives `403`.

While its policy wait is running, show the dashboard in this order:

1. **Events** — filter for SQL injection and the three `203.0.113.7x` addresses.
2. **Campaigns** — open the correlated campaign and its explanation.
3. **Policy** — show the active, expiring decisions.
4. **JMeter Summary Report** — show the final `403` assertions.

The key message is: detectors create evidence during a request; the control
plane decides later; the gateway enforces the cached decision without waiting
for the control plane or a model.

## Other maintained plans

All maintained plans live directly in `testing/jmeter/`; their comments state
the reset, settings, and expected-response prerequisites.

| Plan | Demonstrates |
|---|---|
| `1-Gateway forwarding, response capture, and telemetry.jmx` | Forwarding, client identity, and telemetry. |
| `2- Request-size protection.jmx` | Normal login and a gateway `413` body-size rejection. |
| `3A-Brute-force detection.jmx`; `3B-Password Spraying detection.jmx` | Credential-attack evidence and throttle behaviour. |
| `5-Enumeration and path-traversal detection.jmx` | Bounded traversal/enumeration evidence and the reflex response. |
| `6-Unknown-route scanning.jmx` | Advisory unknown-route evidence and correlation. |
| `7-Immediate gateway reflex for API flooding.jmx`; `8-Gateway reflex allowlist and exemption settings.jmx` | Flood reflex and its exemption setting. |
| `9-Control-plane campaign correlation.jmx` | Three-IP reconnaissance correlation. |
| `10-Monitor manual and automatic modes.jmx`; `11-Policy enforcement monitor throttle temporary block escalate.jmx` | Operator modes, approval, and policy outcomes. |
| `12-Adaptive rate limiting without attack signature.jmx` | A valid-traffic adaptive throttle; it requires the documented adaptive settings. |
| `14-BOLA ownership and object-enumeration protection.jmx` | BOLA ownership protection, object enumeration, and direct-backend comparison. |

## Close and recover

**Reset console** clears demo evidence and history but not an active policy.
Delete a single policy on **Policy** if a fresh run needs its address, or let
the policy TTL expire. Do not demonstrate policies using localhost or private
addresses: the policy writer rejects them by design.
