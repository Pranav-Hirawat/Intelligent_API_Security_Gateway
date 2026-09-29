# Attack test plans

The eight JMeter plans in this folder exercise the gateway through distinct
RFC 5737 documentation addresses. They run against the repository defaults;
none require a dashboard or gateway settings change. All eight were run end
to end against the source-mounted stack on 29 September 2026, with the results
in the table below.

## Run each plan

1. Start the stack and confirm `http://127.0.0.1:8082/api/health` returns `200`.
2. Start from a clean state for the plan's addresses (named in each plan's
   comments):
   - `POST /api/admin/reset` with `{"confirm":"reset"}`;
   - delete their `policy:*` keys, because resetting history deliberately keeps
     live policy.
3. Run one plan and wait about a minute. Each plan waits 50 seconds for the
   decision-engine cycle and the gateway's policy refresh.
4. Read the final `RESULT` sampler, then check the Events, Campaigns, Policy
   and (for plan 05) Alerts views.

**Where to run JMeter from.** The plans set `X-Forwarded-For` to their
documentation address, and the gateway only believes that header from a
trusted proxy. With `infra/docker-compose.yml` on Docker Desktop, traffic from
the Mac arrives as `192.168.65.1`, which is not trusted. Every plan's requests
then share one private address, and no policy is written because private
addresses are never policed. Run JMeter from inside the compose network
instead, for example:

```bash
docker run --rm --network infra_default \
  -v "$JMETER_HOME":/jmeter:ro -v "$PWD/testing/attacks":/plans:ro \
  eclipse-temurin:21-jre /jmeter/bin/jmeter -n -t /plans/01-SQLi.jmx \
  -JHOST=gateway -JPORT=8082 -JDASHBOARD_HOST=gateway_dashboard
```

`HOST`, `PORT`, `DASHBOARD_HOST` (plan 01 only) and `POLICY_WAIT_MS` are
JMeter properties, so `-J` sets them. The defaults, `localhost:8082`, suit the
desktop app's stack, which receives Mac traffic from a trusted address.

**What `RESULT` checks.** It counts what the follow-up requests actually got
back. It fails when the refusal the plan exists to prove never happened: a
`403` for the block plans (01 and 04), a `429` for the others. The policies it
names are the expected ones. Confirm them in Redis
(`redis-cli --scan --pattern 'policy:*'`) or on the Policy page.

**Throttle counts** assume the default 60 requests-per-minute policy with a
burst of 20, so a burst of 25 follow-ups gets 20 through and 5 `429`s.

**Follow-ups hit the attacked endpoint.** An engine throttle may be scoped to
the endpoint that was attacked (`POST /api/login`, `GET /api/orders/{id}`,
`GET /api/products/search`) once that endpoint has a learned baseline. A
follow-up elsewhere would sit outside the policy and never be throttled, so
each plan repeats its target.

## Results

| # | File | Attack | What the plan does | Follow-up responses | Policies made | Events "Action" column |
|---:|---|---|---|---|---|---|
| 1 | `01-SQLi.jmx` | SQL injection | Three IPs each send two SQLi probes (six `200`s), verify telemetry, wait, re-probe. | `3 x 403` | `3 temporary_block` | Temporary block |
| 2 | `02-Brute-Force.jmx` | Brute force | Three IPs each send six invalid logins, wait, then 25 more invalid logins. | `20 x 401`, `5 x 429` | `3 throttle` | Throttle, then Rate limited |
| 3 | `03-API-Flooding.jmx` | API flooding | Three IPs each send 101 requests (over the detector, under the reflex), wait, then 25 follow-ups. | `20 x 200`, `5 x 429` | `3 throttle` | Throttle, then Rate limited |
| 4 | `04-Enumeration-and-Path-Traversal.jmx` | Enumeration and path traversal | Three IPs each send one traversal probe, which arms the gateway reflex, wait, then one follow-up. | `1 x 403` | `3 throttle` | Temporary block (from the reflex) |
| 5 | `05-Unknown-Route-Scanning.jmx` | Unknown-route scanning | Five IPs each scan eight unknown paths, wait, then 25 follow-ups. | `20 x 404`, `5 x 429` | `5 throttle` + 1 escalation alert | Throttle, then Rate limited |
| 6 | `06-Known-Bad-Addresses.jmx` | Known bad address | Listed address `203.0.113.66` sends one SQLi probe, wait, then 25 searches. Reputation alone cannot enforce. | `20 x 200`, `5 x 429` | `1 throttle` | Throttle, then Rate limited |
| 7 | `07-Ownership-Check.jmx` | Ownership check | Jane reads three orders that are not hers (refused `404`), wait, then reads her own order 25 times. | `20 x 200`, `5 x 429` | `1 throttle` | Refused: not the owner; Throttle; Rate limited |
| 8 | `08-Object-ID-Enumeration-BOLA.jmx` | Object-ID enumeration (BOLA) | Jane walks order IDs 1–30 (24 refused `404`), wait, then reads her own order 25 times. | `20 x 200`, `5 x 429` | `1 throttle` | Refused: not the owner; Throttle; Rate limited |

## Notes

- **Plan 04 is blocked by the gateway, not the engine.** The reflex refuses an
  address before the detectors run, so the engine sees one probe per address.
  One probe is below the two needed for a temporary block, so the engine writes
  a throttle. The more restrictive action wins, so the reflex's five-minute
  block still stands.
- **Plan 05 escalates.** It is a confident five-client campaign, so it raises
  one analyst alert in `iasg_alerts`. Escalation is an alert, not a fourth
  gateway-block policy; the enforced policies stay throttles.
- **Ownership refusals** are the gateway answering for the backend. Their
  event has `gatewayReason: ownership_refused` and origin `gateway`, and shows
  as "Refused: not the owner", not "Allow".

The separate Adaptive Rate Limiting (ARL) test is the one plan here that needs
settings changes: its documented baseline-learning settings. It is not one of
these eight attack plans.
