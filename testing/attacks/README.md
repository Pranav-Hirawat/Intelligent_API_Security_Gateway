# Attack test plans

The eight JMeter plans in this folder exercise the gateway through distinct
RFC 5737 documentation addresses. They run against the repository defaults;
none require a dashboard or gateway settings change. They have not been run as
part of creating this folder.

## Run each plan

1. Start the existing IASG stack and confirm `http://127.0.0.1:8082/api/health`
   returns `200`.
2. Use a clean policy state for the documentation IPs named in the plan's
   comments. Resetting dashboard history does **not** remove `policy:*` keys.
3. Open one `.jmx` plan in JMeter and run it once. Each plan waits 50 seconds
   for the control-plane cycle and policy snapshot refresh.
4. Read the plan's final `RESULT` sampler and verify the Events, Campaigns,
   Policies, and (for escalation) Alerts dashboard views.

Throttle counts assume the default 60 RPM policy with a burst of 20. The
follow-up burst therefore usually permits about 20 requests and returns about
5 `429` responses. A changed policy rate or burst changes those two numbers.

The separate Adaptive Rate Limiting (ARL) test is the only exception: it
requires its documented baseline-learning settings. It is not one of these
eight attack plans.

| # | File | Attack summary | Steps performed by the plan | Expected output: requests -> allowed / throttled / temp_blocked or escalated | Policies made |
|---:|---|---|---|---|---|
| 1 | `01-SQLi.jmx` | SQL injection | Three fixed-source IPs each send two valid SQLi probes as one campaign (six `200` responses), wait, verify two telemetry records per IP, then check all three same-endpoint policies. | `9 -> 6 / 0 / 3 (403)` | `3 temporary_block` |
| 2 | `02-Brute-Force.jmx` | Brute force | Three IPs each send six invalid logins, wait, then send 25 follow-ups. | `43 -> about 38 / about 5 / 0` | `3 throttle` |
| 3 | `03-API-Flooding.jmx` | API flooding | Three IPs each send 101 requests (over the detector threshold but below reflex level), wait, then send 25 follow-ups. | `328 -> about 323 / about 5 / 0` | `3 throttle` |
| 4 | `04-Enumeration-and-Path-Traversal.jmx` | Enumeration and path traversal | Three bounded traversal/enumeration probes, wait, then one follow-up. The local reflex can arm immediately. | `4 -> 3 / 0 / 1 (403)` | `3 temporary_block` |
| 5 | `05-Unknown-Route-Scanning.jmx` | Unknown-route scanning | Five IPs each scan eight unknown paths, wait, then send 25 follow-ups. | `65 -> about 60 / about 5 / 0 gateway blocks; 1 escalation alert` | `5 throttle` |
| 6 | `06-Known-Bad-Addresses.jmx` | Known bad address | Uses listed demo address `203.0.113.66` with a confirmed SQLi probe, wait, then sends 25 follow-ups. Reputation alone intentionally cannot enforce. | `26 -> about 21 / about 5 / 0` | `1 throttle` |
| 7 | `07-Ownership-Check.jmx` | Ownership check | Jane reads three known foreign orders, which must be gateway-refused as `404`, waits, then sends 25 follow-ups. | `29 -> about 21 / about 5 / 0; plus 3 ownership-refused (404)` | `1 throttle` |
| 8 | `08-Object-ID-Enumeration-BOLA.jmx` | Object-ID enumeration (BOLA) | Jane walks order IDs 1–30, crossing the 20-ID enumeration threshold, waits, then sends 25 follow-ups. | `56 -> about 27 / about 5 / 0; about 24 foreign-order refusals (404)` | `1 throttle` |

## Policy coverage

- **Throttle:** plans 2, 3, 5, 6, 7, and 8.
- **Temporary block:** plans 1 and 4.
- **Escalate:** plan 5 creates an escalation alert because it is a confident
  five-client campaign. Escalation is intentionally an analyst alert, not a
  fourth automatic gateway-block policy; the bounded enforced policies remain
  throttles.
