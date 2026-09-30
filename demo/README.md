# IASG attack and adaptive-rate-limit demo

This folder contains the eight JMeter plans needed to demonstrate the supported
attack detections and adaptive rate limiting against the local, deliberately
vulnerable stack. The files are copies of the maintained plans in
`testing/jmeter`; update the original plan first if a test needs maintenance.

## Before every run

1. Start the local stack:

   ```powershell
   docker compose -f infra/docker-compose.yml up -d
   ```
2. Open the dashboard at [http://localhost:5177](http://localhost:5177). Reset the console, then
   delete any active policy for the plan's test IP. Resetting preserves policies.
3. Run JMeter in the Compose network for policy-enforcement plans, so the
   gateway safely honours their `X-Forwarded-For` documentation addresses:

   ```powershell
   docker run --rm --network infra_default -v "${PWD}\demo:/plans" -w /plans justb4/jmeter:5.6.3 `
     -n -t "4-SQL-Injection-Detection.jmx" -JHOST=gateway -JPORT=8082
   ```

   Replace the plan name as needed. If your Compose network is not
   `infra_default`, use the name shown by `docker network ls`.

## Demo plans

| Demonstration                                    | JMeter plan                                                | Expected result                                                                                                                                                                            | Required setting state                                                                                                                                                | Decision and enforcement path                                                                                                                                             |
| ------------------------------------------------ | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Object-ID enumeration and ownership check (BOLA) | `1-BOLA ownership and object-enumeration protection.jmx` | Foreign orders are hidden with`404`; a forged token gets `401`; the direct-backend comparison exposes the intentional BOLA bug. Later policy traffic is `429` or `403`.            | Defaults enable ownership and object enumeration. Use a new attacker IP. For policy proof: Adaptive Automatic, policy decisions and throttling enabled.               | Object-ID diversity/denial/sequential-run scoring; JWT and response-owner check; campaign risk, guardrails and policy safety simulation; Redis token bucket for throttle. |
| Brute force                                      | `2-Brute-force throttle token-bucket proof.jmx`          | 14 failed logins create evidence; post-policy bursts demonstrate`429` throttling and bounded refill. Default 60 RPM / burst 20 produces roughly 20 pass + 10 limited in the first burst. | Fresh documentation IP, no existing policy, Adaptive Automatic, policy enforcement enabled, Redis healthy.                                                            | Consecutive failed-login streak per IP, route and target; risk/guardrails; policy simulation; atomic Redis Lua token bucket.                                              |
| SQL injection                                    | `3-SQL-Injection-Detection.jmx`                          | Compares vulnerable and parameterized routes, then creates three SQLi attack identities. Each should receive`403` after the decision-engine wait.                                        | SQL signatures enabled; Adaptive Automatic; policy decisions enabled; clear policies for`203.0.113.71` through `.73`.                                             | Capped-input SQL signature matching; multi-IP campaign clustering and confidence; weighted risk; expiring block policy.                                                   |
| API flooding                                     | `4-Immediate gateway reflex for API flooding.jmx`        | 200 rapid requests initially return`200`; request 201 returns `403` from the five-minute gateway reflex.                                                                               | Adaptive Monitor; flood detector and reflex enabled;`api_flooding` selected for auto-block; score floor at most 80; rate-limit enforcement off; test IP not exempt. | Per-IP sliding-window request count. At twice the default 100-RPM threshold the signal reaches score 80 and arms the local reflex.                                        |
| Enumeration and path traversal                   | `5-Enumeration and path-traversal detection.jmx`         | Harmless planted probes return`200`; a traversal hit arms the reflex and later requests return `403`.                                                                                  | Default traversal detector/reflex settings work. Test IP must not be exempt; clear old reflex/policy state.                                                           | Traversal and sensitive-path signature matching; high-confidence traversal (score 80) activates the gateway reflex; decision engine may correlate it later.               |
| Unknown-route scanning                           | `6-Unknown-route scanning.jmx`                           | Twelve unmatched paths return`404`; evidence begins at the eighth unique path and a solo Reconnaissance campaign can appear.                                                             | Adaptive Monitor, so it remains a clean evidence/correlation demonstration. Default threshold: eight distinct paths in five minutes.                                  | Counts unique unmatched raw paths, rather than generic backend`404`s; campaign classification is advisory only. No gateway reflex.                                      |
| Known-bad address                                | `7-Known-bad-address-reputation-proof.jmx`               | Listed`203.0.113.66` and a control IP both return `200`; only the listed IP creates one reputation event, with no duplicate inside cooldown.                                           | Reputation enabled; no old policy/reflex block; do not add`ip_reputation` to auto-block signals; static limiter must not reject these requests.                     | Local reputation-feed lookup and five-minute cooldown. Reputation supplies supporting context only and cannot originate enforcement.                                      |
| Adaptive rate limiting                           | `8-Adaptive rate limiting without attack signature.jmx`  | Valid product requests build a one-window baseline, a valid burst gets a dynamic throttle, and the final request returns`429` with `Retry-After`.                                      | Clear`203.0.113.120` policy; Adaptive Automatic; policy decisions/throttling on; behavioural throttles on; Warm-up windows = 1; disarm or exempt the flood reflex.  | Trusted completed windows; rolling median/MAD baseline; behavioural-risk guardrail; policy simulation; Redis token bucket. Behaviour alone can throttle, never block.     |

## What not to use for adaptive rate limiting

`13-Global baseline limiter test.jmx` intentionally demonstrates the static
global `429` limiter. It is not an adaptive-learning demonstration and is not
included here.

## Configuration references

- Gateway detector, reflex, ownership, reputation, and policy defaults:
  `gateway/configs/config.yaml`
- Adaptive baseline, risk and policy guardrails:
  `decision-engine/configs/adaptive.json.example`
- All deterministic procedures and their source locations:
  `gateway/docs/modules/algorithms.md`
