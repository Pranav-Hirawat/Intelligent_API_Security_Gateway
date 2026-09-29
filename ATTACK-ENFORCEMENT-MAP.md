# Attack Detection and Enforcement Map

This is the quick project-level reference for which part of Intelligent API
Security Gateway acts on each supported attack. It reflects the current shipped
configuration in `gateway/configs/config.yaml`.

## Current enforcement map

| Attack / detector | Current automatic handling |
| --- | --- |
| API flooding | **Both.** High-confidence flood evidence can arm the gateway reflex; the decision engine can later write a policy. The baseline rate limiter does not refuse traffic by default. |
| Path traversal | **Both.** The matching request is observed and allowed; the gateway reflex returns `403` for later requests from that IP. The decision engine can also write a policy. |
| Sensitive-path enumeration / forced browsing | **Decision engine only.** Pure enumeration scores `50`, below the reflex minimum score of `80`. |
| SQL injection probing | **Decision engine only.** SQLi can form an immediate campaign, but it is not currently listed for the gateway reflex. |
| Brute force | **Decision engine only.** It may become a monitor, throttle, or temporary-block policy, subject to adaptive guardrails. |
| Password spraying | **Decision engine only.** It is a brute-force campaign classification, not a separate gateway detector. |
| Credential stuffing | **Decision engine only.** It is the multi-IP password-spraying classification, not a separate gateway detector. |
| Unknown-route scanning | **Decision engine only.** |
| Object-ID enumeration / BOLA harvesting | **Decision engine only.** |
| Unauthorized object access / BOLA ownership violation | **Both, but not through the reflex.** The gateway ownership guard immediately hides/refuses an unauthorised object with `404`; its evidence can also inform a decision-engine policy. |
| Known-bad IP reputation | **Context only by default.** It cannot create an automatic policy on its own. It may support a campaign with deterministic evidence, and can be explicitly added to the gateway reflex configuration if an operator chooses to do so. |

## Decision flow

```text
Gateway detector -> telemetry evidence -> decision-engine campaign/risk decision
                 -> expiring policy -> gateway enforcement

High-confidence flood/traversal evidence -> gateway reflex -> later request: 403
```

Decision-engine policy actions are:

- **Monitor**: observe only.
- **Throttle**: forwarded while a token remains; otherwise gateway `429`.
- **Temporary block**: gateway `403` while the policy TTL remains.

## Important notes

- The gateway reflex currently acts only for `api_flooding` and
  `enumeration_path_traversal`; its block duration is `300s`.
- The decision engine decides policy asynchronously. The gateway reads an
  in-memory snapshot, so normal request handling never waits for a decision
  engine or model response.
- `enumeration_path_traversal` is one canonical detector. Traversal-only has
  score `80`, pure sensitive-path enumeration has score `50`, and a request
  matching both scores `100`.
- Ownership protection is immediate gateway enforcement, but it is not a
  reflex. The current unauthorised object response is `404 Not found`.

For the full documentation-site version, see
[`gateway/docs/modules/enforcement-ownership.md`](gateway/docs/modules/enforcement-ownership.md).

