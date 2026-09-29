# Policy Enforcement Module

The gateway enforces decisions made earlier. It does not consult the decision
engine while serving a request.

## Sources and precedence

The enforcer checks the decision-engine policy first and the gateway reflex
second. A decision-engine result wins, even if it is less severe: it has the
benefit of campaign correlation, safety checks, and operator input.

| Result | HTTP behavior |
| --- | --- |
| `monitor` / no policy | Forward the request. |
| `throttle` | Consume a shared token; return `429` and `Retry-After` when empty. |
| `temp_block`, `block`, `escalate` | Return `403` before body capture or detection. |

Policies can apply to an IP or to an IP plus route and method. The policy store
refreshes Redis keys in the background and request handlers read an atomic
local snapshot. A stale or failed refresh clears/ages out the snapshot rather
than adding network delay.

## Rate limiting

Throttle policy and optional baseline limiting use a Redis Lua token bucket
keyed by client IP, exact path, and method. It is shared across gateway
replicas. The operation has a short configured timeout, no retry, failure
backoff, and fail-open behavior; requests do not sleep while waiting to refill.

`enforcement.rate_limit.enforce` is separate from flood detection. Detection
reports a high rate; enabling baseline enforcement makes that configured rate a
limit for all non-exempt addresses.

## Expiry and safety

Every decision-engine policy has a TTL. No component renews it. The policy
writer rejects unsafe targets, including private/reserved addresses and
allowlisted ranges, and caps how many IPs one cycle can action. `--dry-run`
calculates decisions without writing keys.

The local reflex also uses expiry and configured exempt CIDRs. It is intended
only for selected high-confidence signals while the decision engine is still
forming a campaign.

## Relevant configuration

`enforcement.policy`, `enforcement.adaptive_rate_limit`,
`enforcement.rate_limit`, and `enforcement.block` in
`gateway/configs/config.yaml` control this module. The dashboard can change
the `enforcement` block at runtime through Redis; structural settings still
require restart.
