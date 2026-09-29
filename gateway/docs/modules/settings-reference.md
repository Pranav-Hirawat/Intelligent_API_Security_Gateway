# Dashboard and Adaptive Settings Reference

The dashboard has two different settings pages. They configure different modules and apply at different times.

| Page | Controls | Stored in | Takes effect |
| --- | --- | --- |
| **Protection** (`/settings`) | Gateway detectors, reflex, and policy consumption | Redis `iasg:settings` | When the gateway validates and applies it. |
| **Adaptive** (`/adaptive`) | Decision-engine baselines, risk, modes, and policy guardrails | Postgres adaptive settings | On the decision engine's next cycle. |

The dashboard has no authentication in this demo. Treat every visitor as an administrator and keep the console on a trusted network.

## Read this before changing thresholds

A smaller detection threshold creates more alerts. A lower risk or confidence threshold makes enforcement easier to reach. Neither change proves traffic is malicious, so start with observation, change one group at a time, and inspect events and recommendations before enabling automatic enforcement.

## Protection page: gateway settings

The page sends a complete `enforcement` override to Redis. The gateway validates it separately and publishes `iasg:settings:effective`. The page reads that effective value, so **Apply changes** means “requested” until the gateway accepts it. **Revert** removes the Redis override and restores the file configuration used at boot.

Only `enforcement` is live-editable. Backend URL, listener, trusted proxies, routes, ownership rules, JWT settings, policy refresh interval, and Redis connection settings require a configuration change and gateway restart.

### Main switches

| Setting | Meaning | Practical effect |
| --- | --- | --- |
| Gateway reflex: Enabled | Enables temporary local reflex decisions. | Only selected signals meeting the minimum score can affect a later request. |
| Policy decisions: Enabled | Enables decision-engine `policy:*` consumption. | Existing decision-engine blocks and throttles can be enforced. |
| Detector: On/Off | Enables an individual observation module. | Off means no evidence and no reflex effect from that module. |
| Auto-block | Adds an eligible signal to `block.signals`. | Allows the reflex to act after high-confidence evidence; not every signal is eligible. |

### Detector thresholds and limits

| Control | Meaning | Raise it when | Lower it when |
| --- | --- | --- | --- |
| API flooding — Requests per minute | Requests from one IP before flood evidence. | Legitimate users burst often. | You need earlier flood evidence. |
| API flooding — Refuse excess requests (429) | Enables a baseline limit for non-exempt addresses. | You only need detection. | You need a global emergency limit. |
| SQL injection — Signatures | Patterns searched in capped request input. | A pattern has false positives. | Known attack syntax is missing. |
| Failed logins — Consecutive failures | Invalid configured login responses needed for evidence. | Users often mistype passwords. | Brute-force attempts need earlier detection. |
| Failed logins — Window | Maximum gap between failures in one streak. | You only care about rapid attempts. | You need slower attack coverage. |
| Route scanning — Distinct paths / Window | Unique unmatched paths allowed per IP over time. | Clients legitimately probe unknown paths. | Reconnaissance needs earlier evidence. |
| Route scanning — Maximum clients / paths per client | Memory ceilings for retained scan state. | You need more concurrent coverage. | You need tighter memory limits. |
| Object enumeration — Distinct IDs / Window | Unique IDs on `routes.object_templates` before BOLA-harvesting evidence. | Users browse many objects normally. | ID walking needs earlier visibility. |
| Object enumeration — Maximum clients / IDs per client | Memory ceilings for enumeration state. | You need more concurrent coverage. | You need tighter memory limits. |
| Ownership — Refuse responses it cannot check | Chooses fail-closed (`deny`) or pass-through (`allow`) for unreadable responses. | Compatibility requires pass-through. | Data protection matters more than availability. |
| Ownership — Largest checked response | Maximum backend response buffered for ownership comparison. | Protected JSON is larger. | You need a lower response-memory ceiling. |
| Traversal / sensitive-path signatures | Patterns for traversal and forced-browsing evidence. | A pattern matches valid traffic. | A known path or encoding is missing. |
| Reputation — Signal score | Score contributed by a listed address. | Reputation should remain weak context. | An operator explicitly needs more weight from a trusted feed. |
| Reputation — Quiet period | Time before the same IP creates a fresh reputation event. | The feed would flood events. | You need more frequent evidence. |

Object enumeration shows a walking pattern; it is not proof that an object belongs to someone else. Ownership rules protect the configured reads.

### Advanced enforcement settings

| Setting | Meaning |
| --- | --- |
| Minimum auto-block score | The reflex needs a selected signal and at least this score. |
| Block duration | Lifetime of a reflex decision. It expires without renewal. |
| Never auto-block (CIDRs) | Addresses the reflex and baseline limiter must not refuse. |
| Enable policy throttling | Lets decision-engine throttle policy use the shared token bucket. |
| Fallback RPM / burst / Redis timeout | Read-only boot wiring: fallback is for legacy policy without a rate, burst is capacity, and timeout bounds the Redis quota call. |

`delay_ms` exists for compatibility but does not sleep a request. Current throttling uses a bounded shared token bucket and returns `429` when empty.

## Adaptive page: decision-engine settings

Adaptive settings are versioned. Saving creates a console override in the durable store, which the decision engine reads on its next cycle. A stale browser cannot overwrite a newer version. **Revert** restores validated file/boot configuration as a new version.

### Modes

| Mode | What the decision engine does |
| --- | --- |
| Monitor | Learns and records recommendations but writes no active policy. |
| Manual | Learns and creates recommendations that wait for analyst approval. |
| Automatic | Writes policy only when risk, evidence, confidence, simulation, and writer safety rails allow it. |

Explicit human overrides are recorded separately and may be enforced under declared safety rules.

### Baseline learning

The method and one-minute window are fixed. These settings control how much history is learned and how easily a rate looks unusual.

| Setting | Default | Meaning |
| --- | ---: | --- |
| Warm-up windows | 8 | Trusted minute samples required before a baseline can authorize behavioural throttling. |
| Rolling windows | 120 | Recent trusted samples retained for median/MAD calculation. |
| MAD multiplier | 3.0 | Extra variation allowed above the median; a larger value tolerates more variation. |
| Minimum MAD | 1.0 | Minimum assumed variation when traffic is very flat. |
| Minimum / maximum learned RPM | 5 / 600 | Hard lower and upper limits for a learned endpoint threshold. |
| Baseline hysteresis | 0.10 | Proportional change required before a learned threshold changes. |
| Threshold cooldown | 300 seconds | Minimum time between learned-threshold changes. |

The **Endpoint learning** table shows samples, observed RPM, median, MAD, and the resulting threshold. “Warming up” means that the threshold is visible but is not trusted for adaptive action.

### Risk and confidence

| Setting | Default | Meaning |
| --- | ---: | --- |
| Deterministic risk weight | 0.50 | Weight for gateway signal evidence. |
| Behavioural risk weight | 0.20 | Weight for endpoint baseline deviation. |
| Campaign risk weight | 0.30 | Weight for campaign confidence and severity. |
| Throttle risk score | 45 | Score that proposes throttle before guardrails. |
| Temporary-block risk score | 75 | Score that proposes temporary block before guardrails. |
| Detector points | Varies | Base severity of each signal before weights; reputation is supporting context. |
| Repeated-evidence increment | 5 | Extra deterministic score per distinct extra evidence item. |
| Severity multipliers | 0.50–1.00 | Adjust points for low, medium, and high severity. |
| Confidence weights | 0.55 / 0.45 | Split confidence between deterministic evidence and campaign confidence. |

The three risk weights must total 1.0. Risk scores are 0–100; confidence is 0–1.

### Policy guardrails

| Setting | Default | Meaning |
| --- | ---: | --- |
| Maximum automatic action | `temp_block` | Ceiling for automatic actions; can reduce automation to throttle or monitor. |
| Throttle / temporary-block confidence | 0.50 / 0.75 | Confidence required for each action to remain eligible. |
| Evidence required: throttle / temporary block | 1 / 2 | Minimum deterministic evidence items for each action. |
| Maximum policy duration | 1,800 seconds | Absolute upper limit for every policy TTL. |
| Monitor / throttle / temporary-block duration | 300 / 900 / 1,800 seconds | Requested lifetime for each action, capped by maximum duration. Monitor writes no active gateway key. |
| Minimum / default / maximum throttle RPM | 10 / 60 / 300 | Bounds the rate in a throttle policy. |
| Throttle baseline fraction | 0.50 | Fraction of a ready learned threshold used as the route throttle rate. |
| Behavioural throttle minimum deviation | 2.0 | Ready endpoint must exceed its threshold by this ratio before valid traffic can receive the opt-in throttle. It can never create a block. |
| Policy cooldown | 300 seconds | Prevents automatic replacement of a still-new active policy with a different action. |
| Analyst escalation confidence / clients / stages | 0.75 / 5 / 2 | Minimum campaign facts before analyst escalation. |
| Emergency allowlist | Empty | Named IPs/CIDRs receive `allow`; it wins if ranges overlap. |
| Emergency blocklist | Empty | Named IPs/CIDRs receive temporary block with operator precedence. |

The behavioural-throttle path is disabled by default. When enabled, it requires a ready baseline and can produce only a throttle; a statistical burst alone can never produce a block.

## Safe operating sequence

1. Start in **Monitor** mode and review events and endpoint baselines.
2. Tune detector thresholds for real traffic before selecting Auto-block.
3. Use **Manual** mode to review proposed policies and verify expiry.
4. Enable **Automatic** only after validating confidence, evidence, exemptions, and collateral-risk rules.
5. Change one category at a time and use the audit trail to compare intended and actual results.

See [Dashboard Module](dashboard.md), [Adaptive Policy](../adaptive-policy.md), and [Policy Enforcement](../policy-enforcement.md) for the surrounding flow.
