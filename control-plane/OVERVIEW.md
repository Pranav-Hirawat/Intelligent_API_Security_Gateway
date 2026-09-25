# Control Plane Overview

The gateway sees requests; the control plane sees campaigns; the gateway never
waits on thinking. The gateway supplies bounded evidence through Redis, while
the control plane runs asynchronously and writes only time-limited policies.

## Presentation flow

1. Gateway detectors observe known attack shapes and publish evidence; they do
   not refuse the request they inspect.
2. The control plane builds complete, clean one-minute traffic windows and
   learns a stable normal rate for every endpoint.
3. Correlation groups coordinated IPs by shared traits and timing, then keeps
   campaigns connected when attackers return or rotate addresses.
4. Risk scoring combines gateway evidence, baseline deviation, and campaign
   facts into a monitor, throttle, or temporary-block recommendation.
5. Monitor mode records recommendations, manual mode requires an analyst, and
   automatic mode writes only guardrail-compliant temporary policies.

## Algorithm summary

| Algorithm | Main files | Purpose |
| --- | --- | --- |
| Rolling Median + MAD Baseline | `adaptive/baseline.py` | Learns normal endpoint traffic and identifies unusual request-rate spikes. |
| Weighted Risk Scoring with Guardrails | `adaptive/risk.py` | Combines evidence, traffic deviation, and campaign facts into a safe action. |
| Rule-Based Campaign Correlation with Union-Find Clustering | `correlation/features.py`, `cluster.py`, `agent.py` | Groups related IPs into campaigns and assigns confidence, stages, type, and severity. |
| Campaign Continuation Matching | `campaigns/repository.py` | Continues the same incident across cycles, including attacker IP rotation. |

The full pseudocode is in [README.md](README.md#algorithms-and-pseudocode).

## Safety points

- No deterministic gateway evidence means monitor only.
- Reputation cannot originate enforcement.
- Every gateway policy has a TTL and expires without renewal.
- Unsafe, private, reserved, and allowlisted targets are rejected before a
  policy is written.
- Explanation and assessment text are produced after policy selection and can
  never influence enforcement.
