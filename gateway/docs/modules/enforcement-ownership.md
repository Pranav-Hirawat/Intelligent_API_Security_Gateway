# Enforcement and Ownership Modules

## Enforcement

The decision-engine policy source is consulted before the gateway reflex. The gateway applies blocks and throttles before body capture and detection. This means refused traffic is cheap while telemetry still records the decision.

The reflex does not decide a campaign. It observes configured high-confidence evidence after a request completes, then creates a temporary local decision for later requests. Expiry and exempt CIDRs protect against persistent mistakes.

## Demo enforcement categories

The eight focused JMeter demonstrations are grouped by the component that takes
the immediate security action. A reflex hit can still later become a
decision-engine campaign and expiring policy.

| Category | Count | Attacks |
| --- | ---: | --- |
| Gateway reflex | 2 | API Flooding, Path Traversal |
| Decision engine | 4 | Object-ID Enumeration, Brute Force, SQL Injection, Unknown Route Scanning |
| Both | 1 | Ownership Check / BOLA — gateway ownership guard immediately returns `404`; decision engine can later create policy |
| Others | 1 | Known Bad Address — reputation context only; no direct enforcement |

## BOLA / IDOR ownership guard

For each configured read route, the guard verifies the caller's JWT, holds the bounded backend JSON response, compares the caller claim with the configured owner field, returns `404` for a foreign single object or removes foreign list entries, and emits ownership evidence.

Missing/expired tokens return `401`. A forged token and an owner mismatch are high-confidence evidence. If a response cannot be checked, `object_ownership.on_unverifiable` selects fail-closed (`deny`, default) or pass-through (`allow`).

This guard cannot undo a write that the backend already accepted. Keep authorization in the backend as the primary control.
