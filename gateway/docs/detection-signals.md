# Detection Signals Module

Signals are deterministic gateway observations. A signal adds evidence to a
telemetry event; it does not block the request that produced it.

| Signal | Looks for | Important detail |
| --- | --- | --- |
| API flooding | Excess requests from one address | Can arm the gateway reflex. |
| SQL injection | Configured SQL-like patterns | Reads only a capped body. |
| Traversal / forced browsing | Traversal and sensitive-path patterns | Traversal can arm the reflex. |
| Brute force | Consecutive configured invalid-login outcomes | Uses declared route/status rules. |
| Unknown-route scan | Many unmatched paths | Not simply backend `404` responses. |
| Object enumeration | Many IDs on declared object routes | Pattern evidence, not ownership proof. |
| Ownership violation | Caller does not own returned object | The guard also hides the data. |
| IP reputation | Address appears in a local/optional feed | Supporting context with a cooldown. |

Each signal includes a name, score, threshold flag, attack type, and details.
Request-scoped evidence uses a request ID, preventing old evidence from being
attached to a later request.

Tune detection under `enforcement` in `gateway/configs/config.yaml`. Define
route templates, authentication outcomes, object routes, and ownership rules
under `routes`.

```bash
bash testing/signals/run_all.sh
```

The signal scripts prove detection without directly authorizing a detector to
refuse a request.
