# Network-Level Blocking

The implemented gateway refuses at HTTP level: blocks return `403` and throttles return `429`. This page records why connection- and firewall-level blocking are not enabled.

| Layer | What it knows | Trade-off |
| --- | --- | --- |
| HTTP (implemented) | Resolved client IP, route, policy, telemetry context | Preserves visibility and correct proxy attribution. |
| Connection | Direct TCP peer only | Unsafe behind a load balancer or trusted proxy. |
| Firewall | Packet addresses only | Loses application context and needs host privileges. |

When `trusted_proxies` is configured, the TCP peer is usually the proxy, not the caller. Blocking it at connection level would block every user behind that proxy. HTTP-level enforcement reads the trusted forwarded address and still emits refusal telemetry.

Keep HTTP-level enforcement as the default. A future direct-connect-only connection feature would need to reject proxy configurations, retain expiry, and add explicit observability before it could be safe.
