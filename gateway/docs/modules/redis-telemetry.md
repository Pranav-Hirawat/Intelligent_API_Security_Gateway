# Redis and Telemetry Module

Telemetry has three distinct streams:

| Key | Written when | Used by |
| --- | --- | --- |
| `iasg:arrivals` | Before request execution | Traffic windows and adaptive baselines. |
| `iasg:events` | When request handling completes | Dashboard, evidence consumer, campaigns. |
| `iasg:telemetry:health` | Periodically | Telemetry health monitoring. |

Completion events include resolved IP, method, path, route template, response status, decision outcome, detector evidence, redacted snippet, and backend timing. Writers use bounded queues; when Redis is slow or unavailable, events may be dropped instead of delaying requests.

Redis also carries policy keys, settings, overrides, campaigns, alerts, and heartbeat data. Do not use `DEL` on `iasg:events`: it deletes its consumer groups. Use `XTRIM MAXLEN 0` or the dashboard reset function to clear stream contents safely.
