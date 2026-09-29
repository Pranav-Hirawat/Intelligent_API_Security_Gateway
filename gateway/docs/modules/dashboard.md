# Dashboard Module

The Next.js console at `http://localhost:5177` is an operations view over Redis and optional Postgres history.

| Page | Purpose |
| --- | --- |
| Overview | Current traffic, service health, and recent activity. |
| Events and Signals | Request evidence and detector activity. |
| Campaigns and History | Correlated incidents and durable records. |
| Policy | Active route-scoped policy and remaining TTL. |
| Adaptive | Baselines, recommendations, modes, and approvals. |
| Settings | Live `enforcement` configuration. |
| IP detail | Evidence, campaigns, and policy for one address. |

Dashboard writes are instructions, not direct enforcement. Supported settings are watched by the gateway; overrides go to `iasg_overrides` and are processed by the decision engine next cycle under the same safety rails as its own actions.

The current console has no authentication: `lib/auth.js` authorizes every visitor as an admin. Treat it as a trusted local/admin-only service.
