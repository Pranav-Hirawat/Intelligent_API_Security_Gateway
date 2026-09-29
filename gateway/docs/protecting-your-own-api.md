# Protecting Your Own API

Place the gateway at the public HTTP entry point and keep your application behind it. Start in observation mode, validate routes and evidence, then enable enforcement deliberately.

## 1. Point at the backend

```yaml
proxy:
  backend_url: "http://your-api:5000"
  preserve_host: false
```

Use `IASG_BACKEND_URL` for container-specific backend addresses.

## 2. Describe routes and login outcomes

Add normalized routes under `routes.templates`. They drive telemetry, brute-force checks, object enumeration, and route-scoped policies. Add `auth_outcomes` only where you have verified status meanings.

```yaml
routes:
  templates:
    - POST /api/login
    - GET /api/orders/{id}
  auth_outcomes:
    - method: POST
      template: /api/login
      success: [200]
      invalid_credentials: [401]
```

## 3. Attribute clients safely

Add only real ingress/load-balancer CIDRs to `server.trusted_proxies`. Never trust forwarded headers from arbitrary callers. See [Client IP Module](client-ip.md).

## 4. Add optional ownership protection

For read endpoints that return user-owned JSON, configure `routes.ownership` and verified JWT credentials. The gateway compares the token subject to the configured owner field, returns `404` for another user's object, and filters foreign list entries. Continue enforcing ownership in the application, especially for writes.

## 5. Roll out

Keep decision-engine policy and baseline-rate enforcement disabled while validating telemetry. Enable policy consumption, confirm expiry, and enable global baseline limits only when exemptions are correct.
