# Reverse Proxy Module

The gateway wraps Go's reverse proxy and adds security middleware around it.
Once a request is admitted, it forwards to `proxy.backend_url` and adds
`X-Gateway: IASG`.

## Forwarding behavior

- `proxy.preserve_host: false` uses the backend host, which is the safe default
  for virtual hosts and hosted services. The original host remains available in
  `X-Forwarded-Host`.
- `proxy.timeout`, `max_idle_conns`, and `max_conns_per_host` bound backend
  connections.
- Backend errors are proxy failures, not detector decisions.
- Gateway-created responses (policy, ownership, and body-size refusals) receive
  the configured gateway CORS headers. Backend responses keep the backend's CORS policy.

## Body handling

`BodyLimitMiddleware` is above every body reader. `server.max_body_bytes` may
raise or lower the cap, but cannot remove it. This protects telemetry capture
and request-body signal matching from unbounded buffering.

## Health

The liveness handler is outside the normal chain. It is not forwarded, counted,
or inspected, so an upstream or Redis problem does not make it call the rest of
the system.
