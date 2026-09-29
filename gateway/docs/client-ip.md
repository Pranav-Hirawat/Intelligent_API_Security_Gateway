# Client IP Module

Every detector, campaign, and policy needs the same client address. The gateway
resolves it once and stores it in request context.

## Trust rule

The gateway accepts `X-Forwarded-For` only when the direct TCP peer is inside
`server.trusted_proxies`. Otherwise it uses the peer address. This stops a
direct caller from attaching attack evidence to a victim by spoofing a header.

```yaml
server:
  trusted_proxies:
    - 10.0.0.0/8
    - 172.16.0.0/12
```

For a proxy chain, it reads the header from right to left, skipping trusted
proxies and taking the first untrusted address.

| Deployment | Configuration |
| --- | --- |
| Direct clients | Leave `trusted_proxies` empty. |
| Load balancer or ingress | Add only its actual CIDR(s). |
| Docker demo | Use a configured trusted proxy and documentation IPs. |

The decision engine refuses to create policy for loopback, private,
link-local, and reserved addresses. Use `203.0.113.x` when demonstrating the
complete policy loop.
