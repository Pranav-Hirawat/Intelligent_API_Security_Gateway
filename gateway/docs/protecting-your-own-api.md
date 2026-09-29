# Protecting your own API

## Overview

Everything else in these docs runs the gateway in front of `vulnerable-app/`,
the deliberately insecure demo backend. This page puts it in front of an API
you run instead.

The gateway is a single-backend reverse proxy. Clients send requests to it; it
records and inspects each one, refuses what policy says to refuse, and
forwards the rest to one backend URL.

```text
client ──HTTPS──▶ your HTTPS proxy ──HTTP──▶ gateway :8082 ──HTTP──▶ your API
                  (nginx, Caddy, LB)          │
                                              ▼
                                   Redis ◀── decision engine ──▶ Postgres
                                     ▲
                                     └── console :5177 (loopback only)
```

Two files do the work:

| File | What it is |
| --- | --- |
| `infra/docker-compose.own-api.yml` | The gateway, decision engine, console, Redis and Postgres. No demo backend. |
| `gateway/configs/config.own-api.yaml` | A complete gateway config with the four site-specific sections marked `CHANGE ME`. |

The desktop app is not a way to do this. It runs a fixed demo stack: its
compose file points the gateway at the demo backend and is replaced on every
update.

## 1. Get the files

Download `docker-compose.own-api.yml` from the
[latest release](https://github.com/Pranav-Hirawat/Intelligent_API_Security_Gateway/releases/latest).
The release copy already names the image registry and version. Put a copy of
`gateway/configs/config.own-api.yaml` beside it, named `gateway.yaml`:

```text
iasg/
├── docker-compose.own-api.yml
└── gateway.yaml
```

To run from a checkout instead, use `infra/docker-compose.own-api.yml` and set
`IASG_VERSION` and `IASG_REGISTRY` to a published release.

## 2. Edit the four marked sections

Keep the rest of the file as it is. **A detector whose settings are missing
from the config is switched off, not given defaults**, so a trimmed-down file
detects less and says nothing about it. A test keeps the template's
`enforcement` block identical to `config.yaml.example`.

### Backend URL

```yaml
proxy:
  backend_url: "http://your-api:3000"
  preserve_host: false
```

`IASG_BACKEND_URL` overrides `backend_url` if it is set.

By default the backend receives **its own** hostname in `Host`, and the
client's hostname in `X-Forwarded-Host`. That is what a virtual host, a PaaS or
a CDN needs to find the site. Set `preserve_host: true` only if the backend
must see the public hostname in `Host` itself. The gateway always overwrites
`X-Forwarded-Host`, so a client cannot choose the hostname your backend puts in
the links it generates.

### Route templates

```yaml
routes:
  templates:
    - GET /health
    - POST /auth/login
    - GET /users/me
    - GET /users/{id}
```

List every endpoint your API serves, with `{name}` for a segment that varies.
The most specific template wins, whatever the order.

**This is not optional.** A path that matches no template is recorded as
`<unmatched>`, and `unknown_route_scanning` treats a client that requests 8
different unmatched paths within 5 minutes as a scanner. With the template's
example routes left in place, ordinary clients of your API look like attackers.

Templates are read at startup. Restart the gateway after changing them.

### Object endpoints

```yaml
routes:
  object_templates:
    - GET /users/{id}
    - GET /orders/{id}
```

List the endpoints that return one object belonging to someone. The
`object_enumeration` detector watches them for a client requesting many
different ids (BOLA / IDOR harvesting). Each entry must also be in
`routes.templates`, or the gateway refuses to start. Leave out public lookups
such as a product catalogue, where one client opening many ids is normal. The
detector sees the pattern, not ownership: the ownership check in your API is
still what stops the data leaking.

### Ownership checks

The gateway can also refuse the reads themselves, if it can verify your tokens
and your responses name the owner:

```yaml
routes:
  ownership:
    - template: GET /orders/{id}
      owner_field: userId          # dotted path into the response JSON
    - template: GET /orders
      list_field: .                # the body is an array; drop others' items
      owner_field: userId

identity:
  jwt:
    algorithm: HS256               # or RS256 with public_key_file
    secret_env: IASG_JWT_SECRET    # set it in infra/.env, never in this file
    user_claim: sub                # must equal owner_field's value
    bypass_claim: role
    bypass_values: [admin]
```

A response for someone else's object becomes `404` and never leaves the
gateway; a missing, expired or forged token is `401`. Each template must be in
`routes.templates` and be a `GET`, and the gateway will not start if the secret
or key cannot be loaded. Check three things first:

- **The ids must match as text.** `user_claim` in the token and `owner_field` in
  the response are compared as strings, so `7` and `"7"` match, but a token
  carrying an email will never match a numeric owner id.
- **Responses must be JSON and name the owner.** Otherwise they are refused
  (`enforcement.object_ownership.on_unverifiable: deny`). Set it to `allow` while
  you roll out, and watch the gateway log for `[ownership] cannot check`.
- **Writes are not covered.** A `PUT` or `DELETE` has already happened when its
  response arrives. Your API must still check ownership on writes.

### Login outcomes

```yaml
routes:
  auth_outcomes:
    - method: POST
      template: /auth/login
      success: [200]
      invalid_credentials: [401]
```

Brute-force detection counts a failed login only when a request matching this
template gets back a status listed under `invalid_credentials`. With no entry,
it never fires. Check what your API really returns for a wrong password: many
return 400 or 403, not 401. A status in neither list counts as unknown, not as
a success.

### Trusted proxies

```yaml
server:
  trusted_proxies:
    - 172.16.0.0/12
```

List the addresses of whatever forwards traffic to the gateway, so it believes
the `X-Forwarded-For` header they set. This decides which address gets blocked,
so getting it wrong fails in one of two ways:

| Mistake | What happens |
| --- | --- |
| Proxy not listed, proxy on a private network | Every request appears to come from the proxy. Private addresses are exempt from blocking, so **nothing is ever blocked**, and nothing says so. |
| Proxy not listed, proxy on a public address | Every request appears to come from the proxy, so **one block refuses every user**. |
| Range too wide | Any client can put someone else's address in the header and have them blocked. |

Leave it empty only if clients connect to the gateway directly. Step 5 shows how
to check which address the gateway actually sees.

See [Identifying the Client](client-ip.md) for how the header chain is read.

## 3. Start it

```bash
docker compose -f docker-compose.own-api.yml up -d
docker compose -f docker-compose.own-api.yml ps
```

The project is named `iasg-own-api`, so it never collides with the desktop
app's `iasg` stack on the same machine.

If `gateway.yaml` is missing, startup stops with
`bind source path does not exist`. Docker does not create an empty directory
in its place.

| Variable | Default | Purpose |
| --- | --- | --- |
| `IASG_GATEWAY_BIND` | `127.0.0.1` | Interface the gateway port listens on |
| `IASG_GATEWAY_PORT` | `8082` | Host port for the gateway |
| `IASG_GATEWAY_CONFIG` | `./gateway.yaml` | Path to the gateway config |
| `IASG_BACKEND_URL` | unset | Overrides `proxy.backend_url` |
| `POSTGRES_PASSWORD` | `changeme` | Set this for anything beyond a trial |

## 4. Route traffic through it

### Put HTTPS in front

The gateway speaks plain HTTP only. Something else has to terminate HTTPS and
forward to it. A minimal Caddyfile, with Caddy running on the same host:

```text
api.example.com {
    reverse_proxy 127.0.0.1:8082
}
```

Caddy obtains the certificate and sets `X-Forwarded-For`. With nginx, the
equivalent is `proxy_pass http://127.0.0.1:8082;` plus
`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`.

If the HTTPS proxy runs on another machine, set `IASG_GATEWAY_BIND=0.0.0.0` and
firewall port 8082 so only that machine can reach it.

### Close the way around it

The gateway only sees traffic that passes through it. If clients can still
reach your API directly (its own port, its IP address, an old DNS name), an
attacker simply goes around. Make the backend accept connections from the
gateway only: put both on one private Docker network, or firewall the
backend's port.

## 5. Check what the gateway sees

Send a request through the public hostname, then read the event the gateway
recorded:

```bash
curl -s https://api.example.com/health

docker compose -f docker-compose.own-api.yml exec redis \
  redis-cli --raw XREVRANGE iasg:events + - COUNT 1
```

Check two fields:

- **`ip`** should be your own public address. If it shows the proxy's address
  (often something in `172.16.0.0/12` behind Docker), fix `trusted_proxies`.
- **`routeTemplate`** should be the template you expect. `<unmatched>` for a
  real endpoint means the template list is missing it.

The console listens on loopback only. From your own machine:

```bash
ssh -L 5177:127.0.0.1:5177 you@your-server
# then open http://localhost:5177
```

## 6. Decide what may block

The template starts almost in detect-only mode:

| Setting | Template value | Effect |
| --- | --- | --- |
| `enforcement.block.signals` | `[api_flooding]` | The gateway blocks on its own only for floods above `min_score` |
| `enforcement.rate_limit.enforce` | `false` | Over-limit traffic is reported, not refused |
| `enforcement.policy.enabled` | `false` | Decision-engine decisions are recorded, not enforced |

Run it for a while and read the Events and Campaigns pages. Anything that fires
on legitimate traffic is a template, threshold or proxy setting to fix before
you let it act. Then enable policy enforcement from the console's Settings
page. Settings changes are stored in Redis, and **Revert to file** returns to
`gateway.yaml`. How decisions are made is covered in
[Policy Enforcement](policy-enforcement.md) and
[Adaptive Policy and Analyst Control](adaptive-policy.md).

## Known limits

- **No login on the console.** Anyone who reaches port 5177 can change what
  gets blocked. Keep it on loopback. See `SECURITY.md`.
- **One backend per gateway.** Routing by hostname or path to several services
  means one gateway per service, or a router behind the gateway.
- **No HTTPS in the gateway.** It has to sit behind a proxy that terminates it.
- **Adaptive baselines learn from the demo backend's traffic**, so reset and
  warm them before protecting a different API.
- **Detection signatures are generic.** The SQL injection and traversal
  patterns are short lists meant for the demo. Extend them for your API in
  `enforcement.attack_detection` and `enforcement.enumeration_path_traversal`.

## Code references

| Path | What it does |
| --- | --- |
| `infra/docker-compose.own-api.yml` | Stack without the demo backend |
| `gateway/configs/config.own-api.yaml` | Starting config with the site-specific sections marked |
| `gateway/internal/proxy/reverse_proxy.go` | Forwarding, `Host` rewrite and `X-Forwarded-Host` |
| `gateway/internal/proxy/reverse_proxy_test.go` | Host handling, including the forged-header case |
| `gateway/internal/config/config_test.go` | `TestOwnAPITemplateDetectsWhatTheExampleDetects` |
| `gateway/internal/signals/unknown_route_scanning.go` | Why unmatched routes matter |
| `gateway/internal/signals/brute_force.go` | How `auth_outcomes` feeds brute-force detection |
| `decision-engine/iasg/policy/writer.py` | Why private addresses are never blocked |
| `.github/workflows/release.yml` | Attaches the compose file to each release with registry and version filled in |
