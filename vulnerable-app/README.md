# Vulnerable app — the target

A deliberately insecure API and a small front end for it. It exists only so the gateway has a safe, local target to detect.

> **Do not deploy this anywhere.** The intentionally unsafe routes are isolated to demo tables with fictional data and must only run on a machine you control.

## Endpoints

| Method | Path | What it does |
|---|---|---|
| `POST` | `/api/login` | Parameterized login; it remains the brute-force demo target. |
| `GET` | `/api/products` | Successful product-list endpoint for the flood demo. |
| `GET` | `/api/products/search?q=<query>` | Intentionally vulnerable product search for the SQLi demo only. |
| `GET` | `/api/products/search-secure?q=<query>` | Parameterized comparison route. |
| `GET` | `/backup-demo`, `/config-demo`, `/.env-demo` | Harmless planted resources for forced-browsing enumeration. |
| `GET` | `/api/demo-files?file=<relative-path>` | Deliberately permissive, but filesystem-bounded traversal demonstration. |
| `GET` | `/api/orders` | The caller's own orders. |
| `POST` | `/api/orders` | Places an order under the caller's own id (checkout). |
| `GET` | `/api/orders/:id` | Intentionally vulnerable to BOLA / IDOR: returns any customer's order. |
| `GET` | `/api/orders-secure/:id` | Ownership-checked comparison route: someone else's order is `404`. |

## SQL injection demo

There are no runtime authentication modes and no `/api/set-mode` endpoint. Login always uses a parameterized query, which keeps its failed-login behavior predictable for the brute-force demo. The only intentional SQL injection surface is `/api/products/search`.

Normal input returns the matching demo products:

```bash
curl 'http://localhost:5002/api/products/search?q=keyboard'
```

The direct SQLi demonstration makes the database-only consequence visible:

```bash
curl -G 'http://localhost:5002/api/products/search' \
  --data-urlencode "q=' OR 1=1 --"
```

The unsafe `WHERE name ILIKE '%<input>%'` query is changed by the payload and returns the demo catalogue. No secrets, host files, or command execution are exposed. The optional `search-secure` route retains the same input as a parameter and does not change its query semantics.

Repeat the same payload through IASG to create telemetry evidence:

```bash
curl -G 'http://localhost:8082/api/products/search' \
  --data-urlencode "q=' OR 1=1 --"
```

The detector records SQL Injection evidence and forwards the request. Open **Dashboard → IP address → SQL injection evidence** to see the timestamp, endpoint, matched patterns, risk, request ID, HTTP result, and separate gateway decision. Detection is not a claim that the request was blocked; later control-plane policy may throttle or block it.

## Running it

Through Compose, with the gateway in front of it:

```bash
docker compose -f infra/docker-compose.yml up -d
```

| | URL |
|---|---|
| Direct (unprotected) | http://localhost:5002 |
| Through the gateway | http://localhost:8082 |
| Front end | http://localhost:5175 |

Standalone, for working on the app itself:

```bash
cd vulnerable-app/backend && npm install && npm start
cd vulnerable-app && npm install && npm run dev
```

For the SQLi story, use :5002 first to demonstrate the isolated vulnerable endpoint, then repeat the exact request through :8082. Direct traffic intentionally bypasses the gateway; only traffic through :8082 appears in telemetry and the dashboard.

## Tests

```bash
cd vulnerable-app/backend && npm test
cd gateway && go test ./...
```

The shared scripts can also drive a running gateway:

```bash
bash testing/signals/sqli.sh
```

## Other direct-backend demonstrations

`GET /api/products` is a normal successful endpoint, so a direct burst to
`:5002` reaches the application unrestricted. `POST /api/login` intentionally
has no native IP lockout: repeated invalid attempts and attempts against the
seeded demo usernames are normal `401` responses for brute-force and
password-spraying demonstrations.

The planted forced-browsing resources return explicit harmless markers, not
configuration or secrets:

```bash
curl 'http://localhost:5002/.env-demo'
```

The bounded traversal route deliberately resolves relative paths inside
`backend/demo-files` only. This demonstrates a relative-path mistake without
ever exposing container or host files:

```bash
curl -G 'http://localhost:5002/api/demo-files' \
  --data-urlencode 'file=public/../fake-secret.txt'
```

It can return the static `fake-secret.txt` fixture, but a path that resolves
outside `demo-files` is rejected. Use the same requests through `:8082` to
produce traversal/enumeration evidence in IASG.

The signal scripts exercise every direct-demo counterpart through IASG:

```bash
bash testing/signals/sqli.sh
bash testing/signals/flood.sh
bash testing/signals/traversal.sh
bash testing/signals/brute_force.sh
```

## BOLA (object-level authorization) demo

`/api/orders/:id` verifies the caller's token and never checks that the order
is theirs. The SQL is parameterized: this is an authorization bug, not an
injection one. The 40 seeded orders are fictional, and owners are interleaved,
so counting through ids reaches other customers.

### In the storefront

The storefront (`http://localhost:5175`) has a Backend / Gateway switch in the
navbar -- it decides which of the two URLs below every API call goes to, so
the leak and the block can both be shown from the same page:

1. Sign in as Jane Cooper using the credentials in [USERS.md](USERS.md).
   Switch to **Gateway**.
2. Open **My Orders**. Jane owns 1, 6, 11, 16, 21, 26, 31, 36. Open one --
   it's hers.
3. Edit the address bar to `/orders/2`. Through the gateway: "Order not
   found".
4. Switch to **Backend** and reload `/orders/2`. The same URL now shows
   Arjun Mehta's name, address and items -- the vulnerable route, unguarded.
5. Switch back to **Gateway**, add something to the cart and check out. The
   new order is created for real (`POST /api/orders`) and immediately shows
   up in My Orders under its own id.

`POST /api/login` returns a signed HS256 JWT (`auth-token.js`, one hour,
`sub` = user id, `role`). The secret is `IASG_JWT_SECRET`, shared with the
gateway; without it both fall back to the same public demo value.

```bash
TOKEN=$(curl -s http://localhost:5002/api/login -H 'Content-Type: application/json' \
  -d '{"email":"<email from USERS.md>","password":"<password from USERS.md>"}' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

curl -s http://localhost:5002/api/orders -H "Authorization: Bearer $TOKEN"        # her orders
curl -s http://localhost:5002/api/orders/2 -H "Authorization: Bearer $TOKEN"      # someone else's: 200
curl -s http://localhost:5002/api/orders-secure/2 -H "Authorization: Bearer $TOKEN"  # 404
```

Through IASG (port 8082) the same request is refused. The gateway's
`routes.ownership` rule verifies the token, reads `order.userId` from the
backend's answer, and replaces someone else's order with `404` before any of it
is sent. The application still has the bug -- port 5002 still leaks -- which is
the point: the gateway covers the read the developer forgot to protect.

```bash
curl -s http://localhost:8082/api/orders/2 -H "Authorization: Bearer $TOKEN"      # 404 from the gateway
curl -s http://localhost:8082/api/orders/2 -H "Authorization: Bearer $(printf 2 | base64)"  # forged: 401

BACKEND_URL=http://localhost:5002 bash testing/signals/ownership.sh
ATTACK_IP=203.0.113.81 bash testing/signals/object_enumeration.sh
```

`ownership.sh` passes only if no other customer's order comes back through the
gateway. Counting through ids still records `object_enumeration` evidence at 20
distinct ids -- now almost all refused, which scores higher. Neither covers
writes: a `PUT` or `DELETE` on someone else's order needs the check that
`orders-secure` has, in the application.
