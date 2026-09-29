# Network-level blocking

Enforcement today happens at the HTTP layer. A blocked address gets `403`, a
throttled one gets `429`, and both are written by
[`policy.Enforcer`](https://github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/blob/main/gateway/internal/policy/middleware.go)
after the request has been parsed, routed and attributed to a client.

The obvious question is whether we should refuse lower down — close the TCP
connection, or drop the packet at a firewall — so a known attacker never reaches
the Go handler at all. It sounds strictly better. It is not, and the reason is
specific to how this gateway decides who a client is.

This page records that reasoning. **Nothing here is implemented**; it exists so
the decision is on the record before someone writes a listener wrapper.

---

## Three layers, one decision

| Layer | Where refusal happens | What the attacker sees | What we still learn |
|---|---|---|---|
| **L7 — today** | Go middleware, after parse and attribution | `403` with `Retry-After` | Everything: full telemetry record |
| **L4** | `Accept()`, before any HTTP is read | Connection closed or reset | Almost nothing |
| **L3** | Firewall, before the process | Timeout | Nothing |

Going down the table buys efficiency and costs visibility. The whole question is
whether that trade is worth making, and for which traffic.

---

## Why L4 is not free: the trust boundary

The gateway does not learn who the client is from the TCP connection. It learns
it from `X-Forwarded-For`, and only when the connection came from an address in
`trusted_proxies` — see
[Identifying the client](client-ip.md) for why the header cannot be believed
otherwise.

That resolution happens in `Resolver.Resolve`, which needs `*http.Request`. It
cannot run until the headers have been read.

> **At `Accept()` the gateway knows the peer address and nothing else.**

Which gives two deployments with opposite answers:

- **Clients connect directly** (`trusted_proxies` empty). The peer *is* the
  client. L4 blocking is sound.
- **Anything in front** — load balancer, CDN, ingress, or Docker's own NAT. The
  peer is the proxy. Refusing by peer refuses *everyone behind it, at once*.

The second case is not hypothetical here. Under Compose, host traffic commonly
arrives through Docker's NAT address rather than its original client address.

So any implementation would have to carry a hard rule:

> Connection-level blocking may be enabled **only** when `trusted_proxies` is
> empty, and a gateway configured with both must refuse to start — not quietly
> pick one.

That refusal-over-degradation shape already exists in the codebase. `PolicyWriter`
rejects a decision with no expiry rather than writing a permanent block, and
skips any address that is not public, because the failure mode of guessing is
worse than the failure mode of stopping.

---

## What it would buy

For every flood request the gateway currently does: parse the request
line and headers, resolve the client, match a route template, write an arrival
record, run the enforcer, write a completion record. Refusing at accept skips all
of it.

That is a real saving. It is also the best possible case for L4 — a single
address sending 20 requests a second. The saving on a low-and-slow attacker
sending one request every eight seconds rounds to nothing.

---

## What it costs: the observability hole

This is the argument that should decide it.

The middleware chain is built outermost-first as:

```
resolver → telemetry recorder → logging → enforcer → detectors
```

**Telemetry sits outside the enforcer.** So a request that gets `403` today is
still fully recorded: an arrival record when it came in, a completion record
carrying the `403` and its timing. The block is visible in the data.

Refusing at L4 happens *outside* that chain entirely. A dropped connection
produces no arrival and no completion, which has three consequences:

1. **Adaptive baselines lose trustworthy observations.** No records means the
   address simply stops existing for the minute.

2. **A blocked window becomes indistinguishable from a quiet one.** Silence is
   what an idle user looks like, so the decision engine cannot learn whether the
   traffic stopped because of enforcement or because the client left.

3. **The campaign stops being re-scored.** The decision engine reasons over the
   evidence stream. Cut the evidence and a campaign freezes at whatever it last
   believed, so the block's expiry becomes the only thing that can end it —
   there is no longer any input that could argue for releasing it early.

Point 3 is the subtle one. L7 blocking is self-correcting because a blocked
attacker keeps generating evidence about themselves. L4 blocking is not.

---

## Sketch, if it were built

Kept here so the shape is agreed rather than improvised:

- A `net.Listener` wrapper whose `Accept()` consults the same decision source the
  middleware uses, closing denied connections and looping rather than returning
  them.
- The same exempt CIDRs as the reflex blocker. One list, one meaning — the
  trusted-proxy list, both exempt ranges and the reputation feed already parse
  through `netutil.ParseCIDRs` for exactly this reason.
- A **refused-connection counter**, exported. Drops must not be invisible; the
  point of the section above is that they otherwise are.
- Expiry-only, matching the existing rule that enforcement releases itself.
  Nothing renews an L4 refusal either.
- Off by default, and refusing to start alongside a non-empty `trusted_proxies`.

---

## Why not the firewall

L3 was considered and is not recommended for this project:

- It needs `NET_ADMIN` and root. The `gateway` service has neither — it runs an
  unprivileged `golang:alpine` container publishing a port on a bridge network.
- It is Linux-only. On Docker Desktop the containers live inside a VM, so rules
  written on the host would not sit where anyone expects, and the demo would stop
  resembling production rather than start resembling it.
- **Reversibility.** This is the decisive one. A Redis policy key releases itself
  when it expires; that is the property the whole enforcement design leans on. A
  firewall rule does not expire, and a wrong one can lock out the operator
  alongside the attacker.

---

## Recommendation

**Keep L7 as the default.** It is self-correcting, fully observable, and its
worst failure costs one wrong `403` that expires on its own.

**Treat L4 as an opt-in for direct-connect deployments only** — off by default,
refusing to start behind a proxy, and justified by sustained high-rate floods
rather than by attacks in general.

---

## Where the code lives

| Concern | File |
|---|---|
| `403` / `429` refusal | `internal/policy/middleware.go` — `deny`, `rateLimited` |
| Enforcement decision switch | `internal/policy/middleware.go` — `Enforcer.Middleware` |
| Client attribution | `internal/netutil/ip.go` — `Resolver.Resolve`, `ClientIP` |
| Chain order | `internal/proxy/server.go` |
| In-memory reflex blocks | `internal/enforcement/reflex.go` |
| Policy safety rails | `decision-engine/iasg/policy/writer.py` — `PolicyWriter.write` |

## Related

- [Identifying the client](client-ip.md) — why the header is not proof
- [Policy enforcement](policy-enforcement.md) — the policy contract and expiry
