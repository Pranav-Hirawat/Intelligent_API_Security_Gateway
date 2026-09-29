# Who is the client? (and why we got it wrong)

Everything the gateway does depends on knowing **which machine sent a request**.
Detectors count per machine. The decision engine groups machines into campaigns.
Enforcement blocks a machine. Get that one value wrong and all three are wrong
together.

This page explains a bug we had, why it mattered more once we could block
traffic, and how it works now.

---

## The bug, in one picture

Real deployments put a **load balancer** in front of the gateway. Every request
goes to the balancer first, and the balancer passes it on.

```
                   ┌──────────────┐
 Alice   ────────▶ │              │
 Bob     ────────▶ │   balancer   │ ────────▶  gateway
 Attacker────────▶ │              │
                   └──────────────┘
```

The gateway used the address of whoever opened the network connection. But by
that point, the machine opening the connection is **always the balancer**.

So the gateway saw:

| Who really sent it | What the gateway recorded |
|---|---|
| Alice | balancer |
| Bob | balancer |
| Attacker | balancer |

### The mailroom analogy

Imagine analysing survey responses where every envelope is stamped by your
university mailroom instead of the sender. Group by address and you conclude
*one address sent 10,000 responses*. That is not a finding — it is the wrong
grouping key.

---

## Why it went from "wrong" to "dangerous"

While the detectors only **logged**, this was bad data.

Once the decision engine could write a block, it became an outage:

1. Detectors report thousands of attacks, all labelled *balancer*
2. Decision engine concludes the balancer is a serious threat
3. Enforcement blocks the balancer
4. **Every user's traffic now gets a 403** — we took ourselves offline

The system would have confidently attacked itself.

---

## The fix

There is a standard header, `X-Forwarded-For`, where the balancer writes the
real visitor's address — the mailroom noting the original sender on the
envelope before passing it along.

The gateway now reads that instead.

```
X-Forwarded-For: 203.0.113.5      ← the real visitor
RemoteAddr:      10.0.0.7         ← the balancer
```

---

## The catch: the header is not proof

**Anyone can set that header.** It is not verified by anything. An attacker can
attach any address they like to their own request.

If we simply believed it, an attacker could:

- **frame someone else** — send attacks labelled with a classmate's address and
  get *them* blocked
- **escape their own block** — claim a new address on every request

So we do not simply believe it.

> **The rule:** the header is believed **only** when the request arrived from a
> machine we have explicitly listed as one of our own proxies. From anyone else,
> the header is ignored and we use the connection address.

It is the same instinct you already have about data sources. You trust your own
database. You do not trust a CSV a stranger emailed you, even if the columns
look identical.

### How to switch it on

In `configs/config.yaml`:

```yaml
server:
  trusted_proxies: []        # default: trust nobody
    # - 127.0.0.1/32         # local testing
    # - 10.0.0.0/8           # your load balancer's subnet
```

**Empty is the default and it is the safe one.** With nothing listed, the
gateway behaves exactly as it always did. You have to opt in.

### Chains of proxies

With more than one proxy the header holds a list, oldest first:

```
X-Forwarded-For: 203.0.113.5, 10.0.0.9, 10.0.0.8
                 ↑ the client   ↑ proxies we trust
```

We read it **right to left**, skipping addresses we recognise as our own
proxies, and take the first one we do not recognise.

Why right to left? Because the rightmost entry was written by *our* proxy, so we
know it is genuine. Anything further left was copied along from whatever the
caller sent, and the caller may have made it up.

This is what defeats framing. If an attacker sends
`X-Forwarded-For: <victim>`, our proxy appends the attacker's real address on
the right:

```
X-Forwarded-For: <victim>, <attacker's real address>
                                    ↑ we take this one
```

---

## What this unlocked

There was a second, quieter consequence.

The decision engine refuses to block private or local addresses — sensible,
otherwise it could block your own laptop. But when testing locally, every
request looked like `127.0.0.1`, which is exactly the kind of address it
refuses. So **no block was ever issued from real traffic.** The two halves of
the project had never actually worked together end to end.

With the client IP fixed, the full loop runs:

```
6 clients flood the gateway through a trusted proxy
      ↓
detected as 6 separate addresses        (before: 1)
      ↓
decision engine groups them: "Distributed Flood", confidence 1.00
      ↓
6 block decisions written
      ↓
gateway returns 403 to those 6 — and lets everyone else through
```

---

## Where the code lives

| File | Role |
|---|---|
| `internal/netutil/ip.go` | works out the real address; holds the trust rule |
| `internal/proxy/server.go` | runs it first, before anything reads an address |
| `internal/config/config.go` | the `trusted_proxies` setting |

It runs **once per request**, at the very front, and stores the answer. Every
detector and the enforcer then read that same value, so they cannot disagree
about who the caller is.

---

## Things this page does not fix

One known gap is deliberately left alone:

- **Detectors log but never block.** That is the team's decision, not an
  oversight. Blocking happens only through the decision engine.
