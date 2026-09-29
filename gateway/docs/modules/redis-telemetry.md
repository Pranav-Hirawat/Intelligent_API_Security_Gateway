# Redis Telemetry

The gateway writes one **security event** per request to Redis. This is the hot store for the dashboard and the later isolated agent. Full history still belongs in Postgres (not implemented yet).

## What is stored

Redis is a **capped live window**, not an archive of every request forever.

| Key | Type | Purpose |
| --- | --- | --- |
| `iasg:events` | stream (`MAXLEN` ≈ 2000) | Recent events as JSON |
| `iasg:stats` | hash | Counters: `requests`, `alerts`, `decision:allow`, `signal:*` |
| `iasg:attackers` | sorted set | IP → alert count (top attackers) |
| `iasg:ip:{ip}:latest` | string JSON, TTL 24h | Last event for that IP |
| `iasg:arrivals` | stream | One record per request, written **before** it runs |
| `iasg:telemetry:health` | stream | One heartbeat per second from the gateway |

### Three streams, and which consumer reads which

`iasg:events` is written when a request **finishes**. `iasg:arrivals` is written
when it **starts**. They are separate streams rather than one stream with a
`kind` field, because the console, the `iasg:stats` and `iasg:attackers`
counters and the decision engine's Evidence consumer all read `iasg:events` — and
none of them should have to learn to skip half of it.

| Consumer | Reads | Must not read |
| --- | --- | --- |
| Console / dashboard | `iasg:events` | — |
| Decision engine (`iasg-agent`) | `iasg:events` | — |
**Why arrivals exist at all.** Adaptive baseline windowing keys on
arrival time. A request that arrives at 12:00:59 and finishes at 12:01:02
belongs to the 12:00 window; with completion records alone it would be counted
in the wrong minute, and slow requests are what an attack produces, so that
error is not random. A request still in flight — or one the backend never
answers — has no completion record at all, and the arrival is the only evidence
it existed.

This is the one thing on the request path that this adds, and it is safe
because `AsyncWriter.WriteEvent` is a `select` with a `default`: a channel send
or an immediate drop, never I/O, never a lock. A dead Redis costs an arrival
record, not a slow request. It has its own queue, so a slow backend's
completions cannot crowd out the arrivals of the requests still waiting on it.

**Why a heartbeat.** It answers three things no per-request record can: whether
telemetry was dropped (from the counters, which are process-wide, so the flag is
window-wide and cannot be attributed to one address), whether the whole minute
was observed (sixty consecutive `seq` values — a gap means a window is short for
reasons unrelated to its traffic), and how many requests were still in flight.
With no traffic at all, "gateway up and watching" is otherwise indistinguishable
from "gateway down".

```json
{"seq": 412, "at": "...", "droppedTotal": 0, "arrivalsDroppedTotal": 0,
 "inFlight": 3, "queueCap": 1024, "queueLen": 0,
 "arrivalQueueCap": 1024, "arrivalQueueLen": 0}
```

Event payload (field `event` on the stream):

```json
{
  "requestId": "a1b2c3d4e5f60708",
  "ts": "2026-08-14T10:00:00Z",
  "ip": "10.0.0.2",
  "method": "POST",
  "path": "/api/login",
  "query": "",
  "status": 401,
  "userAgent": "...",
  "decision": "allow",
  "riskScore": 70,
  "fired": ["consecutive_failed_logins"],
  "signals": [ { "signal": "consecutive_failed_logins", "score": 70, "thresholdCross": true, "details": {} } ],
  "snippet": "{\"email\":\"admin\",\"password\":\"[redacted]\"}",
  "backendMs": 12
}
```

Passwords and token-like JSON fields are redacted. Bodies are truncated to 512 bytes. `decision` is `allow` unless the optional policy enforcer applied `throttle`, `temp_block`, or `escalate`. `riskScore` is the sum of detector `Metrics()` scores.

The Python decision engine consumes this same stream (`IASG_EVIDENCE_STREAM=iasg:events`). Clean requests are ignored; each fired signal becomes one Evidence record. Policy keys are written separately as `policy:<ip>` and do not collide with `iasg:*`.

Reset the streams with `POST /api/admin/reset` (`{"confirm":"reset"}`), never
`DEL` — `DEL` on a stream takes its consumer groups with it, and every later
cycle then fails `NOGROUP` until the decision engine restarts. That endpoint uses
`XTRIM MAXLEN 0` for exactly this reason, and deliberately spares `policy:*`:
clearing history and lifting live blocks are different actions.

If Redis is down, the gateway still proxies. It logs `redis telemetry write failed` and continues.

## Config

Effective configuration, showing every field including the ones the shipped
`configs/config.yaml` leaves out and lets default in code
(`internal/config/config.go`) — the arrival and health stream settings are
valid YAML keys, just not currently written explicitly in the file:

```yaml
storage:
  redis:
    enabled: true
    host: localhost
    port: 6379
    stream_key: iasg:events
    stream_maxlen: 2000
    ip_latest_ttl: 24h
    arrival_stream_key: iasg:arrivals      # defaulted, not in the file
    arrival_maxlen: 2000                   # defaulted, not in the file
    health_stream_key: iasg:telemetry:health  # defaulted, not in the file
    health_maxlen: 86400                   # defaulted, not in the file
```

Docker Compose sets `IASG_REDIS_HOST=redis` so the gateway container talks to the Redis service.

## How it is wired

Outermost middleware: `internal/telemetry`. After all six detectors have run (including brute force's backend-status check), it calls `Collector.Snapshot(ip)` and writes the event.

Code:

- `internal/telemetry/` — event shape, redaction, middleware
- `internal/storage/redis/` — stream / stats / per-IP writes

## Inspect locally

With Compose Redis on `localhost:6379`:

```bash
bash testing/signals/redis_inspect.sh
```

Or:

```bash
redis-cli XREVRANGE iasg:events + - COUNT 5
redis-cli XREVRANGE iasg:arrivals + - COUNT 5
redis-cli XREVRANGE iasg:telemetry:health + - COUNT 1
redis-cli HGETALL iasg:stats
redis-cli ZREVRANGE iasg:attackers 0 9 WITHSCORES
```
