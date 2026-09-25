# IASG Control Plane

The Python half of the Intelligent API Security Gateway — Lane 2 of the proposal.

The Go gateway is the **data plane**: it sees every request and decides allow/block in
microseconds. This is the **control plane**: it never touches a live request, wakes up
every 30 seconds, works out which attackers are acting together, and writes policy the
gateway enforces.

Kill this process and the gateway keeps protecting traffic, using the last policy it was
given until those keys expire. It just stops getting smarter.

```
                 evidence
   Go gateway  ──────────▶  iasg:events (Redis stream)
       ▲                              │
       │                              ▼
       │                    correlate → remember → decide → explain
       │                              │
       └──────────────────────────────┘
              policy:<ip> (Redis, TTL)
```

The gateway writes arrivals and completion events. One independent consumer
turns fired signals into campaign Evidence; another keeps clean traffic long
enough to finish privacy-safe 60-second windows and endpoint baselines.
`iasg.evidence.ingest` remains as a fallback for piping old SECURITY ALERT logs.

## The four control-plane algorithms

Gateway detectors emit input evidence, but they are not control-plane
algorithms. The control plane runs these four deterministic algorithms:

1. **Adaptive endpoint baseline** learns trusted normal traffic per method and route.
2. **Campaign correlation** groups related activity across IP addresses.
3. **Campaign continuation matching** keeps the same incident connected across cycles and IP rotation.
4. **Weighted risk scoring with guardrails** makes a bounded, explainable recommendation.

IP reputation is supporting evidence, not independent policy authority. Body
limits, cooldowns, Redis streams, policy TTLs, and token buckets support safe
enforcement or reliable delivery rather than acting as detection algorithms.
LLM explanation and assessment run only after policy selection; the default
`null` provider renders templates offline and cannot affect enforcement.

See [OVERVIEW.md](OVERVIEW.md) for presentation notes and a short algorithm
summary. [`../gateway/docs/adaptive-policy.md`](../gateway/docs/adaptive-policy.md)
documents the baseline, risk/confidence, and policy guardrail contract.

## Algorithms and pseudocode

### 1. Rolling Median + MAD Baseline

```text
FOR each endpoint every minute:
    count its requests

    IF the traffic window is trusted:
        add the count to recent history
        keep only the latest N windows

        normal_rate = median(history)
        spread = median absolute deviation(history)
        new_limit = normal_rate + (spread x multiplier)
        keep new_limit inside minimum and maximum limits

        IF warm-up completed, change is large enough, and cooldown ended:
            save new_limit as the endpoint baseline
```

### 2. Weighted Risk Scoring with Guardrails

```text
FOR each suspicious IP:
    deterministic_score = strongest detector score
    add points for repeated detector evidence

    behavioural_score = how far traffic exceeds endpoint baseline
    campaign_score = campaign confidence x campaign severity

    total_risk =
        deterministic_score x weight
        + behavioural_score x weight
        + campaign_score x weight

    choose action from total_risk:
        high score -> temporary block
        medium score -> throttle
        otherwise -> monitor

    apply safety rules:
        no real detector evidence -> monitor only
        too little evidence or confidence -> reduce action
        maximum automatic action -> never exceed it
```

### 3. Rule-Based Campaign Correlation with Union-Find Clustering

```text
FOR each new evidence event:
    group events by source IP
    build one activity profile for each IP

FOR each pair of IP profiles:
    compare endpoint, user agent, attack type, subnet, and activity time

    IF IPs overlap in time AND share at least two identity traits:
        link both IPs into one group

merge all linked IPs using Union-Find

FOR each group:
    IF one IP has too little evidence:
        ignore it as noise
    OTHERWISE:
        calculate confidence, attack stages, campaign type, and severity

return campaigns sorted by highest confidence
```

### 4. Campaign Continuation Matching

```text
FOR each new campaign:
    compare it with saved campaigns

    IF enough IP addresses overlap:
        treat it as the same campaign
    OTHERWISE IF behaviour signatures match closely and activity is recent:
        treat it as the same campaign with rotated IP addresses
    OTHERWISE:
        create a new campaign

FOR a matching campaign:
    merge IPs, evidence, stages, and severity
    increase confidence slightly
    reset quiet-cycle count

FOR an active campaign not seen this cycle:
    increase quiet-cycle count
    IF quiet cycles reach 3:
        mark it contained
```

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev,postgres]"
```

Needs Redis on `localhost:6379`. Nothing else — no Docker, no Postgres, no LLM.

## Run it

```bash
# 1. make some fake attacks
.venv/bin/python -m tools.seed_evidence --scenario credential-stuffing

# 2. one cycle
.venv/bin/python -m iasg --once

# 3. see what it decided
redis-cli --scan --pattern 'policy:*'
redis-cli GET policy:203.0.113.5
redis-cli TTL policy:203.0.113.5      # expires by itself
```

Expected output:

```
[cycle] read 36 events
[correlation] Campaign #1 -- Credential Stuffing
              6 IPs, confidence 1.00, high
              6 IPs sharing same endpoint (/api/login), same User-Agent
              (curl/8.4.0), same attack type (bruteforce), same subnet
              (203.0.113.0/24), overlapping timing
[explain]     Between 16:48 and 16:49, the system detected a coordinated
              credential stuffing campaign involving 6 IP addresses targeting
              /api/login...
[policy]      wrote 6 policy keys
[escalate]    Campaign #1 raised for human review -- 6 IPs, confidence 1.00
```

Other options:

```bash
.venv/bin/python -m iasg                  # loop forever, every 30s
.venv/bin/python -m iasg --once --dry-run # decide everything, write nothing
.venv/bin/pytest                          # 310 tests (17 skipped without Postgres), no Redis needed
```

Scenarios: `credential-stuffing`, `brute-force`, `flood`, `enumeration`, `path-traversal`,
`recon`, `sqli`, `noise`, `mixed`. Add `--clear` to wipe the stream first.

`noise` is the one that must produce *nothing*. Unrelated traffic being reported as a
campaign is worse than missing a real one, so there is a scenario whose whole job is to be
rejected.

## Against the real gateway

The gateway prints its detections to stdout. Pipe them in:

```bash
cd ../gateway && go run ./cmd/server 2>&1 | ../control-plane/.venv/bin/python -m iasg.evidence.ingest
```

Then attack `localhost:8082/api/login` and run `python -m iasg --once` in another terminal.

One thing that bites here: if the gateway sits behind a proxy it must be configured with
`trusted_proxies`, or every request is attributed to `127.0.0.1` — which the writer refuses
as a non-public address, so no policy is ever written. See
[client-ip.md](../gateway/docs/client-ip.md).

## What it actually works out

Beyond grouping addresses, the parts worth knowing about:

**A lone attacker can be actioned.** Confidence is built from traits shared *between*
addresses, and one machine shares traits with nobody — so a single IP could never exceed
0.15 and never be blocked, however many times a detector fired. Solo campaigns are now
scored on their own volume and severity instead, capped below the level that wakes a human.

**Campaigns survive the attacker moving.** Matching on addresses alone meant every
rotation opened a new campaign and the investigation restarted. When no addresses are
shared, the behavioural signature — endpoint, user agent, detector — identifies the
campaign instead. Deliberately strict: merging two unrelated attackers hides one behind
the other.

**It notices whether acting worked.** A campaign that goes quiet is marked contained; one
that returns after enforcement has that counted against the action, and the next response
moves a rung up the ladder rather than repeating what just failed.

What "contained" honestly means is written into the code: for a block it is close to
circular, since a blocked address never reaches the detectors. It confirms enforcement is
holding, not that the attacker gave up. For monitor and throttle it is a real signal.

**Several attack phases from one actor read as one intrusion.** Someone who hunts for
`.env`, attacks the login they find, then probes the database is a *Multi-Stage Intrusion*
— not three separate incidents named after whichever detector was loudest. Phases are
ordered by when each was actually observed, and each phase beyond the first raises the
response.

**Escalation means something.** It writes to the `iasg_alerts` stream with the campaign and
its readable explanation, and its block outlasts an ordinary one — a human has been asked
to look, and it should still be in place when they do. Once per campaign, not once per
cycle.

## Before a policy is written

Deciding whether traffic is malicious and deciding whether the response is safe are
different questions, and `policy/simulation.py` asks the second one. It runs last, so
nothing reaches the gateway without passing it.

Its limit is stated in the module rather than hidden: the gateway reports attacks and
never ordinary traffic, so nothing here can measure how many real users sit behind an
address. It does not invent a percentage. It works with what is observable:

```bash
# never policed, whatever the evidence says and whoever asks
IASG_ALLOWLIST=10.0.0.0/8,203.0.113.9
# an office NAT or campus gateway: slowed if it attacks, never cut off
IASG_SHARED_RANGES=198.51.100.0/24
```

It also refuses to trade a standing policy for a weaker one — campaigns are re-decided
every cycle, so otherwise the quiet caused by a block could downgrade the block that
caused it.

One check is inference rather than configuration: an address speaking with many distinct
user agents looks shared. That one only softens campaigns the evidence was unsure about.
Softening a confident campaign would be an evasion route — rotate the header enough and a
block becomes a throttle — so above 0.9 confidence the action stands and the doubt is
reported instead.

## When a human disagrees

An admin instructs the agent by writing to a stream, from a dashboard, a script, or
`redis-cli`:

```bash
redis-cli XADD iasg_overrides '*' \
    ip 203.0.113.5 action temp_block actor pranav reason "confirmed attack"
```

An instruction about an address no campaign mentioned still writes policy — blocking
something the agent has not noticed is the plainest use of this. An unparseable action is
refused rather than written.

Precedence is decided rather than left to ordering, and the two kinds of check answer to
different people. **Declared configuration binds everyone**, including a human at a
console: an operator who allowlisted a range has already answered, and an instruction
typed in a hurry should not quietly undo it. **The inferred checks bind only the agent**,
since someone who says block anyway has seen something a heuristic cannot.

Disagreement is tallied per campaign type, and after enough consistent corrections in one
direction the agent starts making that correction itself. Bounded hard: one rung ever,
several samples before it moves at all, opposing corrections cancel, and it shifts only
the starting recommendation — the checks above run afterwards and are not learnable, since
a system that could learn its way past its own rails eventually would. Feedback
cannot authorize enforcement without deterministic evidence.

In practice it is the risk engine's proposed action that moves (`adaptive/risk.py`),
before the evidence, confidence and ceiling guardrails run. A cycle that used it
prints a `[learned]` line, and the policy's explanation records `learned_rungs`.
With the defaults, two consistent "block it" corrections on brute force turn the
agent's own next answer from a throttle into a temporary block.

Both features are off until configured. With nothing set, the ladder behaves exactly as it
did before they existed, and a test pins that.

## Where the AI is, and is not

Grouping, confidence scoring and the block/throttle decision are **plain deterministic
Python**. No LLM is anywhere near them. Rules can't be talked out of blocking someone,
give the same answer twice, and need no network.

The LLM writes two pieces of **text only**: the admin paragraph (`campaign.explanation`)
and a review of the grouping (`campaign.assessment`). Both run *after* policy is already
written, and nothing reads them back to make a decision. A hallucinated or
prompt-injected assessment can mislead a human reader; it cannot unblock an attacker.

Compose and a bare `python -m iasg` both default to `null` and render templates
offline. In Compose, start the opt-in internal Ollama service and set
`IASG_LLM_PROVIDER=ollama` in `infra/.env`; see [`../infra/README.md`](../infra/README.md#narration).
For a bare control-plane process, run Ollama on the host and point
`IASG_OLLAMA_URL` at it:

```bash
brew install ollama
brew services start ollama   # runs in the background, restarts at login
ollama pull llama3.2         # ~2GB, stored in ~/.ollama (not in this repo)
IASG_LLM_PROVIDER=ollama IASG_OLLAMA_URL=http://localhost:11434 .venv/bin/python -m iasg --once
```

## Safety rails on policy writes

`policy/writer.py` is the only code that can influence the gateway, so the guards live
there together:

- reputation is optional context only. The live adaptive risk engine excludes it
  from its evidence floor and score, and the default gateway configuration does
  not arm it for reflex enforcement
- never writes policy for loopback, private, link-local or reserved addresses
  (the RFC 5737 documentation ranges used by the seeder are explicitly allowed)
- `monitor` writes nothing at all
- `IASG_MAX_IPS_PER_CYCLE` caps how many IPs one cycle may action
- `--dry-run` logs every intended write and performs none

## Layout

| path | what it does |
|---|---|
| `iasg/config.py` | settings from `IASG_*` env vars, all with defaults |
| `iasg/models.py` | `Evidence` → `Campaign` → `PolicyDecision`, and the action ladder |
| `iasg/store/` | Redis access, plus an in-memory fake for tests |
| `iasg/evidence/consumer.py` | reads the stream via a consumer group |
| `iasg/evidence/ingest.py` | parses the gateway's `SECURITY ALERT` blocks |
| `iasg/anomaly/` | parses telemetry and rejects incomplete windows from baseline learning |
| `iasg/adaptive/` | learns baselines, scores risk, and stages current policy recommendations |
| `iasg/correlation/` | **groups IPs into campaigns** — union-find over shared traits |
| `iasg/campaigns/` | memory: campaigns persist, merge, and are reviewed for outcome |
| `iasg/policy/simulation.py` | is the response safe? collateral checks, run last |
| `iasg/policy/writer.py` | the only code that writes policy, and its rails |
| `iasg/feedback/` | human overrides, and what the agent learns from them |
| `iasg/alerts.py` | escalation to a human, on its own stream |
| `iasg/reasoning/` | LLM providers, and the per-cycle narration budget |
| `iasg/explanation/` | the admin-facing paragraph |
| `iasg/assessment/` | the LLM's review of what the rules concluded |
| `iasg/runner.py` | the loop |

## Notes

**Run commands as modules** (`python -m tools.seed_evidence`, not
`python tools/seed_evidence.py`). Setuptools' editable install doesn't wire up
`sys.path` correctly on Python 3.14, so `-m` — which puts the current directory on the
path — is the dependable form. `pytest` and `python -m iasg` work either way.

**Postgres is the durable record when configured.** Campaigns, feedback,
adaptive settings, endpoint baseline summaries and samples, recommendations,
and the policy audit lifecycle survive restarts there. Redis remains transport
and the expiring active-policy lookup. See the Adaptive Policy documentation
for baseline, migration, and three-mode demo steps.
