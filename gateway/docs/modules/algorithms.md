# The 17 Algorithms

This module documents the pseudocode used by the gateway and decision engine.
Here, “algorithm” means a repeatable rule or calculation; it does **not** mean
an LLM.

## Decision-engine algorithms

| File | Algorithm name | Use |
| ----- | ----- | ----- |
| `adaptive/baseline.py` | Rolling Median and MAD Baseline | Learns each endpoint’s normal request rate and detects unusual traffic spikes. |
| `adaptive/risk.py` | Weighted Risk Scoring with Guardrails | Combines detector evidence, traffic abnormality, and campaign information to safely select monitor, throttle, or temporary block. |
| `correlation/features.py` + `cluster.py` + `agent.py` | Rule-Based Campaign Correlation with Union-Find Clustering | Groups related IPs into attack campaigns and calculates campaign confidence, type, stages, and severity. |
| `campaigns/repository.py` | Campaign Continuation Matching | Continues the same attack campaign across cycles, including when attackers change IP addresses. |

### 1. Rolling Median and MAD Baseline

**File:** `decision-engine/iasg/adaptive/baseline.py`
**Purpose:** Uses a rolling **median + MAD** baseline, with warm-up, minimum/maximum limits, hysteresis, and cooldown.

**Pseudocode:**

```text
FOR each endpoint every minute:
    count its requests

    IF traffic window is trusted:
        add count to recent history
        keep only latest N windows

        normal_rate = median(history)
        spread = median absolute deviation(history)

        new_limit = normal_rate + (spread × multiplier)
        keep new_limit inside minimum and maximum limits

        IF enough history exists AND limit changed enough AND cooldown ended:
            save new_limit as the endpoint baseline
```

### 2. Weighted Risk Scoring with Guardrails

**File:** `decision-engine/iasg/adaptive/risk.py`
**Purpose:** Combines deterministic evidence, traffic deviation, campaign confidence, weighted scoring, action thresholds, and enforcement guardrails.

**Pseudocode:**

```text
FOR each suspicious IP:
    deterministic_score = strongest detector score
    add points for repeated detector evidence

    behavioural_score = how far traffic exceeds endpoint baseline
    campaign_score = campaign confidence × campaign severity

    total_risk =
        deterministic_score × weight
        + behavioural_score × weight
        + campaign_score × weight

    choose action from total_risk:
        high score → temporary block
        medium score → throttle
        otherwise → monitor

    apply safety rules:
        no real detector evidence → monitor only
        too little evidence/confidence → reduce action
        maximum automatic action → never exceed it

    return score, confidence, selected action, explanation
```

### 3. Rule-Based Campaign Correlation with Union-Find Clustering

**Files:** `decision-engine/iasg/correlation/features.py`, `cluster.py`, and `agent.py`

**Pseudocode:**

```text
FOR each new evidence event:
    group events by source IP
    build one activity profile for each IP

FOR each pair of IP profiles:
    compare shared traits:
        endpoint
        user agent
        attack type
        subnet
        activity time

    IF IPs overlap in time
       AND share at least two identity traits:
        link both IPs into one group

merge all linked IPs using Union-Find
→ each group becomes a possible campaign

FOR each campaign group:
    IF one IP has too little evidence:
        ignore it as noise

    calculate confidence from:
        shared traits for multiple IPs
        OR event volume and severity for one IP

    identify attack stages
    assign campaign type and severity

sort campaigns by highest confidence

return related attack campaigns
```

### 4. Campaign Continuation Matching

**File:** `decision-engine/iasg/campaigns/repository.py`

**Pseudocode:**

```text
FOR each new campaign from this control cycle:
    compare it with all saved campaigns

    first_match = IP address overlap

    IF enough IP addresses overlap:
        treat it as the same campaign

    OTHERWISE:
        compare behaviour signature:
            same detector
            same endpoint
            same user agent
            same subnet
            recent enough activity

        IF behaviour similarity reaches threshold:
            treat it as the same campaign
            mark that attacker rotated IP addresses

    IF no matching campaign exists:
        create a new campaign ID

    IF a matching campaign exists:
        merge new IPs, evidence, stages, and severity
        increase confidence slightly
        reset quiet-cycle count

FOR each saved active campaign not seen this cycle:
    increase quiet-cycle count

    IF quiet cycles reach 3:
        mark campaign as contained

return updated campaigns
```

## Gateway algorithms

| File | Algorithm | Purpose |
| ----- | ----- | ----- |
| `signals/evidence.go` | Ratio score mapping | Converts detector counts into a 0–100 evidence score. |
| `signals/api_flooding.go` | Sliding-window flood detection | Detects too many requests from one IP in one minute. |
| `signals/brute_force.go` | Consecutive failed-login detection | Detects repeated failed logins per IP and account. |
| `signals/sqli_injection.go` | SQLi signature matching | Detects configured SQL-injection patterns. |
| `signals/enumeration_path_traversal.go` | Traversal/enumeration signature matching | Detects path traversal and forced-browsing patterns. |
| `signals/unknown_route_scanning.go` | Distinct unknown-route detection | Detects an IP probing many unconfigured paths. |
| `signals/object_enumeration.go` | Object-ID harvesting detection | Detects BOLA/IDOR-style walking through object IDs. |
| `signals/ip_reputation.go` | Reputation lookup with cooldown | Flags IPs present in a known-bad feed. |
| `ownership/guard.go` | Object ownership guard | Prevents a user receiving another user’s protected data. |
| `enforcement/reflex.go` | Bounded gateway reflex | Temporarily blocks an IP after trusted high-score evidence. |
| `policy/redis_limiter.go` + `token_bucket.lua` | Distributed token bucket | Enforces one shared throttle quota across gateway replicas. |
| `policy/limiter.go` | Local sliding-window limiter | Older/local limiter used by tests or standalone embedding; normal server use is Redis token buckets. |
| `telemetry/route.go` | Most-specific route matching | Matches a request to its configured route template. |

### 5. Shared evidence score

**File:** `gateway/internal/signals/evidence.go`

```text
FOR each detector count and threshold:

    IF count is zero OR threshold is invalid:
        return score 0

    IF count is below threshold:
        return a small proportional score from 0 to 30

    IF count is at or above 5 × threshold:
        return score 100

    IF count is at or above 2 × threshold:
        return score 80

    OTHERWISE:
        return score 60
```

### 6. API flood detector

**File:** `gateway/internal/signals/api_flooding.go`

```text
FOR each request from an IP:

    remove timestamps older than one minute
    add the current request timestamp

    request_count = timestamps remaining

    IF request_count is greater than configured RPM threshold:
        emit api_flooding evidence
        mark threshold crossed

    score = shared ratio score(request_count, RPM threshold)

    allow the current request to continue
```

### 7. Brute-force login detector

**File:** `gateway/internal/signals/brute_force.go`

```text
FOR each configured login request:

    send request to backend
    read backend response status

    IF status means invalid credentials:
        identify client IP + login route + username/email
        increase that target's consecutive failure streak

    IF status means successful login:
        clear that target's failure streak

    remove streaks older than the configured window

    strongest_streak = largest failure streak for this IP

    IF strongest_streak >= maximum failures:
        emit consecutive_failed_logins evidence

    score = shared ratio score(strongest_streak, maximum failures)
```

### 8. SQL-injection detector

**File:** `gateway/internal/signals/sqli_injection.go`

```text
FOR each request:

    read safely capped body
    read path, raw path, and decoded query values
    combine them into one inspection text
    normalize SQL comments and uppercase text

    matched_patterns = configured SQL patterns found in text

    IF no patterns match:
        score = 0

    ELSE IF only low-confidence pattern "--" matches:
        score = 20
        do not fire an alert

    ELSE:
        mark threshold crossed
        one match   → score 70
        two matches → score 85
        3+ matches  → score 100

    store evidence for this request
    allow the request to continue
```

### 9. Path traversal and forced-browsing detector

**File:** `gateway/internal/signals/enumeration_path_traversal.go`

```text
FOR each request:

    inspect path and query in original form
    decode URL text up to two times

    traversal_hits = match patterns such as "../" or encoded variants
    enum_hits = match sensitive paths such as "/.env" or "/etc/passwd"

    IF traversal and enumeration both match:
        score = 100

    ELSE IF traversal matches:
        score = 80

    ELSE IF enumeration matches:
        score = 50

    ELSE:
        score = 0

    threshold is crossed whenever either pattern type matches
    store request evidence
```

### 10. Unknown-route scanning detector

**File:** `gateway/internal/signals/unknown_route_scanning.go`

```text
FOR each request:

    route = match request against configured route templates

    IF route is known:
        ignore it

    IF route is unmatched:
        keep the raw path for this IP
        remove paths older than the configured window
        do not count repeated paths twice

    distinct_paths = number of retained unknown paths

    IF distinct_paths >= configured threshold:
        emit unknown_route_scanning evidence

    score = shared ratio score(distinct_paths, threshold)
```

### 11. Object-enumeration / BOLA harvesting detector

**File:** `gateway/internal/signals/object_enumeration.go`

```text
FOR each request to a configured protected object route:

    extract object ID from route template
    send request to backend
    record whether response was denied: 401, 403, or 404

    keep distinct object IDs per IP and route
    remove IDs older than configured window

    distinct_ids = number of different IDs requested
    denied_share = denied responses / distinct IDs
    sequential_run = longest numeric sequence among IDs

    score = shared ratio score(distinct_ids, threshold)

    IF distinct_ids reaches threshold:
        mark threshold crossed

        IF denied_share >= 50%:
            add 20 points

        IF sequential_run >= 5:
            add 10 points

        cap score at 100
```

### 12. IP reputation detector

**File:** `gateway/internal/signals/ip_reputation.go`

```text
FOR each request:

    IF IP is not in known-bad reputation feed:
        score = 0
        stop

    score = configured reputation score

    IF this IP has not fired during cooldown:
        mark threshold crossed
        record current request ID
        start cooldown

    OTHERWISE:
        keep score, but do not create another fresh signal
```

### 13. Object ownership guard

**File:** `gateway/internal/ownership/guard.go`

```text
FOR each protected object request:

    verify caller JWT

    IF token is invalid or missing:
        return 401

    IF caller has bypass role:
        forward request unchanged

    hold backend response safely
    read object owner field from JSON response

    IF single object's owner != caller identity:
        record ownership_violation evidence
        return 404

    IF response is a list:
        remove items not owned by caller
        return filtered list

    IF same IP has 3+ ownership violations in 5 minutes:
        raise evidence score from 80 to 100
```

### 14. Gateway reflex block

**File:** `gateway/internal/enforcement/reflex.go`

```text
AFTER detectors finish processing a request:

    FOR each detector evidence item:

        IF reflex is disabled:
            stop

        IF IP is exempt, invalid, private, or loopback:
            stop

        IF detector is not explicitly allowed in block.signals:
            continue

        IF detector did not cross its threshold:
            continue

        IF evidence score is below reflex minimum score:
            continue

        IF IP is not already blocked:
            create temporary block until now + configured duration

        stop after first qualifying signal

ON later requests:

    IF temporary block has not expired:
        return 403

    IF expired:
        allow request and remove block
```

### 15. Distributed Redis token bucket

**Files:** `gateway/internal/policy/redis_limiter.go`, `token_bucket.lua`

```text
FOR each request covered by a throttle policy:

    confirm policy still exists and has a positive TTL

    bucket_key = hash(IP + route + method + policy identity)

    read bucket tokens and last update time
    refill tokens based on elapsed time and policy RPM
    cap tokens at burst capacity

    IF tokens >= 1:
        remove one token
        allow request

    ELSE:
        calculate time until one token is available
        return 429 with Retry-After

    expire bucket when it would naturally refill,
    never later than the policy TTL

IF Redis is unavailable:
    fail open immediately
    temporarily avoid repeated Redis attempts
```

### 16. Local sliding-window limiter

**File:** `gateway/internal/policy/limiter.go`

```text
FOR each throttled IP:

    remove request timestamps older than one minute
    add current request timestamp

    IF request count <= policy limit:
        allow request

    OTHERWISE:
        retry_after =
            oldest request timestamp + one minute - now

        return rate-limited result
```

This is retained for tests and standalone embedding. The normal gateway server
uses the distributed Redis token bucket instead, so multiple replicas cannot
each create their own separate allowance.

### 17. Most-specific route matcher

**File:** `gateway/internal/telemetry/route.go`

```text
FOR each request path:

    split request path into segments

    FOR each route template with same HTTP method:

        reject it if segment count differs

        compare every segment:
            literal segment must match exactly
            wildcard segment accepts one non-empty value

    choose the matching template with most literal segments

    IF no template matches:
        return "<unmatched>"
```

For example, `/api/products/search` wins over `/api/products/{id}` because it
has more fixed literal segments.
