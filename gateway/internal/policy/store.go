// Package policy lets the gateway act on decisions made by the Python control
// plane. The control plane writes policy:<ip> keys into Redis; this package
// reads them and the middleware enforces them.
//
// The read is deliberately not a Redis call per request. A GET over TCP costs
// a few hundred microseconds, which is orders of magnitude more than any
// detector in the chain, and it would tie the gateway's latency -- and its
// availability -- to Redis. Instead a background goroutine copies the whole
// policy set into a map on an interval, and requests read that map. A lookup
// is then a few nanoseconds and never touches the network.
//
// The cost is staleness: a decision takes up to RefreshInterval to take
// effect. The control plane only produces decisions every 30s, so a 5s
// refresh is already faster than new decisions arrive.
package policy

import (
	"cmp"
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Actions the control plane can write. Anything else is treated as unknown
// and allowed through -- an unrecognised action must never block traffic.
const (
	ActionAllow          = "allow"
	ActionMonitor        = "monitor"
	ActionThrottle       = "throttle"
	ActionBlock          = "block"
	ActionTempBlock      = "temp_block"
	ActionTemporaryBlock = "temporary_block"
	ActionEscalate       = "escalate"
)

// OutcomeRateLimited is recorded when a throttled address exceeded the rate
// its policy allowed and the request was refused with 429.
//
// It is an outcome, not an action: the control plane never writes it. The
// action stays "throttle" -- this is what throttling did to one request, and
// telemetry needs to tell a request that was let through under a throttle from
// one that was turned away by it, or there is no way to show the limit working.
const OutcomeRateLimited = "rate_limited"

// Decision mirrors the JSON at policy:<ip>, written by PolicyDecision.to_json
// in control-plane/iasg/models.py. That method and this struct are the two
// halves of the contract between the lanes.
type Decision struct {
	Action             string          `json:"action"`
	PolicyID           string          `json:"policy_id"`
	Scope              string          `json:"scope"`
	TargetIdentity     string          `json:"target_identity"`
	CampaignID         string          `json:"campaign_id"`
	Confidence         float64         `json:"confidence"`
	RiskScore          float64         `json:"risk_score"`
	Reason             string          `json:"reason"`
	IssuedAt           string          `json:"issued_at"`
	ExpiresIn          int             `json:"expires_in"`
	Mode               string          `json:"mode"`
	IssuedBy           string          `json:"issued_by"`
	BaselineVersion    string          `json:"baseline_version"`
	ConfigVersion      int             `json:"config_version"`
	SupersedesPolicyID string          `json:"supersedes_policy_id"`
	Explanation        json.RawMessage `json:"explanation"`
	EndpointScope      *EndpointScope  `json:"endpoint_scope"`

	// RequestsPerMinute is what a throttled address may send while this policy
	// stands. It is what makes the rate limiting adaptive: the control plane
	// picks the number from how bad the campaign is, rather than every
	// throttled caller being slowed by the same fixed amount.
	//
	// Zero means the policy named no rate, which is what a control plane older
	// than this field writes. The gateway falls back to its configured
	// throttle behaviour then, so an old policy still enforces something.
	RequestsPerMinute int    `json:"requests_per_minute"`
	Route             string `json:"route,omitempty"`
	Method            string `json:"method,omitempty"`
	Source            string `json:"source,omitempty"`

	// Redis owns the lifetime. Keeping its observed deadline locally prevents
	// a missed refresh from extending a block after the key has expired.
	ExpiresAt  time.Time `json:"-"`
	cacheUntil time.Time
	redisKey   string
	rawPolicy  string
}

type EndpointScope struct {
	Method        string `json:"method"`
	RouteTemplate string `json:"route_template"`
}

// Lookuper is what the middleware actually depends on, so tests can supply a
// map instead of standing up Redis.
type Lookuper interface {
	Lookup(ip string) (Decision, bool)
}

// Config controls how policy is fetched.
type Config struct {
	Addr            string
	Password        string
	DB              int
	PoolSize        int
	KeyPrefix       string
	RefreshInterval time.Duration
	RefreshTimeout  time.Duration
	RedisTimeout    time.Duration
	FailureBackoff  time.Duration
	CacheMaxAge     time.Duration
	BucketPrefix    string
}

// Store keeps a local snapshot of every active policy key.
type Store struct {
	client         *redis.Client
	prefix         string
	interval       time.Duration
	refreshTimeout time.Duration
	cacheMaxAge    time.Duration

	// Swapped wholesale on each refresh, so readers never see a half-built
	// map and never take a lock.
	snapshot atomic.Pointer[map[string]Decision]

	// How many unexpiring keys the last refresh refused, so the warning is
	// logged when the situation changes rather than on every tick.
	unexpiring atomic.Int64

	cancel context.CancelFunc
	done   chan struct{}
}

func NewStore(cfg Config) *Store {
	cfg = defaults(cfg)

	return &Store{
		client:         newRedisClient(cfg),
		prefix:         cfg.KeyPrefix,
		interval:       cfg.RefreshInterval,
		refreshTimeout: cfg.RefreshTimeout,
		cacheMaxAge:    cfg.CacheMaxAge,
		done:           make(chan struct{}),
	}
}

// Lookup returns the decision for an IP, if one is active.
func (s *Store) Lookup(ip string) (Decision, bool) {
	m := s.snapshot.Load()
	if m == nil {
		return Decision{}, false
	}
	d, ok := (*m)[ip]
	now := time.Now()
	if ok && ((!d.ExpiresAt.IsZero() && !now.Before(d.ExpiresAt)) ||
		(!d.cacheUntil.IsZero() && !now.Before(d.cacheUntil))) {
		return Decision{}, false
	}
	return d, ok
}

// LookupRequest considers only the two bounded candidates a request can have:
// its address-wide policy and its exact normalized endpoint policy. Manual
// overrides outrank adaptive decisions; within the same origin the endpoint
// policy is more specific.
func (s *Store) LookupRequest(ip, route, method string) (Decision, bool) {
	m := s.snapshot.Load()
	if m == nil {
		return Decision{}, false
	}
	global, globalOK := live((*m)[ip])
	if globalOK && !matches(global, route, method) {
		globalOK = false
	}
	scoped, scopedOK := live((*m)[indexKey(ip, method, route)])
	if !globalOK {
		return scoped, scopedOK
	}
	if !scopedOK {
		return global, true
	}
	if decisionPriority(global) > decisionPriority(scoped) {
		return global, true
	}
	return scoped, true
}

func live(d Decision) (Decision, bool) {
	if d.Action == "" {
		return Decision{}, false
	}
	now := time.Now()
	if (!d.ExpiresAt.IsZero() && !now.Before(d.ExpiresAt)) ||
		(!d.cacheUntil.IsZero() && !now.Before(d.cacheUntil)) {
		return Decision{}, false
	}
	return d, true
}

func decisionPriority(d Decision) int {
	if d.Source == "human" || d.Source == "manual_override" || d.Mode == "manual_override" {
		return 3
	}
	if d.Source == "approved" {
		return 2
	}
	return 1
}

func indexKey(ip, method, route string) string {
	if method == "" && route == "" {
		return ip
	}
	return ip + "\x00" + strings.ToUpper(method) + "\x00" + route
}

// Start loads policy once, then keeps refreshing in the background.
func (s *Store) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	// One synchronous attempt, so a gateway restart enforces existing policy
	// immediately instead of running open for a whole interval. A failure
	// here is logged and ignored: the gateway must start even if Redis is
	// down, which is the whole point of the two lanes being independent.
	first, done := context.WithTimeout(ctx, s.refreshTimeout)
	if err := s.refresh(first); err != nil {
		log.Printf("[policy] initial load failed, allowing all traffic: %v", err)
	} else {
		log.Printf("[policy] loaded %d active policies", s.size())
	}
	done()

	go s.loop(ctx)
}

func (s *Store) loop(ctx context.Context) {
	defer close(s.done)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c, cancel := context.WithTimeout(ctx, s.refreshTimeout)
			if err := s.refresh(c); err != nil {
				log.Printf("[policy] refresh failed, allowing traffic: %v", err)
			}
			cancel()
		}
	}
}

// refresh rebuilds the snapshot from Redis.
func (s *Store) refresh(ctx context.Context) (err error) {
	// A snapshot may span many short Redis calls. Giving their whole scan the
	// quota call's budget would discard healthy policy as the keyspace grows.
	ctx, cancel := context.WithTimeout(ctx, s.refreshTimeout)
	defer cancel()
	defer func() {
		if err != nil {
			// An unavailable policy source cannot authorise continued blocks.
			// The next successful refresh restores live decisions normally.
			s.snapshot.Store(nil)
		}
	}()
	started := time.Now()
	next := make(map[string]Decision)
	var unexpiring int

	// SCAN rather than KEYS: KEYS walks the entire keyspace in one blocking
	// call, which stalls Redis for every other client including the control
	// plane.
	var cursor uint64
	for {
		keys, cur, err := s.client.Scan(ctx, cursor, s.prefix+"*", 256).Result()
		if err != nil {
			return err
		}

		if len(keys) > 0 {
			observed := time.Now()
			values, ttls, err := s.valuesWithTTLs(ctx, keys)
			if err != nil {
				return err
			}

			unexpiring += collectAt(next, keys, values, ttls, s.prefix, observed, started.Add(s.cacheMaxAge))
		}

		cursor = cur
		if cursor == 0 {
			break
		}
	}

	// Logged on change rather than every tick: this is a standing
	// misconfiguration, not a per-refresh event.
	if prev := s.unexpiring.Swap(int64(unexpiring)); int64(unexpiring) != prev {
		switch {
		case unexpiring > 0:
			log.Printf("[policy] refusing %d key(s) with no expiry: enforcement must be time-bounded", unexpiring)
		case prev > 0:
			log.Printf("[policy] no unexpiring keys remain")
		}
	}

	s.snapshot.Store(&next)
	return nil
}

// Reading value and lifetime atomically avoids assigning a replacement key's
// TTL to the old decision when the writer updates it during a refresh.
const policySnapshotScript = `return {redis.call('GET', KEYS[1]), redis.call('PTTL', KEYS[1])}`

func (s *Store) valuesWithTTLs(ctx context.Context, keys []string) ([]any, []time.Duration, error) {
	pipe := s.client.Pipeline()
	cmds := make([]*redis.Cmd, len(keys))
	for i, key := range keys {
		cmds[i] = pipe.Eval(ctx, policySnapshotScript, []string{key})
	}
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, nil, err
	}

	values := make([]any, len(keys))
	ttls := make([]time.Duration, len(keys))
	for i, cmd := range cmds {
		ttls[i] = -1
		parts, err := cmd.Slice()
		if err != nil || len(parts) != 2 {
			continue
		}
		ttl, ok := parts[1].(int64)
		if !ok {
			continue
		}
		values[i] = parts[0]
		ttls[i] = time.Duration(ttl) * time.Millisecond
	}
	return values, ttls, nil
}

// collect decodes one SCAN batch into the snapshot being built and reports how
// many keys were refused for having no expiry. Split out from refresh so the
// decoding rules can be tested without a Redis server.
func collect(into map[string]Decision, keys []string, values []any, ttls []time.Duration, prefix string) int {
	return collectAt(into, keys, values, ttls, prefix, time.Now(), time.Time{})
}

func collectAt(into map[string]Decision, keys []string, values []any, ttls []time.Duration, prefix string, observed, cacheUntil time.Time) int {
	unexpiring := 0

	for i, v := range values {
		if i >= len(keys) {
			return unexpiring
		}

		raw, ok := v.(string)
		if !ok {
			continue // nil: the key expired between the SCAN and the MGET
		}

		// Every action the control plane can take is time-bounded, and the
		// gateway relies on Redis dropping the key to restore service by
		// itself. A key with no expiry has no such release: nothing renews it
		// and nothing clears it, so one mistyped key would refuse an address
		// permanently, with no record of why. Refuse it instead.
		if i >= len(ttls) || ttls[i] <= 0 {
			unexpiring++
			continue
		}

		var d Decision
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			// One malformed key must not discard every good one.
			log.Printf("[policy] ignoring unparseable key %s: %v", keys[i], err)
			continue
		}
		d.Source = cmp.Or(d.Source, "agent")
		if d.EndpointScope != nil {
			d.Method = cmp.Or(d.Method, d.EndpointScope.Method)
			d.Route = cmp.Or(d.Route, d.EndpointScope.RouteTemplate)
		}
		d.ExpiresAt = observed.Add(ttls[i])
		d.cacheUntil = cacheUntil
		d.redisKey, d.rawPolicy = keys[i], raw

		explicitTarget := d.TargetIdentity != ""
		target := d.TargetIdentity
		target = cmp.Or(target, strings.TrimPrefix(keys[i], prefix))
		key := target
		if explicitTarget {
			key = indexKey(target, d.Method, d.Route)
		}
		into[key] = d
	}

	return unexpiring
}

func (s *Store) size() int {
	m := s.snapshot.Load()
	if m == nil {
		return 0
	}
	return len(*m)
}

func (s *Store) Close() error {
	if s.cancel != nil {
		s.cancel()
		<-s.done
	}
	return s.client.Close()
}
