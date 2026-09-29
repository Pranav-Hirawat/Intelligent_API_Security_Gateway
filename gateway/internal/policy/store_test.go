package policy

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// The JSON the Python decision engine actually writes.
const realPolicy = `{"action": "temp_block", "campaign_id": "2", "confidence": 0.97,` +
	` "reason": "Credential Stuffing", "issued_at": "2026-08-12T06:30:30.270057+00:00",` +
	` "expires_in": 1800}`

func TestCollectDecodesAndStripsPrefix(t *testing.T) {
	snapshot := map[string]Decision{}
	collect(snapshot,
		[]string{"policy:203.0.113.5"},
		[]any{realPolicy},
		[]time.Duration{time.Minute},
		"policy:")

	d, ok := snapshot["203.0.113.5"]
	if !ok {
		t.Fatalf("key not stored under the stripped IP, snapshot = %v", snapshot)
	}
	if d.Action != ActionTempBlock || d.CampaignID != "2" || d.ExpiresIn != 1800 {
		t.Fatalf("decoded wrongly: %+v", d)
	}
}

// A key can expire between the SCAN that listed it and the MGET that fetches
// it, in which case Redis returns nil.
func TestCollectSkipsExpiredKeys(t *testing.T) {
	snapshot := map[string]Decision{}
	collect(snapshot,
		[]string{"policy:203.0.113.5", "policy:203.0.113.9"},
		[]any{nil, realPolicy},
		[]time.Duration{time.Minute, time.Minute},
		"policy:")

	if _, ok := snapshot["203.0.113.5"]; ok {
		t.Error("an expired key was stored")
	}
	if _, ok := snapshot["203.0.113.9"]; !ok {
		t.Error("the live key alongside it was lost")
	}
}

// One bad key must not cost us every good one.
func TestCollectSkipsMalformedJSON(t *testing.T) {
	snapshot := map[string]Decision{}
	collect(snapshot,
		[]string{"policy:203.0.113.5", "policy:203.0.113.9"},
		[]any{"{not json", realPolicy},
		[]time.Duration{time.Minute, time.Minute},
		"policy:")

	if len(snapshot) != 1 {
		t.Fatalf("want 1 usable entry, got %d: %v", len(snapshot), snapshot)
	}
	if _, ok := snapshot["203.0.113.9"]; !ok {
		t.Error("the valid key was discarded along with the broken one")
	}
}

// Redis should never return more values than keys, but a mismatch must not
// panic on an index out of range.
func TestCollectSurvivesLengthMismatch(t *testing.T) {
	snapshot := map[string]Decision{}
	collect(snapshot,
		[]string{"policy:203.0.113.5"},
		[]any{realPolicy, realPolicy, realPolicy},
		[]time.Duration{time.Minute},
		"policy:")

	if len(snapshot) != 1 {
		t.Fatalf("want 1 entry, got %d", len(snapshot))
	}
}

func TestCollectHandlesEmptyBatch(t *testing.T) {
	snapshot := map[string]Decision{}
	collect(snapshot, nil, nil, nil, "policy:")

	if len(snapshot) != 0 {
		t.Fatalf("want empty, got %v", snapshot)
	}
}

// Before the first refresh there is no snapshot at all. Lookup must report
// "no policy" rather than panicking on a nil map.
func TestLookupBeforeFirstRefresh(t *testing.T) {
	s := NewStore(Config{Addr: "127.0.0.1:6379"})
	defer s.Close()

	if _, found := s.Lookup("203.0.113.5"); found {
		t.Fatal("found a decision before any refresh ran")
	}
	if n := s.size(); n != 0 {
		t.Fatalf("size = %d, want 0", n)
	}
}

func TestLookupReadsCurrentSnapshot(t *testing.T) {
	s := NewStore(Config{Addr: "127.0.0.1:6379"})
	defer s.Close()

	snapshot := map[string]Decision{"203.0.113.5": {Action: ActionTempBlock}}
	s.snapshot.Store(&snapshot)

	d, found := s.Lookup("203.0.113.5")
	if !found || d.Action != ActionTempBlock {
		t.Fatalf("lookup returned %+v found=%v", d, found)
	}
	if _, found := s.Lookup("198.51.100.1"); found {
		t.Fatal("an address with no policy was reported as found")
	}
}

func TestNewStoreAppliesDefaults(t *testing.T) {
	s := NewStore(Config{Addr: "127.0.0.1:6379"})
	defer s.Close()

	if s.prefix != "policy:" {
		t.Errorf("prefix = %q, want the default policy:", s.prefix)
	}
	if s.interval != 5*time.Second {
		t.Errorf("interval = %v, want the default 5s", s.interval)
	}
}

func TestNewStoreKeepsExplicitSettings(t *testing.T) {
	s := NewStore(Config{
		Addr:            "127.0.0.1:6379",
		KeyPrefix:       "block:",
		RefreshInterval: 30 * time.Second,
	})
	defer s.Close()

	if s.prefix != "block:" || s.interval != 30*time.Second {
		t.Fatalf("settings overridden: prefix=%q interval=%v", s.prefix, s.interval)
	}
}

// Close must be safe on a store that was never started.
func TestCloseWithoutStart(t *testing.T) {
	if err := NewStore(Config{Addr: "127.0.0.1:6379"}).Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// An unreachable Redis must leave the store empty and usable, never blocking
// or panicking -- the gateway has to keep serving when the decision engine is
// down.
func TestRefreshAgainstUnreachableRedisFailsOpen(t *testing.T) {
	s := NewStore(Config{Addr: "127.0.0.1:1", RefreshInterval: time.Second})
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := s.refresh(ctx); err == nil {
		t.Fatal("expected an error from an unreachable Redis")
	}
	if _, found := s.Lookup("203.0.113.5"); found {
		t.Fatal("a failed refresh must not invent policy")
	}
}

// Integration tests use an explicitly selected disposable Redis database.
func TestRefreshAgainstRealRedis(t *testing.T) {
	s := NewStore(Config{Addr: integrationRedisAddr(t), KeyPrefix: "policytest:", RedisTimeout: time.Second})
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := s.client.Ping(ctx).Err(); err != nil {
		t.Fatalf("Redis unavailable: %v", err)
	}

	keys := []string{"policytest:203.0.113.5", "policytest:203.0.113.9"}
	for _, k := range keys {
		if err := s.client.Set(ctx, k, realPolicy, time.Minute).Err(); err != nil {
			t.Fatalf("seed %s: %v", k, err)
		}
	}
	defer s.client.Del(ctx, keys...)

	if err := s.refresh(ctx); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	for _, ip := range []string{"203.0.113.5", "203.0.113.9"} {
		d, found := s.Lookup(ip)
		if !found {
			t.Errorf("%s missing from the snapshot", ip)
			continue
		}
		if d.Action != ActionTempBlock || d.ExpiresIn != 1800 {
			t.Errorf("%s decoded wrongly: %+v", ip, d)
		}
	}

	// Deleting the key must drop it from the next snapshot, which is what
	// makes a policy expiring in Redis restore service by itself.
	s.client.Del(ctx, "policytest:203.0.113.5")
	if err := s.refresh(ctx); err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if _, found := s.Lookup("203.0.113.5"); found {
		t.Error("a deleted key survived the refresh")
	}
}

// Start must load once up front and then keep the goroutine running, and
// Close must shut it down without hanging.
func TestStartAndCloseLifecycle(t *testing.T) {
	s := NewStore(Config{Addr: "127.0.0.1:6379", RefreshInterval: time.Second})

	s.Start()

	done := make(chan error, 1)
	go func() { done <- s.Close() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close hung -- the refresh goroutine did not stop")
	}
}

// A policy key with no expiry is refused rather than enforced.
//
// Every action the decision engine can take is time-bounded and the gateway
// relies on Redis dropping the key to restore service by itself. A key that
// never expires has no such release, so honouring it would refuse an address
// permanently -- the one failure a security gateway must not have by accident.
func TestCollectRefusesKeysWithNoExpiry(t *testing.T) {
	snapshot := map[string]Decision{}
	unexpiring := collect(snapshot,
		[]string{"policy:203.0.113.5", "policy:203.0.113.9"},
		[]any{realPolicy, realPolicy},
		// -1 is what Redis reports for a key with no TTL.
		[]time.Duration{-1, time.Minute},
		"policy:")

	if unexpiring != 1 {
		t.Fatalf("reported %d unexpiring keys, want 1", unexpiring)
	}
	if _, ok := snapshot["203.0.113.5"]; ok {
		t.Error("an unexpiring key was enforced")
	}
	if _, ok := snapshot["203.0.113.9"]; !ok {
		t.Error("the properly-expiring key alongside it was lost")
	}
}

// The JSON's own expires_in is intent, not state: a hand-written key can claim
// a lifetime it does not have. Only the real TTL decides.
func TestCollectIgnoresExpiresInWhenTheKeyHasNoTTL(t *testing.T) {
	snapshot := map[string]Decision{}
	unexpiring := collect(snapshot,
		[]string{"policy:203.0.113.5"},
		// realPolicy declares "expires_in": 1800 ...
		[]any{realPolicy},
		// ... while Redis holds it forever.
		[]time.Duration{-1},
		"policy:")

	if unexpiring != 1 || len(snapshot) != 0 {
		t.Fatalf("a key claiming an expiry it does not have was enforced: %v", snapshot)
	}
}

// Missing lifetime evidence cannot authorise an unbounded restriction.
func TestCollectRefusesKeysWhenTTLsAreMissing(t *testing.T) {
	snapshot := map[string]Decision{}
	unexpiring := collect(snapshot,
		[]string{"policy:203.0.113.5"},
		[]any{realPolicy},
		nil, // no TTLs fetched at all
		"policy:")

	if unexpiring != 1 {
		t.Errorf("reported %d unexpiring, want 1", unexpiring)
	}
	if _, ok := snapshot["203.0.113.5"]; ok {
		t.Error("enforcement was invented without a bounded lifetime")
	}
}

// End to end against Redis: a key written with no expiry must never reach the
// snapshot, while an ordinary one does.
func TestRefreshRefusesUnexpiringKeyInRedis(t *testing.T) {
	s := NewStore(Config{Addr: integrationRedisAddr(t), KeyPrefix: "ttltest:", RedisTimeout: time.Second})
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := s.client.Ping(ctx).Err(); err != nil {
		t.Fatalf("Redis unavailable: %v", err)
	}

	forever := "ttltest:203.0.113.5"
	bounded := "ttltest:203.0.113.9"
	// No expiry, exactly like a key set by hand with redis-cli SET.
	if err := s.client.Set(ctx, forever, realPolicy, 0).Err(); err != nil {
		t.Fatalf("seed %s: %v", forever, err)
	}
	if err := s.client.Set(ctx, bounded, realPolicy, time.Minute).Err(); err != nil {
		t.Fatalf("seed %s: %v", bounded, err)
	}
	defer s.client.Del(ctx, forever, bounded)

	if err := s.refresh(ctx); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if _, found := s.Lookup("203.0.113.5"); found {
		t.Error("a key with no expiry was loaded into the snapshot")
	}
	if _, found := s.Lookup("203.0.113.9"); !found {
		t.Error("the bounded key was not loaded")
	}
	if n := s.unexpiring.Load(); n != 1 {
		t.Errorf("unexpiring count = %d, want 1", n)
	}
}

func integrationRedisAddr(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("IASG_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set IASG_TEST_REDIS_ADDR to run against a disposable Redis instance")
	}
	return addr
}

func TestSnapshotExpiresWithoutAnotherRefresh(t *testing.T) {
	s := NewStore(Config{Addr: "127.0.0.1:1"})
	defer s.Close()
	now := time.Now()
	for _, tc := range []struct {
		name                string
		expires, cacheUntil time.Time
	}{
		{"policy TTL", now.Add(-time.Millisecond), now.Add(time.Hour)},
		{"cache max age", now.Add(time.Hour), now.Add(-time.Millisecond)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := map[string]Decision{"203.0.113.5": {
				Action: ActionTempBlock, ExpiresAt: tc.expires, cacheUntil: tc.cacheUntil,
			}}
			s.snapshot.Store(&snapshot)
			if _, found := s.Lookup("203.0.113.5"); found {
				t.Fatal("a stale snapshot continued restricting traffic")
			}
		})
	}
}

func TestSnapshotDeadlineDoesNotExtendByNetworkLatency(t *testing.T) {
	observed := time.Now().Add(-time.Minute)
	snapshot := map[string]Decision{}
	collectAt(snapshot, []string{"policy:203.0.113.5"}, []any{realPolicy},
		[]time.Duration{time.Minute}, "policy:", observed, observed.Add(10*time.Second))
	d := snapshot["203.0.113.5"]
	if d.ExpiresAt != observed.Add(time.Minute) || d.cacheUntil != observed.Add(10*time.Second) {
		t.Fatalf("deadlines extended after the Redis read: %+v", d)
	}
	if d.Source != "agent" || d.redisKey != "policy:203.0.113.5" || d.rawPolicy != realPolicy {
		t.Fatalf("lost policy origin or generation: %+v", d)
	}
}

func TestSnapshotPreservesPolicySource(t *testing.T) {
	snapshot := map[string]Decision{}
	collect(snapshot, []string{"policy:203.0.113.5"},
		[]any{`{"action":"throttle","source":"reputation","route":"/api/login","method":"POST","requests_per_minute":5}`},
		[]time.Duration{time.Minute}, "policy:")
	d := snapshot["203.0.113.5"]
	if d.Source != "reputation" || d.Route != "/api/login" || d.Method != "POST" || d.RequestsPerMinute != 5 {
		t.Fatalf("policy fields lost: %+v", d)
	}
}

func TestRefreshFailureDropsPriorRestrictions(t *testing.T) {
	s := NewStore(Config{Addr: "127.0.0.1:1"})
	defer s.Close()
	snapshot := map[string]Decision{"203.0.113.5": {Action: ActionTempBlock, ExpiresAt: time.Now().Add(time.Hour)}}
	s.snapshot.Store(&snapshot)
	if err := s.refresh(context.Background()); err == nil {
		t.Fatal("expected Redis connection failure")
	}
	if _, found := s.Lookup("203.0.113.5"); found {
		t.Fatal("an unavailable source retained enforcement")
	}
}

func TestSnapshotRefreshBudgetIsIndependentOfSocketBudget(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cfg         Config
		wantRefresh time.Duration
	}{
		{"defaults", Config{Addr: "127.0.0.1:1", RedisTimeout: 25 * time.Millisecond}, 2 * time.Second},
		{"configured", Config{Addr: "127.0.0.1:1", RedisTimeout: 25 * time.Millisecond, RefreshTimeout: 750 * time.Millisecond}, 750 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStore(tc.cfg)
			defer s.Close()
			if s.refreshTimeout != tc.wantRefresh {
				t.Fatalf("refresh budget = %v, want %v", s.refreshTimeout, tc.wantRefresh)
			}
			opts := s.client.Options()
			if opts.ReadTimeout != tc.cfg.RedisTimeout || opts.WriteTimeout != tc.cfg.RedisTimeout ||
				opts.DialTimeout != tc.cfg.RedisTimeout || opts.PoolTimeout != tc.cfg.RedisTimeout {
				t.Fatal("background refresh budget relaxed the individual Redis operation bounds")
			}
		})
	}
}

// Time between SCAN pages consumes the background budget without making any
// individual Redis call slow, as scheduling and decoding do in production.
type delayedScanHook struct {
	delay time.Duration
	calls int
}

func (h *delayedScanHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *delayedScanHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *delayedScanHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "scan" {
			h.calls++
			timer := time.NewTimer(h.delay)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
			}
		}
		return next(ctx, cmd)
	}
}

func TestRedisSnapshotCanSpanManyFastCallsButRetainsTotalDeadline(t *testing.T) {
	addr := integrationRedisAddr(t)
	prefix := fmt.Sprintf("iasg-test:refresh-budget:%d:", time.Now().UnixNano())
	seed := newRedisClient(defaults(Config{Addr: addr, RedisTimeout: time.Second}))
	defer seed.Close()
	ctx := context.Background()
	keys := make([]string, 1024)
	pipe := seed.Pipeline()
	for i := range keys {
		keys[i] = fmt.Sprintf("%s%d", prefix, i)
		pipe.Set(ctx, keys[i], realPolicy, time.Minute)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		t.Fatalf("seed policies: %v", err)
	}
	defer seed.Del(ctx, keys...)

	s := NewStore(Config{Addr: addr, KeyPrefix: prefix, RedisTimeout: 25 * time.Millisecond, RefreshTimeout: 2 * time.Second})
	defer s.Close()
	hook := &delayedScanHook{delay: 15 * time.Millisecond}
	s.client.AddHook(hook)
	started := time.Now()
	if err := s.refresh(ctx); err != nil {
		t.Fatalf("healthy multipage snapshot failed: %v", err)
	}
	if hook.calls < 2 || time.Since(started) <= s.client.Options().ReadTimeout {
		t.Fatalf("test did not exceed a single-call budget: scan pages=%d, elapsed=%v", hook.calls, time.Since(started))
	}
	if s.size() != len(keys) {
		t.Fatalf("loaded %d policies, want %d", s.size(), len(keys))
	}

	s.refreshTimeout = 20 * time.Millisecond
	if err := s.refresh(ctx); err == nil {
		t.Fatal("multipage scan ignored its configured total deadline")
	}
	if s.size() != 0 {
		t.Fatal("timed-out snapshot retained restrictions")
	}
}
