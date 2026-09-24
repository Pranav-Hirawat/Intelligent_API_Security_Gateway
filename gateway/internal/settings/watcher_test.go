package settings

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/redis/go-redis/v9"
)

// Its own database, so these tests cannot collide with a running gateway's
// keys or with another package's tests sharing the same server.
const testDB = 11

func testRedis(t *testing.T) (*redis.Client, string) {
	t.Helper()
	addr := os.Getenv("IASG_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set IASG_TEST_REDIS_ADDR to run against a disposable Redis instance")
	}
	client := redis.NewClient(&redis.Options{Addr: addr, DB: testDB})
	if err := client.FlushDB(context.Background()).Err(); err != nil {
		t.Fatalf("redis: %v", err)
	}
	t.Cleanup(func() { _ = client.FlushDB(context.Background()).Err(); _ = client.Close() })
	return client, addr
}

// recorder is an Applier that remembers what it was given and can be told to
// refuse, the way the proxy's live.apply refuses a CIDR that will not parse.
type recorder struct {
	mu      sync.Mutex
	applied []config.EnforcementConfig
	refuse  func(config.EnforcementConfig) bool
}

func (r *recorder) apply(c config.EnforcementConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.refuse != nil && r.refuse(c) {
		return errors.New("refused")
	}
	r.applied = append(r.applied, c)
	return nil
}

func (r *recorder) last() (config.EnforcementConfig, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.applied) == 0 {
		return config.EnforcementConfig{}, 0
	}
	return r.applied[len(r.applied)-1], len(r.applied)
}

func effective(t *testing.T, client *redis.Client) map[string]any {
	t.Helper()
	raw, err := client.Get(context.Background(), EffectiveKey).Result()
	if err != nil {
		t.Fatalf("effective key: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func rpm(t *testing.T, client *redis.Client) float64 {
	t.Helper()
	return effective(t, client)["rate_limit"].(map[string]any)["requests_per_minute"].(float64)
}

func override(t *testing.T, client *redis.Client, c config.EnforcementConfig) {
	t.Helper()
	raw, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Set(context.Background(), Key, raw, 0).Err(); err != nil {
		t.Fatal(err)
	}
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func startWatcher(t *testing.T, addr string, r *recorder) *Watcher {
	t.Helper()
	w := NewWatcher(Config{Addr: addr, DB: testDB, Interval: 50 * time.Millisecond}, base(), r.apply)
	w.Start()
	t.Cleanup(func() { _ = w.Close() })
	return w
}

// A restart must pick up an override already in place, not run the file's
// settings for a whole interval first.
func TestOverrideAlreadyInPlaceIsAppliedAtStart(t *testing.T) {
	client, addr := testRedis(t)
	want := base()
	want.RateLimit.RequestsPerMinute = 42
	override(t, client, want)

	r := &recorder{}
	startWatcher(t, addr, r)

	got, n := r.last()
	if n == 0 || got.RateLimit.RequestsPerMinute != 42 {
		t.Fatalf("after Start applied %d times, rpm=%d; want the override before the first tick", n, got.RateLimit.RequestsPerMinute)
	}
	if src := effective(t, client)["source"]; src != "console" {
		t.Errorf("source = %v, want console", src)
	}
}

// The published settings are what is running, never what was asked for. A
// refused override must leave the effective key reporting the old settings.
func TestRefusedOverrideIsNeverPublishedAsEffective(t *testing.T) {
	client, addr := testRedis(t)
	r := &recorder{refuse: func(c config.EnforcementConfig) bool { return c.RateLimit.RequestsPerMinute == 7 }}
	startWatcher(t, addr, r)

	if got := rpm(t, client); got != 100 {
		t.Fatalf("boot rpm = %v, want the file's 100", got)
	}
	bad := base()
	bad.RateLimit.RequestsPerMinute = 7
	override(t, client, bad)

	time.Sleep(300 * time.Millisecond)
	if got := rpm(t, client); got != 100 {
		t.Errorf("effective rpm = %v after a refused override; the console would show a change that is not live", got)
	}
	if src := effective(t, client)["source"]; src != "file" {
		t.Errorf("source = %v, want file", src)
	}
	if _, n := r.last(); n != 0 {
		t.Errorf("applier recorded %d successful applies", n)
	}
}

func TestGarbageOverrideKeepsTheSettingsInForce(t *testing.T) {
	client, addr := testRedis(t)
	good := base()
	good.RateLimit.RequestsPerMinute = 55
	override(t, client, good)
	r := &recorder{}
	startWatcher(t, addr, r)

	if err := client.Set(context.Background(), Key, "{not json", 0).Err(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if got := rpm(t, client); got != 55 {
		t.Errorf("effective rpm = %v after garbage, want 55 still in force", got)
	}
	if _, n := r.last(); n != 1 {
		t.Errorf("applied %d times; garbage must not be applied or re-tried every tick", n)
	}
}

// Deleting the override is "revert to the file": the boot settings come back.
func TestDeletingTheOverrideRevertsToTheFile(t *testing.T) {
	client, addr := testRedis(t)
	changed := base()
	changed.RateLimit.RequestsPerMinute = 33
	override(t, client, changed)
	r := &recorder{}
	startWatcher(t, addr, r)

	if err := client.Del(context.Background(), Key).Err(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "revert to file", func() bool {
		got, _ := r.last()
		return got.RateLimit.RequestsPerMinute == 100
	})
	eventually(t, "file published as effective", func() bool {
		return rpm(t, client) == 100 && effective(t, client)["source"] == "file"
	})
}

// A stopped gateway must stop advertising settings as current.
func TestEffectiveSettingsCarryATTL(t *testing.T) {
	client, addr := testRedis(t)
	startWatcher(t, addr, &recorder{})
	ttl, err := client.PTTL(context.Background(), EffectiveKey).Result()
	if err != nil || ttl <= 0 {
		t.Fatalf("effective key TTL = %v (%v); it must expire when the gateway stops", ttl, err)
	}
}

// Redis being down must never stop the gateway starting, and must not apply
// anything: the file's settings stay in force.
func TestUnreachableRedisStartsOnTheFileSettings(t *testing.T) {
	r := &recorder{}
	w := NewWatcher(Config{Addr: "127.0.0.1:1", Interval: 50 * time.Millisecond}, base(), r.apply)
	done := make(chan struct{})
	go func() { w.Start(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start blocked on an unreachable Redis")
	}
	time.Sleep(120 * time.Millisecond)
	_ = w.Close()
	if _, n := r.last(); n != 0 {
		t.Errorf("applied %d times with no Redis", n)
	}
}

func TestCloseIsSafeBeforeStart(t *testing.T) {
	var nilWatcher *Watcher
	if err := nilWatcher.Close(); err != nil {
		t.Fatal(err)
	}
	if err := NewWatcher(Config{Addr: "127.0.0.1:1"}, base(), (&recorder{}).apply).Close(); err != nil {
		t.Fatal(err)
	}
}
