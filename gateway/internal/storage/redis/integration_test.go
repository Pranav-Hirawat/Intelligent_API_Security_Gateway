package redisstore

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/telemetry"
	"github.com/redis/go-redis/v9"
)

// Its own database: the counters and per-IP keys have fixed names.
const testDB = 12

func liveStore(t *testing.T, tweak func(*config.RedisConfig)) (*Store, config.RedisConfig, *redis.Client) {
	t.Helper()
	addr := os.Getenv("IASG_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set IASG_TEST_REDIS_ADDR to run against a disposable Redis instance")
	}
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	cfg := config.RedisConfig{
		Enabled: true, Host: host, Port: port, DB: testDB,
		StreamMaxLen: 1000, IPLatestTTL: time.Hour, TelemetryWriteTimeout: time.Second,
	}
	if tweak != nil {
		tweak(&cfg)
	}
	client := redis.NewClient(&redis.Options{Addr: addr, DB: testDB})
	if err := client.FlushDB(context.Background()).Err(); err != nil {
		t.Fatalf("redis: %v", err)
	}
	store, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = store.Close()
		_ = client.FlushDB(context.Background()).Err()
		_ = client.Close()
	})
	return store, cfg, client
}

func TestDisabledRedisBuildsNothing(t *testing.T) {
	store, err := New(config.RedisConfig{Enabled: false})
	if store != nil || err != nil {
		t.Fatalf("disabled Redis = %v, %v; want nil, nil", store, err)
	}
	var nilStore *Store
	if nilStore.Arrivals(config.RedisConfig{}) != nil || nilStore.Health(config.RedisConfig{}) != nil {
		t.Error("a nil store handed out writers")
	}
	if err := nilStore.WriteEvent(context.Background(), telemetry.Event{}); err != nil {
		t.Error(err)
	}
	if err := nilStore.Close(); err != nil {
		t.Error(err)
	}
}

// What the console and the control plane read: the stream entry with its
// indexed fields, the counters, the attacker board, and the per-IP latest.
func TestAnEventLandsEverywhereItsReadersLook(t *testing.T) {
	store, _, client := liveStore(t, nil)
	ctx := context.Background()

	clean := telemetry.Event{IP: "203.0.113.5", Path: "/api/health", Decision: "allow"}
	attack := telemetry.Event{IP: "203.0.113.9", Path: "/api/search", Decision: "allow", RiskScore: 90,
		Fired: []string{"sql_injection", "sql_injection", "", "api_flooding"}}
	for _, ev := range []telemetry.Event{clean, attack} {
		if err := store.WriteEvent(ctx, ev); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	entries, err := client.XRange(ctx, KeyEvents, "-", "+").Result()
	if err != nil || len(entries) != 2 {
		t.Fatalf("stream has %d entries (%v), want 2", len(entries), err)
	}
	second := entries[1].Values
	if second["ip"] != "203.0.113.9" || second["fired"] != "sql_injection,sql_injection,,api_flooding" || second["riskScore"] != "90" {
		t.Errorf("indexed fields = %v", second)
	}
	var decoded telemetry.Event
	if err := json.Unmarshal([]byte(second["event"].(string)), &decoded); err != nil || decoded.Seq != 2 {
		t.Errorf("payload seq = %d (%v); the console numbers requests from this", decoded.Seq, err)
	}

	stats, _ := client.HGetAll(ctx, KeyStats).Result()
	want := map[string]string{"requests": "2", "decision:allow": "2", "alerts": "1", "signal:sql_injection": "1", "signal:api_flooding": "1"}
	for k, v := range want {
		if stats[k] != v {
			t.Errorf("stats[%s] = %q, want %q (all: %v)", k, stats[k], v, stats)
		}
	}
	// A repeated signal is one alert of that kind, and an empty name is none.
	if _, ok := stats["signal:"]; ok {
		t.Error("an empty signal name was counted")
	}

	board, _ := client.ZRangeWithScores(ctx, KeyAttackers, 0, -1).Result()
	if len(board) != 1 || board[0].Member != "203.0.113.9" {
		t.Errorf("attacker board = %v; a clean request must not put an address on it", board)
	}

	ttl, _ := client.TTL(ctx, "iasg:ip:203.0.113.5:latest").Result()
	if ttl <= 0 || ttl > time.Hour {
		t.Errorf("per-IP latest TTL = %v, want bounded by ip_latest_ttl", ttl)
	}
}

func TestTheEventStreamIsCapped(t *testing.T) {
	store, _, client := liveStore(t, func(c *config.RedisConfig) { c.StreamMaxLen = 10 })
	ctx := context.Background()
	for i := 0; i < 500; i++ {
		if err := store.WriteEvent(ctx, telemetry.Event{IP: "203.0.113.5"}); err != nil {
			t.Fatal(err)
		}
	}
	// MAXLEN ~ trims in whole nodes, so the bound is loose but must hold.
	if n, _ := client.XLen(ctx, KeyEvents).Result(); n >= 500 {
		t.Errorf("stream length %d after 500 writes with maxlen 10: it is not being trimmed", n)
	}
}

// Arrivals and the heartbeat go to their own streams and never touch the
// counters, which mean "requests the gateway finished handling".
func TestArrivalsAndHeartbeatsHaveTheirOwnStreams(t *testing.T) {
	store, cfg, client := liveStore(t, nil)
	ctx := context.Background()

	arrivals := store.Arrivals(cfg)
	if err := arrivals.WriteEvent(ctx, telemetry.Arrival{RequestID: "r1", IP: "203.0.113.5", Path: "/a"}); err != nil {
		t.Fatal(err)
	}
	health := store.Health(cfg)
	if err := health.WriteEvent(ctx, telemetry.Health{Seq: 7}); err != nil {
		t.Fatal(err)
	}

	a, _ := client.XRange(ctx, KeyArrivals, "-", "+").Result()
	if len(a) != 1 || a[0].Values["requestId"] != "r1" || a[0].Values["ip"] != "203.0.113.5" || a[0].Values["arrival"] == nil {
		t.Errorf("arrival entry = %v", a)
	}
	h, _ := client.XRange(ctx, KeyHealth, "-", "+").Result()
	if len(h) != 1 || h[0].Values["seq"] != "7" || h[0].Values["health"] == nil {
		t.Errorf("health entry = %v", h)
	}
	if n, _ := client.Exists(ctx, KeyStats, KeyAttackers, KeyEvents).Result(); n != 0 {
		t.Errorf("%d request-completion keys written by arrivals/heartbeat; the console would double-count", n)
	}

	var nilArrivals *ArrivalStore
	if err := nilArrivals.WriteEvent(ctx, telemetry.Arrival{}); err != nil {
		t.Error(err)
	}
}

func TestStreamKeysAndCapsFollowConfig(t *testing.T) {
	store, cfg, _ := liveStore(t, func(c *config.RedisConfig) {
		c.ArrivalStreamKey, c.HealthStreamKey = "custom:arrivals", "custom:health"
	})
	if got := store.Arrivals(cfg); got.key != "custom:arrivals" || got.maxLen != cfg.StreamMaxLen {
		t.Errorf("arrivals = %s/%d; an unset arrival cap follows the event stream's", got.key, got.maxLen)
	}
	if got := store.Health(cfg); got.key != "custom:health" || got.maxLen != 86400 {
		t.Errorf("health = %s/%d, want a day of heartbeats by default", got.key, got.maxLen)
	}
	cfg.ArrivalStreamKey, cfg.HealthStreamKey = "", ""
	if store.Arrivals(cfg).key != KeyArrivals || store.Health(cfg).key != KeyHealth {
		t.Error("empty stream keys did not fall back to the defaults the control plane reads")
	}
}
