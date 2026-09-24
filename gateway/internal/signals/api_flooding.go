/*
	API Flood detection signal
		- Tracks how many requests each IP sends inside a sliding window
		- If the count exceeds the configured threshold, logs a security alert
		- Exposes Metrics(ip) for the future decision engine
		- DOES NOT BLOCK. Every request is forwarded to the backend.

	Core Idea
		“ For each IP address, track how many requests they send within a time window. ”

	Sharding
		IPs are split across 32 buckets so each bucket has its own mutex.
*/

package signals

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

// floodClientData stores the timestamps of recent requests for a specific IP.
type floodClientData struct {
	Requests []time.Time
}

// floodTunables is everything the console can move at runtime. It is swapped
// whole rather than field by field, so a request either sees the old settings
// or the new ones and never a mix of the two.
type floodTunables struct {
	enabled   bool
	threshold int
}

// FloodDetector manages request tracking across multiple shards to reduce lock contention.
type FloodDetector struct {
	// One atomic load per request, no lock on the hot path.
	tun    atomic.Pointer[floodTunables]
	shards []*floodShard
	window time.Duration
}

// settings returns the tunables in force right now. Never nil: the constructor
// always stores a value before the detector can be reached.
func (fd *FloodDetector) settings() floodTunables {
	return *fd.tun.Load()
}

// Apply swaps in new settings. The per-IP request history is deliberately left
// alone: a caller who is mid-flood should not get a clean slate because someone
// opened the settings page.
func (fd *FloodDetector) Apply(cfg config.RateLimitConfig) {
	fd.tun.Store(&floodTunables{
		enabled:   cfg.Enabled,
		threshold: floodThreshold(cfg),
	})
}

func floodThreshold(cfg config.RateLimitConfig) int {
	if cfg.RequestsPerMinute <= 0 {
		return 100
	}
	return cfg.RequestsPerMinute
}

type floodShard struct {
	mu      sync.Mutex
	clients map[string]*floodClientData
}

func NewFloodDetector(cfg config.RateLimitConfig) *FloodDetector {
	// The shards are built even when the detector starts disabled, so that
	// enabling it from the console is a flag flip rather than an allocation --
	// a disabled detector that returned an empty struct would panic on the
	// first request after being switched on.
	numShards := 32
	fd := &FloodDetector{
		shards: make([]*floodShard, numShards),
		window: time.Minute,
	}
	fd.Apply(cfg)

	for i := 0; i < numShards; i++ {
		fd.shards[i] = &floodShard{
			clients: make(map[string]*floodClientData),
		}
	}

	go fd.startCleanupTimer()
	return fd
}

func (fd *FloodDetector) getShard(ip string) *floodShard {
	var hash uint32
	for i := 0; i < len(ip); i++ {
		hash = 31*hash + uint32(ip[i])
	}
	return fd.shards[hash%uint32(len(fd.shards))]
}

func (fd *FloodDetector) startCleanupTimer() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		now := time.Now()
		for _, shard := range fd.shards {
			shard.mu.Lock()
			for ip, client := range shard.clients {
				if len(client.Requests) == 0 || now.Sub(client.Requests[len(client.Requests)-1]) > fd.window {
					delete(shard.clients, ip)
				}
			}
			shard.mu.Unlock()
		}
	}
}

func (fd *FloodDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read once per request: the settings can change underneath a request
		// otherwise, and counting against one threshold while alerting on
		// another would be a confusing way to fail.
		tun := fd.settings()
		if !tun.enabled || tun.threshold <= 0 {
			next.ServeHTTP(w, r)
			return
		}

		ip := netutil.ClientIP(r)
		now := time.Now()
		shard := fd.getShard(ip)

		shard.mu.Lock()
		if _, exists := shard.clients[ip]; !exists {
			shard.clients[ip] = &floodClientData{}
		}
		client := shard.clients[ip]
		client.Requests = trimExpired(client.Requests, now.Add(-fd.window))
		client.Requests = append(client.Requests, now)
		requestCount := len(client.Requests)
		shard.mu.Unlock()

		if requestCount > tun.threshold {
			fd.logAlert(ip, r, requestCount, tun.threshold)
		}

		next.ServeHTTP(w, r)
	})
}

// Metrics returns flood evidence for an IP. Safe to call concurrently.
func (fd *FloodDetector) Metrics(ip string) Evidence {
	tun := fd.settings()
	ev := Evidence{Signal: SignalFlood, Details: map[string]any{
		"requestRate": 0,
		"threshold":   tun.threshold,
		"window":      fd.window.String(),
	}}
	if !tun.enabled || len(fd.shards) == 0 {
		return ev
	}

	shard := fd.getShard(ip)
	shard.mu.Lock()
	client, exists := shard.clients[ip]
	count := 0
	if exists {
		count = len(trimExpired(client.Requests, time.Now().Add(-fd.window)))
	}
	shard.mu.Unlock()

	crossed := count > tun.threshold
	ev.Details["requestRate"] = count
	score := ratioScore(count, tun.threshold)
	if count == tun.threshold {
		// ratioScore's boundary is inclusive (count == threshold scores 60,
		// "at threshold"). Flood's is exclusive -- count == threshold is
		// still clean, matching `crossed` above -- so only this one case is
		// overridden, with ratioScore's own below-threshold formula
		// (count*30/threshold), rather than shifting the whole curve or
		// carrying a second copy of it. That formula is exactly 30 whenever
		// count == threshold; written out so the boundary stays visibly tied
		// to ratioScore's shape instead of becoming its own magic number.
		score = count * 30 / tun.threshold
	}
	ev.Score = score
	ev.ThresholdCross = crossed
	if crossed {
		ev.AttackType = SignalFlood
	}
	return ev
}

func trimExpired(times []time.Time, cutoff time.Time) []time.Time {
	firstValid := len(times)
	for i, t := range times {
		if t.After(cutoff) {
			firstValid = i
			break
		}
	}
	return times[firstValid:]
}

func (fd *FloodDetector) logAlert(ip string, r *http.Request, count, threshold int) {
	severity := "LOW"
	if count > threshold*5 {
		severity = "HIGH"
	} else if count > threshold*2 {
		severity = "MEDIUM"
	}

	fmt.Printf(`
			========================================
			SECURITY ALERT: API FLOOD DETECTED
			----------------------------------------
			IP Address     : %s
			Endpoint       : %s
			Requests       : %d
			Time Window    : %s
			User-Agent     : %s
			Severity       : %s
			Timestamp      : %s
			ACTION         : DETECTED (ALLOWING REQUEST)
			========================================
			`,
		ip,
		r.URL.Path,
		count,
		fd.window,
		r.Header.Get("User-Agent"),
		severity,
		time.Now().Format(time.RFC3339),
	)
}
