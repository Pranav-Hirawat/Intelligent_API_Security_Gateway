package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

func policyRequest(h http.Handler, method, path, peer, forwarded string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = peer
	r.Header.Set("X-Forwarded-For", forwarded)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, AttachOutcome(r))
	return w
}

// Exercise the contract through HTTP so an atomic bucket alone cannot hide a
// wiring error in the client resolver, policy lookup, or action mapping.
func TestRedisHTTPPolicyLifecycle(t *testing.T) {
	s, l, q := redisFixture(t)
	var forwarded atomic.Int64
	resolver, err := netutil.NewResolver([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	h := resolver.Middleware(NewEnforcer(s, true).WithQuotaLimiter(l, 1, 1).Middleware(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			forwarded.Add(1)
			w.WriteHeader(http.StatusOK)
		})))
	send := func(method, path, ip string, want int) *httptest.ResponseRecorder {
		t.Helper()
		before := forwarded.Load()
		w := policyRequest(h, method, path, "127.0.0.1:4321", ip)
		if w.Code != want {
			t.Fatalf("%s %s from %s: got %d want %d", method, path, ip, w.Code, want)
		}
		if got := forwarded.Load() - before; (want == http.StatusOK && got != 1) || (want != http.StatusOK && got != 0) {
			t.Fatalf("status %d forwarded %d times", want, got)
		}
		return w
	}
	set := func(d Decision, ttl time.Duration) {
		t.Helper()
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.client.Set(context.Background(), q.Decision.redisKey, raw, ttl).Err(); err != nil {
			t.Fatal(err)
		}
		if err := s.refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	send("POST", "/api/login", "203.0.113.99", http.StatusOK)
	send("POST", "/api/login", q.IP, http.StatusOK)
	w := send("POST", "/api/login?attempt=2", q.IP, http.StatusTooManyRequests)
	if retry, err := strconv.Atoi(w.Header().Get("Retry-After")); err != nil || retry < 1 || retry > 60 {
		t.Fatalf("invalid Retry-After: %q", w.Header().Get("Retry-After"))
	}
	send("POST", "/api/products", q.IP, http.StatusOK)
	send("GET", "/api/login", q.IP, http.StatusOK)

	// A client connected directly cannot impersonate the policy's IP through
	// a forwarding header, nor change its own identity to escape its quota.
	w = policyRequest(h, "POST", "/api/login", "203.0.113.99:4321", q.IP)
	if w.Code != http.StatusOK {
		t.Fatalf("untrusted forwarding header invented enforcement: %d", w.Code)
	}
	w = policyRequest(h, "POST", "/api/login", q.IP+":4321", "203.0.113.99")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed IP bypassed quota: %d", w.Code)
	}

	for _, action := range []string{ActionAllow, ActionMonitor, "unknown"} {
		set(Decision{Action: action}, time.Minute)
		for i := 0; i < 3; i++ {
			send("POST", "/api/login", q.IP, http.StatusOK)
		}
	}
	for _, action := range []string{ActionBlock, ActionTempBlock, ActionEscalate} {
		set(Decision{Action: action, ExpiresIn: 600}, 150*time.Millisecond)
		send("POST", "/api/login", q.IP, http.StatusForbidden)
		// No background refresh is running. Both throttle and block release
		// themselves even though expires_in claims a much longer lifetime.
		time.Sleep(170 * time.Millisecond)
		send("POST", "/api/login", q.IP, http.StatusOK)
	}
	set(Decision{Action: ActionThrottle, RequestsPerMinute: 1, ExpiresIn: 600}, 150*time.Millisecond)
	send("POST", "/api/login", q.IP, http.StatusOK)
	send("POST", "/api/login", q.IP, http.StatusTooManyRequests)
	time.Sleep(170 * time.Millisecond)
	send("POST", "/api/login", q.IP, http.StatusOK)
}

func TestRedisHTTPReplicasShareQuota(t *testing.T) {
	s, first, q := redisFixture(t)
	second := NewRedisLimiter(Config{Addr: first.client.Options().Addr, BucketPrefix: first.prefix, RedisTimeout: 2 * time.Second, PoolSize: 64})
	defer second.Close()
	var forwarded atomic.Int64
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { forwarded.Add(1); w.WriteHeader(http.StatusOK) })
	handlers := []http.Handler{
		NewEnforcer(s, true).WithQuotaLimiter(first, 1, 1).Middleware(backend),
		NewEnforcer(s, true).WithQuotaLimiter(second, 1, 1).Middleware(backend),
	}
	var allowed, denied, unexpected atomic.Int64
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 80; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			<-start
			switch policyRequest(handlers[i%2], "POST", "/api/login", q.IP+":4321", "").Code {
			case http.StatusOK:
				allowed.Add(1)
			case http.StatusTooManyRequests:
				denied.Add(1)
			default:
				unexpected.Add(1)
			}
		}(i)
	}
	close(start)
	workers.Wait()
	if allowed.Load() != 1 || denied.Load() != 79 || unexpected.Load() != 0 || forwarded.Load() != 1 {
		t.Fatalf("shared HTTP quota: allowed=%d denied=%d unexpected=%d forwarded=%d", allowed.Load(), denied.Load(), unexpected.Load(), forwarded.Load())
	}
}

func TestHTTPRedisOutageFailsOpen(t *testing.T) {
	l := NewRedisLimiter(Config{Addr: "127.0.0.1:1", RedisTimeout: 20 * time.Millisecond, FailureBackoff: time.Second})
	defer l.Close()
	e := NewEnforcer(fakeLookup{"203.0.113.5": {Action: ActionThrottle, RequestsPerMinute: 1}}, true).WithQuotaLimiter(l, 1, 1)
	for i := 0; i < 3; i++ {
		if code, reached := run(t, e, "203.0.113.5"); code != http.StatusOK || !reached {
			t.Fatalf("outage interrupted forwarding: %d reached=%v", code, reached)
		}
	}
}

func TestScopedPolicyPreservesOtherSourceOutsideItsScope(t *testing.T) {
	chain := Chain{
		fakeLookup{"203.0.113.5": {Action: ActionAllow, Route: "/api/login", Method: "POST"}},
		fakeLookup{"203.0.113.5": {Action: ActionTempBlock}},
	}
	h := NewEnforcer(chain, true).Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	for _, tc := range []struct {
		method, route string
		want          int
	}{
		{"POST", "/api/login", 200}, {"GET", "/api/login", 403}, {"POST", "/api/products", 403},
	} {
		if w := policyRequest(h, tc.method, tc.route, "203.0.113.5:4321", ""); w.Code != tc.want {
			t.Fatalf("%s %s returned %d want %d", tc.method, tc.route, w.Code, tc.want)
		}
	}
}
