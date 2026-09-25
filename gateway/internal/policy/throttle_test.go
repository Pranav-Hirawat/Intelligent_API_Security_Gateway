package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// windowQuota is the smallest QuotaLimiter that can say no: the first
// RequestsPerMinute calls for a route pass and later ones are refused. It
// stands in for the Redis bucket, which is the only limiter production wires.
type windowQuota struct {
	mu    sync.Mutex
	seen  map[string]int
	calls int
}

func newWindowQuota() *windowQuota { return &windowQuota{seen: map[string]int{}} }

func (q *windowQuota) Take(_ context.Context, r QuotaRequest) (QuotaResult, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.calls++
	key := r.IP + "\x00" + r.Route + "\x00" + r.Method
	q.seen[key]++
	if q.seen[key] > r.RequestsPerMinute {
		return QuotaResult{RetryAfter: time.Minute}, nil
	}
	return QuotaResult{Allowed: true, Reason: "within_quota"}, nil
}

// The end of the loop the whole feature exists for: a policy naming a rate
// turns into a 429 for the request that exceeds it.
func TestThrottlePolicyEnforcesItsRate(t *testing.T) {
	decision := Decision{Action: ActionThrottle, RequestsPerMinute: 3, CampaignID: "c-1"}
	e := NewEnforcer(fixed{"203.0.113.5": decision}, true).WithQuotaLimiter(newWindowQuota(), 60, 20)

	handler := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	codes := map[int]int{}
	var lastRetry string
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, requestFrom("203.0.113.5"))
		codes[rec.Code]++
		if rec.Code == http.StatusTooManyRequests {
			lastRetry = rec.Header().Get("Retry-After")
		}
	}

	if codes[http.StatusOK] != 3 {
		t.Errorf("allowed %d requests, want 3", codes[http.StatusOK])
	}
	if codes[http.StatusTooManyRequests] != 2 {
		t.Errorf("refused %d requests with 429, want 2", codes[http.StatusTooManyRequests])
	}
	if lastRetry == "" {
		t.Error("a 429 carried no Retry-After")
	}
}

// A throttle with no rate is an older control plane's policy. It must still
// enforce something rather than becoming a pass-through.
func TestThrottleWithoutARateUsesConfiguredFallback(t *testing.T) {
	decision := Decision{Action: ActionThrottle}
	e := NewEnforcer(fixed{"203.0.113.6": decision}, true).WithQuotaLimiter(newWindowQuota(), 1, 1)

	handler := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requestFrom("203.0.113.6"))
	if rec.Code != http.StatusOK {
		t.Errorf("code = %d, want 200: a rateless throttle should still serve", rec.Code)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, requestFrom("203.0.113.6"))
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("legacy policy did not enforce fallback: %d", rec.Code)
	}
}

// An address that is not under policy must never reach the limiter.
func TestUnthrottledAddressIsNotRateLimited(t *testing.T) {
	q := newWindowQuota()
	e := NewEnforcer(fixed{}, true).WithQuotaLimiter(q, 60, 20)
	handler := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 30; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, requestFrom("198.51.100.9"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d got %d, want 200", i, rec.Code)
		}
	}
	if q.calls != 0 {
		t.Error("an address with no policy was recorded by the limiter")
	}
}

type fixed map[string]Decision

func (f fixed) Lookup(ip string) (Decision, bool) {
	d, ok := f[ip]
	return d, ok
}

func requestFrom(ip string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/thing", nil)
	r.RemoteAddr = ip + ":1234"
	return AttachOutcome(r)
}
