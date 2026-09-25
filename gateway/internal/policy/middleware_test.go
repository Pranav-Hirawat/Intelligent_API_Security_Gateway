package policy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeLookup stands in for the Redis-backed store.
type fakeLookup map[string]Decision

func (f fakeLookup) Lookup(ip string) (Decision, bool) {
	d, ok := f[ip]
	return d, ok
}

// run sends one request from ip and reports the status and whether it reached
// the backend.
func run(t *testing.T, e *Enforcer, ip string) (int, bool) {
	t.Helper()

	reached := false
	handler := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/login", nil)
	req.RemoteAddr = ip + ":54321"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	return rec.Code, reached
}

func TestUnknownIPPassesThrough(t *testing.T) {
	e := NewEnforcer(fakeLookup{}, true)

	if code, reached := run(t, e, "203.0.113.5"); code != http.StatusOK || !reached {
		t.Fatalf("want 200 and backend reached, got %d reached=%v", code, reached)
	}
}

func TestTempBlockIsRejected(t *testing.T) {
	e := NewEnforcer(fakeLookup{
		"203.0.113.5": {Action: ActionTempBlock, CampaignID: "1", ExpiresIn: 1800},
	}, true)

	code, reached := run(t, e, "203.0.113.5")
	if code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", code)
	}
	if reached {
		t.Fatal("blocked request reached the backend")
	}
}

func TestEscalateIsRejected(t *testing.T) {
	e := NewEnforcer(fakeLookup{
		"203.0.113.9": {Action: ActionEscalate, CampaignID: "2"},
	}, true)

	if code, _ := run(t, e, "203.0.113.9"); code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", code)
	}
}

func TestMonitorDoesNotBlock(t *testing.T) {
	e := NewEnforcer(fakeLookup{
		"203.0.113.5": {Action: ActionMonitor},
	}, true)

	if code, reached := run(t, e, "203.0.113.5"); code != http.StatusOK || !reached {
		t.Fatalf("monitor must not block, got %d reached=%v", code, reached)
	}
}

// A typo or a newer action from the control plane must not take the API down.
func TestUnrecognisedActionFailsOpen(t *testing.T) {
	e := NewEnforcer(fakeLookup{
		"203.0.113.5": {Action: "quarantine_forever"},
	}, true)

	if code, reached := run(t, e, "203.0.113.5"); code != http.StatusOK || !reached {
		t.Fatalf("unknown action must pass through, got %d reached=%v", code, reached)
	}
}

func TestDisabledEnforcerIgnoresPolicy(t *testing.T) {
	e := NewEnforcer(fakeLookup{
		"203.0.113.5": {Action: ActionTempBlock},
	}, false)

	if code, reached := run(t, e, "203.0.113.5"); code != http.StatusOK || !reached {
		t.Fatalf("disabled enforcer must not block, got %d reached=%v", code, reached)
	}
}

func TestThrottleNeverSleeps(t *testing.T) {
	e := NewEnforcer(fakeLookup{
		"203.0.113.5": {Action: ActionThrottle},
	}, true)

	start := time.Now()
	code, reached := run(t, e, "203.0.113.5")
	elapsed := time.Since(start)

	if code != http.StatusOK || !reached {
		t.Fatalf("throttle must still forward, got %d reached=%v", code, reached)
	}
	if elapsed > time.Second {
		t.Fatalf("throttle delayed a request: %v", elapsed)
	}
}

func TestBlockSetsRetryAfter(t *testing.T) {
	e := NewEnforcer(fakeLookup{
		"203.0.113.5": {Action: ActionTempBlock, ExpiresIn: 1800},
	}, true)

	handler := e.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Retry-After"); got != "1800" {
		t.Fatalf("want Retry-After 1800, got %q", got)
	}
}

// The response must not tell the caller which campaign they tripped.
func TestBlockResponseLeaksNothing(t *testing.T) {
	e := NewEnforcer(fakeLookup{
		"203.0.113.5": {
			Action:     ActionTempBlock,
			CampaignID: "7",
			Confidence: 0.97,
			Reason:     "Credential Stuffing (campaign 7)",
		},
	}, true)

	handler := e.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	for _, leak := range []string{"campaign", "Credential", "0.97", "7"} {
		if strings.Contains(body, leak) {
			t.Fatalf("response body leaked %q: %s", leak, body)
		}
	}
}

// The control plane writes this exact shape; if the contract drifts, this
// breaks before production does.
func TestDecisionParsesControlPlaneJSON(t *testing.T) {
	raw := `{"action": "escalate", "campaign_id": "2", "confidence": 1.0,` +
		` "reason": "Credential Stuffing (campaign 2), confidence 1.00, severity high",` +
		` "issued_at": "2026-08-12T06:30:30.270057+00:00", "expires_in": 1800}`

	var d Decision
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatalf("cannot parse control-plane policy: %v", err)
	}

	if d.Action != ActionEscalate {
		t.Errorf("action = %q, want %q", d.Action, ActionEscalate)
	}
	if d.CampaignID != "2" {
		t.Errorf("campaign_id = %q, want 2", d.CampaignID)
	}
	if d.ExpiresIn != 1800 {
		t.Errorf("expires_in = %d, want 1800", d.ExpiresIn)
	}
}

func TestRetryAfterRoundsUpAndUsesRemainingLifetime(t *testing.T) {
	e := NewEnforcer(nil, true)
	w := httptest.NewRecorder()
	e.rateLimited(w, 1100*time.Millisecond)
	if w.Header().Get("Retry-After") != "2" {
		t.Fatal("fractional refill time was rounded down")
	}
	w = httptest.NewRecorder()
	e.deny(w, Decision{ExpiresIn: 600, ExpiresAt: time.Now().Add(1500 * time.Millisecond)})
	if w.Header().Get("Retry-After") != "2" {
		t.Fatal("block advertised its original rather than remaining lifetime")
	}
}
