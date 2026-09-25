package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/enforcement"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/policy"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
)

// tag records the order middleware runs in.
func tag(order *[]string, name string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*order = append(*order, name)
			next.ServeHTTP(w, r)
		})
	}
}

// The listed order must be the execution order. The security chain depends on
// it: the IP resolver has to run before anything reads the client IP, and the
// enforcer before any detector spends work on a blocked address.
func TestChainRunsInListedOrder(t *testing.T) {
	var order []string

	handler := ChainMiddleware(
		tag(&order, "first"),
		tag(&order, "second"),
		tag(&order, "third"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	got := strings.Join(order, ",")
	if want := "first,second,third,handler"; got != want {
		t.Fatalf("order = %q, want %q", got, want)
	}
}

func TestChainWithNoMiddlewareCallsHandler(t *testing.T) {
	called := false
	handler := ChainMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if !called {
		t.Fatal("handler was not reached")
	}
}

// A middleware that short-circuits must stop everything after it.
func TestChainStopsAtShortCircuit(t *testing.T) {
	var order []string

	blocker := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "blocker")
			w.WriteHeader(http.StatusForbidden)
		})
	}

	handler := ChainMiddleware(
		tag(&order, "before"),
		blocker,
		tag(&order, "after"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if got := strings.Join(order, ","); got != "before,blocker" {
		t.Fatalf("order = %q, want %q", got, "before,blocker")
	}
}

// Login failures are learned only after the backend replies. They are evidence
// for the control plane, never a gateway reflex authority.
func TestBruteForceEvidenceNeverArmsTheGatewayReflex(t *testing.T) {
	const attacker = "203.0.113.44"

	brute := signals.NewBruteForceDetector(config.BruteForceConfig{
		Enabled:     true,
		MaxFailures: 5,
		Window:      time.Minute,
	}, []config.AuthOutcomeConfig{{
		Method: "POST", Template: "/api/login", Success: []int{http.StatusOK}, InvalidCredentials: []int{http.StatusUnauthorized},
	}}, func(method, path string) string {
		if method == http.MethodPost && path == "/api/login" {
			return "/api/login"
		}
		return "<unmatched>"
	})
	collector := signals.NewCollector(brute)
	reflex, err := enforcement.New(enforcement.Config{
		Enabled:     true,
		Duration:    time.Minute,
		Signals:     []string{signals.SignalFlood},
		MinScore:    80,
		ExemptCIDRs: []string{},
	})
	if err != nil {
		t.Fatalf("new reflex: %v", err)
	}

	backendCalls := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalls++
		if r.URL.Path == "/api/login" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// This has the same relevant nesting as Server.Start: enforcement remains
	// outermost, and the reflex observer wraps the response-aware detector.
	handler := ChainMiddleware(
		policy.NewEnforcer(reflex, true).Middleware,
		observedDetectors(reflex, collector, brute.Middleware),
	)(backend)

	for i := 0; i < 5; i++ {
		rec := bruteForceRequest(handler, http.MethodPost, "/api/login", attacker)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d status = %d, want 401", i+1, rec.Code)
		}
	}

	// Five failures fire the detector but score 60, below the reflex floor.
	atFive := brute.Metrics(attacker)
	if !atFive.ThresholdCross || atFive.Int("failedLogins") != 5 || atFive.Score != 60 {
		t.Fatalf("five failures = %+v, want fired score 60 with five failures", atFive)
	}
	if _, found := reflex.Lookup(attacker); found {
		t.Fatal("reflex blocked at score 60")
	}

	for i := 0; i < 5; i++ {
		rec := bruteForceRequest(handler, http.MethodPost, "/api/login", attacker)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d status = %d, want 401", i+6, rec.Code)
		}
	}

	ev := brute.Metrics(attacker)
	if ev.Int("failedLogins") < 10 || ev.Score < 80 || !ev.ThresholdCross {
		t.Fatalf("ten failures = %+v, want at least ten, score >= 80, and fired", ev)
	}
	if _, found := reflex.Lookup(attacker); found {
		t.Fatal("consecutive login evidence armed a gateway reflex block")
	}

	allowed := bruteForceRequest(handler, http.MethodGet, "/api/products", attacker)
	if allowed.Code != http.StatusOK {
		t.Fatalf("request after login evidence = %d, want backend 200", allowed.Code)
	}
	if backendCalls != 11 {
		t.Fatalf("backend calls = %d, want ten login attempts plus the later request", backendCalls)
	}
}

func TestObservedDetectorsStillBlocksFlooding(t *testing.T) {
	const attacker = "203.0.113.47"

	flood := signals.NewFloodDetector(config.RateLimitConfig{
		Enabled:           true,
		RequestsPerMinute: 5,
	})
	collector := signals.NewCollector(flood)
	reflex, err := enforcement.New(enforcement.Config{
		Enabled:     true,
		Duration:    time.Minute,
		Signals:     []string{signals.SignalFlood},
		MinScore:    80,
		ExemptCIDRs: []string{},
	})
	if err != nil {
		t.Fatalf("new reflex: %v", err)
	}

	backendCalls := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendCalls++
		w.WriteHeader(http.StatusOK)
	})
	handler := ChainMiddleware(
		policy.NewEnforcer(reflex, true).Middleware,
		observedDetectors(reflex, collector, flood.Middleware),
	)(backend)

	for i := 0; i < 10; i++ {
		if rec := bruteForceRequest(handler, http.MethodGet, "/api/products", attacker); rec.Code != http.StatusOK {
			t.Fatalf("flood request %d status = %d, want 200", i+1, rec.Code)
		}
	}
	if _, found := reflex.Lookup(attacker); !found {
		t.Fatal("flood evidence did not arm the reflex")
	}
	if rec := bruteForceRequest(handler, http.MethodGet, "/api/products", attacker); rec.Code != http.StatusForbidden {
		t.Fatalf("request after flood reflex block = %d, want 403", rec.Code)
	}
	if backendCalls != 10 {
		t.Fatalf("backend calls = %d, want the ten allowed flood requests only", backendCalls)
	}
}

func bruteForceRequest(handler http.Handler, method, target, ip string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = ip + ":54321"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func ExampleChainMiddleware() {
	logged := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Println("middleware")
			next.ServeHTTP(w, r)
		})
	}

	handler := ChainMiddleware(logged)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("handler")
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	// Output:
	// middleware
	// handler
}

// The liveness probe must not reach anything behind it. Docker polls it every
// thirty seconds for as long as the container runs, so anything it touches sees
// traffic no client sent.
func TestLivenessProbeNeverReachesTheChain(t *testing.T) {
	reached := false
	behind := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	handler := WithLiveness(behind)

	probe := httptest.NewRecorder()
	handler.ServeHTTP(probe, httptest.NewRequest(http.MethodGet, LivenessPath, nil))
	if probe.Code != http.StatusOK {
		t.Fatalf("liveness probe answered %d, want 200", probe.Code)
	}
	if reached {
		t.Fatal("liveness probe was passed through to the handler behind it")
	}

	// Everything else still goes through, including the backend's own health
	// endpoint -- that one belongs to the application and stays observable.
	for _, path := range []string{"/api/health", "/api/products", "/"} {
		reached = false
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
		if !reached {
			t.Fatalf("%s was swallowed; only %s may be answered here", path, LivenessPath)
		}
	}
}
