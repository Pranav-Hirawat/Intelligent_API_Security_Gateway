package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/policy"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
)

// captureWriter stands in for Redis and keeps what telemetry recorded.
type captureWriter struct {
	events []Event
}

func (c *captureWriter) WriteEvent(_ context.Context, ev Event) error {
	c.events = append(c.events, ev)
	return nil
}

func (c *captureWriter) last() Event {
	return c.events[len(c.events)-1]
}

// silenceAlerts hides the detectors' stdout alerts for the duration of fn, so
// a test that deliberately sends an attack does not litter the run output.
func silenceAlerts(t *testing.T, fn func()) {
	t.Helper()

	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, r)
		close(done)
	}()

	fn()

	_ = w.Close()
	os.Stdout = original
	<-done
}

func send(t *testing.T, handler http.Handler, method, target, ip, body string) {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	req.RemoteAddr = ip + ":54321"
	handler.ServeHTTP(httptest.NewRecorder(), req)
}

func firedContains(ev Event, signal string) bool {
	for _, name := range ev.Fired {
		if name == signal {
			return true
		}
	}
	return false
}

// A request the enforcer answers never reaches the detectors. Telemetry must
// then report no signals rather than the attack that got the address blocked:
// the control plane turns every name in Fired into a fresh piece of evidence,
// so replaying one would keep a campaign alive on traffic nobody inspected.
func TestBlockedRequestReportsNoSignalsOfItsOwn(t *testing.T) {
	const attacker = "203.0.113.7"

	sqli := signals.NewSQLiDetector(config.AttackDetectionConfig{Enabled: true})
	collector := signals.NewCollector(sqli)
	writer := &captureWriter{}

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// The chain as it runs when a request is inspected.
	inspected := Middleware(writer, collector, nil, nil)(sqli.Middleware(backend))

	// The chain as it runs once the address is under a block: the enforcer
	// answers before the detectors get a turn.
	enforced := Middleware(writer, collector, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))

	silenceAlerts(t, func() {
		send(t, inspected, http.MethodPost, "/api/login", attacker, `{"email":"' OR 1=1--"}`)
	})

	attack := writer.last()
	if !firedContains(attack, signals.SignalSQLi) {
		t.Fatalf("the attack itself should fire sql_injection, got %v", attack.Fired)
	}

	// Same address, a clean request, blocked before any detector sees it.
	send(t, enforced, http.MethodGet, "/api/health", attacker, "")

	blockedEvent := writer.last()
	if firedContains(blockedEvent, signals.SignalSQLi) {
		t.Fatalf("a blocked request replayed the earlier attack: fired=%v", blockedEvent.Fired)
	}
	if len(blockedEvent.Fired) != 0 {
		t.Fatalf("expected no signals for an uninspected request, got %v", blockedEvent.Fired)
	}
	if blockedEvent.RiskScore != 0 {
		t.Fatalf("expected no risk score for an uninspected request, got %d", blockedEvent.RiskScore)
	}
	if blockedEvent.Status != http.StatusForbidden {
		t.Fatalf("expected the block to be recorded, got status %d", blockedEvent.Status)
	}
}

// The fix must not silence real detection: a request that does reach the
// detectors still reports exactly what it carried.
func TestInspectedRequestsReportTheirOwnSignals(t *testing.T) {
	const ip = "203.0.113.8"

	sqli := signals.NewSQLiDetector(config.AttackDetectionConfig{Enabled: true})
	collector := signals.NewCollector(sqli)
	writer := &captureWriter{}

	handler := Middleware(writer, collector, nil, nil)(sqli.Middleware(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
	)))

	silenceAlerts(t, func() {
		send(t, handler, http.MethodPost, "/api/login", ip, `{"email":"' OR 1=1--"}`)
	})
	if !firedContains(writer.last(), signals.SignalSQLi) {
		t.Fatalf("attack not reported: %v", writer.last().Fired)
	}

	// A clean request from the same address, inspected this time, reports clean.
	send(t, handler, http.MethodGet, "/api/health", ip, "")
	if len(writer.last().Fired) != 0 {
		t.Fatalf("clean request reported signals: %v", writer.last().Fired)
	}
}

func TestSQLiProductSearchTelemetryContainsEvidence(t *testing.T) {
	const ip = "203.0.113.48"

	sqli := signals.NewSQLiDetector(config.AttackDetectionConfig{Enabled: true})
	collector := signals.NewCollector(sqli)
	writer := &captureWriter{}
	backendCalls := 0
	handler := Middleware(writer, collector, nil, nil)(sqli.Middleware(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			backendCalls++
			w.WriteHeader(http.StatusOK)
		},
	)))

	silenceAlerts(t, func() {
		send(t, handler, http.MethodGet, "/api/products/search?q=%27+OR+1%3D1+--", ip, "")
	})

	ev := writer.last()
	if ev.Decision != "allow" || ev.Status != http.StatusOK || backendCalls != 1 {
		t.Fatalf("SQLi request was not forwarded as an allowed request: %+v, calls=%d", ev, backendCalls)
	}
	if !firedContains(ev, signals.SignalSQLi) {
		t.Fatalf("telemetry did not fire SQLi: %v", ev.Fired)
	}
	if len(ev.Signals) != 1 || ev.Signals[0].Signal != signals.SignalSQLi {
		t.Fatalf("telemetry omitted SQLi evidence: %+v", ev.Signals)
	}
	if ev.Signals[0].Int("matchCount") == 0 || len(ev.Signals[0].Strings("matchedPatterns")) == 0 {
		t.Fatalf("telemetry omitted SQLi match details: %+v", ev.Signals[0])
	}
	if ev.Snippet != "" {
		t.Fatalf("GET request unexpectedly acquired a body snippet: %q", ev.Snippet)
	}
}

// The Docker liveness probe must not make an idle console look like it has
// client traffic, but the endpoint itself remains a normal attack surface.
func TestDockerHealthcheckIsOmittedWithoutHidingHealthEndpointAttacks(t *testing.T) {
	sqli := signals.NewSQLiDetector(config.AttackDetectionConfig{Enabled: true})
	collector := signals.NewCollector(sqli)
	writer := &captureWriter{}
	handler := Middleware(writer, collector, nil, nil)(sqli.Middleware(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
	)))

	probe := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	probe.RemoteAddr = "[::1]:54321"
	probe.Header.Set("User-Agent", dockerHealthcheckUserAgent)
	handler.ServeHTTP(httptest.NewRecorder(), probe)
	if len(writer.events) != 0 {
		t.Fatalf("routine Docker healthcheck became telemetry: %+v", writer.events)
	}

	silenceAlerts(t, func() {
		send(t, handler, http.MethodGet, "/api/health?q=%27+OR+1%3D1+--", "203.0.113.48", "")
	})
	if len(writer.events) != 1 || !firedContains(writer.last(), signals.SignalSQLi) {
		t.Fatalf("attack through /api/health was hidden: %+v", writer.events)
	}
}

func TestTelemetryRedactsSensitiveQueryValues(t *testing.T) {
	writer := &captureWriter{}
	handler := Middleware(writer, signals.NewCollector(), nil, nil)(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
	))

	send(t, handler, http.MethodGet,
		"/api/products?q=keyboard&password=not-for-redis&token=also-not-for-redis",
		"203.0.113.49", "")

	if got, want := writer.last().Query,
		"password=%5Bredacted%5D&q=keyboard&token=%5Bredacted%5D"; got != want {
		t.Fatalf("query = %q, want %q", got, want)
	}
}

// Windowed detectors are deliberately unaffected: "this address made N
// requests in the last minute" stays true whether or not the request being
// recorded reached the detector.
func TestWindowedDetectorsStillReportOnBlockedRequests(t *testing.T) {
	const ip = "203.0.113.9"

	flood := signals.NewFloodDetector(config.RateLimitConfig{
		Enabled:           true,
		RequestsPerMinute: 20,
		Burst:             5,
	})
	collector := signals.NewCollector(flood)
	writer := &captureWriter{}

	inspected := Middleware(writer, collector, nil, nil)(flood.Middleware(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
	)))
	enforced := Middleware(writer, collector, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))

	silenceAlerts(t, func() {
		for i := 0; i < 30; i++ {
			send(t, inspected, http.MethodGet, "/api/health", ip, "")
		}
	})

	before := writer.last().Signals
	if len(before) == 0 {
		t.Fatal("flood detector reported nothing while being hammered")
	}

	send(t, enforced, http.MethodGet, "/api/health", ip, "")

	after := writer.last().Signals
	if len(after) != 1 || after[0].Signal != signals.SignalFlood {
		t.Fatalf("windowed evidence disappeared on a blocked request: %+v", after)
	}
	if after[0].Int("requestRate") == 0 {
		t.Fatalf("windowed counts should survive a block, got %+v", after[0].Details)
	}
}

func TestPolicyTelemetryKeepsActionAndOutcomeSeparate(t *testing.T) {
	for _, tc := range []struct {
		name, action, outcome, decision string
		status                          int
	}{
		{"within_quota", "throttle", "allowed", "throttle", http.StatusOK},
		{"quota_exhausted", "throttle", "throttled", "rate_limited", http.StatusTooManyRequests},
		{"blocked", "temp_block", "blocked", "temp_block", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer := &captureWriter{}
			match := policy.Match{
				Action: tc.action, Source: "agent", ClientIP: "203.0.113.60",
				Route: "/api/login", Method: http.MethodPost, RequestsPerMinute: 12,
				Reason: "campaign exceeded login quota", Outcome: tc.outcome,
			}
			handler := Middleware(writer, nil, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				policy.RecordMatch(r, match)
				policy.Record(r, tc.decision)
				w.WriteHeader(tc.status)
			}))
			send(t, handler, http.MethodPost, "/api/login", match.ClientIP, "")
			ev := writer.last()
			if ev.Policy == nil || *ev.Policy != match {
				t.Fatalf("policy context lost: %+v", ev.Policy)
			}
			if ev.Decision != tc.decision || ev.Status != tc.status {
				t.Fatalf("existing outcome fields changed: %+v", ev)
			}
			payload, err := json.Marshal(ev)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal(payload, &document); err != nil {
				t.Fatal(err)
			}
			stored, ok := document["policy"].(map[string]any)
			if !ok || stored["requests_per_minute"] != float64(12) || stored["source"] != "agent" {
				t.Fatalf("stored policy schema lost limit/source: %s", payload)
			}
		})
	}
}

func TestBodyCapturePreservesPayloadAndRedactsOnlyTheEvent(t *testing.T) {
	const payload = `{"password":"never-store-this","user":"jay"}`
	writer := &captureWriter{}
	var backendBody string
	handler := Middleware(writer, nil, nil, nil)(CaptureBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		backendBody = string(body)
	})))
	send(t, handler, http.MethodPost, "/api/login", "203.0.113.60", payload)
	if backendBody != payload {
		t.Fatalf("backend body changed to %q", backendBody)
	}
	if got := writer.last().Snippet; got != `{"password":"[redacted]","user":"jay"}` {
		t.Fatalf("stored snippet = %q", got)
	}
}

func TestNoRedisWriterStillAssignsRequestIDsAndLogsPolicyContext(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	defer slog.SetDefault(previous)
	var requestIDs []string
	handler := Middleware(nil, nil, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestIDs = append(requestIDs, r.Header.Get(signals.RequestIDHeader))
		policy.RecordMatch(r, policy.Match{
			Action: "temp_block", Source: "agent", ClientIP: "203.0.113.60",
			Route: "/api/login", Method: http.MethodPost, Reason: "active campaign", Outcome: "blocked",
		})
		policy.Record(r, "temp_block")
		w.WriteHeader(http.StatusForbidden)
	}))
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
		req.Header.Set(signals.RequestIDHeader, "attacker-chosen-id")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if id := rec.Header().Get(signals.RequestIDHeader); id == "" || id == "attacker-chosen-id" || id != requestIDs[i] {
			t.Fatalf("request ID was absent, trusted client input, or differed: %q", id)
		}
	}
	if requestIDs[0] == requestIDs[1] {
		t.Fatal("requests share an ID without Redis, which could replay detector evidence")
	}
	var entry map[string]any
	if err := json.NewDecoder(&output).Decode(&entry); err != nil {
		t.Fatal(err)
	}
	if entry["msg"] != "policy_match" || entry["policy_source"] != "agent" || entry["status"] != float64(403) || entry["reason"] != "active campaign" {
		t.Fatalf("structured policy fallback missing: %+v", entry)
	}
}

// The route table has to actually reach the recorded event. Wiring it into the
// server but not into the middleware would leave every request recording
// <unmatched> with nothing failing.
func TestEventRecordsTheMatchedRouteTemplate(t *testing.T) {
	writer := &captureWriter{}
	routes, err := NewTable([]string{"GET /api/products/{id}", "GET /api/products/search"})
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	handler := Middleware(writer, nil, routes, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		target string
		want   string
	}{
		{"/api/products/12", "/api/products/{id}"},
		{"/api/products/34", "/api/products/{id}"},
		{"/api/products/search", "/api/products/search"},
		{"/wp-admin", UnmatchedRoute},
	}

	for _, tc := range cases {
		send(t, handler, http.MethodGet, tc.target, "203.0.113.5", "")
		if got := writer.last().RouteTemplate; got != tc.want {
			t.Errorf("%s recorded routeTemplate %q, want %q", tc.target, got, tc.want)
		}
	}
}

// The path is what the anomaly features measure diversity on, and it is what
// the traversal detector matches against. Cleaning it here would erase both.
func TestEventKeepsTraversalSegmentsInThePath(t *testing.T) {
	writer := &captureWriter{}
	handler := Middleware(writer, nil, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	send(t, handler, http.MethodGet, "/api/../../etc/passwd", "203.0.113.5", "")

	if got := writer.last().Path; !strings.Contains(got, "..") {
		t.Errorf("recorded path %q lost its traversal segments", got)
	}
}

// A gateway with no route table must still produce a consistent column rather
// than an empty string that reads as missing data.
func TestNoRouteTableStillRecordsACategory(t *testing.T) {
	writer := &captureWriter{}
	handler := Middleware(writer, nil, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	send(t, handler, http.MethodGet, "/api/products", "203.0.113.5", "")

	if got := writer.last().RouteTemplate; got != UnmatchedRoute {
		t.Errorf("recorded routeTemplate %q, want %q", got, UnmatchedRoute)
	}
}
