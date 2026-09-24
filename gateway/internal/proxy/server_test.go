package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/enforcement"
)

// stubBackend answers like the demo API: orders belong to user (id % 3) + 1.
func stubBackend(t *testing.T) *httptest.Server {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/api/orders/") {
			id := strings.TrimPrefix(r.URL.Path, "/api/orders/")
			owner := int(id[0]-'0')%3 + 1
			_ = json.NewEncoder(w).Encode(map[string]any{"order": map[string]any{"id": id, "userId": owner}})
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(backend.Close)
	return backend
}

// shippedConfig is what the gateway actually boots with, pointed at a stub
// backend and with Redis off. Testing the real file means a section added to it
// that the server does not wire shows up here rather than in production.
func shippedConfig(t *testing.T, backend string) Config {
	t.Helper()
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "config.yaml"))
	if err != nil {
		t.Fatalf("the shipped config no longer loads: %v", err)
	}
	cfg.Proxy.BackendURL = backend
	cfg.Storage.Redis.Enabled = false
	list := filepath.Join(t.TempDir(), "reputation.txt")
	if err := os.WriteFile(list, []byte("203.0.113.99\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Enforcement.IPReputation.FeedPath = list
	return ConfigFrom(cfg)
}

func buildHandler(t *testing.T, cfg Config) http.Handler {
	t.Helper()
	var cleanup cleanups
	handler, err := NewServer(cfg).handler(&cleanup)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	t.Cleanup(cleanup.run)
	return handler
}

// fromClient sends a request as if a trusted proxy had forwarded it for ip.
func fromClient(handler http.Handler, method, path, ip string, body io.Reader, header map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, body)
	r.RemoteAddr = "127.0.0.1:40000"
	r.Header.Set("X-Forwarded-For", ip)
	for k, v := range header {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	return rec
}

func token(secret, sub string) string {
	part := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signing := part(map[string]string{"alg": "HS256", "typ": "JWT"}) + "." +
		part(map[string]any{"sub": sub, "exp": time.Now().Add(time.Hour).Unix()})
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestShippedConfigServesTrafficThroughTheWholeChain(t *testing.T) {
	handler := buildHandler(t, shippedConfig(t, stubBackend(t).URL))

	rec := fromClient(handler, http.MethodGet, "/api/health", "203.0.113.10", nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("a clean request = %d %q, want the backend's 200", rec.Code, rec.Body.String())
	}
}

// Invariant 1: detectors report and allow. An injection attempt still reaches
// the backend; only a decision made earlier may refuse it.
func TestDetectorsNeverRefuseTheRequestThatTrippedThem(t *testing.T) {
	handler := buildHandler(t, shippedConfig(t, stubBackend(t).URL))

	rec := fromClient(handler, http.MethodGet, "/api/products/search?q=%27%20OR%201%3D1%20--", "203.0.113.11", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("a request that tripped SQLi = %d, want the backend's 200", rec.Code)
	}
}

// The gateway's own reflex acts on the request after the one that fired it.
func TestTraversalArmsTheReflexForTheNextRequest(t *testing.T) {
	handler := buildHandler(t, shippedConfig(t, stubBackend(t).URL))
	const ip = "203.0.113.12"

	if rec := fromClient(handler, http.MethodGet, "/api/demo-files?f=../../etc/passwd", ip, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("the request that fired = %d, want 200", rec.Code)
	}
	rec := fromClient(handler, http.MethodGet, "/api/health", ip, nil, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("the next request from that address = %d, want 403", rec.Code)
	}
	if other := fromClient(handler, http.MethodGet, "/api/health", "203.0.113.13", nil, nil); other.Code != http.StatusOK {
		t.Errorf("an unrelated address = %d, want 200", other.Code)
	}
}

// Invariant 6: a body cap sits above everything that reads a body.
func TestOversizedBodyIsRefusedBeforeAnyStageReadsIt(t *testing.T) {
	cfg := shippedConfig(t, stubBackend(t).URL)
	cfg.MaxBodyBytes = 16
	handler := buildHandler(t, cfg)

	rec := fromClient(handler, http.MethodPost, "/api/orders", "203.0.113.14", strings.NewReader(strings.Repeat("x", 64)),
		map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a 64-byte body under a 16-byte cap = %d, want 413", rec.Code)
	}
}

func TestListedAddressStillReachesTheBackendUntilPolicyNamesIt(t *testing.T) {
	handler := buildHandler(t, shippedConfig(t, stubBackend(t).URL))
	for i := 0; i < 2; i++ {
		if rec := fromClient(handler, http.MethodGet, "/api/health", "203.0.113.99", nil, nil); rec.Code != http.StatusOK {
			t.Fatalf("request %d from a listed address = %d: reputation alone must not enforce", i, rec.Code)
		}
	}
}

// Someone else's order is answered 404 by the gateway and never leaves it.
func TestOwnershipGuardHidesAnotherUsersOrder(t *testing.T) {
	cfg := shippedConfig(t, stubBackend(t).URL)
	handler := buildHandler(t, cfg)
	secret := cfg.Identity.JWT.Secret
	auth := func(sub string) map[string]string {
		return map[string]string{"Authorization": "Bearer " + token(secret, sub)}
	}

	// Order 1 belongs to user 2, order 2 to user 3.
	if rec := fromClient(handler, http.MethodGet, "/api/orders/1", "203.0.113.20", nil, auth("2")); rec.Code != http.StatusOK {
		t.Errorf("own order = %d, want 200", rec.Code)
	}
	if rec := fromClient(handler, http.MethodGet, "/api/orders/2", "203.0.113.20", nil, auth("2")); rec.Code != http.StatusNotFound {
		t.Errorf("someone else's order = %d, want 404", rec.Code)
	}
	if rec := fromClient(handler, http.MethodGet, "/api/orders/1", "203.0.113.20", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", rec.Code)
	}
}

// A configuration that cannot be honoured stops the gateway; it never starts
// half-armed.
func TestBadConfigurationStopsTheGateway(t *testing.T) {
	backend := stubBackend(t).URL
	cases := map[string]func(*Config){
		"trusted proxy that is not a CIDR":   func(c *Config) { c.TrustedProxies = []string{"not-a-cidr"} },
		"route template that cannot compile": func(c *Config) { c.Routes.Templates = []string{"GET"} },
		"reputation list that is missing":    func(c *Config) { c.Enforcement.IPReputation.FeedPath = "/nonexistent/list.txt" },
		"exempt range that is not a CIDR":    func(c *Config) { c.Enforcement.Block.ExemptCIDRs = []string{"nope"} },
		"ownership with no way to verify tokens": func(c *Config) {
			c.Identity.JWT.Secret, c.Identity.JWT.SecretEnv = "", "IASG_TEST_UNSET_SECRET"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := shippedConfig(t, backend)
			mutate(&cfg)
			var cleanup cleanups
			defer cleanup.run()
			if _, err := NewServer(cfg).handler(&cleanup); err == nil {
				t.Fatal("the gateway started with a configuration it cannot honour")
			}
		})
	}
}

func TestLiveSettingsChangeMovesEveryDetector(t *testing.T) {
	cfg := shippedConfig(t, stubBackend(t).URL)
	var cleanup cleanups
	defer cleanup.run()
	feed, err := startReputationFeed(cfg.Enforcement.IPReputation, &cleanup)
	if err != nil {
		t.Fatal(err)
	}
	detectors := newDetectors(cfg.Enforcement, cfg.Routes, feed, nil, nil, nil)
	reflex, err := enforcement.New(reflexConfig(cfg.Enforcement.Block))
	if err != nil {
		t.Fatal(err)
	}
	enforcer, gate, closePolicy, err := NewServer(cfg).newEnforcer(reflex)
	if err != nil {
		t.Fatal(err)
	}
	defer closePolicy()
	l := live{detectors, reflex, enforcer, gate}

	// A setting the reflex refuses leaves everything as it was.
	bad := cfg.Enforcement
	bad.Block.ExemptCIDRs = []string{"nope"}
	if err := l.apply(bad); err == nil {
		t.Fatal("an unparseable exempt range was accepted")
	}

	off := cfg.Enforcement
	off.AttackDetection.Enabled = false
	if err := l.apply(off); err != nil {
		t.Fatalf("apply: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/x?q=UNION+SELECT+1", nil)
	rec := httptest.NewRecorder()
	detectors.sqli.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec, r)
	if ev := detectors.sqli.Metrics("192.0.2.1"); ev.ThresholdCross {
		t.Errorf("SQLi still fires after being switched off: %+v", ev)
	}
	if ev := detectors.collector().SnapshotFor("192.0.2.1", "").Evidence; len(ev) != 8 {
		t.Errorf("collector reads %d detectors, want all 8", len(ev))
	}
}

func TestConfigHelpers(t *testing.T) {
	if got := maxBodyBytes(0); got != DefaultMaxBodyBytes {
		t.Errorf("maxBodyBytes(0) = %d, want the default: the cap cannot be removed", got)
	}
	if got := maxBodyBytes(-5); got != DefaultMaxBodyBytes {
		t.Errorf("maxBodyBytes(-5) = %d, want the default", got)
	}
	if got := maxBodyBytes(100); got != 100 {
		t.Errorf("maxBodyBytes(100) = %d", got)
	}

	if src := reputationSourceFrom(config.IPReputationConfig{FeedPath: "p"}); src.Timeout != 10*time.Second || src.Path != "p" {
		t.Errorf("reputation source = %+v, want a 10s default timeout", src)
	}

	rules := authRulesFrom([]config.AuthOutcomeConfig{{Method: "POST", Template: "/api/login", Success: []int{200}, InvalidCredentials: []int{401}}})
	if len(rules) != 1 || rules[0].Template != "/api/login" || rules[0].InvalidCredentials[0] != 401 {
		t.Errorf("auth rules = %+v", rules)
	}

	got := reflexConfig(config.BlockConfig{Enabled: true, Duration: time.Minute, Signals: []string{"a"}, MinScore: 7})
	if !got.Enabled || got.Duration != time.Minute || got.MinScore != 7 || got.Signals[0] != "a" {
		t.Errorf("reflex config = %+v", got)
	}
}

func TestBaselineOnlyExistsWhenEnforcementIsSwitchedOn(t *testing.T) {
	off, err := baselineFrom(config.RateLimitConfig{RequestsPerMinute: 100}, config.BlockConfig{})
	if err != nil || off.RequestsPerMinute != 0 {
		t.Errorf("a flood threshold without enforce = %+v, %v; noticing is not refusing", off, err)
	}
	on, err := baselineFrom(config.RateLimitConfig{Enforce: true, RequestsPerMinute: 100}, config.BlockConfig{})
	if err != nil || on.RequestsPerMinute != 100 || len(on.Exempt) == 0 {
		t.Errorf("enforced baseline = %+v, %v; want the default exempt ranges", on, err)
	}
	if _, err := baselineFrom(config.RateLimitConfig{Enforce: true, RequestsPerMinute: 100}, config.BlockConfig{ExemptCIDRs: []string{"x"}}); err == nil {
		t.Error("a bad exempt range was accepted")
	}
}

// A streamed answer must survive the CORS wrapper: the reverse proxy flushes
// through it.
func TestGatewayAnswerCORSKeepsFlushingAndLabelsRefusals(t *testing.T) {
	handler := GatewayAnswerCORS([]string{"http://localhost:5175"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "chunk")
		w.(http.Flusher).Flush()
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "http://localhost:5175")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5175" {
		t.Errorf("allowed origin = %q", got)
	}
	if !rec.Flushed || rec.Body.String() != "chunk" {
		t.Errorf("flushed=%v body=%q; the wrapper broke streaming", rec.Flushed, rec.Body.String())
	}
}

func TestLoggingMiddlewarePassesTheRequestOn(t *testing.T) {
	called := false
	LoggingMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	if !called {
		t.Fatal("the logging middleware swallowed the request")
	}
}
