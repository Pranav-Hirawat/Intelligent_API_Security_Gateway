package ownership

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/identity"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/telemetry"
)

const secret = "ownership-test-secret-value"

func token(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	signed := enc(map[string]any{"alg": "HS256"}) + "." + enc(claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	return "Bearer " + signed + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// orders is a backend with the bug: any logged-in caller reads any order.
func orders() http.Handler {
	owners := map[string]int{"1": 2, "2": 3, "3": 2}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/orders":
			fmt.Fprint(w, `{"orders":[{"id":1,"userId":2},{"id":2,"userId":3},{"id":3,"userId":2}],"page":1}`)
		case r.URL.Path == "/api/big/1":
			fmt.Fprintf(w, `{"order":{"userId":3,"notes":%q}}`, strings.Repeat("x", 4096))
		case r.URL.Path == "/api/text/1":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "owner is 3")
		case strings.HasPrefix(r.URL.Path, "/api/orders/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/orders/")
			owner, ok := owners[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `{"message":"Order not found"}`)
				return
			}
			fmt.Fprintf(w, `{"order":{"id":%s,"userId":%d,"shippingAddress":"secret street"}}`, id, owner)
		}
	})
}

func newTestGuard(t *testing.T, cfg config.ObjectOwnershipConfig) http.Handler {
	t.Helper()
	g, _ := guardAndHandler(t, cfg)
	return g
}

func guardAndHandler(t *testing.T, cfg config.ObjectOwnershipConfig) (http.Handler, *Guard) {
	t.Helper()
	table, err := telemetry.NewTable([]string{"GET /api/orders", "GET /api/orders/{id}", "GET /api/big/{id}", "GET /api/text/{id}"})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := identity.NewVerifier(config.JWTConfig{
		Algorithm: "HS256", Secret: secret, UserClaim: "sub",
		BypassClaim: "role", BypassValues: []string{"admin"},
	}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 1024
	}
	cfg.Enabled = true
	g := NewGuard(cfg, []config.OwnershipRule{
		{Template: "GET /api/orders/{id}", OwnerField: "order.userId"},
		{Template: "GET /api/orders", OwnerField: "userId", ListField: "orders"},
		{Template: "GET /api/big/{id}", OwnerField: "order.userId"},
		{Template: "GET /api/text/{id}", OwnerField: "owner"},
	}, verifier, table.Match)
	return g.Middleware(orders()), g
}

func get(h http.Handler, path, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.RemoteAddr = "203.0.113.9:1234"
	r.Header.Set(signals.RequestIDHeader, path+auth)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestOwnObjectPassesUnchanged(t *testing.T) {
	h := newTestGuard(t, config.ObjectOwnershipConfig{})
	w := get(h, "/api/orders/1", token(t, map[string]any{"sub": 2}))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "secret street") {
		t.Fatalf("own order: %d %s", w.Code, w.Body)
	}
}

func TestSomeoneElsesObjectNeverLeavesTheGateway(t *testing.T) {
	h, g := guardAndHandler(t, config.ObjectOwnershipConfig{})
	w := get(h, "/api/orders/2", token(t, map[string]any{"sub": "2"}))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if strings.Contains(w.Body.String(), "secret street") || strings.Contains(w.Body.String(), "userId") {
		t.Fatalf("the other customer's order leaked: %s", w.Body)
	}

	ev := g.Metrics("203.0.113.9")
	if !ev.ThresholdCross || ev.Score != violationScore || ev.Details["reason"] != ReasonOwnerMismatch || ev.Details["owner"] != "3" {
		t.Errorf("evidence = %+v", ev)
	}
}

func TestRepeatedViolationsScoreHigher(t *testing.T) {
	h, g := guardAndHandler(t, config.ObjectOwnershipConfig{})
	auth := token(t, map[string]any{"sub": "3"})
	for _, id := range []string{"1", "3", "1"} {
		get(h, "/api/orders/"+id, auth)
	}
	if ev := g.Metrics("203.0.113.9"); ev.Score != repeatScore || ev.Int("recentViolations") != 3 {
		t.Errorf("after three violations: %+v", ev)
	}
}

func TestTokensAreVerified(t *testing.T) {
	h, g := guardAndHandler(t, config.ObjectOwnershipConfig{})

	if w := get(h, "/api/orders/1", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d, want 401", w.Code)
	}
	if ev := g.Metrics("203.0.113.9"); ev.ThresholdCross {
		t.Errorf("a missing token crossed the threshold: %+v", ev)
	}

	// The demo's old token: base64 of the user id. Anyone can make one.
	forged := "Bearer " + base64.StdEncoding.EncodeToString([]byte("2"))
	if w := get(h, "/api/orders/1", forged); w.Code != http.StatusUnauthorized {
		t.Errorf("forged token: %d, want 401", w.Code)
	}
	if ev := g.Metrics("203.0.113.9"); !ev.ThresholdCross || ev.Details["reason"] != ReasonForgedToken {
		t.Errorf("forged token evidence: %+v", ev)
	}
}

func TestBackendErrorsPassThrough(t *testing.T) {
	h := newTestGuard(t, config.ObjectOwnershipConfig{})
	w := get(h, "/api/orders/99", token(t, map[string]any{"sub": "2"}))
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "Order not found") {
		t.Errorf("backend 404: %d %s", w.Code, w.Body)
	}
}

func TestListsKeepOnlyTheCallersItems(t *testing.T) {
	h, g := guardAndHandler(t, config.ObjectOwnershipConfig{})
	w := get(h, "/api/orders", token(t, map[string]any{"sub": "2"}))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var body struct {
		Orders []struct{ ID, UserID int } `json:"orders"`
		Page   int                        `json:"page"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Orders) != 2 || body.Page != 1 {
		t.Errorf("filtered list = %+v", body)
	}
	for _, o := range body.Orders {
		if o.UserID != 2 {
			t.Errorf("kept someone else's order: %+v", o)
		}
	}
	if ev := g.Metrics("203.0.113.9"); ev.ThresholdCross || ev.Int("removedItems") != 1 {
		t.Errorf("list evidence = %+v", ev)
	}
}

func TestAdminsBypass(t *testing.T) {
	h := newTestGuard(t, config.ObjectOwnershipConfig{})
	w := get(h, "/api/orders/2", token(t, map[string]any{"sub": "1", "role": "admin"}))
	if w.Code != http.StatusOK {
		t.Errorf("admin read: %d", w.Code)
	}
}

func TestUnverifiableResponses(t *testing.T) {
	auth := token(t, map[string]any{"sub": "3"})

	deny := newTestGuard(t, config.ObjectOwnershipConfig{OnUnverifiable: "deny"})
	for _, path := range []string{"/api/big/1", "/api/text/1"} {
		if w := get(deny, path, auth); w.Code != http.StatusNotFound {
			t.Errorf("deny %s: %d, want 404", path, w.Code)
		}
	}

	allow := newTestGuard(t, config.ObjectOwnershipConfig{OnUnverifiable: "allow"})
	if w := get(allow, "/api/big/1", auth); w.Code != http.StatusOK || w.Body.Len() < 4096 {
		t.Errorf("allow big: %d, %d bytes", w.Code, w.Body.Len())
	}
	if w := get(allow, "/api/text/1", auth); w.Code != http.StatusOK || w.Body.String() != "owner is 3" {
		t.Errorf("allow text: %d %q", w.Code, w.Body)
	}
}

func TestDisabledAndUnlistedRoutesAreUntouched(t *testing.T) {
	h, g := guardAndHandler(t, config.ObjectOwnershipConfig{})
	g.Apply(config.ObjectOwnershipConfig{Enabled: false})
	if w := get(h, "/api/orders/2", token(t, map[string]any{"sub": "2"})); w.Code != http.StatusOK {
		t.Errorf("disabled guard refused: %d", w.Code)
	}
}

func TestMetricsForOnlyReportsTheRequestThatWasChecked(t *testing.T) {
	h, g := guardAndHandler(t, config.ObjectOwnershipConfig{})
	auth := token(t, map[string]any{"sub": "2"})
	get(h, "/api/orders/2", auth)

	if ev := g.MetricsFor("203.0.113.9", "/api/orders/2"+auth); !ev.ThresholdCross {
		t.Errorf("the refused request reports nothing: %+v", ev)
	}
	if ev := g.MetricsFor("203.0.113.9", "another-request"); ev.ThresholdCross {
		t.Errorf("another request inherited the violation: %+v", ev)
	}
}

// A read the guard refused must be recorded as the gateway's answer. Recorded
// as the backend's own 404, the console showed it as an allowed request for an
// order that happened not to exist.
func TestARefusalIsRecordedAsTheGatewaysAnswer(t *testing.T) {
	h, _ := guardAndHandler(t, config.ObjectOwnershipConfig{})
	send := func(path, auth string) (*httptest.ResponseRecorder, *telemetry.Upstream) {
		r, upstream := telemetry.AttachUpstream(httptest.NewRequest(http.MethodGet, path, nil))
		r.RemoteAddr = "203.0.113.9:1234"
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w, upstream
	}

	for name, tc := range map[string]struct {
		path, auth, reason string
		status             int
	}{
		"someone else's order": {"/api/orders/2", token(t, map[string]any{"sub": "2"}), telemetry.ReasonOwnershipRefused, http.StatusNotFound},
		"no token":             {"/api/orders/1", "", telemetry.ReasonAuthRequired, http.StatusUnauthorized},
	} {
		w, upstream := send(tc.path, tc.auth)
		if w.Code != tc.status || upstream.GatewayReason != tc.reason || upstream.Origin() != telemetry.OriginGateway {
			t.Errorf("%s: status %d reason %q origin %q", name, w.Code, upstream.GatewayReason, upstream.Origin())
		}
	}

	if _, upstream := send("/api/orders/1", token(t, map[string]any{"sub": "2"})); upstream.GatewayReason != "" {
		t.Errorf("the caller's own order was recorded as a refusal: %q", upstream.GatewayReason)
	}
}
