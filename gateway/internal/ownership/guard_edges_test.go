package ownership

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/identity"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/telemetry"
)

// guardOver puts a guard with one rule in front of a backend written for the test.
func guardOver(t *testing.T, cfg config.ObjectOwnershipConfig, protected config.OwnershipRule, backend http.HandlerFunc) (http.Handler, *Guard) {
	t.Helper()
	table, err := telemetry.NewTable([]string{protected.Template})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := identity.NewVerifier(config.JWTConfig{Algorithm: "HS256", Secret: secret, UserClaim: "sub"}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	cfg.Enabled = true
	g := NewGuard(cfg, []config.OwnershipRule{protected}, verifier, table.Match)
	return g.Middleware(backend), g
}

func jsonBody(body string, headers ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for i := 0; i+1 < len(headers); i += 2 {
			w.Header().Set(headers[i], headers[i+1])
		}
		fmt.Fprint(w, body)
	}
}

var single = config.OwnershipRule{Template: "GET /api/orders/{id}", OwnerField: "order.userId"}

// A flush is a way of sending early. While the body is held it must not reach
// the client, or a flushing backend would leak the object before the check.
func TestAHeldResponseCannotBeFlushedEarly(t *testing.T) {
	h, _ := guardOver(t, config.ObjectOwnershipConfig{}, single, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"order":{"userId":3}}`)
		w.(http.Flusher).Flush()
	})
	w := get(h, "/api/orders/1", token(t, map[string]any{"sub": "2"}))
	if w.Code != http.StatusNotFound || w.Flushed || strings.Contains(w.Body.String(), "userId") {
		t.Errorf("someone else's order escaped: %d flushed=%v %q", w.Code, w.Flushed, w.Body)
	}
}

func TestAnErrorResponseStreamsAndFlushesStraightThrough(t *testing.T) {
	h, _ := guardOver(t, config.ObjectOwnershipConfig{}, single, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, "busy")
		w.(http.Flusher).Flush()
	})
	w := get(h, "/api/orders/1", token(t, map[string]any{"sub": "2"}))
	if w.Code != http.StatusServiceUnavailable || !w.Flushed || w.Body.String() != "busy" {
		t.Errorf("error response: %d flushed=%v %q", w.Code, w.Flushed, w.Body)
	}
}

func TestResponsesThatCarryNoObjectPassUntouched(t *testing.T) {
	for name, backend := range map[string]http.HandlerFunc{
		"empty success": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) },
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/login", http.StatusFound)
		},
		"empty 200": func(w http.ResponseWriter, r *http.Request) {},
	} {
		h, _ := guardOver(t, config.ObjectOwnershipConfig{}, single, backend)
		want := httptest.NewRecorder()
		backend(want, httptest.NewRequest(http.MethodGet, "/api/orders/1", nil))
		if w := get(h, "/api/orders/1", token(t, map[string]any{"sub": "2"})); w.Code != want.Code {
			t.Errorf("%s: %d, want %d", name, w.Code, want.Code)
		}
	}
}

func TestAnAnswerTheGuardCannotReadIsRefusedWhenDenying(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"compressed":           jsonBody(`not really gzip`, "Content-Encoding", "gzip"),
		"owner missing":        jsonBody(`{"order":{"id":1}}`),
		"owner empty":          jsonBody(`{"order":{"userId":""}}`),
		"owner nested wrongly": jsonBody(`{"order":"3"}`),
	}
	for name, backend := range cases {
		deny, _ := guardOver(t, config.ObjectOwnershipConfig{OnUnverifiable: "deny"}, single, backend)
		if w := get(deny, "/api/orders/1", token(t, map[string]any{"sub": "2"})); w.Code != http.StatusNotFound {
			t.Errorf("deny %s: %d, want 404", name, w.Code)
		}
		allow, _ := guardOver(t, config.ObjectOwnershipConfig{OnUnverifiable: "allow"}, single, backend)
		if w := get(allow, "/api/orders/1", token(t, map[string]any{"sub": "2"})); w.Code != http.StatusOK {
			t.Errorf("allow %s: %d, want 200", name, w.Code)
		}
	}
	// Identity encoding is no encoding at all.
	h, _ := guardOver(t, config.ObjectOwnershipConfig{}, single, jsonBody(`{"order":{"userId":2}}`, "Content-Encoding", "identity"))
	if w := get(h, "/api/orders/1", token(t, map[string]any{"sub": "2"})); w.Code != http.StatusOK {
		t.Errorf("identity encoding: %d", w.Code)
	}
}

var list = config.OwnershipRule{Template: "GET /api/orders", OwnerField: "userId", ListField: "data.orders"}

func TestAFilteredListDropsHeadersThatDescribedTheOriginal(t *testing.T) {
	body := `{"data":{"orders":[{"userId":2,"note":"<mine>"},{"userId":3}]}}`
	h, _ := guardOver(t, config.ObjectOwnershipConfig{}, list, jsonBody(body, "ETag", `"v1"`, "Content-Length", fmt.Sprint(len(body))))
	w := get(h, "/api/orders", token(t, map[string]any{"sub": "2"}))

	if got := w.Body.String(); got != `{"data":{"orders":[{"note":"<mine>","userId":2}]}}` {
		t.Errorf("filtered body = %s", got)
	}
	if w.Header().Get("ETag") != "" || w.Header().Get("Content-Length") != "" {
		t.Errorf("stale headers kept: %v", w.Header())
	}
}

func TestListItemsWithNoOwnerFollowTheUnverifiableSetting(t *testing.T) {
	body := `{"data":{"orders":[{"userId":2},{"id":9}]}}`
	deny, _ := guardOver(t, config.ObjectOwnershipConfig{OnUnverifiable: "deny"}, list, jsonBody(body))
	if got := get(deny, "/api/orders", token(t, map[string]any{"sub": "2"})).Body.String(); got != `{"data":{"orders":[{"userId":2}]}}` {
		t.Errorf("deny kept an unowned item: %s", got)
	}
	allow, _ := guardOver(t, config.ObjectOwnershipConfig{OnUnverifiable: "allow"}, list, jsonBody(body))
	if got := get(allow, "/api/orders", token(t, map[string]any{"sub": "2"})).Body.String(); got != body {
		t.Errorf("allow changed the list: %s", got)
	}
}

func TestAListThatIsNotAListCannotBeChecked(t *testing.T) {
	h, _ := guardOver(t, config.ObjectOwnershipConfig{}, list, jsonBody(`{"data":{"orders":{"userId":3}}}`))
	if w := get(h, "/api/orders", token(t, map[string]any{"sub": "2"})); w.Code != http.StatusNotFound {
		t.Errorf("object where a list belongs: %d, want 404", w.Code)
	}
}

func TestATopLevelArrayIsFilteredInPlace(t *testing.T) {
	top := config.OwnershipRule{Template: "GET /api/orders", OwnerField: "userId", ListField: "."}
	h, _ := guardOver(t, config.ObjectOwnershipConfig{}, top, jsonBody(`[{"userId":3},{"userId":2}]`))
	if got := get(h, "/api/orders", token(t, map[string]any{"sub": "2"})).Body.String(); got != `[{"userId":2}]` {
		t.Errorf("top-level array = %s", got)
	}
}

// After a refused read, the same client's next clean read must not keep
// reporting the old refusal: the evidence describes the latest request.
func TestACleanReadClearsTheLastRefusal(t *testing.T) {
	h, g := guardAndHandler(t, config.ObjectOwnershipConfig{})
	auth := token(t, map[string]any{"sub": "2"})
	get(h, "/api/orders/2", auth)
	if !g.Metrics("203.0.113.9").ThresholdCross {
		t.Fatal("the refusal was not recorded")
	}
	get(h, "/api/orders/1", auth)
	if ev := g.Metrics("203.0.113.9"); ev.ThresholdCross {
		t.Errorf("a clean read still reports the refusal: %+v", ev)
	}
	if ev := g.Metrics("198.51.100.1"); ev.ThresholdCross {
		t.Errorf("an unseen client reports evidence: %+v", ev)
	}
}

func TestSeverityFollowsTheScore(t *testing.T) {
	for score, want := range map[int]string{repeatScore: "high", violationScore: "high", 65: "medium", itemsRemovedScore: "low", 0: "none"} {
		if got := severity(score); got != want {
			t.Errorf("severity(%d) = %q, want %q", score, got, want)
		}
	}
}

// Memory is bounded: a scan from many addresses cannot grow the guard forever.
// Expired clients go first, then the stalest.
func TestTrackedClientsAreBounded(t *testing.T) {
	_, g := guardAndHandler(t, config.ObjectOwnershipConfig{})
	for i := 0; i < maxTrackedClients; i++ {
		g.record(fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255), "", "t", ReasonItemsRemoved, "", "", 1)
	}
	g.mu.Lock()
	stale := g.last["10.0.0.0"]
	stale.at = time.Now().Add(-2 * violationWindow)
	g.last["10.0.0.0"] = stale
	g.mu.Unlock()

	g.record("203.0.113.1", "", "t", ReasonItemsRemoved, "", "", 1)
	g.mu.Lock()
	_, expiredKept := g.last["10.0.0.0"]
	size := len(g.last)
	g.mu.Unlock()
	if expiredKept || size != maxTrackedClients {
		t.Errorf("expired kept=%v size=%d, want expired gone and %d tracked", expiredKept, size, maxTrackedClients)
	}

	g.record("203.0.113.2", "", "t", ReasonItemsRemoved, "", "", 1)
	g.mu.Lock()
	_, newestKept := g.last["203.0.113.2"]
	size = len(g.last)
	g.mu.Unlock()
	if !newestKept || size != maxTrackedClients {
		t.Errorf("newest kept=%v size=%d, want the stalest evicted instead", newestKept, size)
	}
}
