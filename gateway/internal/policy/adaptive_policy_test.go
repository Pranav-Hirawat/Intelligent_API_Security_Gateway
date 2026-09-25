package policy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEndpointPolicyIsMoreSpecificThanAdaptiveAddressPolicy(t *testing.T) {
	snapshot := map[string]Decision{}
	collect(snapshot,
		[]string{"policy:203.0.113.5", "policy:203.0.113.5:login"},
		[]any{
			`{"action":"temp_block","target_identity":"203.0.113.5","source":"adaptive"}`,
			`{"action":"throttle","target_identity":"203.0.113.5","source":"adaptive","endpoint_scope":{"method":"POST","route_template":"/api/login"}}`,
		},
		[]time.Duration{time.Minute, time.Minute}, "policy:")
	store := &Store{}
	store.snapshot.Store(&snapshot)

	login, ok := store.LookupRequest("203.0.113.5", "/api/login", "POST")
	if !ok || login.Action != ActionThrottle {
		t.Fatalf("login policy = %+v, %v; want scoped throttle", login, ok)
	}
	products, ok := store.LookupRequest("203.0.113.5", "/api/products", "GET")
	if !ok || products.Action != ActionTempBlock {
		t.Fatalf("products policy = %+v, %v; want address block", products, ok)
	}
}

func TestManualAddressAllowOutranksAdaptiveEndpointBlock(t *testing.T) {
	snapshot := map[string]Decision{}
	collect(snapshot,
		[]string{"policy:203.0.113.5", "policy:203.0.113.5:login"},
		[]any{
			`{"action":"allow","target_identity":"203.0.113.5","source":"human","mode":"manual_override"}`,
			`{"action":"temporary_block","target_identity":"203.0.113.5","source":"adaptive","endpoint_scope":{"method":"POST","route_template":"/api/login"}}`,
		},
		[]time.Duration{time.Minute, time.Minute}, "policy:")
	store := &Store{}
	store.snapshot.Store(&snapshot)

	decision, ok := store.LookupRequest("203.0.113.5", "/api/login", "POST")
	if !ok || decision.Action != ActionAllow {
		t.Fatalf("decision = %+v, %v; manual allow must win", decision, ok)
	}
}

type requestLookup struct {
	route string
	d     Decision
}

func (l *requestLookup) Lookup(string) (Decision, bool) { return Decision{}, false }
func (l *requestLookup) LookupRequest(_, route, _ string) (Decision, bool) {
	l.route = route
	return l.d, true
}

func TestEnforcerUsesNormalizedRouteAndAcceptsContractBlockName(t *testing.T) {
	lookup := &requestLookup{d: Decision{Action: ActionTemporaryBlock}}
	enforcer := NewEnforcer(lookup, true).WithRouteResolver(func(method, path string) string {
		return "/api/products/{id}"
	})
	reached := false
	handler := enforcer.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/products/42", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)

	if lookup.route != "/api/products/{id}" {
		t.Fatalf("lookup route = %q; want normalized template", lookup.route)
	}
	if response.Code != http.StatusForbidden || reached {
		t.Fatalf("status=%d reached=%v; want an early 403", response.Code, reached)
	}
}
