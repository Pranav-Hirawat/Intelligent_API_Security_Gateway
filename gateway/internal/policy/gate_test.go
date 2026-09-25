package policy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type scopedLookup struct{ fixed }

func (s scopedLookup) LookupRequest(ip, route, method string) (Decision, bool) {
	d, ok := s.fixed[ip]
	return d, ok && d.Route == route && d.Method == method
}

// Switching the control plane off from the console must stop its decisions
// applying at once, and switching back on must not wait for a refresh.
func TestGateSwitchesDecisionsWithoutLosingThem(t *testing.T) {
	inner := fixed{"203.0.113.5": {Action: ActionTempBlock}}
	g := NewGate(inner, false)

	if _, ok := g.Lookup("203.0.113.5"); ok || g.On() {
		t.Fatal("a closed gate returned a decision")
	}
	g.Set(true)
	if d, ok := g.Lookup("203.0.113.5"); !ok || d.Action != ActionTempBlock || !g.On() {
		t.Fatal("reopening the gate did not bring the decision straight back")
	}
}

func TestGatePassesEndpointScopeThrough(t *testing.T) {
	scoped := NewGate(scopedLookup{fixed{"203.0.113.6": {Action: ActionTempBlock, Route: "/a", Method: "GET"}}}, true)
	if _, ok := scoped.LookupRequest("203.0.113.6", "/a", "GET"); !ok {
		t.Error("the scoped decision was not found for its own endpoint")
	}
	if _, ok := scoped.LookupRequest("203.0.113.6", "/b", "GET"); ok {
		t.Error("an endpoint-scoped decision applied to another endpoint")
	}

	// A plain source falls back to the address-wide decision, still honouring scope.
	plain := NewGate(fixed{"203.0.113.7": {Action: ActionTempBlock}}, true)
	if _, ok := plain.LookupRequest("203.0.113.7", "/any", "GET"); !ok {
		t.Error("an address-wide decision did not apply through a plain source")
	}
}

// A nil gate is what the server has when Redis is off; it must be inert.
func TestNilGateHasNoOpinion(t *testing.T) {
	var g *Gate
	g.Set(true)
	if g.On() {
		t.Error("a nil gate reported on")
	}
	if _, ok := g.Lookup("203.0.113.5"); ok {
		t.Error("a nil gate returned a decision")
	}
	if _, ok := g.LookupRequest("203.0.113.5", "/", "GET"); ok {
		t.Error("a nil gate returned a scoped decision")
	}
}

// Telemetry reads the outcome after the chain returns; a request that never
// had one attached must read as a plain allow, not panic.
func TestOutcomeDefaultsToAllow(t *testing.T) {
	bare := httptest.NewRequest(http.MethodGet, "/", nil)
	Record(bare, ActionTempBlock)
	RecordMatch(bare, Match{Action: ActionTempBlock})
	if Applied(bare) != "allow" || Matched(bare) != nil {
		t.Error("a request without an attached outcome recorded one")
	}

	r := AttachOutcome(httptest.NewRequest(http.MethodGet, "/", nil))
	Record(r, "")
	if Applied(r) != "allow" {
		t.Error("an empty action replaced the default")
	}
	Record(r, ActionThrottle)
	RecordMatch(r, Match{PolicyID: "p1"})
	if Applied(r) != ActionThrottle || Matched(r).PolicyID != "p1" {
		t.Errorf("recorded outcome = %s / %+v", Applied(r), Matched(r))
	}
}
