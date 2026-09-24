package enforcement

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
)

type fixedObserver struct {
	snapshot signals.Snapshot
	calls    int
}

func (o *fixedObserver) SnapshotFor(string, string) signals.Snapshot {
	o.calls++
	return o.snapshot
}

func serveFrom(handler http.Handler, ip string) int {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = ip + ":1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	return rec.Code
}

// The observer only ever reads. The request that crossed a threshold is served;
// the block it records is for the caller's next request.
func TestObserverNeverRefusesTheRequestItObserves(t *testing.T) {
	reflex := armed(t, nil)
	obs := &fixedObserver{snapshot: snap(signals.SignalFlood, 100, true)}
	reached := 0
	handler := Middleware(reflex, obs)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusOK)
	}))

	if code := serveFrom(handler, "203.0.113.40"); code != http.StatusOK || reached != 1 {
		t.Fatalf("observed request = %d, reached backend %d times", code, reached)
	}
	if _, blocked := reflex.Lookup("203.0.113.40"); !blocked {
		t.Error("a crossed, listed signal did not record a block")
	}
}

// Switched off, the observer is not even in the chain: no snapshot is taken.
func TestInactiveReflexAddsNothingToTheChain(t *testing.T) {
	obs := &fixedObserver{snapshot: snap(signals.SignalFlood, 100, true)}
	for name, reflex := range map[string]*Reflex{
		"disabled":   armed(t, func(c *Config) { c.Enabled = false }),
		"no signals": armed(t, func(c *Config) { c.Signals = nil }),
		"nil":        nil,
	} {
		serveFrom(Middleware(reflex, obs)(http.NotFoundHandler()), "203.0.113.41")
		if obs.calls != 0 {
			t.Errorf("%s: observer took %d snapshots", name, obs.calls)
		}
	}
	serveFrom(Middleware(armed(t, nil), nil)(http.NotFoundHandler()), "203.0.113.41")
}

func TestDescribeSaysWhatWillActuallyBlock(t *testing.T) {
	var nilReflex *Reflex
	cases := map[string]struct {
		r    *Reflex
		want string
	}{
		"nil":        {nilReflex, "off"},
		"disabled":   {armed(t, func(c *Config) { c.Enabled = false }), "off"},
		"no signals": {armed(t, func(c *Config) { c.Signals = nil }), "nothing will be blocked"},
		"armed":      {armed(t, nil), signals.SignalFlood},
	}
	for name, tc := range cases {
		if got := tc.r.Describe(); !strings.Contains(got, tc.want) {
			t.Errorf("%s: Describe() = %q, want it to mention %q", name, got, tc.want)
		}
	}
}

func TestStartAndCloseStopTheSweeper(t *testing.T) {
	r := armed(t, nil)
	r.Start()
	done := make(chan struct{})
	go func() { r.Close(); close(done) }()
	<-done
	var nilReflex *Reflex
	nilReflex.Close()
}
