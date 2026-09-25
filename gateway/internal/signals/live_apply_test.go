package signals

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
)

// A detector that booted disabled must still work once the console enables it.
// The flood detector used to return an empty struct when disabled, which would
// have panicked on the first request after being switched on.
func TestFloodDetectorCanBeEnabledAfterBootingDisabled(t *testing.T) {
	fd := NewFloodDetector(config.RateLimitConfig{Enabled: false})

	handler := fd.Middleware(okBackend())
	// While off, nothing is counted however hard it is hit.
	for i := 0; i < 5; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), request("1.2.3.4"))
	}
	if got := fd.Metrics("1.2.3.4").Details["requestRate"]; got != 0 {
		t.Fatalf("a disabled detector counted %v requests", got)
	}

	fd.Apply(config.RateLimitConfig{Enabled: true, RequestsPerMinute: 2})

	for i := 0; i < 4; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), request("1.2.3.4"))
	}

	ev := fd.Metrics("1.2.3.4")
	if ev.Details["requestRate"] != 4 {
		t.Errorf("requestRate = %v, want 4 after enabling", ev.Details["requestRate"])
	}
	if !ev.ThresholdCross {
		t.Error("4 requests against a threshold of 2 did not cross")
	}
}

// Lowering the threshold must judge the history already recorded, not start
// from zero -- otherwise changing a setting hands an active attacker a reprieve.
func TestFloodHistorySurvivesAnApply(t *testing.T) {
	fd := NewFloodDetector(config.RateLimitConfig{Enabled: true, RequestsPerMinute: 100})
	handler := fd.Middleware(okBackend())

	for i := 0; i < 10; i++ {
		handler.ServeHTTP(httptest.NewRecorder(), request("9.9.9.9"))
	}
	if fd.Metrics("9.9.9.9").ThresholdCross {
		t.Fatal("10 requests crossed a threshold of 100")
	}

	// Tighten the limit below what this caller has already sent.
	fd.Apply(config.RateLimitConfig{Enabled: true, RequestsPerMinute: 5})

	ev := fd.Metrics("9.9.9.9")
	if ev.Details["requestRate"] != 10 {
		t.Errorf("requestRate = %v, want the 10 already recorded", ev.Details["requestRate"])
	}
	if !ev.ThresholdCross {
		t.Error("the 10 requests already sent did not cross the new threshold of 5")
	}
}

func TestBruteForceFailuresSurviveAnApply(t *testing.T) {
	bd := NewBruteForceDetector(config.BruteForceConfig{
		Enabled: true, MaxFailures: 100, Window: time.Minute,
	}, loginOutcomes, loginMatch)

	for i := 0; i < 3; i++ {
		bd.recordFailure("5.5.5.5", "/api/login", "a@b.c", time.Now(), bd.settings())
	}

	bd.Apply(config.BruteForceConfig{
		Enabled: true, MaxFailures: 3, Window: time.Minute,
	})

	ev := bd.Metrics("5.5.5.5")
	if ev.Details["failedLogins"] != 3 {
		t.Errorf("failedLogins = %v, want the 3 already recorded", ev.Details["failedLogins"])
	}
	if !ev.ThresholdCross {
		t.Error("3 failures did not cross the new threshold of 3")
	}
}

func TestSQLiCanBeDisabledLive(t *testing.T) {
	sd := NewSQLiDetector(config.AttackDetectionConfig{Enabled: true})
	handler := sd.Middleware(okBackend())

	r := httptest.NewRequest(http.MethodGet, "/?q=UNION+SELECT+password", nil)
	r.RemoteAddr = "7.7.7.7:1234"
	handler.ServeHTTP(httptest.NewRecorder(), r)
	if !sd.Metrics("7.7.7.7").ThresholdCross {
		t.Fatal("an obvious injection was not detected while enabled")
	}

	sd.Apply(config.AttackDetectionConfig{Enabled: false})

	r2 := httptest.NewRequest(http.MethodGet, "/?q=UNION+SELECT+password", nil)
	r2.RemoteAddr = "8.8.8.8:1234"
	handler.ServeHTTP(httptest.NewRecorder(), r2)
	if sd.Metrics("8.8.8.8").ThresholdCross {
		t.Error("the detector still fired after being disabled")
	}
}

// The whole point of the atomic swap: settings may change while requests are
// in flight. Run with -race, this fails loudly if a reader and Apply can
// overlap unsafely.
func TestApplyIsSafeUnderConcurrentTraffic(t *testing.T) {
	fd := NewFloodDetector(config.RateLimitConfig{Enabled: true, RequestsPerMinute: 50})
	bd := NewBruteForceDetector(config.BruteForceConfig{Enabled: true, MaxFailures: 5, Window: time.Minute}, loginOutcomes, loginMatch)
	sd := NewSQLiDetector(config.AttackDetectionConfig{Enabled: true})
	td := NewTraversalEnumDetector(config.EnumerationConfig{Enabled: true})
	od := NewObjectEnumerationDetector(config.ObjectEnumerationConfig{Enabled: true, DistinctIDs: 5, Window: time.Minute},
		[]string{"GET /api/orders/{id}"}, objectRouteMatch)

	chain := fd.Middleware(sd.Middleware(td.Middleware(od.Middleware(bd.Middleware(okBackend())))))

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Traffic.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					chain.ServeHTTP(httptest.NewRecorder(), request("4.4.4.4"))
					orders := request("4.4.4.4")
					orders.URL.Path = "/api/orders/7"
					chain.ServeHTTP(httptest.NewRecorder(), orders)
					fd.Metrics("4.4.4.4")
					bd.Metrics("4.4.4.4")
					od.Metrics("4.4.4.4")
				}
			}
		}()
	}

	// Settings changing underneath it, on this goroutine so the traffic is
	// stopped only once every apply has been made.
	for i := 0; i < 300; i++ {
		on := i%2 == 0
		fd.Apply(config.RateLimitConfig{Enabled: on, RequestsPerMinute: 10 + i})
		bd.Apply(config.BruteForceConfig{Enabled: on, MaxFailures: 1 + i%9, Window: time.Minute})
		sd.Apply(config.AttackDetectionConfig{Enabled: on})
		td.Apply(config.EnumerationConfig{Enabled: on})
		od.Apply(config.ObjectEnumerationConfig{Enabled: on, DistinctIDs: 2 + i%9, Window: time.Minute})
	}

	close(stop)
	wg.Wait()
}

func request(ip string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/thing", nil)
	r.RemoteAddr = ip + ":1234"
	return r
}
