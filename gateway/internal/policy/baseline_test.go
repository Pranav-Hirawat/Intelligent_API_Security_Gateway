package policy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

func baseline(t *testing.T, rpm int, exempt ...string) Baseline {
	t.Helper()
	nets, err := netutil.ParseCIDRs(exempt, "exempt range")
	if err != nil {
		t.Fatalf("exempt ranges: %v", err)
	}
	return Baseline{RequestsPerMinute: rpm, Exempt: nets}
}

func serve(e *Enforcer, ip string, n int) map[int]int {
	handler := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	codes := map[int]int{}
	for i := 0; i < n; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, requestFrom(ip))
		codes[rec.Code]++
	}
	return codes
}

// Every address, not just the ones under a policy.
func TestBaselineAppliesToTrafficWithNoPolicy(t *testing.T) {
	e := NewEnforcer(fixed{}, false).WithQuotaLimiter(newWindowQuota(), 60, 20)
	e.ApplyAll(false, baseline(t, 5))

	codes := serve(e, "203.0.113.10", 8)

	if codes[http.StatusOK] != 5 {
		t.Errorf("allowed %d, want 5", codes[http.StatusOK])
	}
	if codes[http.StatusTooManyRequests] != 3 {
		t.Errorf("refused %d, want 3", codes[http.StatusTooManyRequests])
	}
}

// The whole point: a policy replaces the baseline rather than stacking with it.
func TestAPolicyRateOverridesTheBaseline(t *testing.T) {
	// Tighter than the baseline.
	tight := NewEnforcer(
		fixed{"203.0.113.11": {Action: ActionThrottle, RequestsPerMinute: 2}}, true,
	).WithQuotaLimiter(newWindowQuota(), 60, 20)
	tight.ApplyAll(true, baseline(t, 100))

	codes := serve(tight, "203.0.113.11", 6)
	if codes[http.StatusOK] != 2 {
		t.Errorf("allowed %d against a policy of 2 under a baseline of 100, want 2", codes[http.StatusOK])
	}

	// Looser than the baseline. The policy still wins: the control plane looked
	// at this address and said so.
	loose := NewEnforcer(
		fixed{"203.0.113.12": {Action: ActionThrottle, RequestsPerMinute: 10}}, true,
	).WithQuotaLimiter(newWindowQuota(), 60, 20)
	loose.ApplyAll(true, baseline(t, 3))

	codes = serve(loose, "203.0.113.12", 10)
	if codes[http.StatusOK] != 10 {
		t.Errorf("allowed %d against a policy of 10 under a baseline of 3, want 10", codes[http.StatusOK])
	}
}

// A blocked address is refused outright, and never reaches the counter.
func TestBlockedAddressIsNotRateLimited(t *testing.T) {
	q := newWindowQuota()
	e := NewEnforcer(
		fixed{"203.0.113.13": {Action: ActionTempBlock}}, true,
	).WithQuotaLimiter(q, 60, 20)
	e.ApplyAll(true, baseline(t, 5))

	codes := serve(e, "203.0.113.13", 8)
	if codes[http.StatusForbidden] != 8 {
		t.Errorf("blocked %d of 8 with 403, want all", codes[http.StatusForbidden])
	}
	if q.calls != 0 {
		t.Error("a blocked address was counted by the limiter")
	}
}

// An explicit permissive policy wins over the configured baseline.
func TestMonitoredAddressIsAllowedNormally(t *testing.T) {
	e := NewEnforcer(
		fixed{"203.0.113.14": {Action: ActionMonitor}}, true,
	).WithQuotaLimiter(newWindowQuota(), 60, 20)
	e.ApplyAll(true, baseline(t, 3))

	codes := serve(e, "203.0.113.14", 6)
	if codes[http.StatusOK] != 6 {
		t.Errorf("allowed %d, want 6: monitor must forward normally", codes[http.StatusOK])
	}
}

func TestExemptAddressesSkipTheBaseline(t *testing.T) {
	e := NewEnforcer(fixed{}, false).WithQuotaLimiter(newWindowQuota(), 60, 20)
	e.ApplyAll(false, baseline(t, 2, "127.0.0.0/8", "10.0.0.0/8"))

	for _, ip := range []string{"127.0.0.1", "10.1.2.3"} {
		codes := serve(e, ip, 10)
		if codes[http.StatusOK] != 10 {
			t.Errorf("%s: allowed %d of 10, want all — it is exempt", ip, codes[http.StatusOK])
		}
	}

	// Someone outside the exempt list is still held to it.
	codes := serve(e, "203.0.113.15", 5)
	if codes[http.StatusTooManyRequests] != 3 {
		t.Errorf("refused %d, want 3 for a non-exempt address", codes[http.StatusTooManyRequests])
	}
}

// Off by default: no baseline means the gateway refuses nothing on rate alone,
// which is how it behaved before this existed.
func TestNoBaselineRefusesNothing(t *testing.T) {
	q := newWindowQuota()
	e := NewEnforcer(fixed{}, false).WithQuotaLimiter(q, 60, 20)
	e.ApplyAll(false, Baseline{})

	codes := serve(e, "203.0.113.16", 200)
	if codes[http.StatusOK] != 200 {
		t.Errorf("allowed %d of 200, want all when no baseline is set", codes[http.StatusOK])
	}
	if q.calls != 0 {
		t.Error("addresses were counted with no baseline configured")
	}
}

// Apply is the narrow call the settings watcher used to make; it must not
// silently drop a baseline that was already in force.
func TestApplyKeepsTheBaseline(t *testing.T) {
	e := NewEnforcer(fixed{}, false).WithQuotaLimiter(newWindowQuota(), 60, 20)
	e.ApplyAll(false, baseline(t, 4))

	e.Apply(true)

	codes := serve(e, "203.0.113.17", 6)
	if codes[http.StatusOK] != 4 {
		t.Errorf("allowed %d after Apply, want 4: the baseline was dropped", codes[http.StatusOK])
	}
}
