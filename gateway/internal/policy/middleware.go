package policy

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

// Enforcer applies control-plane decisions to live requests. It is the only
// place where anything the control plane produced can affect real traffic.
// enforcerTunables is what the console can move at runtime, swapped whole.
type enforcerTunables struct {
	// policyOn decides whether the lookup sources are consulted at all.
	policyOn bool

	// baseline is the requests per minute every address is held to when no
	// policy names a rate for it. Zero means no baseline, which is the default:
	// refusing ordinary traffic is a deliberate choice, not something the
	// gateway should start doing because a threshold existed.
	baseline int

	// exempt addresses skip the baseline entirely. The reflex's list is reused
	// so there is one answer to "who does this gateway never refuse".
	exempt []*net.IPNet
}

// active reports whether the middleware has anything to do. When neither a
// policy source nor a baseline can have an opinion the request is passed
// straight through, with no lookup and no counting.
func (t *enforcerTunables) active() bool {
	return t.policyOn || t.baseline > 0
}

type Enforcer struct {
	lookup Lookuper
	tun    atomic.Pointer[enforcerTunables]

	quota         QuotaLimiter
	fallbackRPM   int
	burst         int
	routeResolver func(method, path string) string
}

func NewEnforcer(l Lookuper, enabled bool) *Enforcer {
	e := &Enforcer{lookup: l}
	e.Apply(enabled)
	return e
}

// Quota settings are fixed at boot; the policy's rate remains live. No token
// grants are cached locally, so replicas cannot each spend the same allowance.
func (e *Enforcer) WithQuotaLimiter(l QuotaLimiter, fallbackRPM, burst int) *Enforcer {
	e.quota, e.fallbackRPM, e.burst = l, fallbackRPM, burst
	return e
}

// WithRouteResolver gives policy lookup the same normalized route templates
// telemetry uses. It is an in-memory table lookup fixed at boot.
func (e *Enforcer) WithRouteResolver(resolve func(method, path string) string) *Enforcer {
	e.routeResolver = resolve
	return e
}

// Baseline is the rate every non-exempt address is held to when no policy names
// one for it, and the ranges that skip it.
type Baseline struct {
	RequestsPerMinute int
	Exempt            []*net.IPNet
}

// Throttling consumes quota and never sleeps on a request goroutine.
func (e *Enforcer) Apply(enabled bool) {
	current := e.tun.Load()
	next := &enforcerTunables{policyOn: enabled}
	if current != nil {
		next.baseline, next.exempt = current.baseline, current.exempt
	}
	e.tun.Store(next)
}

// ApplyAll sets the policy switch and baseline in one swap,
// so a request is never judged against a new baseline and an old
// exemption list.
func (e *Enforcer) ApplyAll(enabled bool, b Baseline) {
	e.tun.Store(&enforcerTunables{
		policyOn: enabled,
		baseline: b.RequestsPerMinute,
		exempt:   b.Exempt,
	})
}

// Middleware sits at the front of the chain, so a blocked IP is turned away
// before the detectors spend any work on it.
func (e *Enforcer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tun := e.tun.Load()
		if !tun.active() {
			next.ServeHTTP(w, r)
			return
		}

		ip := netutil.ClientIP(r)
		route := e.route(r.Method, r.URL.Path)

		var decision Decision
		var found bool
		if tun.policyOn && e.lookup != nil {
			if scoped, ok := e.lookup.(interface {
				LookupRequest(string, string, string) (Decision, bool)
			}); ok {
				decision, found = scoped.LookupRequest(ip, route, r.Method)
			} else {
				decision, found = e.lookup.Lookup(ip)
				found = found && matches(decision, route, r.Method)
			}
		}

		if found {
			e.match(r, ip, decision, decision.RequestsPerMinute, "matched", "")
			switch decision.Action {
			case ActionBlock, ActionTempBlock, ActionTemporaryBlock, ActionEscalate:
				Record(r, decision.Action)
				e.match(r, ip, decision, 0, "blocked", "")
				e.deny(w, decision)
				return

			case ActionThrottle:
				limit := decision.RequestsPerMinute
				if limit <= 0 {
					limit = e.fallbackRPM
				}
				e.limited(w, r, next, ip, decision, limit, ActionThrottle)
				return
			case ActionAllow, ActionMonitor:
				e.match(r, ip, decision, 0, "allowed", "")
			}
			// An explicit permissive decision wins over the baseline too.
			// Unknown labels cannot acquire enforcement through a fallback.
			next.ServeHTTP(w, r)
			return
		}

		// No policy rate applies. Hold the address to the baseline, if there is
		// one and it is not exempt.
		if tun.baseline > 0 && !netutil.NetworksContain(tun.exempt, ip) {
			e.limited(w, r, next, ip, Decision{Action: ActionThrottle, Source: "baseline", Reason: "configured baseline"}, tun.baseline, "")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// limited counts one request against a rate and either serves it or refuses it
// with 429. `applied` is the outcome to record when the request is allowed
// through -- empty for the baseline, where nothing was done to the request.
func (e *Enforcer) limited(
	w http.ResponseWriter, r *http.Request, next http.Handler,
	ip string, d Decision, limit int, applied string,
) {
	result := QuotaResult{Allowed: true}
	if limit > 0 && e.quota != nil {
		var err error
		result, err = e.quota.Take(r.Context(), QuotaRequest{
			IP: ip, Route: e.route(r.Method, r.URL.Path), Method: r.Method, Decision: d,
			RequestsPerMinute: limit, Burst: e.burst,
		})
		if err != nil {
			result = QuotaResult{Allowed: true, Reason: "redis_unavailable"}
		}
	} else {
		result.Reason = "quota_unavailable"
	}
	if !result.Allowed {
		Record(r, OutcomeRateLimited)
		e.match(r, ip, d, limit, "throttled", "quota_exhausted")
		e.rateLimited(w, result.RetryAfter)
		return
	}
	enforced := result.Reason == "" || result.Reason == "within_quota"
	if !enforced {
		e.match(r, ip, d, limit, "fail_open", result.Reason)
	} else {
		e.match(r, ip, d, limit, "allowed", "")
	}
	if applied != "" && enforced {
		Record(r, applied)
	}
	next.ServeHTTP(w, r)
}

func (e *Enforcer) match(r *http.Request, ip string, d Decision, limit int, outcome, reason string) {
	source := d.Source
	if source == "" {
		source = "agent"
		if d.CampaignID == "gateway" {
			source = "gateway_reflex"
		}
	}
	if reason == "" {
		reason = d.Reason
	} else if d.Reason != "" {
		reason = d.Reason + "; " + reason
	}
	RecordMatch(r, Match{Action: d.Action, Source: source, ClientIP: ip,
		Route: e.route(r.Method, r.URL.Path), Method: r.Method,
		PolicyID: d.PolicyID, CampaignID: d.CampaignID, RiskScore: d.RiskScore,
		Confidence: d.Confidence, Mode: d.Mode, IssuedBy: d.IssuedBy,
		RequestsPerMinute: limit, Reason: reason, Outcome: outcome})
}

func (e *Enforcer) route(method, path string) string {
	if e.routeResolver == nil {
		return path
	}
	return e.routeResolver(method, path)
}

func (e *Enforcer) deny(w http.ResponseWriter, d Decision) {
	// Deliberately generic. The campaign id, confidence and reason go to the
	// log, not to the response -- telling an attacker which campaign they
	// tripped and how sure we are just helps them tune around it.
	seconds := d.ExpiresIn
	if !d.ExpiresAt.IsZero() {
		seconds = int(math.Ceil(time.Until(d.ExpiresAt).Seconds()))
	}
	if seconds > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"forbidden"}`))
}

// rateLimited turns away a throttled caller who has exceeded their allowance.
//
// 429 rather than the 403 a block gets: the difference is real and worth
// keeping. A block says "not you"; this says "not this fast", and Retry-After
// tells a well-behaved client exactly when it is worth trying again.
func (e *Enforcer) rateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(math.Ceil(retryAfter.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))

	// Deliberately generic, like deny: the campaign id and the reason go to
	// the log, not to the caller. Telling an attacker which rate they tripped
	// is telling them what to stay under.
	http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
}
