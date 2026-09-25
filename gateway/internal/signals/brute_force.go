package signals

import (
	"cmp"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

type bruteTunables struct {
	enabled             bool
	maxFailures         int
	window              time.Duration
	maxClients          int
	maxTargetsPerClient int
}

type loginOutcomeRule struct {
	success map[int]struct{}
	invalid map[int]struct{}
}

type loginStreak struct {
	route       string
	target      string
	consecutive int
	lastFailure time.Time
	lastSeen    time.Time
}

// BruteForceDetector records consecutive configured backend credential
// failures. It owns no status-code folklore: a 401 means wrong credentials
// only for the login route that configuration says it does.
type BruteForceDetector struct {
	tun     atomic.Pointer[bruteTunables]
	match   func(method, path string) string
	rules   map[string]loginOutcomeRule
	mu      sync.Mutex
	clients map[string]map[string]*loginStreak
}

func NewBruteForceDetector(cfg config.BruteForceConfig, outcomes []config.AuthOutcomeConfig, match func(string, string) string) *BruteForceDetector {
	d := &BruteForceDetector{
		match:   match,
		rules:   loginOutcomeRules(outcomes),
		clients: make(map[string]map[string]*loginStreak),
	}
	d.Apply(cfg)
	go d.startCleanupTimer()
	return d
}

func loginOutcomeRules(entries []config.AuthOutcomeConfig) map[string]loginOutcomeRule {
	rules := make(map[string]loginOutcomeRule, len(entries))
	for _, entry := range entries {
		if len(entry.InvalidCredentials) == 0 {
			continue
		}
		rule := loginOutcomeRule{success: make(map[int]struct{}), invalid: make(map[int]struct{})}
		for _, status := range entry.Success {
			rule.success[status] = struct{}{}
		}
		for _, status := range entry.InvalidCredentials {
			rule.invalid[status] = struct{}{}
		}
		rules[routeKey(entry.Method, entry.Template)] = rule
	}
	return rules
}

func routeKey(method, route string) string {
	return strings.ToUpper(method) + " " + route
}

func (d *BruteForceDetector) settings() bruteTunables { return *d.tun.Load() }

func (d *BruteForceDetector) Apply(cfg config.BruteForceConfig) {
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = 5
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	if cfg.MaxClients <= 0 {
		cfg.MaxClients = 10_000
	}
	if cfg.MaxTargetsPerClient <= 0 {
		cfg.MaxTargetsPerClient = 64
	}
	tun := &bruteTunables{
		enabled:             cfg.Enabled,
		maxFailures:         cfg.MaxFailures,
		window:              cfg.Window,
		maxClients:          cfg.MaxClients,
		maxTargetsPerClient: cfg.MaxTargetsPerClient,
	}
	d.tun.Store(tun)

	// A live settings change must not leave the old, larger allocation behind.
	// Losing the stalest streak is safer than letting an account spray retain
	// arbitrary client and target strings until its original expiry.
	d.mu.Lock()
	for len(d.clients) > tun.maxClients {
		dropOldest(d.clients, oldestStreak)
	}
	for _, byTarget := range d.clients {
		for len(byTarget) > tun.maxTargetsPerClient {
			dropOldest(byTarget, func(s *loginStreak) time.Time { return s.lastSeen })
		}
	}
	d.mu.Unlock()
}

func (d *BruteForceDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tun := d.settings()
		route, rule, login := d.loginRule(r)
		if !tun.enabled || !login {
			next.ServeHTTP(w, r)
			return
		}

		// This is below BodyLimitMiddleware in the gateway chain. The target is
		// optional enrichment, but it must not become a new unbounded body read.
		target := extractIdentity(r)
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)

		now := time.Now()
		if _, invalid := rule.invalid[rec.status]; invalid {
			d.recordFailure(netutil.ClientIP(r), route, target, now, tun)
			return
		}
		if _, success := rule.success[rec.status]; success {
			d.recordSuccess(netutil.ClientIP(r), route, target)
		}
	})
}

func (d *BruteForceDetector) loginRule(r *http.Request) (string, loginOutcomeRule, bool) {
	if d.match == nil {
		return "", loginOutcomeRule{}, false
	}
	route := d.match(r.Method, r.URL.Path)
	rule, ok := d.rules[routeKey(r.Method, route)]
	return route, rule, ok
}

func (d *BruteForceDetector) recordFailure(ip, route, target string, now time.Time, tun bruteTunables) {
	key := streakKey(route, target)
	d.mu.Lock()
	byTarget := d.clients[ip]
	if byTarget == nil {
		if len(d.clients) >= tun.maxClients {
			// Address spraying must not turn failed logins into an unbounded map.
			dropOldest(d.clients, oldestStreak)
		}
		byTarget = make(map[string]*loginStreak)
		d.clients[ip] = byTarget
	}
	streak := byTarget[key]
	if streak == nil || now.Sub(streak.lastFailure) > tun.window {
		if streak == nil && len(byTarget) >= tun.maxTargetsPerClient {
			// Account names are attacker input too. Retain recency, not every
			// guessed identity, so one client cannot fill process memory.
			dropOldest(byTarget, func(s *loginStreak) time.Time { return s.lastSeen })
		}
		streak = &loginStreak{route: route, target: target}
		byTarget[key] = streak
	}
	streak.consecutive++
	streak.lastFailure, streak.lastSeen = now, now
	d.mu.Unlock()
}

func (d *BruteForceDetector) recordSuccess(ip, route, target string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	byTarget := d.clients[ip]
	if byTarget == nil {
		return
	}
	if target != "" {
		delete(byTarget, streakKey(route, target))
	} else {
		// A success without an identity can clear this login route, but must not
		// hide failures against another route by clearing the whole client.
		for key, streak := range byTarget {
			if streak.route == route {
				delete(byTarget, key)
			}
		}
	}
	if len(byTarget) == 0 {
		delete(d.clients, ip)
	}
}

func streakKey(route, target string) string {
	target = cmp.Or(target, "<unknown>")
	return route + "\x00" + target
}

// oldestStreak is when a client was last seen on its quietest target, so the
// client evicted from a full table is the one that has been silent longest.
func oldestStreak(byTarget map[string]*loginStreak) time.Time {
	var oldest time.Time
	for _, s := range byTarget {
		if oldest.IsZero() || s.lastSeen.Before(oldest) {
			oldest = s.lastSeen
		}
	}
	return oldest
}

func (d *BruteForceDetector) Metrics(ip string) Evidence {
	tun := d.settings()
	ev := Evidence{Signal: SignalBruteForce, Details: map[string]any{
		"consecutiveFailures": 0,
		"failedLogins":        0,
		"distinctUsers":       0,
		"maxFailures":         tun.maxFailures,
		"window":              tun.window.String(),
		"route":               "",
		"target":              "",
	}}
	if !tun.enabled {
		return ev
	}

	now := time.Now()
	d.mu.Lock()
	byTarget := d.clients[ip]
	var strongest *loginStreak
	distinctUsers := 0
	for key, streak := range byTarget {
		if now.Sub(streak.lastFailure) > tun.window {
			delete(byTarget, key)
			continue
		}
		// Count only accounts whose own failure streak reached the configured
		// threshold. Otherwise one brute-force target plus a few ordinary typos
		// could be mislabeled as password spraying by the control plane.
		if streak.target != "" && streak.consecutive >= tun.maxFailures {
			distinctUsers++
		}
		if strongest == nil || streak.consecutive > strongest.consecutive {
			strongest = streak
		}
	}
	var strongestValue loginStreak
	if strongest != nil {
		strongestValue = *strongest
	}
	if len(byTarget) == 0 {
		delete(d.clients, ip)
	}
	d.mu.Unlock()
	if strongest == nil {
		return ev
	}

	ev.Details["consecutiveFailures"] = strongestValue.consecutive
	// Retained for evidence consumers that display the old name; it is now a
	// streak, never a total count across unrelated login targets.
	ev.Details["failedLogins"] = strongestValue.consecutive
	ev.Details["distinctUsers"] = distinctUsers
	ev.Details["route"] = strongestValue.route
	ev.Details["target"] = strongestValue.target
	ev.Score = ratioScore(strongestValue.consecutive, tun.maxFailures)
	ev.Details["severity"] = evidenceSeverity(ev.Score)
	ev.ThresholdCross = strongestValue.consecutive >= tun.maxFailures
	if ev.ThresholdCross {
		ev.AttackType = SignalBruteForce
	}
	return ev
}

func (d *BruteForceDetector) startCleanupTimer() {
	ticker := time.NewTicker(time.Minute)
	for now := range ticker.C {
		tun := d.settings()
		d.mu.Lock()
		for ip, byTarget := range d.clients {
			for key, streak := range byTarget {
				if now.Sub(streak.lastSeen) > tun.window {
					delete(byTarget, key)
				}
			}
			if len(byTarget) == 0 {
				delete(d.clients, ip)
			}
		}
		d.mu.Unlock()
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(body []byte) (int, error) {
	sr.status = cmp.Or(sr.status, http.StatusOK)
	return sr.ResponseWriter.Write(body)
}

func (sr *statusRecorder) Flush() {
	if f, ok := sr.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func extractIdentity(r *http.Request) string {
	bodyBytes, err := readAndRestoreBody(r)
	if err != nil || len(bodyBytes) == 0 {
		return ""
	}
	var payload struct {
		Email    string `json:"email"`
		Username string `json:"username"`
	}
	if json.Unmarshal(bodyBytes, &payload) != nil {
		return ""
	}
	if email := strings.TrimSpace(payload.Email); email != "" {
		return email
	}
	return strings.TrimSpace(payload.Username)
}
