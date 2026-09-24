// Package ownership stops Broken Object Level Authorization at the gateway.
//
// For each read endpoint listed in routes.ownership, the guard verifies the
// caller's token, lets the backend answer, and reads the owner of what it
// answered with. Someone else's object is replaced with a 404 before a byte of
// it leaves the gateway; in a list, other people's items are removed.
//
// It is the enforcement counterpart of the object enumeration detector: that
// one notices a client walking identifiers, this one makes the walk return
// nothing. Neither replaces an ownership check in the application -- above
// all for writes, which have happened by the time a response could be read.
package ownership

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/identity"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
)

// Reasons recorded on the evidence. Only a mismatch and a forged token cross
// the threshold: those are things a client did. The rest describe the caller
// being logged out or the backend answering in a way that cannot be checked.
const (
	ReasonOwnerMismatch = "owner_mismatch"
	ReasonForgedToken   = "forged_token"
	ReasonNoToken       = "missing_or_expired_token"
	ReasonItemsRemoved  = "items_removed"
	ReasonUnverifiable  = "unverifiable"
)

const (
	violationScore      = 80
	repeatScore         = 100
	repeatViolations    = 3
	itemsRemovedScore   = 30
	violationWindow     = 5 * time.Minute
	maxTrackedClients   = 10_000
	maxTrackedViolation = 64
)

type tunables struct {
	enabled        bool
	denyUnverified bool
	maxBodyBytes   int64
}

type rule struct {
	template   string
	ownerField []string
	listField  []string
	list       bool
}

type recorded struct {
	at        time.Time
	requestID string
	evidence  signals.Evidence
}

// Guard is both the enforcing middleware and the detector that reports what it
// refused, so telemetry and the control plane see every blocked read.
type Guard struct {
	tun      atomic.Pointer[tunables]
	verifier *identity.Verifier
	match    func(method, path string) string
	rules    map[string]rule

	mu         sync.Mutex
	last       map[string]recorded
	violations map[string][]time.Time
	warned     sync.Map
}

// NewGuard builds a guard for the configured rules. A nil verifier is only
// valid with no rules; the proxy refuses to start otherwise.
func NewGuard(cfg config.ObjectOwnershipConfig, rules []config.OwnershipRule, verifier *identity.Verifier, match func(method, path string) string) *Guard {
	g := &Guard{
		verifier:   verifier,
		match:      match,
		rules:      make(map[string]rule, len(rules)),
		last:       make(map[string]recorded),
		violations: make(map[string][]time.Time),
	}
	for _, r := range rules {
		compiled := rule{template: r.Template, ownerField: splitPath(r.OwnerField)}
		if r.ListField != "" {
			compiled.list = true
			compiled.listField = splitPath(r.ListField)
		}
		g.rules[r.Template] = compiled
	}
	g.Apply(cfg)
	return g
}

func splitPath(path string) []string {
	path = strings.TrimSpace(path)
	if path == "" || path == "." {
		return nil
	}
	return strings.Split(path, ".")
}

// Apply swaps the runtime settings. Rules and keys are boot-only.
func (g *Guard) Apply(cfg config.ObjectOwnershipConfig) {
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = 1 << 20
	}
	g.tun.Store(&tunables{
		enabled:        cfg.Enabled,
		denyUnverified: cfg.OnUnverifiable != "allow",
		maxBodyBytes:   maxBody,
	})
}

func (g *Guard) settings() tunables { return *g.tun.Load() }

func (g *Guard) ruleFor(r *http.Request) (rule, bool) {
	if g.match == nil || len(g.rules) == 0 || g.verifier == nil {
		return rule{}, false
	}
	template := g.match(r.Method, r.URL.Path)
	found, ok := g.rules[strings.ToUpper(r.Method)+" "+template]
	return found, ok
}

func (g *Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tun := g.settings()
		protected, ok := g.ruleFor(r)
		if !tun.enabled || !ok {
			next.ServeHTTP(w, r)
			return
		}

		ip := netutil.ClientIP(r)
		requestID := r.Header.Get(signals.RequestIDHeader)

		caller, err := g.verifier.FromRequest(r)
		if err != nil {
			reason := ReasonNoToken
			if errors.Is(err, identity.ErrForged) {
				reason = ReasonForgedToken
			}
			g.record(ip, requestID, protected.template, reason, "", "", 0)
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeJSON(w, http.StatusUnauthorized, `{"success":false,"message":"Authentication required"}`)
			return
		}
		if caller.Bypasses {
			next.ServeHTTP(w, r)
			return
		}

		// The owner must be readable, so ask for an uncompressed answer. Go's
		// transport still negotiates gzip with the backend on its own and
		// decompresses it before we see the body.
		r.Header.Del("Accept-Encoding")

		held := newHeldResponse(w, tun.maxBodyBytes, !tun.denyUnverified)
		next.ServeHTTP(held, r)

		g.decide(w, held, protected, caller, ip, requestID, tun)
	})
}

func (g *Guard) decide(w http.ResponseWriter, held *heldResponse, protected rule, caller identity.Caller, ip, requestID string, tun tunables) {
	status := held.statusCode()
	unverifiable := func(why string) {
		g.warnOnce(protected.template, why)
		g.record(ip, requestID, protected.template, ReasonUnverifiable, caller.ID, "", 0)
		if tun.denyUnverified {
			writeNotFound(w)
			return
		}
		held.release()
	}

	// Errors and redirects streamed through already: they carry nobody's
	// object. An empty success carries nothing either.
	if held.streaming && !held.overflow {
		return
	}
	if !held.overflow && held.body.Len() == 0 {
		held.release()
		return
	}
	if held.overflow {
		unverifiable("response larger than object_ownership.max_body_bytes")
		return
	}
	if encoding := held.header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		unverifiable("compressed response (" + encoding + ")")
		return
	}

	var body any
	decoder := json.NewDecoder(bytes.NewReader(held.body.Bytes()))
	decoder.UseNumber()
	if err := decoder.Decode(&body); err != nil {
		unverifiable("response is not JSON")
		return
	}

	if !protected.list {
		owner, found := lookup(body, protected.ownerField)
		ownerID := identity.ClaimString(owner)
		if !found || ownerID == "" {
			unverifiable("owner_field not found in response")
			return
		}
		if ownerID != caller.ID {
			g.record(ip, requestID, protected.template, ReasonOwnerMismatch, caller.ID, ownerID, 0)
			writeNotFound(w)
			return
		}
		g.clear(ip, requestID)
		held.release()
		return
	}

	listValue, found := lookup(body, protected.listField)
	items, isList := listValue.([]any)
	if !found || !isList {
		unverifiable("list_field is not an array in response")
		return
	}
	kept := make([]any, 0, len(items))
	removed := 0
	firstForeign := ""
	for _, item := range items {
		owner, ok := lookup(item, protected.ownerField)
		ownerID := identity.ClaimString(owner)
		switch {
		case ok && ownerID == caller.ID:
			kept = append(kept, item)
		case (!ok || ownerID == "") && !tun.denyUnverified:
			kept = append(kept, item)
		default:
			removed++
			firstForeign = cmp.Or(firstForeign, ownerID)
		}
	}
	if removed == 0 {
		g.clear(ip, requestID)
		held.release()
		return
	}

	g.record(ip, requestID, protected.template, ReasonItemsRemoved, caller.ID, firstForeign, removed)
	filtered, ok := replace(body, protected.listField, kept)
	if !ok {
		writeNotFound(w)
		return
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(filtered); err != nil {
		writeNotFound(w)
		return
	}
	held.header.Del("Content-Length")
	held.header.Del("ETag")
	held.copyHeaderTo(w)
	w.WriteHeader(status)
	_, _ = w.Write(bytes.TrimRight(out.Bytes(), "\n"))
}

func (g *Guard) warnOnce(template, why string) {
	if _, loaded := g.warned.LoadOrStore(template+"|"+why, true); !loaded {
		log.Printf("[ownership] cannot check %s: %s", template, why)
	}
}

// lookup walks a dotted path through decoded JSON objects.
func lookup(value any, path []string) (any, bool) {
	current := value
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[key]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

// replace sets the value at path, returning the new root.
func replace(root any, path []string, value any) (any, bool) {
	if len(path) == 0 {
		return value, true
	}
	object, ok := root.(map[string]any)
	if !ok {
		return nil, false
	}
	child, ok := replace(object[path[0]], path[1:], value)
	if !ok {
		return nil, false
	}
	object[path[0]] = child
	return object, true
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// writeNotFound answers the way a correct application does: someone else's
// object is indistinguishable from one that does not exist, so the response
// does not even confirm which identifiers are real.
func writeNotFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, `{"success":false,"message":"Not found"}`)
}

func (g *Guard) record(ip, requestID, template, reason, callerID, ownerID string, removed int) {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()

	crossed := reason == ReasonOwnerMismatch || reason == ReasonForgedToken
	recent := g.recentViolations(ip, now, crossed)

	ev := signals.Evidence{
		Signal: signals.SignalOwnership,
		Details: map[string]any{
			"template":         template,
			"reason":           reason,
			"caller":           callerID,
			"owner":            ownerID,
			"removedItems":     removed,
			"recentViolations": recent,
			"window":           violationWindow.String(),
		},
	}
	switch {
	case crossed:
		ev.ThresholdCross = true
		ev.AttackType = reason
		ev.Score = violationScore
		if recent >= repeatViolations {
			ev.Score = repeatScore
		}
	case reason == ReasonItemsRemoved:
		ev.Score = itemsRemovedScore
	}
	ev.Details["severity"] = severity(ev.Score)

	if _, exists := g.last[ip]; !exists && len(g.last) >= maxTrackedClients {
		g.dropOldest(now)
	}
	g.last[ip] = recorded{at: now, requestID: requestID, evidence: ev}
	if crossed {
		log.Printf("[ownership] refused %s for %s: %s (caller %q, owner %q, %d in %s)", template, ip, reason, callerID, ownerID, recent, violationWindow)
	}
}

// recentViolations prunes the IP's window and, when counting, adds now.
// Called with g.mu held.
func (g *Guard) recentViolations(ip string, now time.Time, add bool) int {
	times := g.violations[ip]
	kept := times[:0]
	for _, at := range times {
		if now.Sub(at) <= violationWindow {
			kept = append(kept, at)
		}
	}
	if add {
		if len(kept) >= maxTrackedViolation {
			kept = kept[1:]
		}
		kept = append(kept, now)
	}
	if len(kept) == 0 {
		delete(g.violations, ip)
		return 0
	}
	g.violations[ip] = kept
	return len(kept)
}

// dropOldest evicts expired clients, or the stalest one. Called with g.mu held.
func (g *Guard) dropOldest(now time.Time) {
	oldestIP := ""
	var oldest time.Time
	for ip, hit := range g.last {
		if now.Sub(hit.at) > violationWindow {
			delete(g.last, ip)
			delete(g.violations, ip)
			continue
		}
		if oldestIP == "" || hit.at.Before(oldest) {
			oldestIP, oldest = ip, hit.at
		}
	}
	if len(g.last) >= maxTrackedClients && oldestIP != "" {
		delete(g.last, oldestIP)
		delete(g.violations, oldestIP)
	}
}

// clear forgets the last evidence for an IP after an allowed read, so a
// client's clean request does not keep reporting its previous refusal.
func (g *Guard) clear(ip, requestID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if hit, ok := g.last[ip]; ok {
		hit.requestID = requestID
		hit.evidence = signals.Evidence{Signal: signals.SignalOwnership}
		g.last[ip] = hit
	}
}

// Metrics is the IP's latest ownership evidence.
func (g *Guard) Metrics(ip string) signals.Evidence {
	g.mu.Lock()
	defer g.mu.Unlock()
	hit, ok := g.last[ip]
	if !ok || time.Since(hit.at) > violationWindow {
		return signals.Evidence{Signal: signals.SignalOwnership}
	}
	return hit.evidence
}

// MetricsFor is the evidence of one request, and nothing for a request the
// guard did not check.
func (g *Guard) MetricsFor(ip, requestID string) signals.Evidence {
	g.mu.Lock()
	defer g.mu.Unlock()
	hit, ok := g.last[ip]
	if !ok || requestID == "" || hit.requestID != requestID || time.Since(hit.at) > violationWindow {
		return signals.Evidence{Signal: signals.SignalOwnership}
	}
	return hit.evidence
}

func severity(score int) string {
	switch {
	case score >= 80:
		return "high"
	case score >= 60:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

var (
	_ signals.Detector      = (*Guard)(nil)
	_ signals.RequestScoped = (*Guard)(nil)
)
