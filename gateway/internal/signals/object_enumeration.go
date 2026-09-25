package signals

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

// Bonuses on top of the distinct-identifier score, applied only once the
// threshold is crossed. Below it, a handful of denied or consecutive lookups
// is ordinary: a stale bookmark, a user paging through their own orders.
const (
	objectDeniedShare     = 0.5
	objectDeniedBonus     = 20
	objectSequentialRun   = 5
	objectSequentialBonus = 10
	objectSupportingIDs   = 8
)

type objectEnumerationTunables struct {
	enabled         bool
	distinctIDs     int
	window          time.Duration
	maxClients      int
	maxIDsPerClient int
}

type objectLookup struct {
	at     time.Time
	denied bool
}

type objectClient struct {
	// Keyed by "METHOD /template", then by identifier.
	trails   map[string]map[string]objectLookup
	lastSeen time.Time
}

// ObjectEnumerationDetector notices one client requesting many distinct object
// identifiers on an endpoint that returns someone's object -- the pattern of
// Broken Object Level Authorization (BOLA / IDOR) being exploited.
//
// Every one of those requests is individually valid, which is why nothing in
// the application sees it. What the gateway cannot see is ownership: it has no
// idea whose order 17 is. So this is evidence of harvesting behaviour, never
// proof of an authorization failure, and it is advisory-only for the reflex.
// The fix for BOLA itself is an ownership check in the application.
type ObjectEnumerationDetector struct {
	tun     atomic.Pointer[objectEnumerationTunables]
	match   func(method, path string) (string, []string)
	watched map[string]bool
	mu      sync.Mutex
	clients map[string]*objectClient
}

// NewObjectEnumerationDetector watches the given "METHOD /path/{param}"
// templates. A nil match or no templates leaves it observing nothing.
func NewObjectEnumerationDetector(cfg config.ObjectEnumerationConfig, templates []string, match func(string, string) (string, []string)) *ObjectEnumerationDetector {
	d := &ObjectEnumerationDetector{
		match:   match,
		watched: make(map[string]bool, len(templates)),
		clients: make(map[string]*objectClient),
	}
	for _, raw := range templates {
		if fields := strings.Fields(raw); len(fields) == 2 {
			d.watched[strings.ToUpper(fields[0])+" "+fields[1]] = true
		}
	}
	d.Apply(cfg)
	go d.startCleanupTimer()
	return d
}

func (d *ObjectEnumerationDetector) settings() objectEnumerationTunables { return *d.tun.Load() }

// Apply keeps observations already made, so tightening a limit judges the
// identifiers a client has already walked instead of granting a fresh allowance.
func (d *ObjectEnumerationDetector) Apply(cfg config.ObjectEnumerationConfig) {
	if cfg.DistinctIDs <= 0 {
		cfg.DistinctIDs = 20
	}
	if cfg.Window <= 0 {
		cfg.Window = 5 * time.Minute
	}
	if cfg.MaxClients <= 0 {
		cfg.MaxClients = 10_000
	}
	if cfg.MaxIDsPerClient <= 0 {
		cfg.MaxIDsPerClient = 256
	}
	d.tun.Store(&objectEnumerationTunables{
		enabled:         cfg.Enabled,
		distinctIDs:     cfg.DistinctIDs,
		window:          cfg.Window,
		maxClients:      cfg.MaxClients,
		maxIDsPerClient: cfg.MaxIDsPerClient,
	})
}

func (d *ObjectEnumerationDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tun := d.settings()
		key, id, ok := d.objectFor(r)
		if !tun.enabled || !ok {
			next.ServeHTTP(w, r)
			return
		}

		// Observed after the backend answers: a run of refusals is what an
		// attacker guessing identifiers they may not read looks like.
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		d.observe(netutil.ClientIP(r), key, id, deniedStatus(rec.status), time.Now(), tun)
	})
}

func (d *ObjectEnumerationDetector) objectFor(r *http.Request) (key, id string, ok bool) {
	if d.match == nil || len(d.watched) == 0 {
		return "", "", false
	}
	template, params := d.match(r.Method, r.URL.Path)
	key = strings.ToUpper(r.Method) + " " + template
	if !d.watched[key] || len(params) == 0 {
		return "", "", false
	}
	// A template with several parameters names one object by all of them:
	// /users/5/orders/17 is not the same object as /users/6/orders/17.
	return key, strings.Join(params, "/"), true
}

func deniedStatus(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound
}

func (d *ObjectEnumerationDetector) observe(ip, key, id string, denied bool, now time.Time, tun objectEnumerationTunables) {
	d.mu.Lock()
	defer d.mu.Unlock()

	client := d.clients[ip]
	if client == nil {
		if len(d.clients) >= tun.maxClients {
			// Identifiers are attacker input; an address spray must not become
			// unbounded memory. Losing the stalest client is the safer failure.
			dropOldest(d.clients, func(c *objectClient) time.Time { return c.lastSeen })
		}
		client = &objectClient{trails: make(map[string]map[string]objectLookup)}
		d.clients[ip] = client
	}

	trail := client.trails[key]
	if trail == nil {
		trail = make(map[string]objectLookup)
		client.trails[key] = trail
	}
	pruneObjectLookups(trail, now.Add(-tun.window))
	if _, seen := trail[id]; seen || len(trail) < tun.maxIDsPerClient {
		// A repeat adds no diversity, but it refreshes the identifier's place in
		// the window and records whether it was refused this time.
		trail[id] = objectLookup{at: now, denied: denied}
	}
	client.lastSeen = now
}

// Metrics reports the client's most-walked object template.
func (d *ObjectEnumerationDetector) Metrics(ip string) Evidence {
	tun := d.settings()
	ev := Evidence{Signal: SignalObjectEnum, Details: map[string]any{
		"template":        "",
		"distinctIds":     0,
		"deniedResponses": 0,
		"deniedShare":     0.0,
		"sequentialRun":   0,
		"threshold":       tun.distinctIDs,
		"window":          tun.window.String(),
		"supportingIds":   []string{},
	}}
	if !tun.enabled {
		return ev
	}

	d.mu.Lock()
	var bestKey string
	var best map[string]objectLookup
	bestDenied := 0
	if client := d.clients[ip]; client != nil {
		now := time.Now()
		client.lastSeen = now
		for key, trail := range client.trails {
			pruneObjectLookups(trail, now.Add(-tun.window))
			denied := countDenied(trail)
			if len(trail) > len(best) || (len(trail) == len(best) && denied > bestDenied) {
				bestKey, best, bestDenied = key, trail, denied
			}
		}
	}
	count := len(best)
	ids := make([]string, 0, count)
	lookups := make([]objectLookup, 0, count)
	for id, lookup := range best {
		ids = append(ids, id)
		lookups = append(lookups, lookup)
	}
	d.mu.Unlock()

	if count == 0 {
		ev.Details["severity"] = evidenceSeverity(0)
		return ev
	}

	// Newest first, so the sample in an alert is what the client did last.
	order := make([]int, count)
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool { return lookups[order[a]].at.After(lookups[order[b]].at) })
	supporting := make([]string, 0, min(count, objectSupportingIDs))
	for _, i := range order[:min(count, objectSupportingIDs)] {
		supporting = append(supporting, ids[i])
	}

	share := float64(bestDenied) / float64(count)
	run := longestConsecutiveRun(ids)

	ev.Details["template"] = bestKey
	ev.Details["distinctIds"] = count
	ev.Details["deniedResponses"] = bestDenied
	ev.Details["deniedShare"] = share
	ev.Details["sequentialRun"] = run
	ev.Details["supportingIds"] = supporting

	ev.Score = ratioScore(count, tun.distinctIDs)
	ev.ThresholdCross = count >= tun.distinctIDs
	if ev.ThresholdCross {
		ev.AttackType = SignalObjectEnum
		if share >= objectDeniedShare {
			ev.Score += objectDeniedBonus
		}
		if run >= objectSequentialRun {
			ev.Score += objectSequentialBonus
		}
		ev.Score = clampScore(ev.Score)
	}
	ev.Details["severity"] = evidenceSeverity(ev.Score)
	return ev
}

// longestConsecutiveRun is the longest stretch of integers n, n+1, n+2, ...
// among the identifiers. A script counting through ids produces one; a person
// opening the orders on their own account page rarely does. Non-numeric ids
// (UUIDs, multi-part keys) contribute nothing, which is correct: they cannot be
// counted through.
func longestConsecutiveRun(ids []string) int {
	numbers := make([]int, 0, len(ids))
	for _, id := range ids {
		if n, err := strconv.Atoi(id); err == nil {
			numbers = append(numbers, n)
		}
	}
	if len(numbers) == 0 {
		return 0
	}
	sort.Ints(numbers)
	longest, current := 1, 1
	for i := 1; i < len(numbers); i++ {
		switch numbers[i] - numbers[i-1] {
		case 0:
		case 1:
			current++
			longest = max(longest, current)
		default:
			current = 1
		}
	}
	return longest
}

func countDenied(trail map[string]objectLookup) int {
	denied := 0
	for _, lookup := range trail {
		if lookup.denied {
			denied++
		}
	}
	return denied
}

func (d *ObjectEnumerationDetector) startCleanupTimer() {
	ticker := time.NewTicker(time.Minute)
	for now := range ticker.C {
		tun := d.settings()
		d.mu.Lock()
		for ip, client := range d.clients {
			for key, trail := range client.trails {
				pruneObjectLookups(trail, now.Add(-tun.window))
				if len(trail) == 0 {
					delete(client.trails, key)
				}
			}
			if len(client.trails) == 0 || now.Sub(client.lastSeen) > tun.window {
				delete(d.clients, ip)
			}
		}
		d.mu.Unlock()
	}
}

func pruneObjectLookups(trail map[string]objectLookup, cutoff time.Time) {
	for id, lookup := range trail {
		if !lookup.at.After(cutoff) {
			delete(trail, id)
		}
	}
}
