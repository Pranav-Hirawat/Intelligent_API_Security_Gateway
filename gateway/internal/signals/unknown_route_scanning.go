package signals

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

const unmatchedRoute = "<unmatched>"

type unknownRouteScanTunables struct {
	enabled           bool
	distinctPaths     int
	window            time.Duration
	maxClients        int
	maxPathsPerClient int
}

type scannedPath struct {
	path string
	at   time.Time
}

type unknownRouteClient struct {
	paths    map[string]time.Time
	lastSeen time.Time
}

// UnknownRouteScanDetector notices a client trying several paths the route
// table does not recognise. A repeated missing favicon is not a scan, and a
// backend 404 on a known route is never even considered here.
type UnknownRouteScanDetector struct {
	tun     atomic.Pointer[unknownRouteScanTunables]
	match   func(method, path string) string
	mu      sync.Mutex
	clients map[string]*unknownRouteClient
}

func NewUnknownRouteScanDetector(cfg config.UnknownRouteScanConfig, match func(string, string) string) *UnknownRouteScanDetector {
	d := &UnknownRouteScanDetector{
		match:   match,
		clients: make(map[string]*unknownRouteClient),
	}
	d.Apply(cfg)
	go d.startCleanupTimer()
	return d
}

func (d *UnknownRouteScanDetector) settings() unknownRouteScanTunables { return *d.tun.Load() }

// Apply keeps observations already made. Tightening a limit must judge the
// paths a client has already probed instead of granting a fresh allowance.
func (d *UnknownRouteScanDetector) Apply(cfg config.UnknownRouteScanConfig) {
	if cfg.DistinctPaths <= 0 {
		cfg.DistinctPaths = 8
	}
	if cfg.Window <= 0 {
		cfg.Window = 5 * time.Minute
	}
	if cfg.MaxClients <= 0 {
		cfg.MaxClients = 10_000
	}
	if cfg.MaxPathsPerClient <= 0 {
		cfg.MaxPathsPerClient = 64
	}
	d.tun.Store(&unknownRouteScanTunables{
		enabled:           cfg.Enabled,
		distinctPaths:     cfg.DistinctPaths,
		window:            cfg.Window,
		maxClients:        cfg.MaxClients,
		maxPathsPerClient: cfg.MaxPathsPerClient,
	})
}

func (d *UnknownRouteScanDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tun := d.settings()
		if tun.enabled && d.routeFor(r) == unmatchedRoute {
			d.observe(netutil.ClientIP(r), rawPath(r), time.Now(), tun)
		}
		next.ServeHTTP(w, r)
	})
}

func (d *UnknownRouteScanDetector) routeFor(r *http.Request) string {
	if d.match == nil {
		return ""
	}
	return d.match(r.Method, r.URL.Path)
}

// rawPath preserves encoded path text when Go retained it. The route table
// deliberately matches URL.Path; using it as the observation key too would
// erase meaningful differences between probes before this detector can see them.
func rawPath(r *http.Request) string {
	if r.URL.RawPath != "" {
		return r.URL.RawPath
	}
	return r.URL.EscapedPath()
}

func (d *UnknownRouteScanDetector) observe(ip, path string, now time.Time, tun unknownRouteScanTunables) {
	d.mu.Lock()
	defer d.mu.Unlock()

	client := d.clients[ip]
	if client == nil {
		if len(d.clients) >= tun.maxClients {
			// A detector must never turn an address spray into unbounded memory.
			// Evict the stalest record; missing one new scanner is safer than
			// making every request retain attacker-controlled path strings.
			dropOldest(d.clients, func(c *unknownRouteClient) time.Time { return c.lastSeen })
		}
		client = &unknownRouteClient{paths: make(map[string]time.Time)}
		d.clients[ip] = client
	}

	pruneUnknownPaths(client.paths, now.Add(-tun.window))
	if _, seen := client.paths[path]; seen || len(client.paths) < tun.maxPathsPerClient {
		// A repeat does not increase diversity, but it does keep this distinct
		// path inside the rolling window it was actually observed in.
		client.paths[path] = now
	}
	client.lastSeen = now
}

func (d *UnknownRouteScanDetector) Metrics(ip string) Evidence {
	tun := d.settings()
	ev := Evidence{Signal: SignalRouteScan, Details: map[string]any{
		"distinctPaths":   0,
		"threshold":       tun.distinctPaths,
		"window":          tun.window.String(),
		"matchedRoute":    unmatchedRoute,
		"supportingPaths": []string{},
	}}
	if !tun.enabled {
		return ev
	}

	d.mu.Lock()
	client := d.clients[ip]
	count := 0
	if client != nil {
		now := time.Now()
		pruneUnknownPaths(client.paths, now.Add(-tun.window))
		client.lastSeen = now
		paths := make([]scannedPath, 0, len(client.paths))
		for path, at := range client.paths {
			paths = append(paths, scannedPath{path: path, at: at})
		}
		// The map is intentionally bounded; retaining a small recent sample makes
		// an alert actionable without turning its details into another path store.
		supporting := make([]string, 0, min(len(paths), 8))
		for len(paths) > 0 && len(supporting) < 8 {
			newest := 0
			for i := 1; i < len(paths); i++ {
				if paths[i].at.After(paths[newest].at) {
					newest = i
				}
			}
			supporting = append(supporting, paths[newest].path)
			paths = append(paths[:newest], paths[newest+1:]...)
		}
		ev.Details["supportingPaths"] = supporting
		count = len(client.paths)
	}
	d.mu.Unlock()

	ev.Details["distinctPaths"] = count
	ev.Score = ratioScore(count, tun.distinctPaths)
	ev.Details["severity"] = evidenceSeverity(ev.Score)
	ev.ThresholdCross = count >= tun.distinctPaths
	if ev.ThresholdCross {
		ev.AttackType = SignalRouteScan
	}
	return ev
}

func (d *UnknownRouteScanDetector) startCleanupTimer() {
	ticker := time.NewTicker(time.Minute)
	for now := range ticker.C {
		tun := d.settings()
		d.mu.Lock()
		for ip, client := range d.clients {
			pruneUnknownPaths(client.paths, now.Add(-tun.window))
			if len(client.paths) == 0 || now.Sub(client.lastSeen) > tun.window {
				delete(d.clients, ip)
			}
		}
		d.mu.Unlock()
	}
}

func pruneUnknownPaths(paths map[string]time.Time, cutoff time.Time) {
	for path, at := range paths {
		if !at.After(cutoff) {
			delete(paths, path)
		}
	}
}
