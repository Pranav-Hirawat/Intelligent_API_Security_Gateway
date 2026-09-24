// Package enforcement gives the gateway a reflex.
//
// Policy enforcement -- internal/policy -- acts on decisions the Python control
// plane has reasoned about. That is the right place for anything involving
// judgement, but it is not fast: a decision takes up to one agent cycle (30s)
// plus one snapshot refresh (5s) to reach the gateway. A flood is finished by
// then.
//
// This is the other half: when a detector the operator has explicitly trusted
// crosses its threshold, the gateway refuses that address itself, immediately,
// without asking anyone. It is deliberately the dumber of the two.
//
// Four rules keep it dumb enough to be safe:
//
//   - Only signals named in the config may trigger it. An empty list enforces
//     nothing, whatever else is switched on.
//   - The evidence has to clear a score floor as well as the detector's own
//     threshold, so a marginal hit is not enough.
//   - Every block expires by itself. Nothing renews one, exactly as with
//     policy keys, so the worst a mistake costs is block.duration.
//   - Addresses that cannot meaningfully be blocked are exempt, and loopback
//     and private ranges are exempt by default.
//
// The control plane still owns correlation, campaigns and escalation. When it
// reaches a decision about an address, that decision wins -- see the ordering
// in policy.Chain.
package enforcement

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/policy"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
)

// RecommendedSignals is what configs/config.yaml.example ships, and what an
// operator should copy if they are unsure.
//
// Flood is windowed and counts repetition rather than one request that happened
// to contain a suspicious string. The request-scoped detectors are absent on
// purpose -- a single request
// carrying "UNION" may be an attack or may be someone searching a catalogue,
// and that is a judgement, which is the control plane's job.
//
// It is a recommendation and not a default. Nothing applies it automatically;
// see New.
var RecommendedSignals = []string{signals.SignalFlood}

// DefaultExempt are the ranges never blocked by reflex.
//
// The documentation ranges of RFC 5737 are deliberately absent: they can never
// belong to a real host, so they are safe to block, and the demo drives
// traffic from them. This mirrors the control plane's own rule in
// policy/writer.py.
var DefaultExempt = []string{
	"127.0.0.0/8",
	"::1/128",
	"10.0.0.0/8",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"fc00::/7",
	"fe80::/10",
}

// Config controls the reflex. The zero value enforces nothing.
type Config struct {
	Enabled     bool
	Duration    time.Duration
	Signals     []string
	MinScore    int
	ExemptCIDRs []string
}

// sweepInterval is how often expired blocks are dropped from memory.
const sweepInterval = 30 * time.Second

type block struct {
	until  time.Time
	signal string
	score  int
}

// Reflex holds the addresses the gateway has refused on its own.
//
// It satisfies policy.Lookuper, so the enforcing middleware does not need to
// know there are two sources of decisions -- there is one place that decides
// what a decision means, and it stays in internal/policy.
// reflexTunables is everything the console can move at runtime. Swapped whole,
// so a request is judged against one consistent set of rules rather than a
// threshold from the new settings and an exemption list from the old.
type reflexTunables struct {
	enabled  bool
	duration time.Duration
	minScore int
	signals  map[string]bool
	exempt   []*net.IPNet
}

type Reflex struct {
	tun atomic.Pointer[reflexTunables]

	mu      sync.RWMutex
	blocked map[string]block

	stop chan struct{}
	done chan struct{}
}

// settings returns the tunables in force. Never nil once New has returned.
func (r *Reflex) settings() *reflexTunables { return r.tun.Load() }

// Apply swaps in new settings, rejecting them if a CIDR will not parse so that
// a typo in the exempt list cannot quietly leave everybody blockable.
//
// Blocks already in force are kept. Lowering the duration does not cut a block
// short and raising it does not extend one -- each block carries the deadline
// it was given, which is the same promise Observe makes.
func (r *Reflex) Apply(cfg Config) error {
	tun, err := buildTunables(cfg)
	if err != nil {
		return err
	}
	r.tun.Store(tun)
	return nil
}

func buildTunables(cfg Config) (*reflexTunables, error) {
	t := &reflexTunables{
		enabled:  cfg.Enabled,
		duration: cfg.Duration,
		minScore: cfg.MinScore,
		signals:  map[string]bool{},
	}

	if t.duration <= 0 {
		t.duration = 5 * time.Minute
	}

	// Signals is *not* defaulted when absent. enforcement.block.enabled has
	// sat in config files since long before anything read it, so a build that
	// armed itself on that flag alone would start refusing traffic on the
	// strength of configuration nobody had revisited. Naming the detectors is
	// the act of consent; Describe reports the enabled-but-silent case so it
	// cannot be mistaken for working.
	for _, name := range cfg.Signals {
		if name = strings.TrimSpace(name); name != "" {
			if signals.AdvisoryOnly(name) {
				return nil, fmt.Errorf("%s is advisory-only and must be enforced through the control-plane policy writer", name)
			}
			t.signals[name] = true
		}
	}

	entries := cfg.ExemptCIDRs
	if entries == nil {
		entries = DefaultExempt
	}
	exempt, err := netutil.ParseCIDRs(entries, "exempt range")
	if err != nil {
		return nil, err
	}
	t.exempt = exempt

	return t, nil
}

// New builds a Reflex. An error means the configuration is unusable, which is
// worth refusing to start over: silently enforcing nothing would look
// identical to enforcing correctly.
func New(cfg Config) (*Reflex, error) {
	r := &Reflex{
		blocked: map[string]block{},
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	if err := r.Apply(cfg); err != nil {
		return nil, err
	}
	return r, nil
}

// Active reports whether this will ever block anything, which is what the
// startup log needs to say honestly. Enabled with no signals is a
// configuration that looks armed and is not.
func (r *Reflex) Active() bool {
	if r == nil {
		return false
	}
	t := r.settings()
	return t.enabled && len(t.signals) > 0
}

// Describe is the one-line summary for the startup log.
func (r *Reflex) Describe() string {
	if r == nil {
		return "gateway-side blocking off"
	}
	t := r.settings()
	if !t.enabled {
		return "gateway-side blocking off"
	}
	if len(t.signals) == 0 {
		return "gateway-side blocking enabled but no signals listed: nothing will be blocked"
	}
	names := make([]string, 0, len(t.signals))
	for name := range t.signals {
		names = append(names, name)
	}
	// Sorted so the log line is stable between restarts.
	sort.Strings(names)
	return "gateway-side blocking on for " + strings.Join(names, ", ") +
		" at score >= " + strconv.Itoa(t.minScore) + " for " + t.duration.String()
}

// Observe records a block when this request's evidence justifies one.
//
// Called after the detectors have run. It never touches the current request --
// that one is already through -- so the earliest a reflex block can apply is
// the caller's next request, which is exactly when it is useful.
func (r *Reflex) Observe(ip string, snap signals.Snapshot) {
	// One read of the settings for the whole decision, so the signal list, the
	// score floor and the duration all come from the same generation.
	t := r.settings()
	if !r.Active() || ip == "" || r.isExempt(t, ip) {
		return
	}

	for _, ev := range snap.Evidence {
		if !ev.ThresholdCross || !t.signals[ev.Signal] {
			continue
		}
		// The detector's own threshold and a score floor: two independent
		// reasons to be confident, so raising the floor is how an operator
		// makes this less trigger-happy without disabling a detector.
		if ev.Score < t.minScore {
			continue
		}

		now := time.Now()
		r.mu.Lock()
		existing, held := r.blocked[ip]
		// Do not extend a block that is already running. A blocked address
		// that keeps knocking would otherwise never be released, which is the
		// unexpiring-enforcement problem in a different costume.
		if !held || !existing.until.After(now) {
			r.blocked[ip] = block{
				until:  now.Add(t.duration),
				signal: ev.Signal,
				score:  ev.Score,
			}
			log.Printf("[enforcement] blocking %s for %s: %s crossed threshold (score %d)",
				ip, t.duration, ev.Signal, ev.Score)
		}
		r.mu.Unlock()
		return
	}
}

// Lookup satisfies policy.Lookuper.
func (r *Reflex) Lookup(ip string) (policy.Decision, bool) {
	if !r.Active() {
		return policy.Decision{}, false
	}

	r.mu.RLock()
	b, held := r.blocked[ip]
	r.mu.RUnlock()

	if !held {
		return policy.Decision{}, false
	}

	// Expiry is checked on read as well as swept in the background, so a block
	// is never enforced past its deadline even if the sweeper is between runs.
	remaining := time.Until(b.until)
	if remaining <= 0 {
		return policy.Decision{}, false
	}

	return policy.Decision{
		Action:     policy.ActionTempBlock,
		CampaignID: "gateway",
		Confidence: 1,
		Reason:     b.signal + " crossed its threshold at the gateway",
		ExpiresIn:  int(remaining.Seconds()),
	}, true
}

// Start sweeps expired blocks so a long run cannot grow the map without bound.
func (r *Reflex) Start() {
	// The sweeper runs whether or not blocking is on right now: the console can
	// arm the reflex later, and a sweeper that only exists when it booted armed
	// would let the block map grow unswept from that moment on. Expiry is also
	// checked on read, so a missed sweep is never a block served past its
	// deadline -- only memory held longer than needed.
	go func() {
		defer close(r.done)
		// Fixed cadence rather than the block duration, which can now change
		// underneath it. Often enough that memory tracks reality, rarely
		// enough to be free.
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-r.stop:
				return
			case <-ticker.C:
				r.sweep(time.Now())
			}
		}
	}()
}

func (r *Reflex) sweep(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for ip, b := range r.blocked {
		if !b.until.After(now) {
			delete(r.blocked, ip)
		}
	}
}

func (r *Reflex) Close() {
	if r == nil {
		return
	}
	close(r.stop)
	<-r.done
}

func (r *Reflex) isExempt(t *reflexTunables, ip string) bool {
	// An address that will not parse cannot be matched against a range either,
	// so refusing to block it is the only safe answer. NetworksContain says
	// "not contained" for those, which for this caller means the opposite.
	if net.ParseIP(ip) == nil {
		return true
	}
	return netutil.NetworksContain(t.exempt, ip)
}
