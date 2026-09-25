/*
	IP Reputation Signal
		- Answers "who is this address" rather than "what did it just do"
		- The only detector that can fire on a first request: every other one
		  here is windowed and needs the attacker to repeat themselves
		- DOES NOT BLOCK on its own. Like every detector it emits evidence;
		  whether it may block is the reflex's `block.signals` allowlist.

	Why it fires on a cooldown
		A listed address is listed on every request it makes. Firing each time
		would write one Evidence per request, which does two bad things: it
		swamps the correlation agent's dominant-detector count so a real attack
		is described as "reputation", and it multiplies volume on a stream the
		control plane already drains slower than a flood fills it.

		So the address is scored every time -- its risk is a standing fact --
		but it only *fires* once per cooldown. This is the same split SQLi
		already makes for a low-confidence match: a score without a threshold
		cross.
*/

package signals

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/reputation"
)

// reputationTunables is what the console can move at runtime, swapped whole.
//
// The feed's *source* is deliberately not in here. Where the list comes from
// is structural, like a listen address: it is read once at startup. What can
// move live is whether the detector is on and how loudly it answers.
type reputationTunables struct {
	enabled  bool
	score    int
	cooldown time.Duration
}

// firing records the last time an address fired, and which request did it.
type firing struct {
	at        time.Time
	requestID string
}

type ReputationDetector struct {
	tun  atomic.Pointer[reputationTunables]
	feed *reputation.Feed

	// Only listed addresses ever land here, so this is bounded by the feed and
	// by who actually shows up -- unlike a map keyed by every client seen. It
	// is swept anyway: a long run should not hold an address that stopped
	// calling hours ago.
	mu    sync.Mutex
	fired map[string]firing
}

func (d *ReputationDetector) settings() reputationTunables { return *d.tun.Load() }

// Apply swaps in new settings. Recorded firings are kept: an address part-way
// through a cooldown should not get a fresh one because the score was edited.
func (d *ReputationDetector) Apply(cfg config.IPReputationConfig) {
	score := cfg.Score
	if score <= 0 {
		score = DefaultReputationScore
	}
	cooldown := cfg.Cooldown
	if cooldown <= 0 {
		cooldown = DefaultReputationCooldown
	}
	d.tun.Store(&reputationTunables{
		enabled:  cfg.Enabled,
		score:    clampScore(score),
		cooldown: cooldown,
	})
}

const (
	// DefaultReputationScore matches the reflex's default min_score, so naming
	// this detector in `block.signals` actually lets it act. A score below that
	// floor would make the allowlist entry look enabled and do nothing.
	DefaultReputationScore = 80

	// DefaultReputationCooldown is how long one address stays quiet after
	// firing. Long enough to keep the stream clean, short enough that a
	// campaign still sees the address if it keeps calling.
	DefaultReputationCooldown = 5 * time.Minute
)

func NewReputationDetector(feed *reputation.Feed, cfg config.IPReputationConfig) *ReputationDetector {
	d := &ReputationDetector{feed: feed, fired: make(map[string]firing)}
	d.Apply(cfg)

	// Started unconditionally: the console can switch this on later, and a
	// sweeper that only exists when it booted enabled would let the map grow
	// from that point on.
	go d.startCleanupTimer()
	return d
}

func (d *ReputationDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tun := d.settings()
		if !tun.enabled {
			next.ServeHTTP(w, r)
			return
		}

		ip := netutil.ClientIP(r)
		if d.feed.Contains(ip) && d.mark(ip, r.Header.Get(RequestIDHeader), tun.cooldown) {
			d.logAlert(ip, r)
		}

		next.ServeHTTP(w, r)
	})
}

// mark reports whether this request is the one that fires. Requests inside the
// cooldown still score; they just do not raise a fresh signal.
func (d *ReputationDetector) mark(ip, requestID string, cooldown time.Duration) bool {
	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	if last, seen := d.fired[ip]; seen && now.Sub(last.at) < cooldown {
		return false
	}
	d.fired[ip] = firing{at: now, requestID: requestID}
	return true
}

// Metrics answers "is this address known", which is true whether or not this
// request was the one that fired.
func (d *ReputationDetector) Metrics(ip string) Evidence {
	tun := d.settings()
	ev := d.baseEvidence(ip, tun)
	if ev.Score == 0 {
		return ev
	}

	d.mu.Lock()
	last, seen := d.fired[ip]
	d.mu.Unlock()

	if seen && time.Since(last.at) < tun.cooldown {
		ev.ThresholdCross = true
		// Same as the signal name, which is how summarize() knows not to list
		// it twice. This detector has one kind of finding: unlike brute force,
		// where the attack type distinguishes spraying from classic guessing,
		// there is nothing here the signal name does not already say.
		ev.AttackType = SignalReputation
	}
	return ev
}

// MetricsFor answers for one request, so only the request that actually fired
// reports a threshold cross. Without this every request from a listed address
// would look like a fresh hit to the control plane for a whole cooldown.
func (d *ReputationDetector) MetricsFor(ip, requestID string) Evidence {
	tun := d.settings()
	ev := d.baseEvidence(ip, tun)
	if ev.Score == 0 || requestID == "" {
		return ev
	}

	d.mu.Lock()
	last, seen := d.fired[ip]
	d.mu.Unlock()

	if seen && last.requestID == requestID {
		ev.ThresholdCross = true
		ev.AttackType = SignalReputation
	}
	return ev
}

// baseEvidence is the part both views agree on: a listed address carries its
// score on every request, because being listed is not a thing that happens --
// it is a thing that is true.
func (d *ReputationDetector) baseEvidence(ip string, tun reputationTunables) Evidence {
	ev := Evidence{
		Signal: SignalReputation,
		Details: map[string]any{
			"listed": false,
		},
	}
	if !tun.enabled || !d.feed.Contains(ip) {
		return ev
	}

	ev.Score = tun.score
	ev.Details["listed"] = true
	ev.Details["feed"] = d.feed.Describe()
	return ev
}

func (d *ReputationDetector) startCleanupTimer() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		cutoff := 2 * d.settings().cooldown
		now := time.Now()

		d.mu.Lock()
		for ip, last := range d.fired {
			if now.Sub(last.at) > cutoff {
				delete(d.fired, ip)
			}
		}
		d.mu.Unlock()
	}
}

func (d *ReputationDetector) logAlert(ip string, r *http.Request) {
	printAlert("KNOWN BAD ADDRESS", "Source", d.feed.Describe(), ip, r)
}
