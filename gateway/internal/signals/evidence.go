package signals

import "time"

// Signal names returned by Evidence.Signal. The decision engine keys off these.
const (
	SignalFlood      = "api_flooding"
	SignalSQLi       = "sql_injection"
	SignalTraversal  = "enumeration_path_traversal"
	SignalBruteForce = "consecutive_failed_logins"
	SignalRouteScan  = "unknown_route_scanning"
	SignalObjectEnum = "object_enumeration"
	SignalOwnership  = "ownership_violation"
	SignalReputation = "ip_reputation"
)

// Evidence is the standardized output every detector exposes via Metrics(ip).
// Detectors never enforce policy; they only fill this struct. A future
// decision engine will sum Score values and inspect ThresholdCross.
type Evidence struct {
	Signal         string         `json:"signal"`
	Score          int            `json:"score"`          // 0-100 contribution for this signal
	ThresholdCross bool           `json:"thresholdCross"` // true when this detector considers the signal fired
	AttackType     string         `json:"attackType"`     // detector-specific label, empty when clean
	Details        map[string]any `json:"details,omitempty"`
}

// Detector is the contract every attack signal implements so a collector
// or decision engine can treat them uniformly.
type Detector interface {
	Metrics(ip string) Evidence
}

// RequestIDHeader carries the id telemetry assigns to a request before the
// rest of the chain runs, so request-scoped detectors can label the evidence
// they store with the request that produced it.
const RequestIDHeader = "X-Request-ID"

// RequestScoped is implemented by detectors whose Evidence describes a single
// request rather than a rolling window.
//
// Telemetry asks these for the evidence belonging to the request it is
// recording. A request that never reached them -- the enforcer answers a
// blocked address first -- then reports nothing instead of the last request's
// result, which is the difference between "not inspected" and "attacked".
type RequestScoped interface {
	MetricsFor(ip, requestID string) Evidence
}

var (
	_ Detector = (*FloodDetector)(nil)
	_ Detector = (*SQLiDetector)(nil)
	_ Detector = (*TraversalEnumDetector)(nil)
	_ Detector = (*BruteForceDetector)(nil)
	_ Detector = (*UnknownRouteScanDetector)(nil)
	_ Detector = (*ObjectEnumerationDetector)(nil)
	_ Detector = (*ReputationDetector)(nil)

	// Windowed detectors (flood, brute force) are deliberately absent: their
	// counts stay true whether or not this request reached them.
	_ RequestScoped = (*SQLiDetector)(nil)
	_ RequestScoped = (*TraversalEnumDetector)(nil)

	// Reputation is request-scoped for a different reason than the other two:
	// its verdict is the same on every request, but it only *fires* once per
	// cooldown, and only the request that fired should report a cross.
	_ RequestScoped = (*ReputationDetector)(nil)
)

const lastEvidenceTTL = 5 * time.Minute

// Int reads a numeric detail. Missing or wrong-typed keys return 0.
func (e Evidence) Int(key string) int {
	if e.Details == nil {
		return 0
	}
	switch v := e.Details[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

// Strings reads a string-slice detail. Missing or wrong-typed keys return nil.
func (e Evidence) Strings(key string) []string {
	if e.Details == nil {
		return nil
	}
	v, _ := e.Details[key].([]string)
	return v
}

// dropOldest makes room in a full table by forgetting the entry seen longest
// ago, so a flood of new addresses cannot grow detector state without bound
// and cannot evict the ones that are still active. An entry with no time is
// never chosen.
func dropOldest[V any](m map[string]V, seen func(V) time.Time) {
	var oldestKey string
	var oldest time.Time
	for key, v := range m {
		if at := seen(v); !at.IsZero() && (oldestKey == "" || at.Before(oldest)) {
			oldestKey, oldest = key, at
		}
	}
	if oldestKey != "" {
		delete(m, oldestKey)
	}
}

func clampScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

// AdvisoryOnly reports detectors whose evidence must make a round trip through
// the control plane before it can affect a request. Their behavioural state is
// useful context, not an authority to install a gateway reflex block.
func AdvisoryOnly(signal string) bool {
	// Ownership is here although every hit is proof: the read it saw was
	// already refused, so there is nothing for a reflex block to add that the
	// control plane's policy does not do with the whole campaign in view.
	return signal == SignalBruteForce || signal == SignalRouteScan || signal == SignalObjectEnum || signal == SignalOwnership
}

func evidenceSeverity(score int) string {
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

// ratioScore maps count vs threshold onto 0-100.
// Below threshold: a weak proportional signal (0-30).
// At/above threshold: 60, 2x: 80, 5x: 100.
func ratioScore(count, threshold int) int {
	if threshold <= 0 || count <= 0 {
		return 0
	}
	if count < threshold {
		return count * 30 / threshold
	}
	if count >= threshold*5 {
		return 100
	}
	if count >= threshold*2 {
		return 80
	}
	return 60
}
