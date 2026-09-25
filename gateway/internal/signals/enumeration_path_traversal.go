package signals

import (
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

func DefaultTraversalPatterns() []string {
	return []string{
		"../",
		"..\\",
		"%2e%2e%2f",
		"%2e%2e/",
		"..%2f",
		"%2e%2e%5c",
	}
}

func DefaultEnumerationPatterns() []string {
	return []string{
		"/.env",
		"/.git",
		"/.aws",
		"/wp-admin",
		"/etc/passwd",
		"/.bash_history",
		"/.ssh",
	}
}

// TraversalEnumDetector inspects URLs for path traversal and enumeration patterns.
// travTunables is what the console can move at runtime, swapped whole.
type travTunables struct {
	enabled             bool
	traversalPatterns   []string
	enumerationPatterns []string
}

type TraversalEnumDetector struct {
	tun atomic.Pointer[travTunables]
	*lastEvidenceStore
}

func (ted *TraversalEnumDetector) settings() travTunables { return *ted.tun.Load() }

// Apply swaps in new settings, leaving the recent-evidence store intact.
func (ted *TraversalEnumDetector) Apply(cfg config.EnumerationConfig) {
	traversal := cfg.TraversalPatterns
	if len(traversal) == 0 {
		traversal = DefaultTraversalPatterns()
	}
	enumeration := cfg.EnumerationPatterns
	if len(enumeration) == 0 {
		enumeration = DefaultEnumerationPatterns()
	}
	ted.tun.Store(&travTunables{
		enabled:             cfg.Enabled,
		traversalPatterns:   traversal,
		enumerationPatterns: enumeration,
	})
}

func NewTraversalEnumDetector(cfg config.EnumerationConfig) *TraversalEnumDetector {
	ted := &TraversalEnumDetector{lastEvidenceStore: newLastEvidenceStore(SignalTraversal)}
	ted.Apply(cfg)
	return ted
}

func (ted *TraversalEnumDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tun := ted.settings()
		if !tun.enabled {
			next.ServeHTTP(w, r)
			return
		}

		ip := netutil.ClientIP(r)
		path, query := urlInspectionText(r)
		traversalHits := findPatternHits(path+" "+query, tun.traversalPatterns)
		enumHits := findPatternHits(path, tun.enumerationPatterns)
		ev := ted.evidenceFrom(traversalHits, enumHits)
		ted.put(ip, r.Header.Get(RequestIDHeader), ev)

		if len(traversalHits) > 0 {
			ted.logAlert(ip, r, "PATH TRAVERSAL", "matched Path Traversal signature in URL or query parameters")
		}
		if len(enumHits) > 0 {
			ted.logAlert(ip, r, "ENUMERATION ATTACK", "matched Enumeration/Forced Browsing signature in URL")
		}

		next.ServeHTTP(w, r)
	})
}

// urlInspectionText retains both the escaped request target and up to two
// decoded forms. Backends often decode a value after the proxy has parsed it;
// inspecting only one form let %252e%252e%252f bypass a ../ signature.
func urlInspectionText(r *http.Request) (string, string) {
	return decodedURLForms(r.URL.Path, r.URL.RawPath), decodedURLForms(r.URL.RawQuery, "")
}

func decodedURLForms(values ...string) string {
	forms := append([]string(nil), values...)
	for pass := 0; pass < 2; pass++ {
		end := len(forms)
		for _, value := range forms[:end] {
			decoded, err := url.PathUnescape(value)
			if err == nil && decoded != value {
				forms = append(forms, decoded)
			}
		}
	}
	return strings.Join(forms, " ")
}

func (ted *TraversalEnumDetector) evidenceFrom(traversalHits, enumHits []string) Evidence {
	ev := Evidence{
		Signal: SignalTraversal,
		Details: map[string]any{
			"pathTraversalDetected": len(traversalHits) > 0,
			"enumerationDetected":   len(enumHits) > 0,
			"traversalMatches":      len(traversalHits),
			"enumerationMatches":    len(enumHits),
			"matchedPatterns":       append(append([]string{}, traversalHits...), enumHits...),
		},
	}

	hasTraversal := len(traversalHits) > 0
	hasEnum := len(enumHits) > 0
	if !hasTraversal && !hasEnum {
		return ev
	}

	ev.ThresholdCross = true
	switch {
	case hasTraversal && hasEnum:
		ev.AttackType = "path_traversal+enumeration"
		ev.Score = 100
	case hasTraversal:
		ev.AttackType = "path_traversal"
		ev.Score = 80
	default:
		ev.AttackType = "enumeration"
		ev.Score = 50
	}
	return ev
}

func findPatternHits(target string, patterns []string) []string {
	lower := strings.ToLower(target)
	var hits []string
	for _, pattern := range patterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			hits = append(hits, pattern)
		}
	}
	return hits
}

func (ted *TraversalEnumDetector) logAlert(ip string, r *http.Request, attackType string, details string) {
	printAlert(attackType+" DETECTED", "Details", details, ip, r)
}
