package signals

import (
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

// The patterns used when configuration names none.
var defaultSQLPatterns = []string{"' OR", "--", "UNION SELECT", " OR 1=1"}

// sqliTunables is what the console can move at runtime, swapped whole.
type sqliTunables struct {
	enabled     bool
	sqlPatterns []string
}

// SQLiDetector inspects request path, query, and body for SQLi signatures.
type SQLiDetector struct {
	tun atomic.Pointer[sqliTunables]
	*lastEvidenceStore
}

func (d *SQLiDetector) settings() sqliTunables { return *d.tun.Load() }

// Apply swaps in new settings. The recent-evidence store is left alone so a
// request already seen still reports what it matched.
func (d *SQLiDetector) Apply(cfg config.AttackDetectionConfig) {
	patterns := cfg.SQLPatterns
	if len(patterns) == 0 {
		patterns = defaultSQLPatterns
	}
	d.tun.Store(&sqliTunables{enabled: cfg.Enabled, sqlPatterns: patterns})
}

func NewSQLiDetector(cfg config.AttackDetectionConfig) *SQLiDetector {
	sd := &SQLiDetector{lastEvidenceStore: newLastEvidenceStore(SignalSQLi)}
	sd.Apply(cfg)
	return sd
}

func (sd *SQLiDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tun := sd.settings()
		if !tun.enabled {
			next.ServeHTTP(w, r)
			return
		}

		ip := netutil.ClientIP(r)
		bodyBytes, _ := readAndRestoreBody(r)
		// URL.RawQuery is escaped, so inspecting it alone misses a real payload
		// such as q=%27+OR+1%3D1+--. Query() decodes values before matching,
		// while Path/RawPath still cover path-based signatures.
		queryText := decodedQuery(r)
		haystack := r.URL.Path + " " + r.URL.RawPath + " " + queryText + " " + string(bodyBytes)
		matched := sd.findMatches(haystack, tun.sqlPatterns)
		ev := sd.evidenceFrom(matched)
		sd.put(ip, r.Header.Get(RequestIDHeader), ev)

		if ev.ThresholdCross {
			sd.logAlert(ip, r, strings.Join(matched, ", "))
		}

		next.ServeHTTP(w, r)
	})
}

func decodedQuery(r *http.Request) string {
	values := r.URL.Query()
	parts := make([]string, 0, len(values)*2)
	for key, entries := range values {
		parts = append(parts, key)
		parts = append(parts, entries...)
	}
	return strings.Join(parts, " ")
}

func (sd *SQLiDetector) findMatches(text string, patterns []string) []string {
	normalizedText := normalizeSQLText(text)
	var matched []string
	for _, pattern := range patterns {
		if strings.Contains(normalizedText, normalizeSQLText(pattern)) {
			matched = append(matched, pattern)
		}
	}
	return matched
}

// normalizeSQLText treats a closed SQL block comment as a token separator. SQL
// accepts UNION/**/SELECT as UNION SELECT, but literal matching did not. An
// unterminated comment is retained so malformed input cannot hide text after it.
func normalizeSQLText(text string) string {
	var normalized strings.Builder
	normalized.Grow(len(text))
	for i := 0; i < len(text); {
		if text[i] == '/' && i+1 < len(text) && text[i+1] == '*' {
			end := strings.Index(text[i+2:], "*/")
			if end >= 0 {
				normalized.WriteByte(' ')
				i += end + 4
				continue
			}
		}
		normalized.WriteByte(text[i])
		i++
	}
	return strings.ToUpper(normalized.String())
}

func (sd *SQLiDetector) evidenceFrom(matched []string) Evidence {
	ev := Evidence{
		Signal: SignalSQLi,
		Details: map[string]any{
			"matchCount":      len(matched),
			"matchedPatterns": matched,
			"confidence":      "none",
		},
	}
	if len(matched) == 0 {
		return ev
	}
	strongMatches := 0
	for _, pattern := range matched {
		if !isLowConfidenceSQLPattern(pattern) {
			strongMatches++
		}
	}
	if strongMatches == 0 {
		// A comment marker alone occurs in legitimate prose. Preserve it as
		// low-risk context, but do not turn it into a fired SQLi event.
		ev.Score = 20
		ev.Details["confidence"] = "low"
		return ev
	}

	ev.ThresholdCross = true
	ev.AttackType = SignalSQLi
	ev.Details["confidence"] = "high"
	switch {
	case len(matched) >= 3:
		ev.Score = 100
	case len(matched) == 2:
		ev.Score = 85
	default:
		ev.Score = 70
	}
	return ev
}

func isLowConfidenceSQLPattern(pattern string) bool {
	return strings.TrimSpace(pattern) == "--"
}

func (sd *SQLiDetector) logAlert(ip string, r *http.Request, details string) {
	printAlert("SQL INJECTION DETECTED", "Details", details, ip, r)
}
