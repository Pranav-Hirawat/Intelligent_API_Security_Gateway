package signals

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
)

const sqliMarker = "SQL INJECTION"

func sqliHandler() http.Handler {
	return NewSQLiDetector(config.AttackDetectionConfig{Enabled: true}).Middleware(okBackend())
}

func TestSQLiIgnoresCleanBody(t *testing.T) {
	out := captureAlerts(t, func() {
		probe(sqliHandler(), http.MethodPost, "/api/login",
			"203.0.113.5", `{"email":"a@b.com","password":"hunter2"}`)
	})

	if strings.Contains(out, sqliMarker) {
		t.Fatalf("clean body raised an alert:\n%s", out)
	}
}

func TestSQLiDetectsSignatureInBody(t *testing.T) {
	for _, payload := range []string{
		`{"email":"' OR 1=1--"}`,
		`{"q":"UNION SELECT * FROM users"}`,
	} {
		out := captureAlerts(t, func() {
			probe(sqliHandler(), http.MethodPost, "/api/login", "203.0.113.5", payload)
		})

		if !strings.Contains(out, sqliMarker) {
			t.Errorf("payload %q went undetected", payload)
		}
	}
}

func TestSQLiCommentOnlyIsLowConfidenceEvidence(t *testing.T) {
	const ip = "203.0.113.56"
	detector := NewSQLiDetector(config.AttackDetectionConfig{Enabled: true})
	handler := detector.Middleware(okBackend())

	out := captureAlerts(t, func() {
		probe(handler, http.MethodPost, "/api/login", ip, `{"note":"-- comment"}`)
	})
	if strings.Contains(out, sqliMarker) {
		t.Fatalf("a comment marker alone raised SQLi: %s", out)
	}
	ev := detector.Metrics(ip)
	if ev.ThresholdCross || ev.Score != 20 || ev.Details["confidence"] != "low" {
		t.Fatalf("comment-only evidence = %+v, want low-confidence non-fired evidence", ev)
	}
}

func TestSQLiMatchingIsCaseInsensitive(t *testing.T) {
	out := captureAlerts(t, func() {
		probe(sqliHandler(), http.MethodPost, "/api/login",
			"203.0.113.5", `{"q":"union select"}`)
	})

	if !strings.Contains(out, sqliMarker) {
		t.Fatal("lowercase 'union select' should still match")
	}
}

func TestSQLiDetectsCommentObfuscatedKeywords(t *testing.T) {
	const ip = "203.0.113.57"
	detector := NewSQLiDetector(config.AttackDetectionConfig{Enabled: true})
	handler := detector.Middleware(okBackend())

	for _, payload := range []string{
		`{"q":"UNION/**/SELECT password FROM users"}`,
		`{"q":"uNiOn/* harmless padding */sElEcT password FROM users"}`,
	} {
		captureAlerts(t, func() {
			probe(handler, http.MethodPost, "/api/products/search", ip, payload)
		})

		ev := detector.Metrics(ip)
		if !ev.ThresholdCross || !slices.Contains(ev.Strings("matchedPatterns"), "UNION SELECT") {
			t.Fatalf("comment-obfuscated payload %q bypassed SQLi detection: %+v", payload, ev)
		}
	}
}

func TestSQLiNeverBlocks(t *testing.T) {
	captureAlerts(t, func() {
		rec := probe(sqliHandler(), http.MethodPost, "/api/login",
			"203.0.113.5", `{"email":"' OR 1=1--"}`)

		if rec.Code != http.StatusOK {
			t.Fatalf("got status %d, detector must not block", rec.Code)
		}
		if rec.Body.String() != "backend reached" {
			t.Fatal("request never reached the backend")
		}
	})
}

// The detector reads the body, so it has to put it back for the proxy.
func TestSQLiRestoresBodyForBackend(t *testing.T) {
	const payload = `{"email":"' OR 1=1--","password":"x"}`

	var seen string
	handler := NewSQLiDetector(config.AttackDetectionConfig{Enabled: true}).Middleware(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			buf := make([]byte, len(payload))
			n, _ := r.Body.Read(buf)
			seen = string(buf[:n])
			w.WriteHeader(http.StatusOK)
		}))

	captureAlerts(t, func() {
		probe(handler, http.MethodPost, "/api/login", "203.0.113.5", payload)
	})

	if seen != payload {
		t.Fatalf("backend received %q, want the original body %q", seen, payload)
	}
}

func TestSQLiDisabledInspectsNothing(t *testing.T) {
	handler := NewSQLiDetector(config.AttackDetectionConfig{Enabled: false}).Middleware(okBackend())

	out := captureAlerts(t, func() {
		probe(handler, http.MethodPost, "/api/login", "203.0.113.5", `{"email":"' OR 1=1--"}`)
	})

	if strings.Contains(out, sqliMarker) {
		t.Fatal("a disabled detector alerted")
	}
}

func TestSQLiCustomPatternsReplaceDefaults(t *testing.T) {
	handler := NewSQLiDetector(config.AttackDetectionConfig{
		Enabled:     true,
		SQLPatterns: []string{"DROP TABLE"},
	}).Middleware(okBackend())

	out := captureAlerts(t, func() {
		probe(handler, http.MethodPost, "/api/x", "203.0.113.5", `{"q":"drop table users"}`)
	})
	if !strings.Contains(out, sqliMarker) {
		t.Error("custom pattern did not match")
	}

	out = captureAlerts(t, func() {
		probe(handler, http.MethodPost, "/api/x", "203.0.113.5", `{"q":"' OR 1=1"}`)
	})
	if strings.Contains(out, sqliMarker) {
		t.Error("default patterns should not apply when custom ones are set")
	}
}

func TestSQLiEmptyPatternsFallBackToDefaults(t *testing.T) {
	handler := NewSQLiDetector(config.AttackDetectionConfig{Enabled: true}).Middleware(okBackend())

	out := captureAlerts(t, func() {
		probe(handler, http.MethodPost, "/api/x", "203.0.113.5", `{"q":"' OR 1=1"}`)
	})

	if !strings.Contains(out, sqliMarker) {
		t.Fatal("an empty pattern list should fall back to the defaults")
	}
}

// Path, query, and body are all inspected. Injection through the query string
// used to be invisible; this pins the current behaviour.
func TestSQLiInspectsQueryString(t *testing.T) {
	out := captureAlerts(t, func() {
		probe(sqliHandler(), http.MethodGet, "/api/products?q=UNION%20SELECT", "203.0.113.5", "")
	})

	if !strings.Contains(out, sqliMarker) {
		t.Fatal("SQLi in the query string should be detected")
	}
}

func TestSQLiProductSearchEvidenceUsesDecodedQueryValues(t *testing.T) {
	const ip = "203.0.113.55"
	detector := NewSQLiDetector(config.AttackDetectionConfig{Enabled: true})
	backendReached := 0
	handler := detector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backendReached++
		w.WriteHeader(http.StatusOK)
	}))

	clean := httptest.NewRequest(http.MethodGet, "/api/products/search?q=keyboard", nil)
	clean.RemoteAddr = ip + ":1234"
	handler.ServeHTTP(httptest.NewRecorder(), clean)
	if ev := detector.Metrics(ip); ev.ThresholdCross {
		t.Fatalf("normal product search fired SQLi: %+v", ev)
	}

	payload := "' OR 1=1 --"
	attack := httptest.NewRequest(http.MethodGet, "/api/products/search?q="+url.QueryEscape(payload), nil)
	attack.RemoteAddr = ip + ":1234"
	captureAlerts(t, func() {
		handler.ServeHTTP(httptest.NewRecorder(), attack)
	})

	ev := detector.Metrics(ip)
	if !ev.ThresholdCross || ev.Score <= 0 {
		t.Fatalf("SQLi product search did not fire: %+v", ev)
	}
	if ev.Int("matchCount") == 0 || len(ev.Strings("matchedPatterns")) == 0 {
		t.Fatalf("SQLi evidence omitted matched patterns: %+v", ev)
	}
	if backendReached != 2 {
		t.Fatalf("backend reached %d times, want both forwarded requests", backendReached)
	}
}
