package signals

import (
	"sync"
	"time"
)

// lastEvidenceStore keeps the most recent Evidence per IP for detectors
// that are request-scoped (SQLi, traversal/enum) rather than windowed.
//
// Every entry remembers which request produced it. Request-scoped evidence
// describes one request and nothing else, so handing it to a later request
// reports an attack that request did not carry -- see GetFor.
type lastEvidenceStore struct {
	mu     sync.Mutex
	hits   map[string]datedEvidence
	signal string
}

type datedEvidence struct {
	at        time.Time
	requestID string
	evidence  Evidence
}

func newLastEvidenceStore(signal string) *lastEvidenceStore {
	return &lastEvidenceStore{hits: make(map[string]datedEvidence), signal: signal}
}

func (s *lastEvidenceStore) put(ip, requestID string, e Evidence) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.hits[ip] = datedEvidence{at: time.Now(), requestID: requestID, evidence: e}
	s.mu.Unlock()
}

// Metrics returns the latest evidence held for an IP, whichever request
// produced it. It answers "what did this address last do", not "what did this
// request contain" -- for the second question use MetricsFor.
func (s *lastEvidenceStore) Metrics(ip string) Evidence {
	if s == nil {
		return Evidence{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hit, ok := s.hits[ip]
	if !ok || time.Since(hit.at) > lastEvidenceTTL {
		return Evidence{Signal: s.signal}
	}
	return hit.evidence
}

// MetricsFor returns evidence only when this exact request produced it, and
// nothing when the request never reached the detector.
//
// A request can reach telemetry without ever reaching the detectors: the
// policy enforcer answers a blocked address before the chain gets that far,
// which leaves the previous request's evidence in place. Matching on the
// request id makes that case report nothing, rather than replaying an attack
// from up to lastEvidenceTTL ago onto a request that was never inspected --
// evidence the control plane would otherwise ingest as a fresh hit.
func (s *lastEvidenceStore) MetricsFor(ip, requestID string) Evidence {
	if s == nil {
		return Evidence{}
	}
	if requestID == "" {
		return Evidence{Signal: s.signal}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hit, ok := s.hits[ip]
	if !ok || hit.requestID != requestID || time.Since(hit.at) > lastEvidenceTTL {
		return Evidence{Signal: s.signal}
	}
	return hit.evidence
}
