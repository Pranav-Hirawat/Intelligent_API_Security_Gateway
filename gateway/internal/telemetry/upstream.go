package telemetry

import (
	"context"
	"net/http"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/policy"
)

// Upstream outcomes. A request that never reached the backend has none of
// these -- the empty string means "the gateway answered without asking".
const (
	OutcomeCompleted      = "completed"
	OutcomeTimeout        = "timeout"
	OutcomeError          = "error"
	OutcomeBodyIncomplete = "body_incomplete"
)

// Reasons the gateway answered a request itself. Recorded so a gateway-written
// status is never mistaken for one the backend chose.
const (
	ReasonPolicyBlock    = "policy_block"
	ReasonRateLimited    = "rate_limited"
	ReasonBodyTooLarge   = "body_too_large"
	ReasonBodyUnreadable = "body_unreadable"
	// The ownership guard answered for the backend: someone else's object,
	// or a response it could not verify, or no valid token at all.
	ReasonOwnershipRefused = "ownership_refused"
	ReasonAuthRequired     = "authentication_required"
)

// Where a recorded status came from.
const (
	OriginBackend = "backend"
	OriginGateway = "gateway"
)

type upstreamKey struct{}

// Upstream is what the request path learned about the backend call, filled in
// as the request travels and read once when the event is built.
//
// It needs no lock. httputil.ReverseProxy calls RoundTrip and copies the
// response body on the same goroutine that is serving the request, and the
// telemetry middleware only reads this after that handler has returned.
type Upstream struct {
	// Attempted is true once the gateway actually issued the backend request.
	// This is what distinguishes a status the backend chose from one the
	// gateway wrote itself, and it is why responseOrigin is derived rather
	// than inferred from the status and the decision -- a 413 from the body
	// cap and a 400 from an unreadable body record decision "allow" and no
	// policy match, so nothing else tells them apart from a backend 413.
	Attempted bool

	Status     int
	HaveStatus bool

	// DurationMS covers from issuing the backend request until its response
	// body finished being read. Absent when the call did not complete: a
	// request that timed out has no duration, and inventing one would put a
	// measurement where there was none.
	DurationMS   int64
	HaveDuration bool

	ResponseBytes     int64
	HaveResponseBytes bool

	Outcome string

	// BodyBytes is the measured request body size. Measured is false when the
	// body was refused or could not be read -- distinct from a confirmed empty
	// body, which is a measured zero.
	BodyBytes    int64
	BodyMeasured bool

	// GatewayReason names why the gateway answered without asking the backend.
	GatewayReason string
}

// Origin reports whether the recorded status came from the backend or from the
// gateway itself.
//
// A named gateway reason wins over a backend call: the ownership guard asks the
// backend and then replaces its answer, and the client got the replacement.
func (u *Upstream) Origin() string {
	if u != nil && u.GatewayReason != "" {
		return OriginGateway
	}
	if u != nil && u.Attempted && u.HaveStatus {
		return OriginBackend
	}
	return OriginGateway
}

// AttachUpstream puts a fresh record on the request context. Called once, at
// the top of the telemetry middleware, so every stage below can fill it in.
func AttachUpstream(r *http.Request) (*http.Request, *Upstream) {
	u := &Upstream{}
	return r.WithContext(context.WithValue(r.Context(), upstreamKey{}, u)), u
}

// UpstreamOf returns the record for this request, or nil when there is none.
// Every caller must tolerate nil: the middleware is optional in tests and the
// stages below it must not depend on having been wired up.
func UpstreamOf(r *http.Request) *Upstream {
	if r == nil {
		return nil
	}
	u, _ := r.Context().Value(upstreamKey{}).(*Upstream)
	return u
}

// RecordGatewayAnswer notes that the gateway answered this request itself.
// Safe to call when no record is attached.
func RecordGatewayAnswer(r *http.Request, reason string) {
	if u := UpstreamOf(r); u != nil {
		u.GatewayReason = reason
	}
}

// RecordBodySize notes a measured request body. A confirmed empty body is a
// measured zero and must be recorded as one.
func RecordBodySize(r *http.Request, n int64) {
	if u := UpstreamOf(r); u != nil {
		u.BodyBytes = n
		u.BodyMeasured = true
	}
}

// gatewayReasonFor names a refusal the enforcer wrote.
//
// Derived here rather than recorded by internal/policy, because telemetry
// already imports policy and the reverse would be an import cycle. It costs
// nothing: unlike the body-cap refusals, which are indistinguishable from
// backend statuses without an explicit marker, a policy refusal is already
// fully described by the decision the enforcer recorded.
func gatewayReasonFor(decision string) string {
	switch decision {
	case policy.ActionBlock, policy.ActionTempBlock, policy.ActionTemporaryBlock, policy.ActionEscalate:
		return ReasonPolicyBlock
	case policy.OutcomeRateLimited:
		return ReasonRateLimited
	}
	// ActionThrottle is deliberately absent: a throttled request is delayed
	// and then served by the backend, so the gateway did not answer it.
	return ""
}

// optionalInt and optionalInt64 turn "value plus whether it was measured" into
// a pointer, so an unmeasured field serialises as JSON null. A zero would read
// as a measurement of zero, which for a duration or a status is a different
// claim entirely.
func optionalInt(v int, have bool) *int {
	if !have {
		return nil
	}
	return &v
}

func optionalInt64(v int64, have bool) *int64 {
	if !have {
		return nil
	}
	return &v
}
