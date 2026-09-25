package telemetry

import (
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/policy"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
)

// Event is one request's security record.
// Redis keeps a capped recent window; Postgres will store history later.
// The isolated agent should read this shape from both stores.
type Event struct {
	RequestID string `json:"requestId"`

	// Seq is this gateway's running count of events recorded, assigned when
	// the event is written to Redis (see redisstore.Store.WriteEvent) -- zero
	// here and left off recorded JSON until then. It is what the console
	// numbers "Req no." from: a stable position in request history rather
	// than a row's position in whatever page happens to be loaded, so it
	// survives polling, filtering and the stream's own MAXLEN trimming, and
	// restarts only when Reset console clears iasg:stats.
	Seq int64 `json:"seq,omitempty"`

	// ArrivalTS is when the request arrived; Timestamp is when it finished.
	// Windowing keys on arrival, so a slow request lands in the window it
	// started in. Timestamp keeps both its name and its completion meaning
	// because the console sorts on it.
	ArrivalTS time.Time `json:"arrivalTs"`
	Timestamp time.Time `json:"ts"`
	IP        string    `json:"ip"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`

	// RouteTemplate is the configured template Path matched, or
	// UnmatchedRoute. Without it every resource identifier looks like a
	// different endpoint, so a client reading twenty products is
	// indistinguishable from one walking twenty unrelated paths.
	RouteTemplate string `json:"routeTemplate"`

	Query  string `json:"query,omitempty"`
	Status int    `json:"status"`
	// RetryAfter preserves the gateway's rate-limit guidance for the console.
	// Old events omit it rather than treating an absent header as zero seconds.
	RetryAfter string             `json:"retryAfter,omitempty"`
	UserAgent  string             `json:"userAgent,omitempty"`
	Decision   string             `json:"decision"` // allow, throttle, temp_block, or escalate
	Policy     *policy.Match      `json:"policy,omitempty"`
	RiskScore  int                `json:"riskScore"`
	Fired      []string           `json:"fired"`
	Signals    []signals.Evidence `json:"signals"`
	Snippet    string             `json:"snippet,omitempty"`

	// ResponseOrigin says who wrote Status: the backend, or the gateway
	// answering by itself. Derived from whether the backend was actually
	// asked, because a 413 from the body cap and a 400 from an unreadable
	// body are otherwise indistinguishable from backend statuses.
	ResponseOrigin string `json:"responseOrigin"`

	// GatewayReason names why the gateway answered without asking.
	GatewayReason string `json:"gatewayReason,omitempty"`

	UpstreamAttempted bool   `json:"upstreamAttempted"`
	UpstreamOutcome   string `json:"upstreamOutcome,omitempty"`

	// Nullable on purpose. A call that timed out has no status and no
	// duration, and a JSON zero would read as a measurement rather than as
	// the absence of one.
	UpstreamStatus     *int   `json:"upstreamStatus"`
	UpstreamDurationMS *int64 `json:"upstreamDurationMs"`
	ResponseBodyBytes  *int64 `json:"responseBodyBytes"`

	// RequestBodyBytes distinguishes a confirmed empty body (zero) from one
	// that was refused or unreadable (null).
	RequestBodyBytes *int64 `json:"requestBodyBytes"`

	// LoginAttempt marks a request to an endpoint where authentication
	// happens; AuthOutcome says what the backend made of the credentials. A
	// login the gateway refused is an attempt with an unknown outcome, which
	// is what keeps a refusal out of the failure ratio's denominator.
	LoginAttempt bool   `json:"loginAttempt,omitempty"`
	AuthOutcome  string `json:"authOutcome,omitempty"`

	// BackendMS is the backend call, which is what its name always claimed and
	// what the console displays. It reads 0 when there was no completed call,
	// so it conflates zero with unknown -- acceptable for a display column,
	// which is why the anomaly features read UpstreamDurationMS instead.
	BackendMS int64 `json:"backendMs"`

	// GatewayMS is the whole chain: every middleware, every detector and the
	// backend call inside them. This is the number BackendMS used to hold.
	GatewayMS int64 `json:"gatewayMs"`
}
