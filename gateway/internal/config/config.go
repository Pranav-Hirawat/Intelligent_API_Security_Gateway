package config

import (
	"cmp"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config maps the gateway YAML configuration.
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Proxy       ProxyConfig       `yaml:"proxy"`
	Routes      RoutesConfig      `yaml:"routes"`
	Storage     StorageConfig     `yaml:"storage"`
	Enforcement EnforcementConfig `yaml:"enforcement"`
	Identity    IdentityConfig    `yaml:"identity"`
}

// IdentityConfig says how the gateway learns who a caller is. Only needed by
// routes.ownership: the gateway cannot compare an object's owner with the
// caller until it can prove who the caller is, and a token it merely decoded
// proves nothing.
type IdentityConfig struct {
	JWT JWTConfig `yaml:"jwt"`
}

type JWTConfig struct {
	// Algorithm is HS256 (shared secret) or RS256 (public key). A token signed
	// any other way -- "none" above all -- is refused.
	Algorithm string `yaml:"algorithm"`

	// SecretEnv names the environment variable holding the HS256 secret. Secret
	// is a literal fallback for demo configs only; a real deployment leaves it
	// empty so a missing variable stops the gateway instead of trusting a
	// secret committed to a file.
	SecretEnv string `yaml:"secret_env"`
	Secret    string `yaml:"secret"`

	// PublicKeyFile is a PEM RSA public key for RS256.
	PublicKeyFile string `yaml:"public_key_file"`

	// Issuer and Audience, when set, must match the token's iss and aud.
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`

	// UserClaim holds the caller's id. Defaults to "sub".
	UserClaim string `yaml:"user_claim"`

	// A token whose BypassClaim holds one of BypassValues may read any object:
	// support staff and administrators, whose reads are legitimate.
	BypassClaim  string   `yaml:"bypass_claim"`
	BypassValues []string `yaml:"bypass_values"`
}

// OwnershipRule protects one read endpoint by comparing the owner named in the
// backend's response with the caller named in a verified token.
type OwnershipRule struct {
	// Template is a "GET /path" entry from routes.templates.
	Template string `yaml:"template"`

	// OwnerField is a dotted path to the owner's id: "order.userId". For a
	// list rule it is read from each item.
	OwnerField string `yaml:"owner_field"`

	// ListField, when set, is a dotted path to an array of objects; items the
	// caller does not own are removed instead of the whole response refused.
	// "." means the response body itself is the array.
	ListField string `yaml:"list_field"`
}

// RoutesConfig describes the backend, not enforcement, which is why it is a
// top-level block rather than a section under enforcement:.
//
// These settings are structural. Changing a route template changes what
// previously recorded telemetry means, so they are read at boot and are
// deliberately not carried by the settings watcher -- unlike detector
// thresholds, which are safe to retune while running.
type RoutesConfig struct {
	// Templates are "METHOD /path/{param}" entries. A path that matches none
	// of them records as unmatched, which is a real category: it is what a
	// client walking paths the application does not serve looks like.
	Templates []string `yaml:"templates"`

	// AuthOutcomes says how to read an authentication result off a backend
	// status, per endpoint. It is configuration rather than an inference
	// because 401 does not mean "wrong password" in general -- it means that
	// on an endpoint documented to answer that way, and nowhere else.
	AuthOutcomes []AuthOutcomeConfig `yaml:"auth_outcomes"`

	// ObjectTemplates names the endpoints that return one object belonging to
	// someone -- "GET /api/orders/{id}" -- and are therefore worth watching for
	// a client walking through identifiers. Configuration rather than an
	// inference: the gateway cannot tell a public catalogue lookup from a
	// private record, and a shopper browsing many products is not an attack.
	// Each must also appear in Templates and carry at least one {param}.
	ObjectTemplates []string `yaml:"object_templates"`

	// Ownership lists read endpoints whose responses the gateway checks
	// against the caller's verified identity (identity.jwt). Someone else's
	// object is answered 404 and never leaves the gateway. Only GET: a write
	// has already happened by the time a response could be checked.
	Ownership []OwnershipRule `yaml:"ownership"`
}

type AuthOutcomeConfig struct {
	Method   string `yaml:"method"`
	Template string `yaml:"template"`

	// Backend statuses that mean the credentials were accepted, and those
	// that mean they were rejected. A status in neither list is unknown,
	// which is not the same as a success: a 500 says the database failed,
	// not that the password was right.
	Success            []int `yaml:"success"`
	InvalidCredentials []int `yaml:"invalid_credentials"`
}

type ServerConfig struct {
	Port         int           `yaml:"port"`
	Host         string        `yaml:"host"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`

	// MaxBodyBytes caps the request body the gateway will read. Unset falls
	// back to the gateway's own default; it is deliberately not possible to
	// disable, because everything downstream buffers what it is handed.
	MaxBodyBytes int64 `yaml:"max_body_bytes"`

	// TrustedProxies lists the CIDRs whose X-Forwarded-For header may be
	// believed. Empty means trust nothing and always use the peer address,
	// which is the safe default: anyone can set the header, so trusting it
	// unconditionally would let an attacker pin blame on another IP.
	TrustedProxies []string `yaml:"trusted_proxies"`

	// CORSAllowedOrigins lists origins allowed to read a response the gateway
	// writes itself -- a refusal from the ownership guard, policy enforcement
	// or the body-size limit, none of which ever reach the backend's own CORS
	// middleware. Empty means none: a browser calling cross-origin sees the
	// refusal only as a network error, same as before this existed. "*"
	// allows any origin. This never touches a response the backend answered;
	// its own CORS policy already governs those.
	CORSAllowedOrigins []string `yaml:"cors_allowed_origins"`
}

type ProxyConfig struct {
	BackendURL string `yaml:"backend_url"`

	// PreserveHost forwards the client's Host header unchanged instead of
	// replacing it with the backend's. Off by default, because a backend that
	// routes by name -- a virtual host, a PaaS, a CDN -- answers the gateway's
	// own name with a 404 or a certificate mismatch. Turn it on only for a
	// backend that must see the public hostname, such as one building absolute
	// links from it; X-Forwarded-Host carries that name either way.
	PreserveHost bool `yaml:"preserve_host"`

	Timeout         time.Duration `yaml:"timeout"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	MaxConnsPerHost int           `yaml:"max_conns_per_host"`
}

type StorageConfig struct {
	Redis RedisConfig `yaml:"redis"`
}

type RedisConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	Password     string `yaml:"password"`
	DB           int    `yaml:"db"`
	PoolSize     int    `yaml:"pool_size"`
	StreamKey    string `yaml:"stream_key"`
	StreamMaxLen int64  `yaml:"stream_maxlen"`

	// Arrival records go to their own stream so every existing consumer of
	// stream_key keeps seeing exactly what it sees today. They are capped
	// separately because there is one per request either way, but a capture
	// run wants far more history than the console does.
	ArrivalStreamKey string `yaml:"arrival_stream_key"`
	ArrivalMaxLen    int64  `yaml:"arrival_maxlen"`

	HealthStreamKey       string        `yaml:"health_stream_key"`
	HealthMaxLen          int64         `yaml:"health_maxlen"`
	IPLatestTTL           time.Duration `yaml:"ip_latest_ttl"`
	TelemetryQueueSize    int           `yaml:"telemetry_queue_size"`
	TelemetryWriteTimeout time.Duration `yaml:"telemetry_write_timeout"`
}

func (c RedisConfig) Addr() string {
	host := c.Host
	host = cmp.Or(host, "localhost")
	port := c.Port
	if port <= 0 {
		port = 6379
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

type EnforcementConfig struct {
	AdaptiveRateLimit AdaptiveRateLimitConfig `yaml:"adaptive_rate_limit"`
	RateLimit         RateLimitConfig         `yaml:"rate_limit"`
	AttackDetection   AttackDetectionConfig   `yaml:"attack_detection"`
	BruteForce        BruteForceConfig        `yaml:"brute_force"`
	UnknownRouteScan  UnknownRouteScanConfig  `yaml:"unknown_route_scanning"`
	ObjectEnumeration ObjectEnumerationConfig `yaml:"object_enumeration"`
	ObjectOwnership   ObjectOwnershipConfig   `yaml:"object_ownership"`
	Enumeration       EnumerationConfig       `yaml:"enumeration_path_traversal"`
	IPReputation      IPReputationConfig      `yaml:"ip_reputation"`
	Throttle          ThrottleConfig          `yaml:"throttle"`
	Block             BlockConfig             `yaml:"block"`
	Policy            PolicyConfig            `yaml:"policy"`
}

// AdaptiveRateLimitConfig is fixed at boot so replicas use the same quota
// contract. Policy rates still change dynamically with the control plane.
type AdaptiveRateLimitConfig struct {
	FallbackRequestsPerMinute int           `yaml:"fallback_requests_per_minute"`
	Burst                     int           `yaml:"burst"`
	RedisTimeout              time.Duration `yaml:"redis_timeout"`
	PolicyRefreshTimeout      time.Duration `yaml:"policy_refresh_timeout"`
	FailureBackoff            time.Duration `yaml:"failure_backoff"`
	CacheMaxAge               time.Duration `yaml:"cache_max_age"`
	BucketKeyPrefix           string        `yaml:"bucket_key_prefix"`
}

func (c AdaptiveRateLimitConfig) WithDefaults() AdaptiveRateLimitConfig {
	c.FallbackRequestsPerMinute = cmp.Or(c.FallbackRequestsPerMinute, 60)
	c.Burst = cmp.Or(c.Burst, 20)
	c.RedisTimeout = cmp.Or(c.RedisTimeout, 25*time.Millisecond)
	c.PolicyRefreshTimeout = cmp.Or(c.PolicyRefreshTimeout, 2*time.Second)
	c.FailureBackoff = cmp.Or(c.FailureBackoff, time.Second)
	c.CacheMaxAge = cmp.Or(c.CacheMaxAge, 10*time.Second)
	c.BucketKeyPrefix = cmp.Or(c.BucketKeyPrefix, "iasg:rate:")
	return c
}

// PolicyConfig controls whether the gateway acts on decisions written by the
// Python control plane. Disabled by default: enabling it is what turns the
// control plane from an observer into something that can refuse traffic.
type PolicyConfig struct {
	Enabled         bool          `yaml:"enabled"`
	KeyPrefix       string        `yaml:"key_prefix"`
	RefreshInterval time.Duration `yaml:"refresh_interval"`
}

type BruteForceConfig struct {
	Enabled             bool          `yaml:"enabled"`
	MaxFailures         int           `yaml:"max_failures"` // consecutive invalid credentials before the signal fires
	Window              time.Duration `yaml:"window"`       // maximum age of a consecutive-failure streak
	MaxClients          int           `yaml:"max_clients"`
	MaxTargetsPerClient int           `yaml:"max_targets_per_client"`
}

// UnknownRouteScanConfig bounds the detector that notices a client walking
// several paths the configured application does not expose. Route templates
// are structural, but these behavioural limits may safely move at runtime.
type UnknownRouteScanConfig struct {
	Enabled           bool          `yaml:"enabled"`
	DistinctPaths     int           `yaml:"distinct_paths"`
	Window            time.Duration `yaml:"window"`
	MaxClients        int           `yaml:"max_clients"`
	MaxPathsPerClient int           `yaml:"max_paths_per_client"`
}

// ObjectEnumerationConfig bounds the detector that notices one client
// requesting many distinct object identifiers on an object template (BOLA /
// IDOR). Which endpoints are watched is structural and lives in
// routes.object_templates; these behavioural limits may move at runtime.
type ObjectEnumerationConfig struct {
	Enabled         bool          `yaml:"enabled"`
	DistinctIDs     int           `yaml:"distinct_ids"`
	Window          time.Duration `yaml:"window"`
	MaxClients      int           `yaml:"max_clients"`
	MaxIDsPerClient int           `yaml:"max_ids_per_client"`
}

// ObjectOwnershipConfig holds what may move at runtime for routes.ownership.
// Which endpoints are protected, and how tokens are verified, are structural.
type ObjectOwnershipConfig struct {
	Enabled bool `yaml:"enabled"`

	// OnUnverifiable is what happens to a response whose owner cannot be read:
	// not JSON, compressed, too large, or missing the owner field. "deny"
	// (default) answers 404; "allow" passes it through. Deny is the safe
	// failure -- a response the gateway cannot read is one it cannot vouch for.
	OnUnverifiable string `yaml:"on_unverifiable"`

	// MaxBodyBytes caps how much of a response is held for checking.
	MaxBodyBytes int64 `yaml:"max_body_bytes"`
}

type AttackDetectionConfig struct {
	Enabled     bool     `yaml:"enabled"`
	SQLPatterns []string `yaml:"sql_patterns"`
}

type EnumerationConfig struct {
	Enabled             bool     `yaml:"enabled"`
	TraversalPatterns   []string `yaml:"traversal_patterns"`
	EnumerationPatterns []string `yaml:"enumeration_patterns"`
}

// IPReputationConfig controls the one detector that knows something before the
// attacker does anything. It lives under `enforcement` rather than the
// top-level `signals` block for two reasons: that block is parsed and never
// read by anything, and only `enforcement` travels through the settings
// watcher, which is what makes this changeable from the console.
type IPReputationConfig struct {
	Enabled bool `yaml:"enabled"`

	// Where the list comes from. Structural, like a listen address: read once
	// at startup, not carried by a live settings change.
	FeedPath        string        `yaml:"feed_path"`
	FeedURL         string        `yaml:"feed_url"`
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	FetchTimeout    time.Duration `yaml:"fetch_timeout"`

	// Score a listed address contributes. Defaults to the reflex's own
	// min_score floor, so naming this in `block.signals` actually lets it act.
	Score int `yaml:"score"`

	// How long an address stays quiet after firing. A listed address is listed
	// on every request; without this it would raise a signal on each one.
	Cooldown time.Duration `yaml:"cooldown"`
}

type RateLimitConfig struct {
	// Enabled turns on flood *detection*: counting requests per address and
	// raising a signal when RequestsPerMinute is exceeded.
	Enabled bool `yaml:"enabled"`

	// Enforce turns that threshold into a limit the gateway acts on, refusing
	// anything over it with 429 rather than only reporting it. Separate from
	// Enabled because refusing traffic is a different decision from noticing
	// it, and this one can turn a legitimate spike into an outage.
	//
	// An address under a throttle policy is held to the rate that policy names
	// instead; this is the baseline everyone else gets.
	Enforce bool `yaml:"enforce"`

	RequestsPerMinute int `yaml:"requests_per_minute"`
	Burst             int `yaml:"burst"`
}

type ThrottleConfig struct {
	Enabled bool `yaml:"enabled"`
	DelayMS int  `yaml:"delay_ms"`
}

// BlockConfig controls the gateway's own blocking -- its reflex, as opposed to
// the considered decisions the control plane writes as policy keys.
//
// Enabled on its own does nothing: Signals has to name at least one detector
// that may act. That is deliberate. This block existed in the config long
// before anything read it, so a build that suddenly honoured Enabled alone
// would start refusing traffic on configuration nobody had revisited.
type BlockConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Duration time.Duration `yaml:"duration"`
	// Detectors trusted to block on their own. Omit the key entirely to take
	// the safe defaults; an explicit empty list enforces nothing.
	Signals []string `yaml:"signals"`
	// A score floor on top of the detector's own threshold, so a marginal hit
	// is not enough on its own.
	MinScore int `yaml:"min_score"`
	// Never blocked. Omit to take loopback and the private ranges.
	ExemptCIDRs []string `yaml:"exempt_cidrs"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse yaml config %s: %w", path, err)
	}

	cfg.Server.Host = cmp.Or(cfg.Server.Host, "0.0.0.0")
	if cfg.Server.Port <= 0 {
		return nil, fmt.Errorf("invalid server.port: %d", cfg.Server.Port)
	}
	if cfg.Proxy.BackendURL == "" {
		return nil, fmt.Errorf("proxy.backend_url must be set")
	}

	cfg.Storage.Redis.StreamKey = cmp.Or(cfg.Storage.Redis.StreamKey, "iasg:events")
	if cfg.Storage.Redis.StreamMaxLen <= 0 {
		cfg.Storage.Redis.StreamMaxLen = 2000
	}
	cfg.Storage.Redis.ArrivalStreamKey = cmp.Or(cfg.Storage.Redis.ArrivalStreamKey, "iasg:arrivals")
	if cfg.Storage.Redis.ArrivalMaxLen <= 0 {
		cfg.Storage.Redis.ArrivalMaxLen = cfg.Storage.Redis.StreamMaxLen
	}
	cfg.Storage.Redis.HealthStreamKey = cmp.Or(cfg.Storage.Redis.HealthStreamKey, "iasg:telemetry:health")
	if cfg.Storage.Redis.HealthMaxLen <= 0 {
		// One record a second, so this is a day of heartbeats.
		cfg.Storage.Redis.HealthMaxLen = 86400
	}
	if cfg.Storage.Redis.IPLatestTTL <= 0 {
		cfg.Storage.Redis.IPLatestTTL = 24 * time.Hour
	}
	if cfg.Storage.Redis.PoolSize <= 0 {
		cfg.Storage.Redis.PoolSize = 10
	}
	cfg.Storage.Redis.TelemetryQueueSize = cmp.Or(cfg.Storage.Redis.TelemetryQueueSize, 1024)
	cfg.Storage.Redis.TelemetryWriteTimeout = cmp.Or(cfg.Storage.Redis.TelemetryWriteTimeout, 100*time.Millisecond)
	if cfg.Storage.Redis.TelemetryQueueSize < 0 || cfg.Storage.Redis.TelemetryWriteTimeout < 0 {
		return nil, fmt.Errorf("Redis telemetry queue size and write timeout must be positive")
	}
	cfg.Enforcement.Policy.KeyPrefix = cmp.Or(cfg.Enforcement.Policy.KeyPrefix, "policy:")
	if cfg.Enforcement.Policy.RefreshInterval <= 0 {
		cfg.Enforcement.Policy.RefreshInterval = 5 * time.Second
	}
	a := cfg.Enforcement.AdaptiveRateLimit.WithDefaults()
	if cfg.Enforcement.AdaptiveRateLimit.CacheMaxAge == 0 && a.CacheMaxAge < 2*cfg.Enforcement.Policy.RefreshInterval {
		a.CacheMaxAge = 2 * cfg.Enforcement.Policy.RefreshInterval
	}
	if a.FallbackRequestsPerMinute < 1 || a.Burst < 1 || a.RedisTimeout < time.Millisecond || a.RedisTimeout > time.Second || a.FailureBackoff < time.Millisecond || a.CacheMaxAge < cfg.Enforcement.Policy.RefreshInterval {
		return nil, fmt.Errorf("adaptive_rate_limit requires positive rates/backoff, redis_timeout between 1ms and 1s, and cache_max_age >= policy.refresh_interval")
	}
	if a.PolicyRefreshTimeout < a.RedisTimeout || a.PolicyRefreshTimeout > 30*time.Second {
		return nil, fmt.Errorf("adaptive_rate_limit.policy_refresh_timeout must be >= redis_timeout and <= 30s")
	}
	if strings.HasPrefix(a.BucketKeyPrefix, cfg.Enforcement.Policy.KeyPrefix) || strings.HasPrefix(cfg.Enforcement.Policy.KeyPrefix, a.BucketKeyPrefix) {
		return nil, fmt.Errorf("adaptive_rate_limit.bucket_key_prefix must not overlap policy.key_prefix")
	}
	cfg.Enforcement.AdaptiveRateLimit = a
	brute, err := ValidatedBruteForce(cfg.Enforcement.BruteForce)
	if err != nil {
		return nil, err
	}
	cfg.Enforcement.BruteForce = brute
	scan, err := ValidatedUnknownRouteScan(cfg.Enforcement.UnknownRouteScan)
	if err != nil {
		return nil, err
	}
	cfg.Enforcement.UnknownRouteScan = scan
	objects, err := ValidatedObjectEnumeration(cfg.Enforcement.ObjectEnumeration)
	if err != nil {
		return nil, err
	}
	cfg.Enforcement.ObjectEnumeration = objects
	if err := validateObjectTemplates(cfg.Routes); err != nil {
		return nil, err
	}
	ownership, err := ValidatedObjectOwnership(cfg.Enforcement.ObjectOwnership)
	if err != nil {
		return nil, err
	}
	cfg.Enforcement.ObjectOwnership = ownership
	if err := validateOwnership(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// ValidatedBruteForce fills safe defaults and rejects a limit that would make
// the detector either unbounded or too broad to be a useful security control.
// Settings uses the same function so a hand-written Redis override receives
// exactly the validation a YAML file does.
func ValidatedBruteForce(cfg BruteForceConfig) (BruteForceConfig, error) {
	cfg.MaxFailures = cmp.Or(cfg.MaxFailures, 5)
	cfg.Window = cmp.Or(cfg.Window, time.Minute)
	cfg.MaxClients = cmp.Or(cfg.MaxClients, 10_000)
	cfg.MaxTargetsPerClient = cmp.Or(cfg.MaxTargetsPerClient, 64)
	if cfg.MaxFailures < 1 || cfg.MaxFailures > 1_000 || cfg.MaxClients < 1 || cfg.MaxClients > 100_000 || cfg.MaxTargetsPerClient < 1 || cfg.MaxTargetsPerClient > 10_000 || cfg.Window < time.Second || cfg.Window > 24*time.Hour {
		return BruteForceConfig{}, fmt.Errorf("brute_force requires max_failures 1..1000, max_clients 1..100000, max_targets_per_client 1..10000, and window 1s..24h")
	}
	return cfg, nil
}

// ValidatedUnknownRouteScan limits every retained dimension. The raw paths are
// attacker input, so capacity is part of correctness rather than tuning.
func ValidatedUnknownRouteScan(cfg UnknownRouteScanConfig) (UnknownRouteScanConfig, error) {
	cfg.DistinctPaths = cmp.Or(cfg.DistinctPaths, 8)
	cfg.Window = cmp.Or(cfg.Window, 5*time.Minute)
	cfg.MaxClients = cmp.Or(cfg.MaxClients, 10_000)
	cfg.MaxPathsPerClient = cmp.Or(cfg.MaxPathsPerClient, 64)
	if cfg.DistinctPaths < 2 || cfg.DistinctPaths > cfg.MaxPathsPerClient || cfg.MaxPathsPerClient > 10_000 || cfg.MaxClients < 1 || cfg.MaxClients > 100_000 || cfg.Window < time.Second || cfg.Window > 24*time.Hour {
		return UnknownRouteScanConfig{}, fmt.Errorf("unknown_route_scanning requires distinct_paths 2..max_paths_per_client, max_paths_per_client <= 10000, max_clients 1..100000, and window 1s..24h")
	}
	return cfg, nil
}

// ValidatedObjectEnumeration limits every retained dimension. Identifiers are
// attacker input, so capacity is part of correctness rather than tuning.
func ValidatedObjectEnumeration(cfg ObjectEnumerationConfig) (ObjectEnumerationConfig, error) {
	cfg.DistinctIDs = cmp.Or(cfg.DistinctIDs, 20)
	cfg.Window = cmp.Or(cfg.Window, 5*time.Minute)
	cfg.MaxClients = cmp.Or(cfg.MaxClients, 10_000)
	cfg.MaxIDsPerClient = cmp.Or(cfg.MaxIDsPerClient, 256)
	if cfg.DistinctIDs < 2 || cfg.DistinctIDs > cfg.MaxIDsPerClient || cfg.MaxIDsPerClient > 10_000 || cfg.MaxClients < 1 || cfg.MaxClients > 100_000 || cfg.Window < time.Second || cfg.Window > 24*time.Hour {
		return ObjectEnumerationConfig{}, fmt.Errorf("object_enumeration requires distinct_ids 2..max_ids_per_client, max_ids_per_client <= 10000, max_clients 1..100000, and window 1s..24h")
	}
	return cfg, nil
}

// validateObjectTemplates refuses an object template the gateway could never
// match. One missing from routes.templates, or with no {param} to read an
// identifier from, would leave the detector silently watching nothing -- which
// looks exactly like an API nobody is enumerating.
func validateObjectTemplates(routes RoutesConfig) error {
	known := make(map[string]bool, len(routes.Templates))
	for _, raw := range routes.Templates {
		known[normalizeTemplate(raw)] = true
	}
	for _, raw := range routes.ObjectTemplates {
		template := normalizeTemplate(raw)
		if !strings.Contains(template, "{") {
			return fmt.Errorf("routes.object_templates entry %q has no {param} to read an identifier from", raw)
		}
		if !known[template] {
			return fmt.Errorf("routes.object_templates entry %q is not listed in routes.templates", raw)
		}
	}
	return nil
}

// ValidatedObjectOwnership fills defaults and bounds the response buffer.
// Settings uses it too, so a hand-written override is held to the same rules.
func ValidatedObjectOwnership(cfg ObjectOwnershipConfig) (ObjectOwnershipConfig, error) {
	cfg.OnUnverifiable = cmp.Or(cfg.OnUnverifiable, "deny")
	cfg.MaxBodyBytes = cmp.Or(cfg.MaxBodyBytes, 1<<20)
	if cfg.OnUnverifiable != "deny" && cfg.OnUnverifiable != "allow" {
		return ObjectOwnershipConfig{}, fmt.Errorf("object_ownership.on_unverifiable must be deny or allow, not %q", cfg.OnUnverifiable)
	}
	if cfg.MaxBodyBytes < 1024 || cfg.MaxBodyBytes > 16<<20 {
		return ObjectOwnershipConfig{}, fmt.Errorf("object_ownership.max_body_bytes must be between 1KB and 16MB")
	}
	return cfg, nil
}

// validateOwnership refuses an ownership rule that could never be enforced. A
// rule that silently matched nothing, or a gateway that could not verify the
// tokens it depends on, would look exactly like a protected API.
func validateOwnership(cfg *Config) error {
	rules := cfg.Routes.Ownership
	if len(rules) == 0 {
		return nil
	}
	known := make(map[string]bool, len(cfg.Routes.Templates))
	for _, raw := range cfg.Routes.Templates {
		known[normalizeTemplate(raw)] = true
	}
	seen := make(map[string]bool, len(rules))
	for i, rule := range rules {
		template := normalizeTemplate(rule.Template)
		if !strings.HasPrefix(template, "GET ") {
			return fmt.Errorf("routes.ownership entry %q: only GET can be checked; a write has already happened when its response arrives", rule.Template)
		}
		if !known[template] {
			return fmt.Errorf("routes.ownership entry %q is not listed in routes.templates", rule.Template)
		}
		if seen[template] {
			return fmt.Errorf("routes.ownership lists %q twice", rule.Template)
		}
		seen[template] = true
		if strings.TrimSpace(rule.OwnerField) == "" {
			return fmt.Errorf("routes.ownership entry %q needs owner_field", rule.Template)
		}
		rules[i].Template = template
	}

	jwt := &cfg.Identity.JWT
	jwt.UserClaim = cmp.Or(jwt.UserClaim, "sub")
	switch jwt.Algorithm {
	case "HS256":
		if jwt.SecretEnv == "" && jwt.Secret == "" {
			return fmt.Errorf("identity.jwt: HS256 needs secret_env (or a demo secret)")
		}
	case "RS256":
		if jwt.PublicKeyFile == "" {
			return fmt.Errorf("identity.jwt: RS256 needs public_key_file")
		}
	default:
		return fmt.Errorf("routes.ownership needs identity.jwt.algorithm HS256 or RS256, not %q", jwt.Algorithm)
	}
	if (jwt.BypassClaim == "") != (len(jwt.BypassValues) == 0) {
		return fmt.Errorf("identity.jwt: bypass_claim and bypass_values go together")
	}
	return nil
}

func normalizeTemplate(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) != 2 {
		return strings.TrimSpace(raw)
	}
	return strings.ToUpper(fields[0]) + " " + fields[1]
}

// ApplyEnvOverrides lets a container point the file's config at its
// neighbours: IASG_BACKEND_URL replaces proxy.backend_url and IASG_REDIS_HOST
// replaces storage.redis.host. It returns one line per override applied, for
// the caller to log.
func ApplyEnvOverrides(cfg *Config, getenv func(string) string) []string {
	var applied []string
	if v := getenv("IASG_BACKEND_URL"); v != "" {
		cfg.Proxy.BackendURL = v
		applied = append(applied, "Overriding backend URL from IASG_BACKEND_URL: "+v)
	}
	if v := getenv("IASG_REDIS_HOST"); v != "" {
		cfg.Storage.Redis.Host = v
		applied = append(applied, "Overriding Redis host from IASG_REDIS_HOST: "+v)
	}
	return applied
}
