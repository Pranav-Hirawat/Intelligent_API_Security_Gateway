// Package proxy provides the core HTTP reverse proxy server functionality
// for the Intelligent API Security Gateway. It handles incoming requests,
// applies security middleware, and forwards traffic to backend services.
package proxy

import (
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/enforcement"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/identity"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/policy"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/reputation"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/telemetry"
)

// Config holds the configuration settings for the proxy server.
type Config struct {
	// ListenAddr is the address the gateway listens on, as "host:port".
	ListenAddr string

	// BackendURL is the backend requests are proxied to, e.g. "http://localhost:4000".
	BackendURL string

	// PreserveHost forwards the client's Host header rather than the backend's.
	PreserveHost bool

	// ReadTimeout bounds reading the whole request, body included, against slow clients.
	ReadTimeout time.Duration

	// WriteTimeout bounds writing the response.
	WriteTimeout time.Duration

	// IdleTimeout is how long a keep-alive connection waits for its next request.
	IdleTimeout time.Duration

	// ProxyTimeout bounds communication with the backend.
	ProxyTimeout time.Duration

	// MaxIdleConns caps idle connections in the proxy transport.
	MaxIdleConns int

	// MaxConnsPerHost caps total connections to the backend.
	MaxConnsPerHost int

	// MaxBodyBytes is the largest request body the gateway will read. Zero
	// falls back to DefaultMaxBodyBytes; the cap cannot be turned off from
	// config, because every stage below it buffers whatever it is handed.
	MaxBodyBytes int64

	// Routes describes the backend's own endpoints, so telemetry can record
	// which template a path matched. Structural and boot-only: changing a
	// template changes what previously recorded telemetry means, which is why
	// it is not part of the block the settings watcher carries.
	Routes config.RoutesConfig

	// Enforcement is every detector and enforcement section, carried whole.
	// It is the block the settings watcher retunes at runtime, so keeping it
	// as one value means a section added to it cannot be dropped on the way in.
	Enforcement config.EnforcementConfig

	// Identity verifies callers for Routes.Ownership. Boot-only: swapping keys
	// under running traffic is a deployment, not a settings change.
	Identity config.IdentityConfig

	// Redis holds hot telemetry and the policy snapshot the control plane writes.
	Redis config.RedisConfig

	// TrustedProxies lists CIDRs whose X-Forwarded-For header is believed.
	TrustedProxies []string

	// CORSAllowedOrigins lists origins allowed to read a response the gateway
	// writes itself. See config.ServerConfig.CORSAllowedOrigins.
	CORSAllowedOrigins []string
}

// ConfigFrom maps the loaded file config onto the server's.
func ConfigFrom(cfg *config.Config) Config {
	return Config{
		ListenAddr:         net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.Port)),
		BackendURL:         cfg.Proxy.BackendURL,
		PreserveHost:       cfg.Proxy.PreserveHost,
		ReadTimeout:        cfg.Server.ReadTimeout,
		WriteTimeout:       cfg.Server.WriteTimeout,
		IdleTimeout:        cfg.Server.IdleTimeout,
		ProxyTimeout:       cfg.Proxy.Timeout,
		MaxIdleConns:       cfg.Proxy.MaxIdleConns,
		MaxConnsPerHost:    cfg.Proxy.MaxConnsPerHost,
		MaxBodyBytes:       cfg.Server.MaxBodyBytes,
		Routes:             cfg.Routes,
		Enforcement:        cfg.Enforcement,
		Identity:           cfg.Identity,
		Redis:              cfg.Storage.Redis,
		TrustedProxies:     cfg.Server.TrustedProxies,
		CORSAllowedOrigins: cfg.Server.CORSAllowedOrigins,
	}
}

// Server represents the API gateway proxy server instance.
type Server struct {
	config Config
}

// NewServer creates a server ready to be started.
func NewServer(cfg Config) *Server {
	return &Server{config: cfg}
}

// Start builds the middleware chain and serves until the listener fails.
//
// The middleware chain is applied in the following order (outermost first):
//  1. Client-IP resolver — trusted-proxy X-Forwarded-For, then context IP
//  2. Gateway-answer CORS — lets a browser read a refusal the gateway itself
//     wrote (ownership, policy, body-size); never touches a backend answer
//  3. Telemetry — records one Redis event after the rest of the chain returns
//  4. Logging
//  5. Policy enforcer — optional; blocked IPs never reach detectors
//  6. Body-size cap, then redacted telemetry body capture
//  7. Reflex observer — optional; records gateway-side blocks after the
//     detectors unwind, applying from the caller's next request. Advisory
//     low-and-slow detectors remain evidence-only.
//  8. Reverse proxy
func (s *Server) Start() error {
	var cleanup cleanups
	defer cleanup.run()

	handler, err := s.handler(&cleanup)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr: s.config.ListenAddr,
		// Outside the chain, so the liveness probe reaches neither the
		// detectors, the recorder, nor the backend.
		Handler:      WithLiveness(handler),
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}
	return server.ListenAndServe()
}

// handler builds everything behind the listener. Background work it starts is
// registered on cleanup, so a failure part-way through still releases it.
func (s *Server) handler(cleanup *cleanups) (http.Handler, error) {
	enf := s.config.Enforcement
	backend := NewReverseProxy(s.config)

	reputationFeed, err := startReputationFeed(enf.IPReputation, cleanup)
	if err != nil {
		return nil, err
	}

	sinks := newTelemetrySinks(s.config.Redis)
	cleanup.add(sinks.Close)

	resolver, err := netutil.NewResolver(s.config.TrustedProxies)
	if err != nil {
		return nil, err
	}

	// A route table that would not compile stops the gateway, for the same
	// reason a bad reputation list does: one that silently loaded nothing
	// records <unmatched> for every real endpoint, and nothing downstream can
	// tell that from a client walking paths the application does not serve.
	routes, err := telemetry.NewTable(s.config.Routes.Templates)
	if err != nil {
		return nil, err
	}
	var routeMatch func(string, string) string
	var routeParams func(string, string) (string, []string)
	if len(s.config.Routes.Templates) > 0 {
		routeMatch = routes.Match
		routeParams = routes.MatchParams
	}

	verifier, err := s.newVerifier()
	if err != nil {
		return nil, err
	}

	detectors := newDetectors(enf, s.config.Routes, reputationFeed, routeMatch, routeParams, verifier)
	collector := detectors.collector()

	// The gateway's own reflex, and the enforcer that acts on both it and the
	// control plane's decisions.
	reflex, err := enforcement.New(reflexConfig(enf.Block))
	if err != nil {
		return nil, err
	}
	reflex.Start()
	cleanup.add(reflex.Close)
	log.Printf("[enforcement] %s", reflex.Describe())

	enforcer, gate, closePolicy, err := s.newEnforcer(reflex)
	if err != nil {
		return nil, err
	}
	enforcer.WithRouteResolver(routes.Match)
	cleanup.add(closePolicy)

	// Live settings. The file is what the gateway boots with; the console can
	// put an override on top of it, and deleting that override comes straight
	// back here. Only the enforcement block travels this way -- see the
	// settings package for why the structural settings do not.
	if watcher := s.startSettingsWatcher(live{detectors, reflex, enforcer, gate}); watcher != nil {
		cleanup.add(func() { _ = watcher.Close() })
	}

	recorder := &telemetry.Recorder{
		Events:    sinks.Events,
		Arrivals:  sinks.Arrivals,
		Collector: collector,
		Routes:    routes,
		Auth:      telemetry.NewAuthOutcomes(authRulesFrom(s.config.Routes.AuthOutcomes)),
	}
	if heartbeat := sinks.Heartbeat; heartbeat != nil {
		// Started here rather than beside the writers so it can report the
		// in-flight count, which only exists once the recorder does.
		heartbeat.Requests = recorder
		stop := make(chan struct{})
		cleanup.add(func() { close(stop) })
		heartbeat.Start(stop)
	}

	// The resolver runs first so the trusted-proxy X-Forwarded-For IP is on the
	// request context before anything else reads it. Telemetry sits just inside
	// it -- still outside every detector, so it records after they run and after
	// policy (a 403 is written to iasg:events too), but it reads the same
	// resolved client IP the detectors keyed their state under. When telemetry
	// wrapped the resolver instead, it held the pre-resolution request and
	// logged the peer address, then looked up detector state under that wrong
	// IP -- so every event behind a proxy recorded fired:[] and the control
	// plane never saw an attack.
	//
	// Refusals are recorded without reading a body. Accepted traffic is capped
	// before the telemetry snippet or any detector buffers client input.
	return ChainMiddleware(
		resolver.Middleware,
		GatewayAnswerCORS(s.config.CORSAllowedOrigins),
		recorder.Middleware,
		LoggingMiddleware,
		enforcer.Middleware,
		BodyLimitMiddleware(maxBodyBytes(s.config.MaxBodyBytes)),
		telemetry.CaptureBody,
		observedDetectors(reflex, collector, detectors.middlewares()...),
	)(backend), nil
}

// newVerifier loads token verification when an ownership rule needs it. A
// secret or key that cannot be loaded stops the gateway: an ownership check
// that could not verify tokens would have to either trust every token or
// refuse every request, and neither is what the config asked for.
func (s *Server) newVerifier() (*identity.Verifier, error) {
	if len(s.config.Routes.Ownership) == 0 {
		return nil, nil
	}
	verifier, err := identity.NewVerifier(s.config.Identity.JWT, os.Getenv)
	if err != nil {
		return nil, err
	}
	log.Printf("[ownership] checking %d endpoint(s) with %s tokens", len(s.config.Routes.Ownership), s.config.Identity.JWT.Algorithm)
	return verifier, nil
}

// cleanups runs registered shutdown work in reverse, like a stack of defers.
type cleanups []func()

func (c *cleanups) add(f func()) { *c = append(*c, f) }

func (c cleanups) run() {
	for i := len(c) - 1; i >= 0; i-- {
		c[i]()
	}
}

// startReputationFeed loads the known-bad address list before the chain is
// built. A list that will not parse is a configuration error and stops the
// gateway, exactly as a bad exempt CIDR does -- a security control that
// silently loaded nothing looks identical to one where no attacker is listed.
func startReputationFeed(cfg config.IPReputationConfig, cleanup *cleanups) (*reputation.Feed, error) {
	feed := reputation.New()
	if !cfg.Enabled {
		return feed, nil
	}

	source := reputationSourceFrom(cfg)
	loader := reputation.NewLoader(feed)
	if err := loader.Load(source); err != nil {
		return nil, err
	}
	log.Printf("[reputation] %s", feed.Describe())

	stop := make(chan struct{})
	cleanup.add(func() { close(stop) })
	loader.Start(source, stop)
	return feed, nil
}

// maxBodyBytes treats zero as unset rather than unlimited. A gateway that reads
// whatever it is sent is the failure this guards, so the config may raise or
// lower the cap but may not remove it.
func maxBodyBytes(configured int64) int64 {
	if configured <= 0 {
		return DefaultMaxBodyBytes
	}
	return configured
}

// observedDetectors keeps the observer outside response-aware detectors. On
// the return path, brute force records the backend status before Reflex reads
// the collector. The policy enforcer remains outside this group, so a blocked
// request reaches neither the detectors nor the observer.
func observedDetectors(reflex *enforcement.Reflex, collector enforcement.Observer, detectors ...Middleware) Middleware {
	middlewares := make([]Middleware, 0, len(detectors)+1)
	middlewares = append(middlewares, enforcement.Middleware(reflex, collector))
	middlewares = append(middlewares, detectors...)
	return ChainMiddleware(middlewares...)
}

// newEnforcer builds the enforcement middleware, the gate that switches the
// control plane's decisions on and off, and the function that releases the
// policy store and limiter.
//
// Both sources are wired in whether or not they are active at boot, because
// the console can turn either on later and the chain cannot be rebuilt once
// requests are flowing. Each source answers "no opinion" while it is off:
// the gate short-circuits, and the reflex checks its own enabled flag. The
// returned gate is nil when there is no Redis to read policy from.
func (s *Server) newEnforcer(reflex *enforcement.Reflex) (*policy.Enforcer, *policy.Gate, func(), error) {
	enf := s.config.Enforcement
	a := enf.AdaptiveRateLimit.WithDefaults()

	// The control plane first, then the gateway's own reflex. policy.Chain
	// documents why that order and not the other one.
	var sources policy.Chain
	var gate *policy.Gate
	var quota policy.QuotaLimiter
	closePolicy := func() {}

	if s.config.Redis.Enabled {
		cfg := policy.Config{
			Addr:            s.config.Redis.Addr(),
			Password:        s.config.Redis.Password,
			DB:              s.config.Redis.DB,
			PoolSize:        s.config.Redis.PoolSize,
			KeyPrefix:       enf.Policy.KeyPrefix,
			RefreshInterval: enf.Policy.RefreshInterval,
			RedisTimeout:    a.RedisTimeout,
			RefreshTimeout:  a.PolicyRefreshTimeout,
			FailureBackoff:  a.FailureBackoff,
			CacheMaxAge:     a.CacheMaxAge,
			BucketPrefix:    a.BucketKeyPrefix,
		}
		store := policy.NewStore(cfg)
		store.Start()
		limiter := policy.NewRedisLimiter(cfg)
		quota = limiter
		closePolicy = func() { _ = store.Close(); _ = limiter.Close() }
		gate = policy.NewGate(store, enf.Policy.Enabled)
		sources = append(sources, gate)
	}

	sources = append(sources, reflex)

	enforcer := policy.NewEnforcer(
		sources, anySourceOn(reflex, gate),
	).WithQuotaLimiter(quota, a.FallbackRequestsPerMinute, a.Burst)

	baseline, err := baselineFrom(enf.RateLimit, enf.Block)
	if err != nil {
		closePolicy()
		return nil, nil, nil, err
	}
	enforcer.ApplyAll(anySourceOn(reflex, gate), baseline)
	if baseline.RequestsPerMinute > 0 {
		log.Printf("[enforcement] baseline rate limit %d/min for every address not under a policy",
			baseline.RequestsPerMinute)
	}

	return enforcer, gate, closePolicy, nil
}

// baselineFrom builds the rate every address is held to when no policy names
// one. Zero unless rate_limit.enforce is on: noticing a flood and refusing one
// are different decisions, and only the second can turn a spike into an outage.
//
// The exempt list is the reflex's, so there is a single answer to "who does
// this gateway never refuse" rather than two lists that can disagree.
func baselineFrom(rl config.RateLimitConfig, block config.BlockConfig) (policy.Baseline, error) {
	if !rl.Enforce || rl.RequestsPerMinute <= 0 {
		return policy.Baseline{}, nil
	}

	entries := block.ExemptCIDRs
	if entries == nil {
		entries = enforcement.DefaultExempt
	}
	exempt, err := netutil.ParseCIDRs(entries, "exempt range")
	if err != nil {
		return policy.Baseline{}, err
	}

	return policy.Baseline{RequestsPerMinute: rl.RequestsPerMinute, Exempt: exempt}, nil
}

// anySourceOn reports whether any source could currently have an opinion.
// When none can, the middleware short-circuits and no lookup happens per
// request. Recomputed rather than read from config: the reflex has its own
// idea of whether it is armed (enabled, with at least one signal named).
func anySourceOn(reflex *enforcement.Reflex, gate *policy.Gate) bool {
	return gate.On() || reflex.Active()
}

// reflexConfig is the gateway's own blocking, from enforcement.block.
func reflexConfig(block config.BlockConfig) enforcement.Config {
	return enforcement.Config{
		Enabled:     block.Enabled,
		Duration:    block.Duration,
		Signals:     block.Signals,
		MinScore:    block.MinScore,
		ExemptCIDRs: block.ExemptCIDRs,
	}
}

// reputationSourceFrom turns config into a feed source, applying the defaults
// for anything left unset.
func reputationSourceFrom(cfg config.IPReputationConfig) reputation.Source {
	timeout := cfg.FetchTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return reputation.Source{
		Path:            cfg.FeedPath,
		URL:             cfg.FeedURL,
		RefreshInterval: cfg.RefreshInterval,
		Timeout:         timeout,
	}
}

// authRulesFrom turns the configured endpoints into the rules telemetry reads
// an authentication outcome with. Configuration rather than inference: 401 does
// not mean "wrong password" in general, only on an endpoint documented to
// answer that way.
func authRulesFrom(entries []config.AuthOutcomeConfig) []telemetry.AuthRule {
	rules := make([]telemetry.AuthRule, 0, len(entries))
	for _, e := range entries {
		rules = append(rules, telemetry.AuthRule{
			Method:             e.Method,
			Template:           e.Template,
			Success:            e.Success,
			InvalidCredentials: e.InvalidCredentials,
		})
	}
	return rules
}
