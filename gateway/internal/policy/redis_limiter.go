package policy

import (
	"cmp"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// QuotaRequest carries the decision already selected from the local snapshot.
// Redis only accounts for its quota; it never makes a security decision.
type QuotaRequest struct {
	IP, Route, Method string
	Decision          Decision
	RequestsPerMinute int
	Burst             int
}

type QuotaResult struct {
	Allowed    bool
	RetryAfter time.Duration
	Reason     string
}

type QuotaLimiter interface {
	Take(context.Context, QuotaRequest) (QuotaResult, error)
}

var errRedisBackoff = errors.New("rate limiter Redis circuit is open")

//go:embed token_bucket.lua
var tokenBucketScript string

// RedisLimiter shares one bounded bucket across all gateway replicas. It uses
// its own pool so telemetry and background scans cannot occupy quota sockets.
type RedisLimiter struct {
	client       *redis.Client
	prefix       string
	timeout      time.Duration
	backoff      time.Duration
	blockedUntil atomic.Int64
	probing      atomic.Bool
}

func defaults(cfg Config) Config {
	cfg.KeyPrefix = cmp.Or(cfg.KeyPrefix, "policy:")
	cfg.BucketPrefix = cmp.Or(cfg.BucketPrefix, "iasg:rate:")
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 5 * time.Second
	}
	if cfg.RefreshTimeout <= 0 {
		cfg.RefreshTimeout = 2 * time.Second
	}
	if cfg.RedisTimeout <= 0 {
		cfg.RedisTimeout = 25 * time.Millisecond
	}
	if cfg.FailureBackoff <= 0 {
		cfg.FailureBackoff = time.Second
	}
	if cfg.CacheMaxAge <= 0 {
		cfg.CacheMaxAge = 10 * time.Second
	}
	return cfg
}

func newRedisClient(cfg Config) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:                  cfg.Addr,
		Password:              cfg.Password,
		DB:                    cfg.DB,
		PoolSize:              cfg.PoolSize,
		DialTimeout:           cfg.RedisTimeout,
		ReadTimeout:           cfg.RedisTimeout,
		WriteTimeout:          cfg.RedisTimeout,
		PoolTimeout:           cfg.RedisTimeout,
		ContextTimeoutEnabled: true,
		// Retrying an ambiguous write could charge the same request twice,
		// and backoff on the request path would defeat the latency bound.
		MaxRetries: -1,
	})
}

func NewRedisLimiter(cfg Config) *RedisLimiter {
	cfg = defaults(cfg)
	return &RedisLimiter{
		client:  newRedisClient(cfg),
		prefix:  cfg.BucketPrefix,
		timeout: cfg.RedisTimeout,
		backoff: cfg.FailureBackoff,
	}
}

func (l *RedisLimiter) Take(ctx context.Context, q QuotaRequest) (QuotaResult, error) {
	if q.RequestsPerMinute <= 0 {
		return QuotaResult{Allowed: true, Reason: "no_limit"}, nil
	}
	if !q.Decision.ExpiresAt.IsZero() && !time.Now().Before(q.Decision.ExpiresAt) {
		return QuotaResult{Allowed: true, Reason: "policy_inactive"}, nil
	}
	if q.Burst <= 0 || q.Burst > q.RequestsPerMinute {
		q.Burst = q.RequestsPerMinute
	}

	if until := l.blockedUntil.Load(); until != 0 {
		if time.Now().UnixNano() < until || !l.probing.CompareAndSwap(false, true) {
			return QuotaResult{Allowed: true, Reason: "redis_unavailable"}, errRedisBackoff
		}
		// Only one request probes a recovering Redis. Everybody else can
		// continue immediately until that probe has established connectivity.
		defer l.probing.Store(false)
	}

	ctx, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()
	keys := []string{bucketKey(l.prefix, q)}
	if q.Decision.redisKey != "" {
		keys = append(keys, q.Decision.redisKey)
	}
	// EVAL uses one round trip even after SCRIPT FLUSH or a Redis restart.
	// An EVALSHA fallback would spend a second round trip inside the budget.
	values, err := l.client.Eval(ctx, tokenBucketScript, keys,
		q.RequestsPerMinute, q.Burst, q.Decision.rawPolicy).Slice()
	var result QuotaResult
	if err == nil {
		result, err = decodeQuotaResult(values)
	}
	if err != nil {
		l.blockedUntil.Store(time.Now().Add(l.backoff).UnixNano())
		return QuotaResult{Allowed: true, Reason: "redis_unavailable"}, err
	}
	l.blockedUntil.Store(0)
	return result, nil
}

func bucketKey(prefix string, q QuotaRequest) string {
	// JSON array framing avoids separator collisions; a fixed hash prevents
	// attacker-controlled paths from becoming arbitrarily large Redis keys.
	// Configuration changes reuse the bucket, so mixed replica settings do
	// not create parallel allowances while a rollout is in progress.
	identity, _ := json.Marshal([]string{
		q.IP, q.Route, q.Method, q.Decision.redisKey, q.Decision.rawPolicy,
	})
	digest := sha256.Sum256(identity)
	return prefix + hex.EncodeToString(digest[:])
}

func decodeQuotaResult(values []any) (QuotaResult, error) {
	if len(values) != 3 {
		return QuotaResult{}, fmt.Errorf("invalid rate limiter response length: %d", len(values))
	}
	allowed, okAllowed := values[0].(int64)
	wait, okWait := values[1].(int64)
	reason, okReason := values[2].(string)
	if !okAllowed || !okWait || !okReason || (allowed != 0 && allowed != 1) || wait < 0 || wait > int64((1<<63-1)/time.Millisecond) {
		return QuotaResult{}, errors.New("invalid rate limiter response")
	}
	return QuotaResult{Allowed: allowed == 1, RetryAfter: time.Duration(wait) * time.Millisecond, Reason: reason}, nil
}

func (l *RedisLimiter) Close() error {
	return l.client.Close()
}
