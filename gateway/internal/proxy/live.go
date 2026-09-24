package proxy

import (
	"log"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/enforcement"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/policy"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/settings"
)

// live gathers everything in the running chain whose settings can be changed
// without rebuilding it. Each of these holds its tunables behind an atomic, so
// applying new settings is a pointer swap and never interrupts a request.
type live struct {
	detectors detectors
	reflex    *enforcement.Reflex
	enforcer  *policy.Enforcer
	gate      *policy.Gate
}

// apply moves the whole chain to a new enforcement config.
//
// Everything that can be rejected is checked before anything is changed. Two
// parts read the exempt list and either can refuse a CIDR that will not parse;
// doing both up front means a typo leaves the running gateway exactly as it
// was, rather than landing half a settings change on it.
func (l live) apply(cfg config.EnforcementConfig) error {
	baseline, err := baselineFrom(cfg.RateLimit, cfg.Block)
	if err != nil {
		return err
	}
	if err := l.reflex.Apply(reflexConfig(cfg.Block)); err != nil {
		return err
	}

	l.detectors.apply(cfg)
	l.gate.Set(cfg.Policy.Enabled)
	l.enforcer.ApplyAll(anySourceOn(l.reflex, l.gate), baseline)

	log.Printf("[enforcement] %s", l.reflex.Describe())
	return nil
}

// startSettingsWatcher begins watching Redis for console overrides. It returns
// nil when there is no Redis configured, in which case the file is the only
// source of settings and nothing can change them at runtime.
func (s *Server) startSettingsWatcher(l live) *settings.Watcher {
	if !s.config.Redis.Enabled {
		return nil
	}

	w := settings.NewWatcher(settings.Config{
		Addr:     s.config.Redis.Addr(),
		Password: s.config.Redis.Password,
		DB:       s.config.Redis.DB,
		PoolSize: s.config.Redis.PoolSize,
		Interval: s.config.Enforcement.Policy.RefreshInterval,
	}, s.config.Enforcement, l.apply)

	w.Start()
	return w
}
