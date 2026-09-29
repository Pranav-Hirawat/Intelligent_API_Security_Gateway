package policy

import "time"

// Chain looks decisions up in several sources and returns the one to enforce.
//
// There are two sources: the decision engine and the gateway's own reflex. When
// both have an opinion about a request, the more severe action wins, and among
// equals the earlier source -- the engine, whose decision carries the policy id
// and campaign the console links to.
//
// The engine used to win outright, even when milder, on the reasoning that its
// decision is the considered one. In practice it is considered on less: the
// reflex refuses an address before the detectors run, so every request after
// the one that armed it is invisible to the engine. A path-traversal probe
// armed a five-minute block, the engine saw that single request, found it below
// the two-observation minimum for a block, wrote a throttle -- and the throttle
// replaced the block, letting the attacker straight back in about a cycle
// later. A milder opinion formed without the evidence cannot lift a block.
//
// A person's instruction is the exception and still wins whatever it says: a
// human override is how an address the gateway blocked by itself is released.
type Chain []Lookuper

func (c Chain) Lookup(ip string) (Decision, bool) {
	return c.pick(func(source Lookuper) (Decision, bool) { return source.Lookup(ip) })
}

// A route-scoped policy must not hide another source's decision on a different
// endpoint. Resolve the scope while choosing the winning source.
func (c Chain) LookupRequest(ip, route, method string) (Decision, bool) {
	return c.pick(func(source Lookuper) (Decision, bool) {
		if scoped, ok := source.(interface {
			LookupRequest(string, string, string) (Decision, bool)
		}); ok {
			return scoped.LookupRequest(ip, route, method)
		}
		d, found := source.Lookup(ip)
		return d, found && matches(d, route, method)
	})
}

func (c Chain) pick(find func(Lookuper) (Decision, bool)) (Decision, bool) {
	var chosen Decision
	found := false
	for _, source := range c {
		if source == nil {
			continue
		}
		d, ok := find(source)
		if !ok {
			continue
		}
		if decisionPriority(d) == humanPriority {
			return d, true
		}
		if !found || severity(d.Action) > severity(chosen.Action) {
			chosen, found = d, true
		}
	}
	return chosen, found
}

// severity orders actions by how much they restrict. Unknown labels rank
// lowest, so an unrecognised action can never outrank a real block.
func severity(action string) int {
	switch action {
	case ActionThrottle:
		return 1
	case ActionBlock, ActionTempBlock, ActionTemporaryBlock:
		return 2
	case ActionEscalate:
		return 3
	}
	return 0
}

func matches(d Decision, route, method string) bool {
	return (d.Route == "" || d.Route == route) &&
		(d.Method == "" || d.Method == method) &&
		(d.ExpiresAt.IsZero() || time.Now().Before(d.ExpiresAt))
}
