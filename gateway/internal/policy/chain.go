package policy

import "time"

// Chain looks decisions up in several sources, in order, and returns the first
// one found.
//
// There are two sources and the order between them is a deliberate choice: the
// decision engine comes first, the gateway's own reflex second.
//
// The reflex exists because the decision engine is slow -- a decision takes up to
// one agent cycle plus one snapshot refresh to arrive. It is a stopgap held by
// a component that knows only what one detector saw. The decision engine, by the
// time it has an opinion, has correlated an address with others, weighed a
// campaign's history, taken account of any human override, and passed the
// whole thing through simulation.
//
// So once the agent has decided something about an address, that decision
// wins, including when it is *less* severe. An agent that has looked at the
// evidence and chosen to throttle rather than block is not to be overruled by
// a reflex that fired before anyone had thought about it -- and this is also
// how a human override reaches an address the gateway blocked by itself.
type Chain []Lookuper

func (c Chain) Lookup(ip string) (Decision, bool) {
	for _, source := range c {
		if source == nil {
			continue
		}
		if decision, found := source.Lookup(ip); found {
			return decision, true
		}
	}
	return Decision{}, false
}

// A route-scoped policy must not hide another source's decision on a different
// endpoint. Resolve the scope while choosing the winning source.
func (c Chain) LookupRequest(ip, route, method string) (Decision, bool) {
	for _, source := range c {
		if source == nil {
			continue
		}
		if scoped, ok := source.(interface {
			LookupRequest(string, string, string) (Decision, bool)
		}); ok {
			if d, found := scoped.LookupRequest(ip, route, method); found {
				return d, true
			}
			continue
		}
		if d, found := source.Lookup(ip); found && matches(d, route, method) {
			return d, true
		}
	}
	return Decision{}, false
}

func matches(d Decision, route, method string) bool {
	return (d.Route == "" || d.Route == route) &&
		(d.Method == "" || d.Method == method) &&
		(d.ExpiresAt.IsZero() || time.Now().Before(d.ExpiresAt))
}
