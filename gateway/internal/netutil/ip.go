// Package netutil works out which address a request should be attributed to.
//
// This matters more than it looks. Every detector keys its state by client IP,
// and the decision engine writes policy against that IP, so getting it wrong
// means both detecting and blocking the wrong machine. Behind a load balancer
// the TCP peer is the balancer, so without X-Forwarded-For every request looks
// like it came from one address -- and enforcing a block on it would take the
// whole API offline.
//
// The header is only believed when the connection came from an address the
// operator has explicitly listed as a proxy. With no list configured, the
// header is ignored entirely, because anyone can set it.
package netutil

import (
	"context"
	"net"
	"net/http"
	"strings"
)

type ctxKey struct{}

// PeerIP is the address that actually opened the connection, port stripped.
func PeerIP(remoteAddr string) string {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return ip
}

// ClientIP returns the address this request is attributed to. It reads what
// the resolver middleware worked out; without that middleware it falls back
// to the peer address, which is the old behaviour.
func ClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(ctxKey{}).(string); ok && ip != "" {
		return ip
	}
	return PeerIP(r.RemoteAddr)
}

// Resolver decides whether a request's X-Forwarded-For header can be believed.
type Resolver struct {
	trusted []*net.IPNet
}

// NewResolver builds a resolver from a list of CIDRs or bare addresses. An
// empty list means no proxy is trusted, so the peer address is always used.
func NewResolver(cidrs []string) (*Resolver, error) {
	trusted, err := ParseCIDRs(cidrs, "trusted proxy")
	if err != nil {
		return nil, err
	}
	return &Resolver{trusted: trusted}, nil
}

// Trusts reports whether an address is a configured proxy.
func (res *Resolver) Trusts(ip string) bool {
	return NetworksContain(res.trusted, ip)
}

// Resolve returns the address the request should be attributed to.
func (res *Resolver) Resolve(r *http.Request) string {
	peer := PeerIP(r.RemoteAddr)

	// Nothing is trusted, or this connection did not come from a proxy we
	// trust. Either way the header is attacker-controlled, so ignore it.
	if len(res.trusted) == 0 || !res.Trusts(peer) {
		return peer
	}

	hops := forwardedHops(r)

	// Walk right to left. The rightmost entry was appended by the proxy we
	// trust, so it is the only one we know is genuine; keep stepping left
	// past entries that are themselves trusted proxies, and the first
	// untrusted address is the real client. Anything further left was
	// supplied by the caller and cannot be believed.
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(hops[i])
		if ip == nil {
			continue
		}
		if res.Trusts(ip.String()) {
			continue
		}
		return ip.String()
	}

	// Header missing, empty, or every hop was a trusted proxy.
	return peer
}

// Middleware resolves the client IP once and puts it on the request context,
// so every detector downstream agrees on who the caller is.
func (res *Resolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := res.Resolve(r)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, ip)))
	})
}

// forwardedHops flattens X-Forwarded-For, which may arrive as several headers
// and as comma-separated lists within each.
func forwardedHops(r *http.Request) []string {
	var hops []string
	for _, value := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(value, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				hops = append(hops, trimmed)
			}
		}
	}
	return hops
}
