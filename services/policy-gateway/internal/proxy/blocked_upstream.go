package proxy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// baseBlockedHostnames are internal service names that agent traffic must
// never reach through the proxy, regardless of deployment.
var baseBlockedHostnames = []string{
	"localhost",
	"postgres",
	"policy-gateway",
	"host.docker.internal",
}

// UpstreamGuard decides whether the proxy may forward to a host.
//
// The control plane is the subtle case (Phase 5.11.7). A gateway legitimately
// talks to the control plane for policy sync, identity resolution, and
// heartbeats - but *proxied agent traffic* must never reach it. Those are two
// different callers sharing one process, and only the second goes through this
// guard.
//
// Relying on the control plane merely resolving to a private IP is not enough:
// in a split production deployment the control plane is publicly addressable
// (CLEARANCE_CONTROL_URL=https://control.example.com), so the private-range
// check would let agent traffic straight through to it. The configured control
// plane host is therefore blocked by name, explicitly.
type UpstreamGuard struct {
	blocked  map[string]struct{}
	resolver Resolver
}

// NewUpstreamGuard builds a guard over the always-blocked internal names plus
// any deployment-specific hosts (typically the control plane).
func NewUpstreamGuard(extraHosts ...string) *UpstreamGuard {
	g := &UpstreamGuard{blocked: make(map[string]struct{}, len(baseBlockedHostnames)+len(extraHosts))}
	for _, h := range baseBlockedHostnames {
		g.add(h)
	}
	for _, h := range extraHosts {
		g.add(h)
	}
	return g
}

func (g *UpstreamGuard) add(host string) {
	normalized := normalizeHost(host)
	if normalized == "" {
		return
	}
	g.blocked[normalized] = struct{}{}
}

// HostFromURL extracts the hostname from a base URL such as
// "https://control.example.com:8443". Returns "" if the URL is empty or
// unparseable, so callers can pass a possibly-unset config value directly.
func HostFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return parsed.Hostname()
}

// IsBlocked reports whether the proxy must refuse to forward to host.
// Internal destinations are hard-denied and never enter the approval queue -
// an operator should not be able to approve their way to the control plane or
// the database.
func (g *UpstreamGuard) IsBlocked(host string) (bool, string) {
	if blocked, reason, decided := g.blockedByName(host); decided {
		return blocked, reason
	}

	// Pre-flight DNS check, so an obviously-internal destination gets a clean
	// 403 before anything is dialled. It is NOT the authoritative check -
	// DialContext re-resolves and validates the address it actually connects
	// to, which is what closes the rebinding window. Keeping this here means a
	// blocked host is reported as blocked rather than as a failed upstream.
	addrs, err := g.lookup(context.Background(), normalizeHost(host))
	if err != nil {
		// Fail closed. If the name cannot be resolved we cannot prove it is
		// not internal, and an unresolvable host would fail to connect anyway
		// - so refusing costs nothing and removes a bypass where an attacker
		// who can disrupt resolution gets an unchecked forward.
		return true, "host could not be resolved"
	}
	for _, a := range addrs {
		if isBlockedIP(a.IP) {
			return true, "hostname resolves to blocked IP"
		}
	}
	return false, ""
}

// blockedByName applies every check that needs no DNS. decided reports whether
// a verdict was reached; when false the caller must still resolve the name.
//
// Split out so the dial path can apply these checks and then resolve exactly
// once. Calling IsBlocked from DialContext would resolve twice, and two
// lookups is the very thing this design exists to avoid.
func (g *UpstreamGuard) blockedByName(host string) (blocked bool, reason string, decided bool) {
	normalized := normalizeHost(host)
	if normalized == "" {
		return true, "empty host", true
	}
	if _, found := g.blocked[normalized]; found {
		return true, "blocked internal hostname", true
	}
	if strings.HasSuffix(normalized, ".local") || strings.HasSuffix(normalized, ".internal") {
		return true, "blocked local domain suffix", true
	}
	if ip := net.ParseIP(normalized); ip != nil {
		if isBlockedIP(ip) {
			return true, "blocked IP range", true
		}
		// An IP literal cannot be rebound: there is no name to re-resolve.
		return false, "", true
	}
	return false, "", false
}

func normalizeHost(host string) string {
	normalized := strings.TrimSpace(strings.ToLower(host))
	if strings.HasPrefix(normalized, "[") && strings.HasSuffix(normalized, "]") {
		normalized = normalized[1 : len(normalized)-1]
	}
	return normalized
}

// defaultGuard preserves the package-level entry point used before the guard
// became configurable.
var defaultGuard = NewUpstreamGuard()

// IsBlockedUpstream reports whether the proxy must refuse to forward to host,
// using only the always-blocked internal names. Handlers use their own
// configured UpstreamGuard so the control plane is included.
func IsBlockedUpstream(host string) (bool, string) {
	return defaultGuard.IsBlocked(host)
}

func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() || ip.IsUnspecified() {
		return true
	}
	return ip.Equal(net.IPv4(169, 254, 169, 254))
}

// ---------------------------------------------------------------------------
// Resolve-and-pin dialing.
//
// IsBlocked alone is not sufficient, and the gap is a real one. It resolves a
// hostname to decide whether to allow the request, and then the transport
// resolves that name *again* when it dials. Those are two separate lookups, so
// a name whose DNS answer changes in between - a public address on the first
// lookup, 169.254.169.254 on the second - passes the check and is then
// fetched anyway. That is DNS rebinding, and it defeats every hostname-based
// SSRF control that validates and dials separately.
//
// The fix is to collapse the two lookups into one: resolve, validate every
// address the resolver returned, then connect to an address that was actually
// validated rather than to the name.
// ---------------------------------------------------------------------------

// Resolver is the subset of net.Resolver the guard needs, so tests can supply
// a resolver whose answers change between calls.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// WithResolver overrides the resolver used for validation and dialing.
func (g *UpstreamGuard) WithResolver(r Resolver) *UpstreamGuard {
	g.resolver = r
	return g
}

func (g *UpstreamGuard) lookup(ctx context.Context, host string) ([]net.IPAddr, error) {
	if g.resolver != nil {
		return g.resolver.LookupIPAddr(ctx, host)
	}
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// ErrBlockedUpstream is returned by DialContext when a destination resolves to
// an address the proxy must not reach.
type ErrBlockedUpstream struct {
	Host   string
	Reason string
}

func (e ErrBlockedUpstream) Error() string {
	return "blocked upstream " + e.Host + ": " + e.Reason
}

// DialContext resolves addr, refuses if any resolved address is internal, and
// then connects to one of the addresses it just validated.
//
// If *any* returned address is blocked the whole dial is refused rather than
// falling through to a permitted one: a hostile resolver can return a mix, and
// picking the acceptable answer out of a set that also contains 127.0.0.1 is
// exactly the behaviour an attacker would be counting on.
func (g *UpstreamGuard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split host/port %q: %w", addr, err)
	}

	blocked, reason, decided := g.blockedByName(host)
	if blocked {
		return nil, ErrBlockedUpstream{Host: host, Reason: reason}
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}

	// An IP literal is already settled: nothing to resolve, nothing to rebind.
	if decided {
		return dialer.DialContext(ctx, network, addr)
	}

	addrs, err := g.lookup(ctx, host)
	if err != nil {
		// Same fail-closed reasoning as IsBlocked: an unresolvable name cannot
		// be proven external.
		return nil, ErrBlockedUpstream{Host: host, Reason: "host could not be resolved"}
	}
	if len(addrs) == 0 {
		return nil, ErrBlockedUpstream{Host: host, Reason: "host resolved to no addresses"}
	}
	for _, a := range addrs {
		if isBlockedIP(a.IP) {
			return nil, ErrBlockedUpstream{Host: host, Reason: "hostname resolves to blocked IP"}
		}
	}

	// Connect to a validated address, never to the name - re-resolving here is
	// what would reopen the window.
	var lastErr error
	for _, a := range addrs {
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(a.IP.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	return nil, lastErr
}
