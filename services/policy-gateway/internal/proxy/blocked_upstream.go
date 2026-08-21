package proxy

import (
	"net"
	"net/url"
	"strings"
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
	blocked map[string]struct{}
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
	normalized := normalizeHost(host)
	if normalized == "" {
		return true, "empty host"
	}

	if _, blocked := g.blocked[normalized]; blocked {
		return true, "blocked internal hostname"
	}
	if strings.HasSuffix(normalized, ".local") || strings.HasSuffix(normalized, ".internal") {
		return true, "blocked local domain suffix"
	}

	if ip := net.ParseIP(normalized); ip != nil {
		if isBlockedIP(ip) {
			return true, "blocked IP range"
		}
		return false, ""
	}

	ips, err := net.LookupIP(normalized)
	if err != nil {
		// Fail closed. If the name cannot be resolved we cannot prove it is
		// not internal, and an unresolvable host would fail to connect anyway
		// - so refusing costs nothing and removes a bypass where an attacker
		// who can disrupt resolution gets an unchecked forward.
		return true, "host could not be resolved"
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return true, "hostname resolves to blocked IP"
		}
	}
	return false, ""
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
