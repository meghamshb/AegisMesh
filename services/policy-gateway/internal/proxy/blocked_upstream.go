package proxy

import (
	"net"
	"strings"
)

var blockedHostnames = map[string]struct{}{
	"localhost":            {},
	"postgres":             {},
	"policy-gateway":       {},
	"host.docker.internal": {},
}

// IsBlockedUpstream reports whether the proxy must refuse to forward to host.
// Internal destinations are hard-denied and cannot enter the approval queue.
func IsBlockedUpstream(host string) (bool, string) {
	normalized := strings.TrimSpace(strings.ToLower(host))
	if normalized == "" {
		return true, "empty host"
	}

	if strings.HasPrefix(normalized, "[") && strings.HasSuffix(normalized, "]") {
		normalized = normalized[1 : len(normalized)-1]
	}

	if _, blocked := blockedHostnames[normalized]; blocked {
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
		return false, ""
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return true, "hostname resolves to blocked IP"
		}
	}
	return false, ""
}

func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() || ip.IsUnspecified() {
		return true
	}
	return ip.Equal(net.IPv4(169, 254, 169, 254))
}
