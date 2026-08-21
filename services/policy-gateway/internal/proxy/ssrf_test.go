package proxy

import "testing"

// Phase 5.11.7: the SSRF guard must keep holding as the architecture grows.
// Every destination below is one an agent could name in a proxied request.

func TestSSRFBlocksInternalDestinations(t *testing.T) {
	guard := NewUpstreamGuard()

	for _, tc := range []struct{ host, why string }{
		{"127.0.0.1", "loopback"},
		{"127.1.2.3", "loopback range"},
		{"localhost", "loopback by name"},
		{"LOCALHOST", "case-insensitive"},
		{"0.0.0.0", "unspecified"},
		{"10.0.0.1", "RFC1918 /8"},
		{"10.255.255.255", "RFC1918 /8 upper"},
		{"172.16.0.1", "RFC1918 /12"},
		{"172.31.255.255", "RFC1918 /12 upper"},
		{"192.168.0.1", "RFC1918 /16"},
		{"192.168.255.255", "RFC1918 /16 upper"},
		{"169.254.169.254", "cloud instance metadata"},
		{"169.254.1.1", "link-local"},
		{"[::1]", "IPv6 loopback"},
		{"::1", "IPv6 loopback bare"},
		{"postgres", "database service name"},
		{"policy-gateway", "gateway service name"},
		{"host.docker.internal", "docker host escape"},
		{"anything.local", "mDNS suffix"},
		{"svc.internal", "internal suffix"},
		{"", "empty host"},
	} {
		t.Run(tc.host+" ("+tc.why+")", func(t *testing.T) {
			blocked, reason := guard.IsBlocked(tc.host)
			if !blocked {
				t.Fatalf("host %q (%s) must be blocked, got allowed", tc.host, tc.why)
			}
			if reason == "" {
				t.Fatalf("host %q blocked without a reason", tc.host)
			}
		})
	}
}

// The distinction Phase 5.11.7 calls out explicitly: this process talks to the
// control plane for policy sync, but proxied agent traffic must not reach it.
// Blocking by name matters because a production control plane is publicly
// addressable, so the private-IP check would not catch it.
func TestSSRFBlocksConfiguredControlPlaneByName(t *testing.T) {
	guard := NewUpstreamGuard(HostFromURL("https://control.example.com:8443"))

	blocked, reason := guard.IsBlocked("control.example.com")
	if !blocked {
		t.Fatal("proxied traffic reached the configured control plane; a publicly addressable control plane is not covered by the private-IP check")
	}
	if reason != "blocked internal hostname" {
		t.Fatalf("reason = %q, want blocked internal hostname", reason)
	}

	// Port variations name the same host.
	if blocked, _ := guard.IsBlocked("CONTROL.EXAMPLE.COM"); !blocked {
		t.Fatal("control plane block must be case-insensitive")
	}
}

func TestSSRFBlocksFleetServiceNames(t *testing.T) {
	// A fleet gateway is configured against its control plane by service name.
	guard := NewUpstreamGuard(HostFromURL("http://control-plane:8080"))

	if blocked, _ := guard.IsBlocked("control-plane"); !blocked {
		t.Fatal("agent traffic must not reach the fleet control plane by service name")
	}
}

// Fail closed: an unresolvable host cannot be proven external, and refusing
// costs nothing because the connection would fail anyway.
func TestSSRFFailsClosedOnUnresolvableHost(t *testing.T) {
	guard := NewUpstreamGuard()

	blocked, reason := guard.IsBlocked("this-host-does-not-exist.invalid")
	if !blocked {
		t.Fatal("an unresolvable host must fail closed, not be forwarded")
	}
	if reason != "host could not be resolved" {
		t.Fatalf("reason = %q, want host could not be resolved", reason)
	}
}

// The guard must still allow ordinary public traffic, or it would be a
// blanket denial rather than an SSRF control.
func TestSSRFAllowsPublicDestinations(t *testing.T) {
	guard := NewUpstreamGuard(HostFromURL("http://control-plane:8080"))

	for _, host := range []string{"8.8.8.8", "1.1.1.1"} {
		if blocked, reason := guard.IsBlocked(host); blocked {
			t.Fatalf("public host %q was blocked (%s); the guard is over-broad", host, reason)
		}
	}
}

func TestHostFromURL(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"http://control-plane:8080", "control-plane"},
		{"https://control.example.com", "control.example.com"},
		{"https://control.example.com:8443/api", "control.example.com"},
		{"", ""},
		{"not a url", ""},
	} {
		if got := HostFromURL(tc.in); got != tc.want {
			t.Fatalf("HostFromURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
