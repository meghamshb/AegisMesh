package proxy

import "testing"

func TestIsBlockedUpstreamHostnames(t *testing.T) {
	tests := []struct {
		host    string
		blocked bool
	}{
		{"postgres", true},
		{"POSTGRES", true},
		{"policy-gateway", true},
		{"localhost", true},
		{"host.docker.internal", true},
		{"example.com", false},
		{"api.github.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			blocked, _ := IsBlockedUpstream(tc.host)
			if blocked != tc.blocked {
				t.Fatalf("IsBlockedUpstream(%q) = %v, want %v", tc.host, blocked, tc.blocked)
			}
		})
	}
}

func TestIsBlockedUpstreamIPs(t *testing.T) {
	tests := []struct {
		host    string
		blocked bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true},
		{"8.8.8.8", false},
	}

	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			blocked, _ := IsBlockedUpstream(tc.host)
			if blocked != tc.blocked {
				t.Fatalf("IsBlockedUpstream(%q) = %v, want %v", tc.host, blocked, tc.blocked)
			}
		})
	}
}
