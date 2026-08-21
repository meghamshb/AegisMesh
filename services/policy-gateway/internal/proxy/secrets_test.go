package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Phase 5.11.10: audit metadata must stay focused on host/port/method/path/
// identity/decision/rule/timing. In particular it must not capture secrets
// that ride along in the request.

// A query string routinely carries API keys and signed URLs
// (?access_token=..., ?X-Amz-Signature=...). ParseRequest must record the path
// only, so those never reach egress_requests or audit_events.
func TestParsedPathExcludesQueryString(t *testing.T) {
	for _, tc := range []struct{ url, wantPath string }{
		{"http://example.com/api?access_token=supersecret", "/api"},
		{"http://example.com/v1/data?sig=abc&key=def", "/v1/data"},
		{"http://example.com/?token=leak", "/"},
		{"http://example.com/plain", "/plain"},
	} {
		t.Run(tc.url, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			parsed, err := ParseRequest(req)
			if err != nil {
				t.Fatalf("ParseRequest: %v", err)
			}
			if parsed.Path != tc.wantPath {
				t.Fatalf("Path = %q, want %q", parsed.Path, tc.wantPath)
			}
			if parsed.Path == tc.url {
				t.Fatal("parsed path retained the full URL including query")
			}
		})
	}
}

// A CONNECT tunnel gives only host-level visibility; the recorded path must be
// the placeholder "/", never anything derived from client-supplied data.
func TestConnectRecordsNoPathDetail(t *testing.T) {
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Method = http.MethodConnect
	req.Host = "example.com:443"

	parsed, err := ParseRequest(req)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if parsed.Path != "/" {
		t.Fatalf("CONNECT path = %q, want /", parsed.Path)
	}
	if parsed.Scheme != "https" {
		t.Fatalf("CONNECT scheme = %q, want https", parsed.Scheme)
	}
}

// An IPv6 literal without an explicit port must still reach the SSRF guard.
// Before this was fixed, net.SplitHostPort rejected "[::1]" for having no
// port, so the request failed to parse and was refused with a 400 - safe by
// accident, but it meant the guard was never consulted for any IPv6 address.
func TestParsesBracketedIPv6WithoutPort(t *testing.T) {
	for _, tc := range []struct {
		url      string
		wantHost string
		wantPort int
	}{
		{"http://[::1]/", "::1", 80},
		{"http://[fd00::1]/x", "fd00::1", 80},
		{"https://[fe80::1]/", "fe80::1", 443},
		{"http://[::1]:8080/", "::1", 8080},
	} {
		t.Run(tc.url, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			parsed, err := ParseRequest(req)
			if err != nil {
				t.Fatalf("ParseRequest(%q): %v", tc.url, err)
			}
			if parsed.Host != tc.wantHost || parsed.Port != tc.wantPort {
				t.Fatalf("got %s:%d, want %s:%d", parsed.Host, parsed.Port, tc.wantHost, tc.wantPort)
			}
			// And, having parsed, it must be blocked by the guard.
			if blocked, _ := NewUpstreamGuard().IsBlocked(parsed.Host); !blocked {
				t.Fatalf("IPv6 host %q reached the guard but was not blocked", parsed.Host)
			}
		})
	}
}
