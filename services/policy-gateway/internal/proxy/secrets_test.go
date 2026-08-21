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
