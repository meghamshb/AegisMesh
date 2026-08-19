package proxy_test

import (
	"net/http"
	"testing"

	"github.com/meghamshb2006/ACP-For-Hermes-Agents/services/policy-gateway/internal/proxy"
)

func TestParseCONNECTRequest(t *testing.T) {
	req, err := http.NewRequest(http.MethodConnect, "http://policy-gateway:8080", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Host = "example.com:443"

	parsed, err := proxy.ParseRequest(req)
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if parsed.Host != "example.com" || parsed.Port != 443 || parsed.Scheme != "https" {
		t.Fatalf("parsed = %+v", parsed)
	}
}

func TestParseAbsoluteHTTPRequest(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.com/path", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	parsed, err := proxy.ParseRequest(req)
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if parsed.Host != "example.com" || parsed.Port != 80 || parsed.Path != "/path" {
		t.Fatalf("parsed = %+v", parsed)
	}
}
