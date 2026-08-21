package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type ParsedRequest struct {
	Method string
	Host   string
	Port   int
	Path   string
	Scheme string
}

func ParseRequest(r *http.Request) (ParsedRequest, error) {
	if r.Method == http.MethodConnect {
		host, port, err := splitHostPort(r.Host, 443)
		if err != nil {
			return ParsedRequest{}, err
		}
		return ParsedRequest{
			Method: r.Method,
			Host:   host,
			Port:   port,
			Path:   "/",
			Scheme: "https",
		}, nil
	}

	if r.URL.Host != "" {
		host, port, err := splitHostPort(r.URL.Host, defaultPort(r.URL.Scheme))
		if err != nil {
			return ParsedRequest{}, err
		}
		path := r.URL.Path
		if path == "" {
			path = "/"
		}
		return ParsedRequest{
			Method: r.Method,
			Host:   host,
			Port:   port,
			Path:   path,
			Scheme: schemeOrDefault(r.URL.Scheme),
		}, nil
	}

	return ParsedRequest{}, fmt.Errorf("not a proxy request")
}

func splitHostPort(raw string, defaultPort int) (string, int, error) {
	if raw == "" {
		return "", 0, fmt.Errorf("empty host")
	}

	// A bracketed IPv6 literal with no port, e.g. "[::1]" or "[fd00::1]".
	// net.SplitHostPort rejects this because it requires a port, which meant
	// an IPv6 destination was refused with a parse error *before* the SSRF
	// guard ever saw it. That was safe by accident rather than by decision -
	// and it left the guard untested for the entire IPv6 address family. Strip
	// the brackets and apply the scheme's default port so the address reaches
	// the guard like any other.
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		host := raw[1 : len(raw)-1]
		if host == "" {
			return "", 0, fmt.Errorf("empty host")
		}
		return host, defaultPort, nil
	}

	if strings.Contains(raw, ":") {
		host, portString, err := net.SplitHostPort(raw)
		if err != nil {
			return "", 0, err
		}
		port, err := strconv.Atoi(portString)
		if err != nil {
			return "", 0, err
		}
		return host, port, nil
	}

	return raw, defaultPort, nil
}

func defaultPort(scheme string) int {
	if scheme == "http" {
		return 80
	}
	return 443
}

func schemeOrDefault(scheme string) string {
	if scheme == "" {
		return "http"
	}
	return scheme
}

func IsProxyRequest(r *http.Request) bool {
	if r.Method == http.MethodConnect {
		return true
	}
	if r.URL.Host != "" {
		return true
	}
	if r.Header.Get("Proxy-Connection") != "" {
		return true
	}
	return false
}

func TargetURL(parsed ParsedRequest) *url.URL {
	return &url.URL{
		Scheme: parsed.Scheme,
		Host:   net.JoinHostPort(parsed.Host, strconv.Itoa(parsed.Port)),
	}
}
