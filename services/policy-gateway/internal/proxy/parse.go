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
