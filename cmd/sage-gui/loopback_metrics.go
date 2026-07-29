package main

import (
	"net"
	"net/http"
	"strings"
)

// loopbackOnlyMetrics keeps the sage-gui Prometheus endpoint consistent with
// its documented local-only contract even when REST_ADDR deliberately exposes
// signed agent and federation data-plane routes on a LAN address.
//
// Both the socket peer and HTTP Host must be loopback. Forwarding headers are
// deny-only: a reverse proxy on localhost must not turn an internet request
// into a local metrics scrape.
func loopbackOnlyMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !metricsRequestIsDirectLoopback(r) {
			http.Error(w, "metrics are available only through localhost", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func metricsRequestIsDirectLoopback(r *http.Request) bool {
	if r == nil || !metricsSocketAddressIsLoopback(r.RemoteAddr) ||
		!metricsHostIsLoopback(r.Host) {
		return false
	}
	for _, name := range []string{
		"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP",
	} {
		if strings.TrimSpace(r.Header.Get(name)) != "" {
			return false
		}
	}
	return true
}

func metricsSocketAddressIsLoopback(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func metricsHostIsLoopback(hostport string) bool {
	hostport = strings.TrimSpace(hostport)
	host := hostport
	if parsed, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsed
	} else if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]")
	} else if strings.Contains(hostport, ":") {
		// An unbracketed IPv6 literal, or malformed host:port, is not a valid
		// HTTP Host for this control surface.
		return false
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
