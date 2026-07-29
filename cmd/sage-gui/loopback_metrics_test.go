package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoopbackOnlyMetricsRejectsNetworkAndProxyRequests(t *testing.T) {
	var calls int
	handler := loopbackOnlyMetrics(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))

	tests := []struct {
		name       string
		remoteAddr string
		host       string
		header     string
		value      string
	}{
		{
			name:       "remote_socket_cannot_forge_localhost_host",
			remoteAddr: "198.51.100.8:4242", host: "localhost:8080",
		},
		{
			name:       "loopback_socket_cannot_use_public_host",
			remoteAddr: "127.0.0.1:4242", host: "sage.example.test:8080",
		},
		{
			name:       "localhost_suffix_is_not_localhost",
			remoteAddr: "127.0.0.1:4242", host: "localhost.example.test:8080",
		},
		{
			name:       "forwarded_proxy_is_not_direct_loopback",
			remoteAddr: "127.0.0.1:4242", host: "localhost:8080",
			header: "Forwarded", value: "for=198.51.100.8",
		},
		{
			name:       "x_forwarded_for_is_not_direct_loopback",
			remoteAddr: "127.0.0.1:4242", host: "localhost:8080",
			header: "X-Forwarded-For", value: "198.51.100.8",
		},
		{
			name:       "x_forwarded_host_is_not_direct_loopback",
			remoteAddr: "127.0.0.1:4242", host: "localhost:8080",
			header: "X-Forwarded-Host", value: "sage.example.test",
		},
		{
			name:       "x_real_ip_is_not_direct_loopback",
			remoteAddr: "127.0.0.1:4242", host: "localhost:8080",
			header: "X-Real-IP", value: "198.51.100.8",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			req.RemoteAddr = test.remoteAddr
			req.Host = test.host
			if test.header != "" {
				req.Header.Set(test.header, test.value)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusForbidden, rec.Code)
		})
	}
	require.Zero(t, calls)
}

func TestLoopbackOnlyMetricsAllowsDirectIPv4AndIPv6Scrapes(t *testing.T) {
	var calls int
	handler := loopbackOnlyMetrics(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, test := range []struct {
		remoteAddr string
		host       string
	}{
		{remoteAddr: "127.0.0.1:4242", host: "localhost:8080"},
		{remoteAddr: "127.0.0.1:4242", host: "127.0.0.1:8080"},
		{remoteAddr: "[::1]:4242", host: "[::1]:8080"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = test.remoteAddr
		req.Host = test.host
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusNoContent, rec.Code)
	}
	require.Equal(t, 3, calls)
}
