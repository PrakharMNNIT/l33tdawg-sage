package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/stretchr/testify/require"
)

func TestClassificationHideLegacyShortIDsNoPanic(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		body   func(string) []byte
	}{
		{
			name: "query", method: http.MethodPost, path: "/v1/memory/query",
			body: func(domain string) []byte {
				body, _ := json.Marshal(QueryMemoryRequest{
					Embedding: []float32{0.1, 0.2}, DomainTag: domain, TopK: 10,
				})
				return body
			},
		},
		{
			name: "search", method: http.MethodPost, path: "/v1/memory/search",
			body: func(domain string) []byte {
				body, _ := json.Marshal(SearchMemoryRequest{
					Query: "legacy", DomainTag: domain, TopK: 10,
				})
				return body
			},
		},
		{
			name: "hybrid", method: http.MethodPost, path: "/v1/memory/hybrid",
			body: func(domain string) []byte {
				body, _ := json.Marshal(HybridSearchMemoryRequest{
					Query: "legacy", Embedding: []float32{0.1, 0.2},
					DomainTag: domain, TopK: 10,
				})
				return body
			},
		},
		{
			name: "list", method: http.MethodGet, path: "/v1/memory/list",
			body: func(string) []byte { return nil },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, memStore, bs, _ := newRBACTestServer(t)
			const (
				domain   = "legacy.short-owner"
				shortID  = "x"
				memoryID = "legacy-short-id-memory"
				secret   = "legacy classified payload"
			)

			path := tt.path
			if tt.method == http.MethodGet {
				path += "?domain=" + domain + "&limit=10"
			}
			body := tt.body(domain)
			req, callerID := signedRequest(t, tt.method, path, body)
			require.NoError(t, bs.RegisterAgent(callerID, "caller", "member", "", "test", "", 1))
			require.NoError(t, bs.RegisterDomain(domain, shortID, "", 1))
			seedMemory(t, memStore, memoryID, shortID, domain, secret)
			require.NoError(t, bs.SetMemoryClassification(memoryID, 2))

			rr := httptest.NewRecorder()
			srv.Router().ServeHTTP(rr, req)

			require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())
			require.NotContains(t, rr.Body.String(), secret)
		})
	}
}

func TestHandlePipeSendLegacyShortTargetEventNoPanic(t *testing.T) {
	srv, memStore := newPipeServer(t)
	const (
		sender = "sender-agent"
		target = "x"
	)
	require.NoError(t, memStore.CreateAgent(context.Background(), &store.AgentEntry{
		AgentID: target, Name: "legacy short target", Status: "active",
	}))

	var eventDescription string
	srv.OnEvent = func(_, _, _, description string, _ any) {
		eventDescription = description
	}
	body, err := json.Marshal(map[string]any{
		"to_agent": target,
		"intent":   "review",
		"payload":  "check this",
	})
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	pipeRouterAs(srv, sender).ServeHTTP(rr,
		httptest.NewRequest(http.MethodPost, "/v1/pipe/send", strings.NewReader(string(body))))

	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	require.Contains(t, eventDescription, "piped work to "+target)
}
