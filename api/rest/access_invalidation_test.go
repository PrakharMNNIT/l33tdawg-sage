package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCommittedAccessMutationEmitsPayloadFreeInvalidation(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		body       string
		wantStatus int
	}{
		{
			name:       "grant",
			path:       "/v1/access/grant",
			body:       `{"grantee_id":"sentinel-private-grantee","domain":"sentinel-private-domain","level":1}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "revoke",
			path:       "/v1/access/revoke",
			body:       `{"grantee_id":"sentinel-private-grantee","domain":"sentinel-private-domain","reason":"sentinel-private-reason"}`,
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			comet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeCometCommitFixture(t, w, r, 0, "", 0, "", 42)
			}))
			defer comet.Close()

			srv, _, _ := newTestServer(t, comet.URL)
			wire := newConnectomeWire(t, srv)
			req, _ := signedRequest(t, http.MethodPost, tc.path, []byte(tc.body))
			rec := httptest.NewRecorder()
			srv.Router().ServeHTTP(rec, req)

			require.Equal(t, tc.wantStatus, rec.Code, rec.Body.String())
			frames := wire.framesOfType(t, "access")
			require.Len(t, frames, 1, "one invalidation tick per committed mutation")

			_, dataLine, ok := strings.Cut(frames[0], "data: ")
			require.True(t, ok)
			var payload map[string]any
			require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(dataLine)), &payload))
			require.Equal(t, map[string]any{
				"type": "access", "memory_id": "",
			}, payload, "the global invalidation event must carry no authorization data")
			for _, secret := range []string{
				"sentinel-private-grantee", "sentinel-private-domain", "sentinel-private-reason",
			} {
				require.NotContains(t, frames[0], secret)
			}
		})
	}
}

func TestRejectedAccessMutationEmitsNoInvalidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		body string
	}{
		{
			name: "grant",
			path: "/v1/access/grant",
			body: `{"grantee_id":"agent-b","domain":"research","level":1}`,
		},
		{
			name: "revoke",
			path: "/v1/access/revoke",
			body: `{"grantee_id":"agent-b","domain":"research","reason":"test"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			comet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeCometCommitFixture(t, w, r, 0, "", 19, "rejected", 42)
			}))
			defer comet.Close()

			srv, _, _ := newTestServer(t, comet.URL)
			wire := newConnectomeWire(t, srv)
			req, _ := signedRequest(t, http.MethodPost, tc.path, []byte(tc.body))
			rec := httptest.NewRecorder()
			srv.Router().ServeHTTP(rec, req)

			require.NotEqual(t, http.StatusOK, rec.Code, rec.Body.String())
			require.NotEqual(t, http.StatusCreated, rec.Code, rec.Body.String())
			require.Empty(t, wire.framesOfType(t, "access"),
				"a rejected mutation must not invalidate authorized projections")
		})
	}
}
