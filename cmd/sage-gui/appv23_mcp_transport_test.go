package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/api/rest/middleware"
	"github.com/l33tdawg/sage/internal/store"
)

func TestAppV23MCPTransportStopsLegacyRootFallbackAtActivation(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := store.NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "mcp.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqliteStore.Close() })

	const (
		bearer         = "legacy-keyless-transport-token"
		transportRoot  = "current-root-credential"
		legacyStoredID = "historical-token-agent"
	)
	digestBytes := sha256.Sum256([]byte(bearer))
	digest := hex.EncodeToString(digestBytes[:])
	require.NoError(t, sqliteStore.InsertMCPToken(
		ctx, "legacy-token-id", "legacy", legacyStoredID, digest,
	))

	active := false
	sqliteStore.SetMCPTokenKeyedIdentityRequirement(func() bool { return active })
	t.Cleanup(func() { sqliteStore.SetMCPTokenKeyedIdentityRequirement(nil) })
	lookup := mcpBearerSignerLookup(sqliteStore, transportRoot)

	agentID, signer, err := lookup(ctx, bearer, digest)
	require.NoError(t, err)
	require.Equal(t, transportRoot, agentID,
		"pre-v23 compatibility retains the historical node-key fallback")
	require.Nil(t, signer)

	active = true
	_, _, err = lookup(ctx, bearer, digest)
	require.Error(t, err)
	require.True(t, errors.Is(err, middleware.ErrMCPTokenRevoked),
		"the activation edge must present a legacy Root-capable bearer as revoked")

	reached := false
	protected := middleware.MCPBearerAuthMiddleware(lookup)(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusNoContent)
		},
	))
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/streamable", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.False(t, reached, "a disabled keyless bearer must never reach MCP")
}
