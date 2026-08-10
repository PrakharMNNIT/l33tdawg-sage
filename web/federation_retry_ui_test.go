package web

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFederationRetryUIUsesExplicitRecoveryRequestOnlyForOperatorClick(t *testing.T) {
	api, err := os.ReadFile("static/js/api.js")
	require.NoError(t, err)
	app, err := os.ReadFile("static/js/app.js")
	require.NoError(t, err)
	assert.Contains(t, string(api), "retry ? '?retry=1' : ''")
	assert.Contains(t, string(app), "await fedPeerStatus(chain, true)")
	assert.Contains(t, string(app), "await fedPeerStatus(connection.remote_chain_id)")
}

func TestFederationRetryUIExplainsUnprovableLegacyBinding(t *testing.T) {
	state, err := os.ReadFile("static/js/federation-route-state.js")
	require.NoError(t, err)
	assert.Contains(t, string(state), "legacy_repair_required")
	assert.Contains(t, string(state), "Pair the two SAGEs again to enable Secure relay")
	assert.Contains(t, string(state), "SAGE will not guess an identity")
}
