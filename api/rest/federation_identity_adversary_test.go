package rest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/stretchr/testify/require"
)

// Once Root rotates, generic local control must follow the current authority,
// not the JOIN-frozen federation transport key. Otherwise the retired Root can
// still mint local MCP identities while the replacement Root is locked out.
func TestAdversaryRootHandoverSeparatesMCPControlFromFederationTransportIdentity(t *testing.T) {
	srv, _ := newTokenServer(t)
	companionID := appV23RESTAgentID("22")
	currentRootID := appV23RESTAgentID("33")
	badger, err := store.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = badger.CloseBadger() })
	require.NoError(t, badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: tokenOperatorID, Scope: "root-transport-split",
		AgentID: companionID, Profile: store.AppV23ProfileStandard,
		HomeDomain: "companion.home", Clearance: 2, Height: 1,
		BootstrapDigest: "adversary",
	}))
	require.NoError(t, badger.RotateAppV23RootCredential(1, currentRootID, 2))
	srv.badgerStore = badger
	srv.SetPostV23ForNextTxAccessor(func() bool { return true })

	for _, tc := range []struct {
		name       string
		callerID   string
		requestID  string
		wantStatus int
	}{
		{
			name:       "retired Root transport key cannot mint",
			callerID:   tokenOperatorID,
			requestID:  tokenOperatorID,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "current Root can mint",
			callerID:   currentRootID,
			requestID:  currentRootID,
			wantStatus: http.StatusCreated,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"agent_id":"` + tc.requestID + `","name":"handover-sentinel"}`)
			rec := httptest.NewRecorder()
			tokenRouterAs(srv, tc.callerID).ServeHTTP(
				rec,
				httptest.NewRequest(http.MethodPost, "/v1/mcp/tokens", bytes.NewReader(body)),
			)
			require.Equal(t, tc.wantStatus, rec.Code, rec.Body.String())
		})
	}
}
