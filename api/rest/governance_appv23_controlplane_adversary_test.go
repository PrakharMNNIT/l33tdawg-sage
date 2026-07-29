package rest

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/api/rest/middleware"
	"github.com/l33tdawg/sage/internal/store"
)

func TestRESTGovernanceAppV23FollowsCurrentRootGeneration(t *testing.T) {
	srv, badger, staleAdminID, _, _ := setupAppV23RESTAccess(t)
	retiredRootID := appV23RESTAgentID("11")
	currentRootID := appV23RESTAgentID("55")
	currentAdminID := appV23RESTAgentID("66")

	staleEnrollment, err := badger.GetAppV23Enrollment(staleAdminID)
	require.NoError(t, err)
	staleRole, err := badger.GetAppV23Role(staleAdminID)
	require.NoError(t, err)
	require.NoError(t, badger.SetAppV23Policy(
		retiredRootID, staleAdminID, store.AppV23RoleAdmin,
		staleEnrollment.Profile, store.AppV23ProfileStandard, 4,
		store.AgentCapabilityReadAllDomains,
		staleRole.Revision, staleEnrollment.Revision, 4,
	))
	require.NoError(t, badger.RotateAppV23RootCredential(1, currentRootID, 5))

	require.NoError(t, badger.RegisterAgent(
		currentAdminID, "current-admin", store.AppV23RoleMember,
		"", "test", "", 6,
	))
	require.NoError(t, badger.ApproveAppV23LocalAgent(store.AppV23LocalEnrollment{
		AgentID: currentAdminID, ApprovedBy: currentRootID, RootGeneration: 2,
		Profile: store.AppV23ProfileStandard, HomeDomain: "current-admin.home",
		Clearance: 4, Capabilities: store.AgentCapabilityReadAllDomains,
		Active: true, UpdatedHeight: 6,
	}, store.AppV23RoleAdmin, 0, 0))

	_, validatorKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	srv.signingKey = validatorKey
	srv.validatorSigningKeyConfigured = true
	srv.governanceOperatorID = retiredRootID

	governanceGate := srv.appV23LocalAdminBoundary(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if srv.requireGovernanceOperator(w, r.Context()) {
				w.WriteHeader(http.StatusNoContent)
			}
		},
	))

	for _, tc := range []struct {
		name       string
		actorID    string
		wantStatus int
	}{
		{
			name:       "retired transport Root is denied",
			actorID:    retiredRootID,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "Admin from retired Root generation is denied",
			actorID:    staleAdminID,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "current Root is accepted",
			actorID:    currentRootID,
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "current local Admin is accepted",
			actorID:    currentAdminID,
			wantStatus: http.StatusNoContent,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://localhost/v1/governance/propose", nil)
			req.RemoteAddr = "127.0.0.1:43123"
			req = req.WithContext(middleware.WithAgentID(req.Context(), tc.actorID))
			rec := httptest.NewRecorder()
			governanceGate.ServeHTTP(rec, req)
			require.Equal(t, tc.wantStatus, rec.Code, rec.Body.String())
		})
	}
}
