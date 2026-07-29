package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/federation"
	"github.com/l33tdawg/sage/internal/store"
)

type appV23FederationActorDriver struct {
	FederationJoinDriver
	hostActor   string
	guestActor  string
	revokeActor string
	hostCalls   int
	guestCalls  int
	revokeCalls int
}

func (d *appV23FederationActorDriver) HostApproveAs(
	actorID, _, _ string,
	_ federation.ScopeWire,
) error {
	d.hostActor = actorID
	d.hostCalls++
	return nil
}

func (d *appV23FederationActorDriver) GuestConfirmAs(
	_ context.Context,
	actorID, _, _ string,
	_ federation.ScopeWire,
) (string, error) {
	d.guestActor = actorID
	d.guestCalls++
	return "guest-confirm", nil
}

func (d *appV23FederationActorDriver) RevokeAgreementNotifyingAs(
	actorID, _ string,
) (*federation.RevokeAgreementResult, error) {
	d.revokeActor = actorID
	d.revokeCalls++
	return &federation.RevokeAgreementResult{TxHash: "revoke"}, nil
}

func TestAppV23DashboardFederationMutationsForwardExactPromotedAdmin(t *testing.T) {
	fixture := newAppV23AccessFixture(t)
	enrollment, err := fixture.badger.GetAppV23Enrollment(fixture.agentID)
	require.NoError(t, err)
	role, err := fixture.badger.GetAppV23Role(fixture.agentID)
	require.NoError(t, err)
	require.NoError(t, fixture.badger.SetAppV23Policy(
		fixture.rootID, fixture.agentID, store.AppV23RoleAdmin,
		enrollment.Profile, store.AppV23ProfileStandard,
		4, store.AgentCapabilityReadAllDomains,
		role.Revision, enrollment.Revision, 2,
	))

	driver := &appV23FederationActorDriver{}
	h := appV23AccessTestHandler(fixture, "", nil)
	h.Federation = driver

	hostReq := appV23AccessRequest(
		t, http.MethodPost,
		"/v1/dashboard/federation/join/host/session/approve",
		"session_id", "session",
		map[string]any{
			"typed_code": "123456", "max_clearance": 2,
			"allowed_domains": []string{"shared"}, "mode": "exchange",
			"direction": "both",
		},
	)
	hostRec := httptest.NewRecorder()
	h.handleFedHostApprove(
		hostRec, appV23AccessAs(hostReq, fixture.agentID),
	)
	require.Equal(t, http.StatusOK, hostRec.Code, hostRec.Body.String())

	guestReq := appV23AccessRequest(
		t, http.MethodPost,
		"/v1/dashboard/federation/join/guest/confirm",
		"", "",
		map[string]any{
			"session_id": "session", "endpoint": "https://127.0.0.1:8444",
			"host_scope": map[string]any{
				"max_clearance": 2, "allowed_domains": []string{"shared"},
				"mode": "exchange", "direction": "both",
			},
		},
	)
	guestRec := httptest.NewRecorder()
	h.handleFedGuestConfirm(
		guestRec, appV23AccessAs(guestReq, fixture.agentID),
	)
	require.Equal(t, http.StatusOK, guestRec.Code, guestRec.Body.String())

	revokeReq := appV23AccessRequest(
		t, http.MethodPost,
		"/v1/dashboard/federation/connections/peer/revoke",
		"chain_id", "peer", nil,
	)
	revokeRec := httptest.NewRecorder()
	h.handleFedRevoke(
		revokeRec, appV23AccessAs(revokeReq, fixture.agentID),
	)
	require.Equal(t, http.StatusOK, revokeRec.Code, revokeRec.Body.String())

	require.Equal(t, fixture.agentID, driver.hostActor)
	require.Equal(t, fixture.agentID, driver.guestActor)
	require.Equal(t, fixture.agentID, driver.revokeActor)
	require.Equal(t, 1, driver.hostCalls)
	require.Equal(t, 1, driver.guestCalls)
	require.Equal(t, 1, driver.revokeCalls)
}
