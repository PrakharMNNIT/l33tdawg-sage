package rest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/api/rest/middleware"
	"github.com/l33tdawg/sage/internal/federation"
	"github.com/l33tdawg/sage/internal/store"
)

type appV23FederationActorService struct {
	*fakeFederation
	hostActor   string
	guestActor  string
	revokeActor string
}

func (s *appV23FederationActorService) HostApproveAs(
	actorID, _, _ string,
	_ federation.ScopeWire,
) error {
	s.hostActor = actorID
	return nil
}

func (s *appV23FederationActorService) GuestConfirmAs(
	_ context.Context,
	actorID, _, _ string,
	_ federation.ScopeWire,
) (string, error) {
	s.guestActor = actorID
	return "guest-confirm", nil
}

func (s *appV23FederationActorService) RevokeAgreementNotifyingAs(
	actorID, _ string,
) (*federation.RevokeAgreementResult, error) {
	s.revokeActor = actorID
	return &federation.RevokeAgreementResult{TxHash: "revoke"}, nil
}

func appV23FederationRESTRequest(
	t *testing.T,
	method, path, paramName, paramValue, actorID string,
	body []byte,
) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Host = "localhost:8080"
	req.RemoteAddr = "127.0.0.1:54321"
	route := chi.NewRouteContext()
	if paramName != "" {
		route.URLParams.Add(paramName, paramValue)
	}
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, route)
	ctx = middleware.WithAgentID(ctx, actorID)
	return req.WithContext(ctx)
}

func TestAppV23RESTFederationMutationsForwardExactPromotedAdmin(t *testing.T) {
	rootPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	adminPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	rootID, adminID := hex.EncodeToString(rootPub), hex.EncodeToString(adminPub)

	badger, err := store.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, badger.CloseBadger()) })
	require.NoError(t, badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: rootID, Scope: "rest-federation-actor",
		AgentID: adminID, Profile: store.AppV23ProfileStandard,
		HomeDomain: "admin.home", Clearance: 1, Height: 1,
		BootstrapDigest: strings.Repeat("d7", 32),
	}))
	enrollment, err := badger.GetAppV23Enrollment(adminID)
	require.NoError(t, err)
	role, err := badger.GetAppV23Role(adminID)
	require.NoError(t, err)
	require.NoError(t, badger.SetAppV23Policy(
		rootID, adminID, store.AppV23RoleAdmin,
		enrollment.Profile, store.AppV23ProfileStandard,
		4, store.AgentCapabilityReadAllDomains,
		role.Revision, enrollment.Revision, 2,
	))

	driver := &appV23FederationActorService{fakeFederation: &fakeFederation{}}
	server := &Server{
		logger: zerolog.Nop(), badgerStore: badger, federation: driver,
	}
	server.SetPostV23ForNextTxAccessor(func() bool { return true })

	hostReq := appV23FederationRESTRequest(
		t, http.MethodPost, "/v1/federation/join/host/session/approve",
		"session_id", "session", adminID,
		[]byte(`{"typed_code":"123456","max_clearance":2,"allowed_domains":["shared"],"mode":"exchange","direction":"both"}`),
	)
	hostRec := httptest.NewRecorder()
	server.handleJoinHostApprove(hostRec, hostReq)
	require.Equal(t, http.StatusOK, hostRec.Code, hostRec.Body.String())

	guestReq := appV23FederationRESTRequest(
		t, http.MethodPost, "/v1/federation/join/guest/confirm",
		"", "", adminID,
		[]byte(`{"session_id":"session","endpoint":"https://127.0.0.1:8444","host_scope":{"max_clearance":2,"allowed_domains":["shared"],"mode":"exchange","direction":"both"}}`),
	)
	guestRec := httptest.NewRecorder()
	server.handleJoinGuestConfirm(guestRec, guestReq)
	require.Equal(t, http.StatusOK, guestRec.Code, guestRec.Body.String())

	revokeReq := appV23FederationRESTRequest(
		t, http.MethodPost, "/v1/federation/cross/peer/revoke",
		"chain_id", "peer", adminID, nil,
	)
	revokeRec := httptest.NewRecorder()
	server.handleCrossFedRevoke(revokeRec, revokeReq)
	require.Equal(t, http.StatusOK, revokeRec.Code, revokeRec.Body.String())

	require.Equal(t, adminID, driver.hostActor)
	require.Equal(t, adminID, driver.guestActor)
	require.Equal(t, adminID, driver.revokeActor)
}
