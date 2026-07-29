package rest

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/l33tdawg/sage/api/rest/middleware"
	"github.com/l33tdawg/sage/internal/federation"
	"github.com/l33tdawg/sage/internal/store"
)

type notifyingRevokeFederation struct {
	*fakeFederation
	called string
	result *federation.RevokeAgreementResult
}

func (f *notifyingRevokeFederation) RevokeAgreementNotifying(chain string) (*federation.RevokeAgreementResult, error) {
	f.called = chain
	return f.result, nil
}

func legacyFederationControlRouter(s *Server, callerID string) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(middleware.WithAgentID(req.Context(), callerID)))
		})
	})
	r.Post("/v1/federation/cross", s.handleCrossFedSet)
	r.Get("/v1/federation/cross", s.handleCrossFedList)
	r.Post("/v1/federation/cross/{chain_id}/revoke", s.handleCrossFedRevoke)
	return r
}

func TestLegacyFederationControlRequiresExactNodeOperator(t *testing.T) {
	_, signingKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{logger: zerolog.Nop(), nodeOperatorID: "node-operator", signingKey: signingKey}

	routes := []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/v1/federation/cross"},
		{method: http.MethodGet, path: "/v1/federation/cross"},
		{method: http.MethodPost, path: "/v1/federation/cross/chain-peer/revoke"},
	}

	for _, route := range routes {
		req := httptest.NewRequest(route.method, route.path, nil)
		rr := httptest.NewRecorder()
		legacyFederationControlRouter(s, "ordinary-signed-agent").ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("nonoperator %s %s status=%d body=%s", route.method, route.path, rr.Code, rr.Body.String())
		}
	}

	// The exact operator crosses the gate. The deliberately unwired fixture then
	// fails at the next dependency/validation guard rather than returning 403.
	for _, route := range routes {
		req := httptest.NewRequest(route.method, route.path, nil)
		rr := httptest.NewRecorder()
		legacyFederationControlRouter(s, "node-operator").ServeHTTP(rr, req)
		if rr.Code == http.StatusForbidden {
			t.Fatalf("operator did not cross federation-control gate for %s %s", route.method, route.path)
		}
	}
}

func TestAppV23FederationControlFollowsCurrentRootNotTransportKey(t *testing.T) {
	transportPub, _, transportKeyErr := ed25519.GenerateKey(nil)
	if transportKeyErr != nil {
		t.Fatal(transportKeyErr)
	}
	currentRootPub, _, currentRootKeyErr := ed25519.GenerateKey(nil)
	if currentRootKeyErr != nil {
		t.Fatal(currentRootKeyErr)
	}
	companionPub, _, companionKeyErr := ed25519.GenerateKey(nil)
	if companionKeyErr != nil {
		t.Fatal(companionKeyErr)
	}
	transportID := fmt.Sprintf("%x", transportPub)
	currentRootID := fmt.Sprintf("%x", currentRootPub)
	companionID := fmt.Sprintf("%x", companionPub)
	badgerStore, storeErr := store.NewBadgerStore(t.TempDir())
	if storeErr != nil {
		t.Fatal(storeErr)
	}
	t.Cleanup(func() { _ = badgerStore.CloseBadger() })
	if bootstrapErr := badgerStore.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: transportID, Scope: "rest-federation-control",
		AgentID: companionID, Profile: store.AppV23ProfileStandard,
		HomeDomain: "companion.home", Clearance: 2, Height: 1,
		BootstrapDigest: strings.Repeat("c9", 32),
	}); bootstrapErr != nil {
		t.Fatal(bootstrapErr)
	}
	if rotateErr := badgerStore.RotateAppV23RootCredential(1, currentRootID, 2); rotateErr != nil {
		t.Fatal(rotateErr)
	}
	s := &Server{
		logger: zerolog.Nop(), nodeOperatorID: transportID,
		signingKey: nil, badgerStore: badgerStore,
	}
	s.SetPostV23ForNextTxAccessor(func() bool { return true })

	retired := httptest.NewRecorder()
	legacyFederationControlRouter(s, transportID).ServeHTTP(
		retired, httptest.NewRequest(http.MethodGet, "/v1/federation/cross", nil),
	)
	if retired.Code != http.StatusForbidden {
		t.Fatalf("retired Root/transport status=%d body=%s", retired.Code, retired.Body.String())
	}

	current := httptest.NewRecorder()
	legacyFederationControlRouter(s, currentRootID).ServeHTTP(
		current, httptest.NewRequest(http.MethodGet, "/v1/federation/cross", nil),
	)
	if current.Code != http.StatusOK {
		t.Fatalf("current Root status=%d body=%s", current.Code, current.Body.String())
	}

	enrollment, enrollmentErr := badgerStore.GetAppV23Enrollment(companionID)
	if enrollmentErr != nil {
		t.Fatal(enrollmentErr)
	}
	role, roleErr := badgerStore.GetAppV23Role(companionID)
	if roleErr != nil {
		t.Fatal(roleErr)
	}
	if policyErr := badgerStore.SetAppV23Policy(
		currentRootID, companionID, store.AppV23RoleAdmin,
		enrollment.Profile, store.AppV23ProfileStandard, 4,
		store.AgentCapabilityReadAllDomains,
		role.Revision, enrollment.Revision, 3,
	); policyErr != nil {
		t.Fatal(policyErr)
	}
	admin := httptest.NewRecorder()
	legacyFederationControlRouter(s, companionID).ServeHTTP(
		admin, httptest.NewRequest(http.MethodGet, "/v1/federation/cross", nil),
	)
	if admin.Code != http.StatusOK {
		t.Fatalf("current-generation Admin status=%d body=%s", admin.Code, admin.Body.String())
	}

	nextRootPub, _, nextRootKeyErr := ed25519.GenerateKey(nil)
	if nextRootKeyErr != nil {
		t.Fatal(nextRootKeyErr)
	}
	if rotateErr := badgerStore.RotateAppV23RootCredential(
		2, fmt.Sprintf("%x", nextRootPub), 4,
	); rotateErr != nil {
		t.Fatal(rotateErr)
	}
	staleAdmin := httptest.NewRecorder()
	legacyFederationControlRouter(s, companionID).ServeHTTP(
		staleAdmin, httptest.NewRequest(http.MethodGet, "/v1/federation/cross", nil),
	)
	if staleAdmin.Code != http.StatusForbidden {
		t.Fatalf("stale-generation Admin status=%d body=%s", staleAdmin.Code, staleAdmin.Body.String())
	}
}

func TestRESTFederationRevokeUsesPeerNotificationWorkflowWhenAvailable(t *testing.T) {
	driver := &notifyingRevokeFederation{
		fakeFederation: &fakeFederation{},
		result: &federation.RevokeAgreementResult{
			TxHash: "tx-notify", PeerNotified: false, NoticeError: "peer was offline",
		},
	}
	s := &Server{logger: zerolog.Nop(), nodeOperatorID: "node-operator", federation: driver}
	req := httptest.NewRequest(http.MethodPost, "/v1/federation/cross/chain-peer/revoke", nil)
	rr := httptest.NewRecorder()
	legacyFederationControlRouter(s, "node-operator").ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if driver.called != "chain-peer" {
		t.Fatalf("notifier called with %q", driver.called)
	}
	var body struct {
		Status              string `json:"status"`
		TxHash              string `json:"tx_hash"`
		PeerNotified        bool   `json:"peer_notified"`
		NotificationWarning string `json:"notification_warning"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "revoked" || body.TxHash != "tx-notify" || body.PeerNotified || body.NotificationWarning != "peer was offline" {
		t.Fatalf("unexpected response: %+v", body)
	}
}
