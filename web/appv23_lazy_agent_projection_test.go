package web

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/store"
)

func TestAppV23SignedOrdinaryAgentRoutesRepairOnlyActiveConsensusProjections(t *testing.T) {
	ctx := context.Background()
	sqlStore, err := store.NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "sage.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlStore.Close()) })
	badgerStore, err := store.NewBadgerStore(filepath.Join(t.TempDir(), "badger"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, badgerStore.CloseBadger()) })

	keys := make(map[string]ed25519.PrivateKey)
	ids := make(map[string]string)
	for _, name := range []string{"root", "member", "manager", "pending", "inactive"} {
		_, key, keyErr := ed25519.GenerateKey(nil)
		require.NoError(t, keyErr)
		keys[name] = key
		ids[name] = agentIDForKey(key)
	}
	require.NoError(t, badgerStore.BootstrapAppV23Genesis(
		store.AppV23GenesisBootstrap{
			RootID: ids["root"], Scope: strings.Repeat("5a", 32),
			AgentID: ids["member"], Profile: store.AppV23ProfileStandard,
			HomeDomain: "member.home", Clearance: 2, Capabilities: 0,
			Height: 1, BootstrapDigest: strings.Repeat("6b", 32),
			ActivateAtGenesis: true, ValidatorID: ids["root"], ValidatorPower: 10,
		},
	))
	approve := func(name, role string, active bool) {
		t.Helper()
		require.NoError(t, badgerStore.RegisterAgentWithCapabilities(
			ids[name], name, store.AppV23RoleMember, "", "test", "", 2, 0,
		))
		require.NoError(t, badgerStore.ApproveAppV23LocalAgent(
			store.AppV23LocalEnrollment{
				AgentID: ids[name], ApprovedBy: ids["root"], RootGeneration: 1,
				Profile: store.AppV23ProfileStandard, HomeDomain: name + ".home",
				Clearance: 2, Capabilities: 0, Active: active, UpdatedHeight: 2,
			},
			role, 0, 0,
		))
	}
	approve("manager", store.AppV23RoleManager, true)
	require.NoError(t, badgerStore.RegisterAgentWithCapabilities(
		ids["pending"], "pending", store.AppV23RoleMember, "", "test", "", 2,
		store.DefaultSelfRegisteredAgentCapabilities,
	))
	approve("inactive", store.AppV23RoleMember, false)
	require.NoError(t, badgerStore.ValidateAppV23State())

	handler := NewDashboardHandler(sqlStore, "test")
	handler.BadgerStore = badgerStore
	handler.AdminSigningKey = keys["root"]
	handler.AppV23ActiveFn = func() bool { return true }

	protected := handler.authMiddleware(
		handler.cerebrumBrowserLocalityGate(http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
		)),
	)
	request := func(name string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(
			http.MethodGet, "/v1/dashboard/task-notifications", nil,
		)
		req.RemoteAddr = "192.0.2.20:54321"
		req.Host = "192.0.2.10:8080"
		signAgentGET(t, req, keys[name])
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		return rec
	}

	for _, name := range []string{"member", "manager"} {
		rec := request(name)
		require.Equal(t, http.StatusNoContent, rec.Code, "%s: %s", name, rec.Body.String())
		projected, projectionErr := sqlStore.GetAgent(ctx, ids[name])
		require.NoError(t, projectionErr)
		require.Equal(t, "active", projected.Status)
		require.Nil(t, projected.RemovedAt)
		wantRole := store.AppV23RoleMember
		if name == "manager" {
			wantRole = store.AppV23RoleManager
		}
		require.Equal(t, wantRole, projected.Role)
	}

	// A stale local row is also repaired from the same immutable consensus
	// identity; removing it locally never revokes or changes on-chain policy.
	require.NoError(t, sqlStore.RemoveAgent(ctx, ids["member"]))
	require.Equal(t, http.StatusNoContent, request("member").Code)
	repaired, err := sqlStore.GetAgent(ctx, ids["member"])
	require.NoError(t, err)
	require.Equal(t, "active", repaired.Status)
	require.Nil(t, repaired.RemovedAt)

	for _, name := range []string{"pending", "inactive", "root"} {
		rec := request(name)
		require.Equal(t, http.StatusForbidden, rec.Code, "%s: %s", name, rec.Body.String())
		_, projectionErr := sqlStore.GetAgent(ctx, ids[name])
		require.Error(t, projectionErr, "%s must not be projected", name)
	}

	// Lazy ordinary-agent repair must not turn the signed agent into a local
	// CEREBRUM operator or expose aggregate node statistics. Legacy MCP receives
	// only the caller-scoped non-exact compatibility lower bound.
	statsReq := httptest.NewRequest(http.MethodGet, "/v1/dashboard/stats", nil)
	statsReq.RemoteAddr = "192.0.2.20:54321"
	statsReq.Host = "192.0.2.10:8080"
	signAgentGET(t, statsReq, keys["member"])
	statsOut := httptest.NewRecorder()
	testRouter(handler).ServeHTTP(statsOut, statsReq)
	require.Equal(t, http.StatusOK, statsOut.Code, statsOut.Body.String())
	var stats map[string]any
	require.NoError(t, json.Unmarshal(statsOut.Body.Bytes(), &stats))
	require.Equal(t, float64(1), stats["total_memories"])
	require.Equal(t, false, stats["total_exact"])
	require.Equal(t, true, stats["has_more"])
	require.Equal(t, "caller", stats["scope"])
	for _, forbidden := range []string{
		"projection", "db_size_bytes", "by_agent", "by_domain", "by_status",
	} {
		require.NotContains(t, stats, forbidden)
	}
}
