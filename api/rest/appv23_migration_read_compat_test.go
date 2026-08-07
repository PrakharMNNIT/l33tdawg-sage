package rest

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/store"
)

func TestAppV23LegacyReadCompatibilityRestrictsLocalRESTButNotPairwiseFederation(t *testing.T) {
	srv, _, badger, _ := newRBACTestServer(t)
	srv.SetPostV22ForNextTxAccessor(func() bool { return true })
	srv.SetPostV23ForNextTxAccessor(func() bool { return true })

	root := fmt.Sprintf("%064x", 9001)
	reader := fmt.Sprintf("%064x", 9002)
	visible := fmt.Sprintf("%064x", 9003)
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		root, "root", store.AppV23RoleAdmin, "", "", "", 1, 0,
	))
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		reader, "reader", store.AppV23RoleMember, "", "", "", 2, 0,
	))
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		visible, "visible", store.AppV23RoleMember, "", "", "", 3, 0,
	))
	require.NoError(t, badger.SetAgentPermissionWithCapabilities(
		reader, 1,
		`[{"domain":"legacy-allowed","read":true}]`,
		`["`+visible+`"]`, "", "", 0,
	))
	require.NoError(t, badger.RegisterDomain("legacy-allowed", root, "", 4))
	require.NoError(t, badger.RegisterDomain("legacy-denied", root, "", 5))
	require.NoError(t, badger.EnsureAppV23Root("rest-legacy-read", 100))
	enrollment, err := badger.GetAppV23Enrollment(reader)
	require.NoError(t, err)
	require.NotNil(t, enrollment)
	require.NotEmpty(t, enrollment.HomeDomain)

	require.Error(t, checkAppV23DomainAccess(
		badger, reader, "legacy-allowed", "read",
	), "the strict local app-v23 resolver must not receive migration widening")
	require.NoError(t, srv.checkDomainAccess(
		context.Background(), reader, "legacy-allowed", "read",
	))
	allowed, err := srv.hasMemoryReadAccess(
		"legacy-allowed", reader, 1, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.True(t, allowed)

	require.NoError(t, badger.SetAccessGrant(
		"legacy-denied", reader, 1, 0, root,
	))
	require.Error(t, srv.checkDomainAccess(
		context.Background(), reader, "legacy-denied", "read",
	), "an immutable explicit legacy allowlist remains a restriction")
	allowed, err = srv.hasMemoryReadAccess(
		"legacy-denied", reader, 1, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.False(t, allowed)

	require.NoError(t, srv.checkDomainAccess(
		context.Background(), reader, enrollment.HomeDomain, "read",
	), "an allocated app-v23 home domain must never become write-only merely because it was absent from the frozen app-v22 allowlist")
	allowed, err = srv.hasMemoryReadAccess(
		enrollment.HomeDomain, reader, 1, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.True(t, allowed)
	homeChild := enrollment.HomeDomain + ".child"
	require.NoError(t, srv.checkDomainAccess(
		context.Background(), reader, homeChild, "read",
	), "write authority inherited from the required home must imply matching read authority")
	allowed, err = srv.hasMemoryReadAccess(
		homeChild, reader, 1, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, err = srv.hasMemoryReadAccess(
		homeChild, reader, 2, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.False(t, allowed, "the home exception must remain clearance bounded")

	require.NoError(t, badger.SetSharedDomain(homeChild))
	require.Error(t, srv.checkDomainAccess(
		context.Background(), reader, homeChild, "read",
	), "a dynamic shared marker must stop inherited home ownership")
	allowed, err = srv.hasMemoryReadAccess(
		homeChild, reader, 1, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.False(t, allowed)

	federated, clearance := srv.federationCallerCanRead(
		context.Background(), reader, "legacy-allowed",
	)
	require.True(t, federated,
		"an active ordinary agent joins each federation connection's Read group by default")
	require.Equal(t, 1, clearance)
	federated, clearance = srv.federationCallerCanRead(
		context.Background(), reader, "legacy-denied",
	)
	require.True(t, federated,
		"a frozen local REST allowlist must not become a same-named remote-domain deny")
	require.Equal(t, 1, clearance)
	require.Equal(t, []string{"legacy-denied"}, srv.federationVisibleRemoteScopes(
		context.Background(), reader, "legacy-denied",
	))

	agents, seeAll := srv.resolveVisibleAgents(reader)
	require.False(t, seeAll)
	require.ElementsMatch(t, []string{reader, visible}, agents)
	require.True(t, srv.appV23LegacyVisibilityRestricted(reader))
}

func TestAppV23LegacyOrgMembershipClearanceSurvivesLocalRESTOnly(t *testing.T) {
	srv, _, badger, _ := newRBACTestServer(t)
	srv.SetPostV22ForNextTxAccessor(func() bool { return true })
	srv.SetPostV23ForNextTxAccessor(func() bool { return true })

	root := fmt.Sprintf("%064x", 9101)
	reader := fmt.Sprintf("%064x", 9102)
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		root, "root", store.AppV23RoleAdmin, "", "", "", 1, 0,
	))
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		reader, "reader", store.AppV23RoleMember, "", "", "", 2, 0,
	))
	require.NoError(t, badger.RegisterDomain("org-domain", root, "", 3))
	require.NoError(t, badger.RegisterOrg("org-local", "Local", "", root, 4))
	require.NoError(t, badger.AddOrgMember("org-local", root, 3, "member", 5))
	require.NoError(t, badger.AddOrgMember("org-local", reader, 3, "member", 6))
	require.NoError(t, badger.EnsureAppV23Root("rest-legacy-org", 100))

	allowed, err := srv.hasMemoryReadAccess(
		"org-domain", reader, 3, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.True(t, allowed,
		"legacy membership clearance, not the lower global slot, is authoritative")
	allowed, err = srv.hasMemoryReadAccess(
		"org-domain", reader, 4, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.False(t, allowed)

	federated, federatedClearance := srv.federationCallerCanRead(
		context.Background(), reader, "org-domain",
	)
	require.True(t, federated,
		"local organization membership is unnecessary for the connection's default pairwise Read")
	require.Equal(t, 1, federatedClearance,
		"local organization clearance must not silently raise the caller's federation ceiling")
}

func TestAppV23MigratedLocalRESTPolicyIsIndependentFromExplicitFederatedReaderOverlay(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "reader-overlay.db")
	ss, err := store.NewSQLiteStore(ctx, path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })

	reader := fmt.Sprintf("%064x", 9152)
	binding := store.FederatedReaderBinding{
		RemoteChainID: "chain-peer",
		PeerAgentID:   fmt.Sprintf("%064x", 9153),
		PolicyEpoch:   "epoch-rest-migration",
		RemoteCAPin:   strings.Repeat("ab", 32),
	}
	require.NoError(t, ss.PrepareSyncControl(ctx, store.SyncControl{
		RemoteChainID: binding.RemoteChainID,
		Role:          "host", ControllerChainID: "chain-local",
		ControllerAgentID: reader, PeerAgentID: binding.PeerAgentID,
		PolicyEpoch: binding.PolicyEpoch, RemoteCAPin: binding.RemoteCAPin,
		PolicyVersion: 3,
	}))
	require.NoError(t, ss.ActivateSyncControl(ctx, binding.RemoteChainID, binding.PolicyEpoch))

	allowed, err := ss.FederatedReaderAllows(ctx, binding, reader, "legacy-denied")
	require.NoError(t, err)
	require.True(t, allowed,
		"absence of a peer-bound reader restriction is the explicit default allow")

	restriction, err := ss.PutBoundFederatedReaderRestrictionCAS(ctx,
		store.FederatedReaderRestriction{
			RemoteChainID: binding.RemoteChainID, LocalAgentID: reader,
			PeerAgentID: binding.PeerAgentID, PolicyEpoch: binding.PolicyEpoch,
			RemoteCAPin:   binding.RemoteCAPin,
			DeniedDomains: []string{"legacy-denied"}, Revision: 1,
			State: store.FederatedReaderRestrictionStateActive,
		}, 0)
	require.NoError(t, err)
	require.Equal(t, int64(1), restriction.Revision)

	allowed, err = ss.FederatedReaderAllows(ctx, binding, reader, "legacy-allowed")
	require.NoError(t, err)
	require.True(t, allowed, "a subtree deny must not recreate the old local allowlist")
	allowed, err = ss.FederatedReaderAllows(ctx, binding, reader, "legacy-denied.child")
	require.NoError(t, err)
	require.False(t, allowed, "the explicit federation deny must cover its remote subtree")

	denyAll := *restriction
	denyAll.Revision = 2
	denyAll.DenyAll = true
	denyAll.DeniedDomains = nil
	denyAllStored, err := ss.PutBoundFederatedReaderRestrictionCAS(ctx, denyAll, 1)
	require.NoError(t, err)
	require.NotNil(t, denyAllStored)
	allowed, err = ss.FederatedReaderAllows(ctx, binding, reader, "legacy-allowed")
	require.NoError(t, err)
	require.False(t, allowed, "the explicit per-peer deny-all overlay must fail closed")

	revoked := *denyAllStored
	revoked.Revision = 3
	revoked.State = store.FederatedReaderRestrictionStateRevoked
	revoked.DenyAll = false
	revokedStored, err := ss.PutBoundFederatedReaderRestrictionCAS(ctx, revoked, 2)
	require.NoError(t, err)
	require.NotNil(t, revokedStored)
	allowed, err = ss.FederatedReaderAllows(ctx, binding, reader, "legacy-allowed")
	require.NoError(t, err)
	require.True(t, allowed, "revoking the explicit restriction restores pairwise default Read")
}

func TestAppV25HistoricalMultiWriterContinuityIsNeverWriteOnly(t *testing.T) {
	srv, _, badger, _ := newRBACTestServer(t)
	srv.SetPostV22ForNextTxAccessor(func() bool { return true })
	srv.SetPostV23ForNextTxAccessor(func() bool { return true })

	root := fmt.Sprintf("%064x", 9201)
	writerA := fmt.Sprintf("%064x", 9202)
	writerB := fmt.Sprintf("%064x", 9203)
	outsider := fmt.Sprintf("%064x", 9204)
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		root, "root", store.AppV23RoleAdmin, "", "", "", 4, 0,
	))
	for _, writer := range []string{writerA, writerB} {
		require.NoError(t, badger.RegisterAgentWithCapabilities(
			writer, writer, store.AppV23RoleMember, "", "", "", 2,
			store.DefaultSelfRegisteredAgentCapabilities,
		))
		require.NoError(t, badger.SetAgentPermissionWithCapabilities(
			writer, 2,
			`[{"domain":"different-legacy-domain","read":true}]`,
			"", "", "", store.DefaultSelfRegisteredAgentCapabilities,
		))
	}
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		outsider, "outsider", store.AppV23RoleMember, "", "", "", 2, 0,
	))
	require.NoError(t, badger.RegisterDomain("historical-shared", root, "", 4))
	require.NoError(t, badger.EnsureAppV23Root("rest-v25-multi-writer", 100))

	writers := []string{writerA, writerB}
	sort.Strings(writers)
	plan := sha256.Sum256([]byte("rest-v25-multi-writer-plan"))
	require.NoError(t, badger.ApplyAppV25DomainContinuity(
		"historical-shared", writers, plan[:], 1, 120,
	))
	require.NoError(t, badger.ValidateAppV23State())

	shared, err := badger.IsAppV23SharedDomain("historical-shared")
	require.NoError(t, err)
	require.True(t, shared)
	group, err := badger.GetAppV23AccessGroup(
		store.AppV25DomainContinuityGroupID(writers),
	)
	require.NoError(t, err)
	require.Equal(t, writers, group.Members)

	for _, writer := range writers {
		require.NoError(t, srv.checkDomainAccess(
			context.Background(), writer, "historical-shared", "write",
		), "historical writer %s must retain exact write authority", writer)
		require.NoError(t, srv.checkDomainAccess(
			context.Background(), writer, "historical-shared", "read",
		), "restored write authority must imply matching read authority for %s", writer)
		allowed, readErr := srv.hasMemoryReadAccess(
			"historical-shared", writer, 2, time.Unix(1000, 0),
		)
		require.NoError(t, readErr)
		require.True(t, allowed,
			"list/tag/query disclosure must admit the exact restored domain for %s", writer)

		allowed, readErr = srv.hasMemoryReadAccess(
			"historical-shared", writer, 3, time.Unix(1000, 0),
		)
		require.NoError(t, readErr)
		require.False(t, allowed,
			"historical continuity must remain bounded by current clearance")

		require.Error(t, srv.checkDomainAccess(
			context.Background(), writer, "unrelated-domain", "read",
		), "exact restoration must not widen the frozen legacy read envelope")
	}
	require.Error(t, srv.checkDomainAccess(
		context.Background(), outsider, "historical-shared", "write",
	), "an unrelated mask-0 migration must not gain write when continuity promotes a formerly private multiwriter domain")
	require.NoError(t, srv.checkDomainAccess(
		context.Background(), outsider, "general", "write",
	), "ordinary compile-time shared domains retain legacy mask-0 write behavior")
}

func TestAppV25LegacyStaticSharedContinuitySignedQueryIsNeverWriteOnly(t *testing.T) {
	srv, memStore, badger, _ := newRBACTestServer(t)
	srv.SetPostV22ForNextTxAccessor(func() bool { return true })
	srv.SetPostV23ForNextTxAccessor(func() bool { return true })

	embedding := make([]float32, 8)
	for i := range embedding {
		embedding[i] = 0.1
	}
	const sharedDomain = "sage-federation-rbac"
	body, err := json.Marshal(QueryMemoryRequest{
		Embedding: embedding, DomainTag: sharedDomain, TopK: 10,
	})
	require.NoError(t, err)
	request, writerID := signedRequest(
		t, http.MethodPost, "/v1/memory/query", body,
	)

	rootID := fmt.Sprintf("%064x", 9301)
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		rootID, "root", store.AppV23RoleAdmin, "", "", "", 1, 0,
	))
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		writerID, "writer", store.AppV23RoleMember, "", "", "", 2,
		store.DefaultSelfRegisteredAgentCapabilities,
	))
	require.NoError(t, badger.SetAgentPermissionWithCapabilities(
		writerID, 2,
		`[{"domain":"different-legacy-domain","read":true}]`,
		"", "", "", store.DefaultSelfRegisteredAgentCapabilities,
	))
	require.NoError(t, badger.EnsureAppV23Root("signed-static-shared", 100))

	// Reproduce the production sequence. The legacy singleton recovery created
	// a static shared continuity record without an owner row. A later private
	// continuity domain moved the writer's home and made the earlier exact grant
	// revision stale. The recovered group remains authoritative for exact Read
	// and Write until the governed v2 repair fills the owner row.
	sharedPlan := sha256.Sum256([]byte("signed-static-shared-v1"))
	require.NoError(t, badger.ApplyAppV25DomainContinuity(
		sharedDomain, []string{writerID}, sharedPlan[:], 1, 110,
	))
	homePlan := sha256.Sum256([]byte("signed-later-home-v1"))
	require.NoError(t, badger.ApplyAppV25DomainContinuity(
		"v11.9-state-sync", []string{writerID}, homePlan[:], 1, 111,
	))
	_, err = badger.GetDomainOwner(sharedDomain)
	require.Error(t, err, "fixture must retain the legacy missing owner row")
	stale, err := badger.AppV25AllowsHistoricalDomainWrite(writerID, sharedDomain)
	require.NoError(t, err)
	require.False(t, stale, "fixture must retain the stale exact grant revision")

	seedMemory(t, memStore, "signed-static-shared-memory", writerID, sharedDomain,
		"historical recovered memory")
	response := httptest.NewRecorder()
	srv.Router().ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var result QueryMemoryResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	require.Equal(t, 1, result.TotalCount,
		"a signed current writer must read the exact shared domain while v2 owner repair is pending")
}
