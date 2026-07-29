package web

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/stretchr/testify/require"
)

func TestDashboardOwnershipResolverStopsAtDynamicSharedIntermediateAfterAppV23(t *testing.T) {
	fixture := newAppV23AccessFixture(t)
	require.NoError(t, fixture.badger.RegisterDomain(
		"team", fixture.agentID, "", 2,
	))
	require.NoError(t, fixture.badger.SetSharedDomain("team.open"))

	active := false
	h := &DashboardHandler{
		BadgerStore:    fixture.badger,
		AppV23ActiveFn: func() bool { return active },
	}

	owner, ownedDomain, err := h.resolveEffectiveOwningAncestor("team.open.notes")
	require.NoError(t, err)
	require.Equal(t, fixture.agentID, owner)
	require.Equal(t, "team", ownedDomain,
		"pre-v23 must preserve the legacy ancestor walk")

	active = true
	owner, ownedDomain, err = h.resolveEffectiveOwningAncestor("team.open.notes")
	require.NoError(t, err)
	require.Empty(t, owner)
	require.Empty(t, ownedDomain,
		"app-v23 must not inherit ownership across the dynamic shared namespace")
}

func TestAppV23PipeContactOwnedDomainsDoNotCrossDynamicSharedIntermediate(t *testing.T) {
	fixture := newAppV23AccessFixture(t)
	require.NoError(t, fixture.badger.RegisterDomain(
		"pipe-team", fixture.agentID, "", 2,
	))
	require.NoError(t, fixture.badger.SetSharedDomain("pipe-team.open"))

	ctx := context.Background()
	sqlStore, err := store.NewSQLiteStore(
		ctx, filepath.Join(t.TempDir(), "pipe-contact.db"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlStore.Close()) })
	require.NoError(t, sqlStore.InsertMemory(ctx, &memory.MemoryRecord{
		MemoryID:        "local-memory",
		SubmittingAgent: fixture.agentID,
		Content:         "shared barrier route test",
		ContentHash:     memory.ComputeContentHash("shared barrier route test"),
		MemoryType:      memory.TypeFact,
		DomainTag:       "pipe-team.open.notes",
		ConfidenceScore: 0.9,
		Status:          memory.StatusCommitted,
		CreatedAt:       time.Now().UTC(),
	}))
	publishAppV23DashboardRecord(
		t, sqlStore, fixture.badger, "local-memory",
		uint8(store.ClearanceInternal), true,
	)
	require.NoError(t, sqlStore.RecordSyncOrigin(ctx, store.SyncOrigin{
		OriginChainID:  "remote-chain",
		OriginMemoryID: "remote-memory",
		LocalMemoryID:  "local-memory",
		DomainTag:      "pipe-team.open.notes",
		Outcome:        "admitted",
	}))

	active := false
	h := &DashboardHandler{
		store:               sqlStore,
		BadgerStore:         fixture.badger,
		NodeOperatorAgentID: fixture.agentID,
		AppV23ActiveFn:      func() bool { return active },
	}

	legacy, err := h.federatedAgentOwnedShareableDomains(ctx, fixture.agentID)
	require.NoError(t, err)
	require.Contains(t, legacy, "pipe-team.open.notes",
		"pre-v23 catalogue behavior is replay/upgrade compatibility")

	active = true
	postV23, err := h.federatedAgentOwnedShareableDomains(ctx, fixture.agentID)
	require.NoError(t, err)
	require.NotContains(t, postV23, "pipe-team.open.notes",
		"a selected local agent must not be advertised as owner across the shared barrier")
}

func TestAppV23FederationGrantCleanupDoesNotBindBroaderOwnerAcrossSharedIntermediate(t *testing.T) {
	fixture := newAppV23AccessFixture(t)
	require.NoError(t, fixture.badger.RegisterDomain(
		"cleanup-team", fixture.agentID, "", 2,
	))
	require.NoError(t, fixture.badger.SetSharedDomain("cleanup-team.open"))

	h := &DashboardHandler{
		BadgerStore:    fixture.badger,
		AppV23ActiveFn: func() bool { return true },
	}
	result := h.revokeFederationManagedGrant(
		"cleanup-team.open.notes", fixture.agentID,
	)
	require.False(t, result.OK)
	require.Equal(t, "owner_missing", result.Code)
	require.Empty(t, result.OwnerID)
	require.Empty(t, result.OwnedDomain)
}
