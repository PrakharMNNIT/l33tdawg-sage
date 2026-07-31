package web

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/governance"
	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

type blockingAppV25LegacyProjectionSource struct {
	*store.SQLiteStore
	scanStarted chan struct{}
	releaseScan chan struct{}
}

type countingAppV25LegacyProjectionSource struct {
	*store.SQLiteStore
	listCalls int
}

func (s *countingAppV25LegacyProjectionSource) ListLegacyMemoryProjectionPage(
	ctx context.Context,
	afterCreatedAt string,
	afterMemoryID string,
	limit int,
) ([]store.LegacyMemoryProjectionRecord, error) {
	s.listCalls++
	return s.SQLiteStore.ListLegacyMemoryProjectionPage(
		ctx, afterCreatedAt, afterMemoryID, limit,
	)
}

func (s *blockingAppV25LegacyProjectionSource) ReadLegacyMemoryProjectionSnapshot(
	ctx context.Context,
	fn func(store.LegacyMemoryProjectionSnapshot) error,
) error {
	return s.SQLiteStore.ReadLegacyMemoryProjectionSnapshot(
		ctx,
		func(snapshot store.LegacyMemoryProjectionSnapshot) error {
			if _, err := snapshot.MemoryProjectionRevision(ctx); err != nil {
				return err
			}
			close(s.scanStarted)
			<-s.releaseScan
			return fn(snapshot)
		},
	)
}

func TestAppV25LegacyAdoptionPlanAdvancesPastBadRowsAndIsRestartIdempotent(t *testing.T) {
	ctx := context.Background()
	fixture := newAppV23AccessFixture(t)
	path := filepath.Join(t.TempDir(), "memories.db")
	sqlite, err := store.NewSQLiteStore(ctx, path)
	require.NoError(t, err)

	goodContent := "verifiable historical memory"
	goodHash := sha256.Sum256([]byte(goodContent))
	require.NoError(t, sqlite.InsertMemory(ctx, &memory.MemoryRecord{
		MemoryID:        "legacy-good",
		SubmittingAgent: fixture.agentID,
		Content:         goodContent,
		ContentHash:     goodHash[:],
		MemoryType:      memory.TypeFact,
		DomainTag:       "historical/domain",
		Status:          memory.StatusCommitted,
	}))
	require.NoError(t, sqlite.InsertMemory(ctx, &memory.MemoryRecord{
		MemoryID:        "legacy-bad",
		SubmittingAgent: fixture.agentID,
		Content:         "content no longer matching its commitment",
		ContentHash:     make([]byte, sha256.Size),
		MemoryType:      memory.TypeFact,
		DomainTag:       "historical/domain",
		Status:          memory.StatusCommitted,
	}))

	handler := NewDashboardHandler(sqlite, "test")
	handler.BadgerStore = fixture.badger
	plan, err := handler.buildAppV25LegacyAdoptionPlan(ctx, sqlite)
	require.NoError(t, err)
	require.Len(t, plan.Entries, 1)
	require.Equal(t, "legacy-good", plan.Entries[0].MemoryID)
	require.Equal(t, 2, plan.Discovered)
	require.Zero(t, plan.Converted)
	require.Equal(t, 1, plan.Unresolved)
	require.Equal(t, []store.LegacyMemoryRecoveryItem{{
		MemoryID: "legacy-bad",
		Reason:   "content_hash_mismatch",
	}}, plan.Recovery)
	firstDigest := append([]byte(nil), plan.PlanDigest...)
	root, err := fixture.badger.GetAppV23Root()
	require.NoError(t, err)
	payload, err := tx.EncodeMemoryLegacyAdoptionPayload(tx.MemoryLegacyAdoptionPayload{
		Version:          1,
		RootCredentialID: root.CredentialID,
		RootGeneration:   root.Generation,
		PlanDigest:       plan.PlanDigest,
		Entries:          plan.Entries,
	})
	require.NoError(t, err)
	targetID, err := tx.MemoryLegacyAdoptionTargetID(payload)
	require.NoError(t, err)
	require.NoError(t, handler.attestAppV25LegacyAdoptionProposal(
		ctx,
		sqlite,
		&governance.ProposalState{
			ProposalID: "matching-local-attestation",
			Operation:  governance.OpMemoryLegacyAdopt,
			TargetID:   targetID,
			Payload:    payload,
		},
	))
	divergent, err := tx.DecodeMemoryLegacyAdoptionPayload(payload)
	require.NoError(t, err)
	divergent.Entries[0].ContentHash[0] ^= 0xff
	divergentPayload, err := tx.EncodeMemoryLegacyAdoptionPayload(*divergent)
	require.NoError(t, err)
	divergentTargetID, err := tx.MemoryLegacyAdoptionTargetID(divergentPayload)
	require.NoError(t, err)
	require.ErrorContains(t, handler.attestAppV25LegacyAdoptionProposal(
		ctx,
		sqlite,
		&governance.ProposalState{
			ProposalID: "divergent-remote-attestation",
			Operation:  governance.OpMemoryLegacyAdopt,
			TargetID:   divergentTargetID,
			Payload:    divergentPayload,
		},
	), "digest does not bind")

	adopted, err := fixture.badger.AdoptLegacyMemories(
		plan.PlanDigest,
		[]store.MemoryLegacyAdoptionEntry{{
			MemoryID:        plan.Entries[0].MemoryID,
			Status:          plan.Entries[0].Status,
			ContentHash:     plan.Entries[0].ContentHash,
			Domain:          plan.Entries[0].Domain,
			Author:          plan.Entries[0].Author,
			AuthorPrincipal: plan.Entries[0].AuthorPrincipal,
			Classification:  plan.Entries[0].Classification,
		}},
	)
	require.NoError(t, err)
	require.Equal(t, 1, adopted.Adopted)
	require.NoError(t, sqlite.Close())

	reopened, err := store.NewSQLiteStore(ctx, path)
	require.NoError(t, err)
	defer func() { require.NoError(t, reopened.Close()) }()
	restarted := NewDashboardHandler(reopened, "test")
	restarted.BadgerStore = fixture.badger
	afterRestart, err := restarted.buildAppV25LegacyAdoptionPlan(ctx, reopened)
	require.NoError(t, err)
	require.Empty(t, afterRestart.Entries,
		"the receipt makes an already-adopted row a restart-safe no-op")
	require.Equal(t, 2, afterRestart.Discovered)
	require.Equal(t, 1, afterRestart.Converted)
	require.Equal(t, 1, afterRestart.Unresolved,
		"the bad row remains isolated without blocking later progress")
	require.NotEqual(t, firstDigest, afterRestart.PlanDigest,
		"progress advances the pending inventory digest")

	recovery, err := reopened.ListLegacyMemoryRecoveryQueue(ctx, false)
	require.NoError(t, err)
	require.Equal(t, []store.LegacyMemoryRecoveryRecord{{
		MemoryID:           "legacy-bad",
		Reason:             "content_hash_mismatch",
		ProjectionRevision: afterRestart.SQLRevision,
	}}, recovery)
}

func TestAppV25LegacyAdoptionStableScanDegradesWhenValidatorSignerUnavailable(t *testing.T) {
	ctx := context.Background()
	fixture := newAppV23AccessFixture(t)
	sqlite, err := store.NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "memories.db"))
	require.NoError(t, err)
	defer func() { require.NoError(t, sqlite.Close()) }()

	content := "historical memory awaiting governed adoption"
	contentHash := sha256.Sum256([]byte(content))
	require.NoError(t, sqlite.InsertMemory(ctx, &memory.MemoryRecord{
		MemoryID:        "legacy-awaiting-signer",
		SubmittingAgent: fixture.agentID,
		Content:         content,
		ContentHash:     contentHash[:],
		MemoryType:      memory.TypeFact,
		DomainTag:       "historical/domain",
		Status:          memory.StatusCommitted,
	}))

	handler := NewDashboardHandler(sqlite, "test")
	handler.BadgerStore = fixture.badger
	handler.ConfigureAppV25Maintenance(true)
	more, err := handler.runAppV25LegacyAdoptionPassWithState(
		ctx, zerolog.Nop(), &appV25LegacyAdoptionRun{},
	)
	require.ErrorContains(t, err, "live validator signing path is unavailable")
	require.False(t, more)

	status := handler.AppV25MaintenanceStatus()
	require.True(t, status.Required)
	require.True(t, status.Checked)
	require.True(t, status.OK)
	require.Equal(t, "migrating", status.State)
	require.False(t, status.Recovery)
}

func TestAppV25LegacyAdoptionOwnReceiptAdvancesCachedPlanWithoutFullRescan(
	t *testing.T,
) {
	ctx := context.Background()
	fixture := newAppV23AccessFixture(t)
	sqlite, err := store.NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "memories.db"))
	require.NoError(t, err)
	defer func() { require.NoError(t, sqlite.Close()) }()

	for _, memoryID := range []string{"legacy-batch-a", "legacy-batch-b"} {
		content := "historical content for " + memoryID
		contentHash := sha256.Sum256([]byte(content))
		require.NoError(t, sqlite.InsertMemory(ctx, &memory.MemoryRecord{
			MemoryID:        memoryID,
			SubmittingAgent: fixture.agentID,
			Content:         content,
			ContentHash:     contentHash[:],
			MemoryType:      memory.TypeFact,
			DomainTag:       "historical/domain",
			Status:          memory.StatusCommitted,
		}))
	}

	handler := NewDashboardHandler(sqlite, "test")
	handler.BadgerStore = fixture.badger
	plan, err := handler.buildAppV25LegacyAdoptionPlan(ctx, sqlite)
	require.NoError(t, err)
	require.Len(t, plan.Entries, 2)
	beforeRevision := plan.CanonicalRevision

	first := plan.Entries[0]
	_, err = fixture.badger.AdoptLegacyMemories(
		appV25LegacyAdoptionPlanDigest([]tx.MemoryLegacyAdoptionEntry{first}),
		[]store.MemoryLegacyAdoptionEntry{{
			MemoryID:        first.MemoryID,
			Status:          first.Status,
			ContentHash:     first.ContentHash,
			Domain:          first.Domain,
			Author:          first.Author,
			AuthorPrincipal: first.AuthorPrincipal,
			Classification:  first.Classification,
		}},
	)
	require.NoError(t, err)
	require.NotEqual(t, beforeRevision,
		fixture.badger.CanonicalMemoryProjectionRevision())

	source := &countingAppV25LegacyProjectionSource{SQLiteStore: sqlite}
	stale, err := handler.refreshAppV25LegacyAdoptionPlan(ctx, source, plan)
	require.NoError(t, err)
	require.False(t, stale,
		"the worker's own canonical receipt must not invalidate the full plan")
	require.Zero(t, source.listCalls,
		"receipt reconciliation must not rescan the SQL inventory")
	require.Len(t, plan.Entries, 1)
	require.Equal(t, "legacy-batch-b", plan.Entries[0].MemoryID)
	require.Equal(t, 1, plan.Converted)
	require.Equal(t,
		fixture.badger.CanonicalMemoryProjectionRevision(),
		plan.CanonicalRevision,
	)
}

func TestAppV25LegacyAdoptionReceiptReconciliationIsBatchBounded(t *testing.T) {
	ctx := context.Background()
	fixture := newAppV23AccessFixture(t)
	handler := NewDashboardHandler(nil, "test")
	handler.BadgerStore = fixture.badger

	entries := make([]tx.MemoryLegacyAdoptionEntry, appV25LegacyAdoptionBatchSize+1)
	for i := range entries {
		contentHash := sha256.Sum256([]byte(
			fmt.Sprintf("bounded legacy entry %d", i),
		))
		entries[i] = tx.MemoryLegacyAdoptionEntry{
			MemoryID:        fmt.Sprintf("legacy-bounded-%03d", i),
			Status:          string(memory.StatusCommitted),
			ContentHash:     contentHash[:],
			Domain:          "historical/domain",
			Author:          fixture.agentID,
			AuthorPrincipal: fixture.agentID,
			Classification:  1,
		}
	}
	tail := entries[len(entries)-1]
	_, err := fixture.badger.AdoptLegacyMemories(
		appV25LegacyAdoptionPlanDigest([]tx.MemoryLegacyAdoptionEntry{tail}),
		[]store.MemoryLegacyAdoptionEntry{{
			MemoryID:        tail.MemoryID,
			Status:          tail.Status,
			ContentHash:     tail.ContentHash,
			Domain:          tail.Domain,
			Author:          tail.Author,
			AuthorPrincipal: tail.AuthorPrincipal,
			Classification:  tail.Classification,
		}},
	)
	require.NoError(t, err)

	plan := &appV25LegacyAdoptionPlan{Entries: append(
		[]tx.MemoryLegacyAdoptionEntry(nil), entries...,
	)}
	require.NoError(t, handler.reconcileAppV25LegacyAdoptionQueue(
		ctx, nil, plan,
	))
	require.Len(t, plan.Entries, len(entries),
		"a receipt outside the bounded front must not trigger a full queue scan")
	require.Zero(t, plan.Converted)

	plan.Entries = plan.Entries[appV25LegacyAdoptionBatchSize:]
	require.NoError(t, handler.reconcileAppV25LegacyAdoptionQueue(
		ctx, nil, plan,
	))
	require.Empty(t, plan.Entries)
	require.Equal(t, 1, plan.Converted,
		"the exact receipt is consumed once it reaches the bounded front")
}

func TestAppV25LegacyAdoptionNormalWriteDoesNotInvalidateLargeCachedPlan(t *testing.T) {
	ctx := context.Background()
	fixture := newAppV23AccessFixture(t)
	sqlite, err := store.NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "memories.db"))
	require.NoError(t, err)
	defer func() { require.NoError(t, sqlite.Close()) }()

	for _, memoryID := range []string{"legacy-retained-a", "legacy-retained-b"} {
		content := "historical retained content " + memoryID
		digest := sha256.Sum256([]byte(content))
		require.NoError(t, sqlite.InsertMemory(ctx, &memory.MemoryRecord{
			MemoryID: memoryID, SubmittingAgent: fixture.agentID,
			Content: content, ContentHash: digest[:], MemoryType: memory.TypeFact,
			DomainTag: "historical/domain", Status: memory.StatusCommitted,
		}))
	}
	handler := NewDashboardHandler(sqlite, "test")
	handler.BadgerStore = fixture.badger
	plan, err := handler.buildAppV25LegacyAdoptionPlan(ctx, sqlite)
	require.NoError(t, err)
	require.Len(t, plan.Entries, 2)
	oldRevision := plan.SQLRevision

	// Model an ordinary post-v25 write: SQL and canonical revisions both move,
	// but the new record is already an exact complete envelope and is not a
	// legacy candidate.
	content := "ordinary current memory"
	digest := sha256.Sum256([]byte(content))
	const currentID = "current-exact-write"
	require.NoError(t, sqlite.InsertMemory(ctx, &memory.MemoryRecord{
		MemoryID: currentID, SubmittingAgent: fixture.agentID,
		Content: content, ContentHash: digest[:], MemoryType: memory.TypeFact,
		DomainTag: "current/domain", Status: memory.StatusCommitted,
	}))
	require.NoError(t, fixture.badger.SetMemoryHash(currentID, digest[:], "committed"))
	require.NoError(t, fixture.badger.SetMemoryDomain(currentID, "current/domain"))
	require.NoError(t, fixture.badger.SetMemoryAuthor(currentID, fixture.agentID))
	require.NoError(t, fixture.badger.SetMemoryAuthorPrincipal(currentID, fixture.agentID))
	require.NoError(t, fixture.badger.SetMemoryClassification(currentID, 1))
	require.NoError(t, fixture.badger.SetMemorySubmissionHeight(currentID, 100))

	source := &countingAppV25LegacyProjectionSource{SQLiteStore: sqlite}
	stale, err := handler.refreshAppV25LegacyAdoptionPlan(ctx, source, plan)
	require.NoError(t, err)
	require.False(t, stale)
	require.Zero(t, source.listCalls, "normal work must not restart the full historical scan")
	require.Len(t, plan.Entries, 2)
	require.Greater(t, plan.SQLRevision, oldRevision)
}

func TestAppV25LegacyAdoptionRejectedBatchBisectsToOneBadRow(t *testing.T) {
	ctx := context.Background()
	fixture := newAppV23AccessFixture(t)
	handler := NewDashboardHandler(nil, "test")
	handler.BadgerStore = fixture.badger
	root, err := fixture.badger.GetAppV23Root()
	require.NoError(t, err)

	entries := make([]tx.MemoryLegacyAdoptionEntry, 4)
	for i := range entries {
		digest := sha256.Sum256([]byte(fmt.Sprintf("rejected-prefix-%d", i)))
		entries[i] = tx.MemoryLegacyAdoptionEntry{
			MemoryID: fmt.Sprintf("rejected-prefix-%d", i), Status: "committed",
			ContentHash: digest[:], Domain: "historical/domain",
			Author: fixture.agentID, AuthorPrincipal: fixture.agentID,
			Classification: 1,
		}
	}
	markRejected := func(candidate []tx.MemoryLegacyAdoptionEntry) {
		t.Helper()
		_, payload, encodeErr := appV25LegacyAdoptionBatch(root, candidate)
		require.NoError(t, encodeErr)
		targetID, targetErr := tx.MemoryLegacyAdoptionTargetID(payload)
		require.NoError(t, targetErr)
		require.NoError(t, fixture.badger.SetState(
			governance.MaintenanceRejectionReceiptKey(
				governance.OpMemoryLegacyAdopt, targetID,
			), []byte{1},
		))
	}

	markRejected(entries)
	batch, _, _, rejected, err := handler.appV25LegacyAdoptionUnrejectedPrefix(
		ctx, root, entries,
	)
	require.NoError(t, err)
	require.False(t, rejected)
	require.Len(t, batch, 2, "a rejected four-row target must preserve its siblings")

	markRejected(entries[:2])
	markRejected(entries[:1])
	batch, _, _, rejected, err = handler.appV25LegacyAdoptionUnrejectedPrefix(
		ctx, root, entries,
	)
	require.NoError(t, err)
	require.True(t, rejected)
	require.Len(t, batch, 1)
	require.Equal(t, entries[0].MemoryID, batch[0].MemoryID)
}

func TestAppV25LegacyAdoptionPreservesChallengedAndMalformedAuthorRowsForRecovery(t *testing.T) {
	ctx := context.Background()
	fixture := newAppV23AccessFixture(t)
	sqlite, err := store.NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "memories.db"))
	require.NoError(t, err)
	defer func() { require.NoError(t, sqlite.Close()) }()

	insert := func(memoryID, author string, status memory.MemoryStatus) {
		t.Helper()
		content := "preserved historical " + memoryID
		digest := sha256.Sum256([]byte(content))
		require.NoError(t, sqlite.InsertMemory(ctx, &memory.MemoryRecord{
			MemoryID: memoryID, SubmittingAgent: author, Content: content,
			ContentHash: digest[:], MemoryType: memory.TypeFact,
			DomainTag: "historical/domain", Status: status,
		}))
	}
	insert("legacy-challenged", fixture.agentID, memory.StatusChallenged)
	insert("legacy-label-author", "old display label", memory.StatusCommitted)

	handler := NewDashboardHandler(sqlite, "test")
	handler.BadgerStore = fixture.badger
	plan, err := handler.buildAppV25LegacyAdoptionPlan(ctx, sqlite)
	require.NoError(t, err)
	require.Equal(t, 2, plan.Discovered)
	require.Equal(t, 2, plan.Unresolved)
	require.Empty(t, plan.Entries)
	require.Equal(t, []store.LegacyMemoryRecoveryItem{
		{MemoryID: "legacy-challenged", Reason: "invalid_status"},
		{MemoryID: "legacy-label-author", Reason: "author_identity_unresolved"},
	}, plan.Recovery)
}

func TestAppV25LegacyAdoptionPreservesCanonicalOrphanAuthorIdentity(t *testing.T) {
	ctx := context.Background()
	fixture := newAppV23AccessFixture(t)
	sqlite, err := store.NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "memories.db"))
	require.NoError(t, err)
	defer func() { require.NoError(t, sqlite.Close()) }()
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	orphanID := hex.EncodeToString(pub)
	content := "historical memory from retired project key"
	digest := sha256.Sum256([]byte(content))
	require.NoError(t, sqlite.InsertMemory(ctx, &memory.MemoryRecord{
		MemoryID: "legacy-orphan-author", SubmittingAgent: orphanID,
		Content: content, ContentHash: digest[:], MemoryType: memory.TypeFact,
		DomainTag: "historical/domain", Status: memory.StatusCommitted,
	}))

	handler := NewDashboardHandler(sqlite, "test")
	handler.BadgerStore = fixture.badger
	plan, err := handler.buildAppV25LegacyAdoptionPlan(ctx, sqlite)
	require.NoError(t, err)
	require.Len(t, plan.Entries, 1)
	require.Equal(t, orphanID, plan.Entries[0].Author)
	require.Equal(t, orphanID, plan.Entries[0].AuthorPrincipal)
	require.Zero(t, plan.Unresolved)
	enrollment, err := fixture.badger.GetAppV23Enrollment(orphanID)
	require.NoError(t, err)
	require.Nil(t, enrollment, "planning must not create authority for historical keys")
}

func TestAppV25LegacyAdoptionSkipsExactCanonicalAndRepairsHashlessCanonical(t *testing.T) {
	ctx := context.Background()
	fixture := newAppV23AccessFixture(t)
	sqlite, err := store.NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "memories.db"))
	require.NoError(t, err)
	defer func() { require.NoError(t, sqlite.Close()) }()

	insert := func(memoryID, content string) []byte {
		t.Helper()
		contentHash := sha256.Sum256([]byte(content))
		require.NoError(t, sqlite.InsertMemory(ctx, &memory.MemoryRecord{
			MemoryID:        memoryID,
			SubmittingAgent: fixture.agentID,
			Content:         content,
			ContentHash:     contentHash[:],
			MemoryType:      memory.TypeFact,
			DomainTag:       "historical/domain",
			Status:          memory.StatusCommitted,
		}))
		return contentHash[:]
	}
	exactHash := insert("legacy-already-canonical", "already canonical")
	_ = insert("legacy-hashless-canonical", "hash lost by historical transition")
	_ = insert("legacy-hashless-principal-missing", "principal predates its projection")

	require.NoError(t, fixture.badger.SetMemoryHash(
		"legacy-already-canonical",
		exactHash,
		"committed",
	))
	require.NoError(t, fixture.badger.SetMemoryDomain(
		"legacy-already-canonical",
		"historical/domain",
	))
	require.NoError(t, fixture.badger.SetMemoryAuthor(
		"legacy-already-canonical",
		fixture.agentID,
	))
	require.NoError(t, fixture.badger.SetMemoryAuthorPrincipal(
		"legacy-already-canonical",
		fixture.agentID,
	))
	require.NoError(t, fixture.badger.SetMemoryClassification(
		"legacy-already-canonical",
		1,
	))

	require.NoError(t, fixture.badger.SetMemoryHash(
		"legacy-hashless-canonical",
		nil,
		"committed",
	))
	require.NoError(t, fixture.badger.SetMemoryDomain(
		"legacy-hashless-canonical",
		"historical/domain",
	))
	require.NoError(t, fixture.badger.SetMemoryAuthor(
		"legacy-hashless-canonical",
		fixture.agentID,
	))
	require.NoError(t, fixture.badger.SetMemoryAuthorPrincipal(
		"legacy-hashless-canonical",
		fixture.agentID,
	))
	require.NoError(t, fixture.badger.SetMemoryClassification(
		"legacy-hashless-canonical",
		1,
	))
	require.NoError(t, fixture.badger.SetMemoryHash(
		"legacy-hashless-principal-missing",
		nil,
		"committed",
	))
	require.NoError(t, fixture.badger.SetMemoryDomain(
		"legacy-hashless-principal-missing",
		"historical/domain",
	))
	require.NoError(t, fixture.badger.SetMemoryAuthor(
		"legacy-hashless-principal-missing",
		fixture.agentID,
	))
	require.NoError(t, fixture.badger.SetMemoryClassification(
		"legacy-hashless-principal-missing",
		1,
	))

	handler := NewDashboardHandler(sqlite, "test")
	handler.BadgerStore = fixture.badger
	plan, err := handler.buildAppV25LegacyAdoptionPlan(ctx, sqlite)
	require.NoError(t, err)
	require.Len(t, plan.Entries, 2)
	require.Equal(t, "legacy-hashless-canonical", plan.Entries[0].MemoryID)
	require.Equal(t, "legacy-hashless-principal-missing", plan.Entries[1].MemoryID)
	require.Equal(t, 2, plan.Discovered,
		"an exact canonical row is not part of the legacy-adoption inventory")
	require.Zero(t, plan.Converted)
	require.Zero(t, plan.Unresolved)
	require.Empty(t, plan.Recovery)

	root, err := fixture.badger.GetAppV23Root()
	require.NoError(t, err)
	batch, payload, err := appV25LegacyAdoptionBatch(root, plan.Entries)
	require.NoError(t, err)
	require.Len(t, batch, 2)
	targetID, err := tx.MemoryLegacyAdoptionTargetID(payload)
	require.NoError(t, err)
	require.NoError(t, handler.attestAppV25LegacyAdoptionProposal(
		ctx,
		sqlite,
		&governance.ProposalState{
			ProposalID: "repair-hashless-canonical",
			Operation:  governance.OpMemoryLegacyAdopt,
			TargetID:   targetID,
			Payload:    payload,
		},
	))
	adoptionEntries := make([]store.MemoryLegacyAdoptionEntry, len(batch))
	for i := range batch {
		adoptionEntries[i] = store.MemoryLegacyAdoptionEntry{
			MemoryID:        batch[i].MemoryID,
			Status:          batch[i].Status,
			ContentHash:     batch[i].ContentHash,
			Domain:          batch[i].Domain,
			Author:          batch[i].Author,
			AuthorPrincipal: batch[i].AuthorPrincipal,
			Classification:  batch[i].Classification,
		}
	}
	adopted, err := fixture.badger.AdoptLegacyMemories(
		appV25LegacyAdoptionPlanDigest(batch),
		adoptionEntries,
	)
	require.NoError(t, err)
	require.Equal(t, 2, adopted.Adopted)

	replanned, err := handler.buildAppV25LegacyAdoptionPlan(ctx, sqlite)
	require.NoError(t, err)
	require.Empty(t, replanned.Entries)
	require.Equal(t, 2, replanned.Converted)
	require.Zero(t, replanned.Unresolved)
}

func TestAppV25LegacyAdoptionInvalidatesCachedPlanWhenCandidateChanges(t *testing.T) {
	ctx := context.Background()
	fixture := newAppV23AccessFixture(t)
	sqlite, err := store.NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "memories.db"))
	require.NoError(t, err)
	defer func() { require.NoError(t, sqlite.Close()) }()

	content := "historical row changes after planning"
	contentHash := sha256.Sum256([]byte(content))
	require.NoError(t, sqlite.InsertMemory(ctx, &memory.MemoryRecord{
		MemoryID:        "legacy-stale-candidate",
		SubmittingAgent: fixture.agentID,
		Content:         content,
		ContentHash:     contentHash[:],
		MemoryType:      memory.TypeFact,
		DomainTag:       "historical/original",
		Status:          memory.StatusCommitted,
	}))

	handler := NewDashboardHandler(sqlite, "test")
	handler.BadgerStore = fixture.badger
	handler.AdminSigningKey = fixture.rootKey
	handler.CometBFTRPC = "http://unused.invalid"
	_, handler.SigningKey, err = ed25519.GenerateKey(nil)
	require.NoError(t, err)

	plan, err := handler.buildAppV25LegacyAdoptionPlan(ctx, sqlite)
	require.NoError(t, err)
	require.Len(t, plan.Entries, 1)
	run := &appV25LegacyAdoptionRun{
		plan:        plan,
		initialized: true,
	}

	require.NoError(t, sqlite.UpdateDomainTag(
		ctx,
		"legacy-stale-candidate",
		"historical/changed",
	))
	more, err := handler.runAppV25LegacyAdoptionPassWithState(
		ctx,
		zerolog.Nop(),
		run,
	)
	require.NoError(t, err)
	require.True(t, more)
	require.False(t, run.initialized,
		"a deterministic candidate mismatch must discard the cached observation")
	require.Nil(t, run.plan)
}

func TestAppV25LegacyAdoptionPlanUsesSnapshotWithoutBlockingTypedWrites(
	t *testing.T,
) {
	ctx := context.Background()
	fixture := newAppV23AccessFixture(t)
	sqlite, err := store.NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "memories.db"))
	require.NoError(t, err)
	defer func() { require.NoError(t, sqlite.Close()) }()

	content := "stable evidence while the adoption inventory is scanned"
	contentHash := sha256.Sum256([]byte(content))
	require.NoError(t, sqlite.InsertMemory(ctx, &memory.MemoryRecord{
		MemoryID:        "legacy-concurrent-write",
		SubmittingAgent: fixture.agentID,
		Content:         content,
		ContentHash:     contentHash[:],
		MemoryType:      memory.TypeFact,
		DomainTag:       "historical/before",
		Status:          memory.StatusCommitted,
	}))

	source := &blockingAppV25LegacyProjectionSource{
		SQLiteStore: sqlite,
		scanStarted: make(chan struct{}),
		releaseScan: make(chan struct{}),
	}
	handler := NewDashboardHandler(source, "test")
	handler.BadgerStore = fixture.badger

	type planResult struct {
		plan *appV25LegacyAdoptionPlan
		err  error
	}
	planDone := make(chan planResult, 1)
	go func() {
		plan, planErr := handler.buildAppV25LegacyAdoptionPlan(ctx, source)
		planDone <- planResult{plan: plan, err: planErr}
	}()

	select {
	case <-source.scanStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("planner did not enter the bounded projection scan")
	}

	writerStarted := make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		close(writerStarted)
		writerDone <- sqlite.UpdateDomainTag(
			ctx,
			"legacy-concurrent-write",
			"historical/after",
		)
	}()
	<-writerStarted

	select {
	case writeErr := <-writerDone:
		require.NoError(t, writeErr)
	case <-time.After(2 * time.Second):
		t.Fatal("typed SQLite write was blocked by the read-only planning snapshot")
	}

	close(source.releaseScan)
	select {
	case result := <-planDone:
		require.NoError(t, result.err)
		require.NotNil(t, result.plan)
		require.Len(t, result.plan.Entries, 1)
	case <-time.After(2 * time.Second):
		t.Fatal("planner did not complete after releasing its bounded snapshot")
	}
}
