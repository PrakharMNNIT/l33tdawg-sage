package store

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/memory"
)

func insertReanchorProjection(
	t *testing.T,
	sql *SQLiteStore,
	canonical *BadgerStore,
	memoryID, content, status string,
) {
	t.Helper()
	hash := sha256.Sum256([]byte(content))
	require.NoError(t, sql.InsertMemory(context.Background(), &memory.MemoryRecord{
		MemoryID: memoryID, SubmittingAgent: "author", Content: content,
		ContentHash: hash[:], MemoryType: memory.TypeObservation,
		DomainTag: "repair/domain", ConfidenceScore: 0.9,
		Status: memory.MemoryStatus(status), CreatedAt: time.Now().UTC(),
	}))
	require.NoError(t, sql.UpdateMemoryClassification(
		context.Background(), memoryID, ClearanceInternal,
	))
	require.NoError(t, canonical.SetMemoryHash(memoryID, nil, status))
	require.NoError(t, canonical.SetMemoryDomain(memoryID, "repair/domain"))
	require.NoError(t, canonical.SetMemoryAuthor(memoryID, "author"))
	require.NoError(t, canonical.SetMemoryAuthorPrincipal(memoryID, "agent:author"))
	require.NoError(t, canonical.SetMemoryClassification(memoryID, uint8(ClearanceInternal)))
}

func TestPlanMemoryHashReanchorEntriesUsesCanonicalSortedInventory(t *testing.T) {
	sql := newTestStore(t)
	canonical := newTestBadger(t)
	insertReanchorProjection(t, sql, canonical, "memory-b", "content-b", "deprecated")
	insertReanchorProjection(t, sql, canonical, "memory-a", "content-a", "committed")
	insertReanchorProjection(t, sql, canonical, "memory-c", "content-c", "committed")

	entries, remaining, err := PlanMemoryHashReanchorEntries(
		context.Background(), sql, canonical, 2,
	)
	require.NoError(t, err)
	require.True(t, remaining)
	require.Equal(t, []string{"memory-a", "memory-b"}, []string{
		entries[0].MemoryID, entries[1].MemoryID,
	})
	require.Equal(t, "committed", entries[0].ExpectedStatus)
	require.Equal(t, "deprecated", entries[1].ExpectedStatus)
}

func TestPlanMemoryHashReanchorEntriesFailsWhenCanonicalCandidateHasNoSQL(t *testing.T) {
	sql := newTestStore(t)
	canonical := newTestBadger(t)
	eligibleHashlessReanchorMemory(t, canonical, "missing-sql", "committed")

	_, _, err := PlanMemoryHashReanchorEntries(
		context.Background(), sql, canonical, 256,
	)
	require.ErrorContains(t, err, "load SQL evidence")
}

func TestAttestMemoryHashReanchorEntriesRejectsSQLContentMutation(t *testing.T) {
	sql := newTestStore(t)
	canonical := newTestBadger(t)
	insertReanchorProjection(t, sql, canonical, "memory-a", "content-a", "committed")
	entries, _, err := PlanMemoryHashReanchorEntries(
		context.Background(), sql, canonical, 256,
	)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.NoError(t, sql.conn.QueryRowContext(
		context.Background(),
		`UPDATE memories SET content = 'mutated' WHERE memory_id = 'memory-a' RETURNING memory_id`,
	).Scan(new(string)))

	err = AttestMemoryHashReanchorEntries(
		context.Background(), sql, canonical, entries,
	)
	require.ErrorContains(t, err, "content/hash evidence mismatches")
}

func TestAttestMemoryHashReanchorEntriesAcceptsExactEvidence(t *testing.T) {
	sql := newTestStore(t)
	canonical := newTestBadger(t)
	insertReanchorProjection(t, sql, canonical, "memory-a", "content-a", "committed")
	entries, _, err := PlanMemoryHashReanchorEntries(
		context.Background(), sql, canonical, 256,
	)
	require.NoError(t, err)
	require.NoError(t, AttestMemoryHashReanchorEntries(
		context.Background(), sql, canonical, entries,
	))
}
