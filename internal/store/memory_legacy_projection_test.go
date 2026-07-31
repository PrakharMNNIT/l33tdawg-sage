package store

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/memory"
)

func TestLegacyMemoryRecoveryQueueSurvivesRestartAndResolvesIdempotently(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "memories.db")
	sqlite, err := NewSQLiteStore(ctx, path)
	require.NoError(t, err)
	require.NoError(t, sqlite.SyncLegacyMemoryRecoveryQueue(
		ctx,
		7,
		[]LegacyMemoryRecoveryItem{{
			MemoryID: "unconvertible-memory",
			Reason:   "content_hash_mismatch",
		}},
	))
	expectedProgress := LegacyMemoryAdoptionProgress{
		State:      "migrating",
		Discovered: 10,
		Converted:  3,
		Remaining:  6,
		Recovery:   1,
		Revision:   7,
		Message:    "SAGE is upgrading memories in the background. Normal work continues.",
	}
	require.NoError(t, sqlite.PublishLegacyMemoryAdoptionProgress(
		ctx,
		expectedProgress,
	))
	require.NoError(t, sqlite.SyncLegacyMemoryRecoveryQueue(
		ctx,
		7,
		[]LegacyMemoryRecoveryItem{{
			MemoryID: "unconvertible-memory",
			Reason:   "content_hash_mismatch",
		}},
	))
	require.NoError(t, sqlite.Close())

	reopened, err := NewSQLiteStore(ctx, path)
	require.NoError(t, err)
	defer func() { require.NoError(t, reopened.Close()) }()
	progress, err := reopened.GetLegacyMemoryAdoptionProgress(ctx)
	require.NoError(t, err)
	require.Equal(t, &expectedProgress, progress)
	records, err := reopened.ListLegacyMemoryRecoveryQueue(ctx, false)
	require.NoError(t, err)
	require.Equal(t, []LegacyMemoryRecoveryRecord{{
		MemoryID:           "unconvertible-memory",
		Reason:             "content_hash_mismatch",
		ProjectionRevision: 7,
	}}, records)

	require.NoError(t, reopened.SyncLegacyMemoryRecoveryQueue(ctx, 8, nil))
	active, err := reopened.ListLegacyMemoryRecoveryQueue(ctx, false)
	require.NoError(t, err)
	require.Empty(t, active)
	all, err := reopened.ListLegacyMemoryRecoveryQueue(ctx, true)
	require.NoError(t, err)
	require.Len(t, all, 1)
	require.True(t, all[0].Resolved)
	require.Equal(t, uint64(7), all[0].ProjectionRevision)
}

func TestLegacyMemoryProjectionPageIncludesClassificationAndDoesNotStallOnBadContent(t *testing.T) {
	ctx := context.Background()
	sqlite, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "memories.db"))
	require.NoError(t, err)
	defer func() { require.NoError(t, sqlite.Close()) }()
	content := "legacy plaintext"
	digest := sha256.Sum256([]byte(content))
	require.NoError(t, sqlite.InsertMemory(ctx, &memory.MemoryRecord{
		MemoryID:        "legacy-projection-a",
		SubmittingAgent: "author",
		Content:         content,
		ContentHash:     digest[:],
		MemoryType:      memory.TypeFact,
		DomainTag:       "historical/domain",
		Status:          memory.StatusCommitted,
	}))
	require.NoError(t, sqlite.UpdateMemoryClassification(
		ctx,
		"legacy-projection-a",
		ClearanceSecret,
	))

	page, err := sqlite.ListLegacyMemoryProjectionPage(ctx, "", "", 10)
	require.NoError(t, err)
	require.Len(t, page, 1)
	require.Equal(t, uint8(ClearanceSecret), page[0].Classification)
	require.Equal(t, content, page[0].Content)
	require.Equal(t, digest[:], page[0].ContentHash)
	require.NotEmpty(t, page[0].CreatedAtCursor)
}
