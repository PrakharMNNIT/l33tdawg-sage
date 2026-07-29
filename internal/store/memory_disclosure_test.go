package store

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/memory"
)

func TestValidateMemoryProjectionRequiresExactCanonicalEnvelope(t *testing.T) {
	badger, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, badger.CloseBadger()) })

	record := &memory.MemoryRecord{
		MemoryID:        "published-memory",
		SubmittingAgent: "agent-a",
		Content:         "exact canonical content",
		ContentHash:     memory.ComputeContentHash("exact canonical content"),
		MemoryType:      memory.TypeFact,
		DomainTag:       "research",
		Status:          memory.StatusCommitted,
	}
	_, err = badger.ValidateMemoryProjection(record)
	require.ErrorIs(t, err, ErrMemoryProjectionUnpublished)

	require.NoError(t, badger.SetMemoryHash(
		record.MemoryID, record.ContentHash, string(record.Status),
	))
	require.NoError(t, badger.SetMemoryDomain(record.MemoryID, record.DomainTag))
	require.NoError(t, badger.SetMemoryAuthor(record.MemoryID, record.SubmittingAgent))
	require.NoError(t, badger.SetMemoryClassification(record.MemoryID, 3))

	state, err := badger.ValidateMemoryProjection(record)
	require.NoError(t, err)
	require.Equal(t, uint8(3), state.Classification)

	for _, mutate := range []func(*memory.MemoryRecord){
		func(rec *memory.MemoryRecord) { rec.Content = "tampered content" },
		func(rec *memory.MemoryRecord) { rec.ContentHash = memory.ComputeContentHash("other") },
		func(rec *memory.MemoryRecord) { rec.Status = memory.StatusProposed },
		func(rec *memory.MemoryRecord) { rec.DomainTag = "other" },
		func(rec *memory.MemoryRecord) { rec.SubmittingAgent = "agent-b" },
	} {
		copyRecord := *record
		copyRecord.ContentHash = append([]byte(nil), record.ContentHash...)
		mutate(&copyRecord)
		_, validateErr := badger.ValidateMemoryProjection(&copyRecord)
		require.ErrorIs(t, validateErr, ErrMemoryProjectionUnpublished)
	}
}

func TestAppV23DisclosureMarkerRequiresCompleteCanonicalFields(t *testing.T) {
	badger, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, badger.CloseBadger()) })

	record := &memory.MemoryRecord{
		MemoryID:        "incomplete-app-v23-memory",
		SubmittingAgent: "agent-a",
		Content:         "new app-v23 content",
		ContentHash:     memory.ComputeContentHash("new app-v23 content"),
		DomainTag:       "research",
		Status:          memory.StatusProposed,
	}
	require.NoError(t, badger.SetMemoryHash(
		record.MemoryID, record.ContentHash, string(record.Status),
	))
	require.NoError(t, badger.SetMemoryAuthorPrincipal(record.MemoryID, "principal-a"))

	_, err = badger.ValidateMemoryProjection(record)
	require.ErrorIs(t, err, ErrMemoryProjectionUnpublished)

	require.NoError(t, badger.SetMemoryDomain(record.MemoryID, record.DomainTag))
	require.NoError(t, badger.SetMemoryAuthor(record.MemoryID, record.SubmittingAgent))
	require.NoError(t, badger.SetMemoryClassification(record.MemoryID, 2))
	state, err := badger.ValidateMemoryProjection(record)
	require.NoError(t, err)
	require.True(t, state.AuthorPrincipalRecorded)
	require.Equal(t, uint8(2), state.Classification)
}

func TestValidateMemoryProjectionAcceptsCanonicalScopedPendingRecord(t *testing.T) {
	badger := newTestBadger(t)
	ballot, content := scopedSubmissionFixture()
	require.NoError(t, badger.SetScopedMemorySubmission(ballot, content))
	require.NoError(t, badger.SetMemoryAuthorPrincipal(content.MemoryID, "principal-a"))

	record := &memory.MemoryRecord{
		MemoryID:        content.MemoryID,
		SubmittingAgent: content.SubmittingAgentID,
		Content:         content.Content,
		ContentHash:     append([]byte(nil), content.ContentHash...),
		MemoryType:      memory.TypeFact,
		DomainTag:       content.Domain,
		ConfidenceScore: content.ConfidenceScore,
		Status:          memory.StatusProposed,
	}
	state, err := badger.ValidateMemoryProjection(record)
	require.NoError(t, err)
	require.Equal(t, content.Classification, state.Classification)
	require.True(t, state.AuthorPrincipalRecorded)
}

func TestValidateMemoryProjectionAcceptsOnlyCanonicalHashOnlyCoCommit(t *testing.T) {
	badger := newTestBadger(t)
	contentHash := memory.ComputeContentHash("content known only to a coauthor")
	record := &memory.MemoryRecord{
		MemoryID:        "hash-only-co-commit",
		SubmittingAgent: "agent-a",
		ContentHash:     contentHash,
		MemoryType:      memory.TypeFact,
		DomainTag:       "research",
		Status:          memory.StatusCommitted,
	}
	require.NoError(t, badger.SetMemoryHash(
		record.MemoryID, record.ContentHash, string(record.Status),
	))
	require.NoError(t, badger.SetMemoryDomain(record.MemoryID, record.DomainTag))
	require.NoError(t, badger.SetMemoryAuthor(record.MemoryID, record.SubmittingAgent))
	require.NoError(t, badger.SetMemoryClassification(record.MemoryID, 1))

	_, err := badger.ValidateMemoryProjection(record)
	require.ErrorIs(t, err, ErrMemoryProjectionUnpublished)

	require.NoError(t, badger.SetCoCommitShared(record.MemoryID, 1))
	require.NoError(t, badger.SetCoCommitCore(
		record.MemoryID, memory.ComputeContentHash("co-commit core"),
	))
	state, err := badger.ValidateMemoryProjection(record)
	require.NoError(t, err)
	require.True(t, state.CoCommitRecorded)

	tampered := *record
	tampered.Content = "not the signed content"
	_, err = badger.ValidateMemoryProjection(&tampered)
	require.ErrorIs(t, err, ErrMemoryProjectionUnpublished)
}
