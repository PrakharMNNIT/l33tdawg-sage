package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/memory"
)

func TestSQLiteRecallCandidateFilterFillsPastHundredDeniedRows(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 140; i++ {
		rec := testMemory(
			fmt.Sprintf("000-denied-%03d", i),
			"denied-agent",
			"needle ranked authorization",
			"denied.domain",
		)
		rec.Status = memory.StatusCommitted
		rec.Embedding = []float32{1, 0}
		require.NoError(t, s.InsertMemory(ctx, rec))
	}
	for i := 0; i < 3; i++ {
		rec := testMemory(
			fmt.Sprintf("zzz-allowed-%03d", i),
			"allowed-agent",
			"needle ranked authorization",
			"allowed.domain",
		)
		rec.Status = memory.StatusCommitted
		rec.Embedding = []float32{0.9, 0.1}
		require.NoError(t, s.InsertMemory(ctx, rec))
	}

	opts := QueryOptions{
		TopK:         2,
		StatusFilter: "committed",
		CandidateFilter: func(rec *memory.MemoryRecord) (bool, error) {
			return strings.HasPrefix(rec.MemoryID, "zzz-allowed-"), nil
		},
	}
	for _, tc := range []struct {
		name string
		run  func() ([]*memory.MemoryRecord, error)
	}{
		{
			name: "semantic",
			run: func() ([]*memory.MemoryRecord, error) {
				return s.QuerySimilar(ctx, []float32{1, 0}, opts)
			},
		},
		{
			name: "text",
			run: func() ([]*memory.MemoryRecord, error) {
				return s.SearchByText(ctx, "needle", opts)
			},
		},
		{
			name: "hybrid",
			run: func() ([]*memory.MemoryRecord, error) {
				return s.SearchHybrid(ctx, "needle", []float32{1, 0}, opts)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results, err := tc.run()
			require.NoError(t, err)
			require.Len(t, results, 2)
			for _, rec := range results {
				require.True(t, strings.HasPrefix(rec.MemoryID, "zzz-allowed-"))
			}
		})
	}
}

func TestSQLiteTextCandidateBatchFilterUsesOneCallPerRankedPage(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 140; i++ {
		rec := testMemory(
			fmt.Sprintf("000-denied-%03d", i),
			"denied-agent",
			"needle ranked batch authorization",
			"denied.domain",
		)
		rec.Status = memory.StatusCommitted
		require.NoError(t, s.InsertMemory(ctx, rec))
	}
	for i := 0; i < 3; i++ {
		rec := testMemory(
			fmt.Sprintf("zzz-allowed-%03d", i),
			"allowed-agent",
			"needle ranked batch authorization",
			"allowed.domain",
		)
		rec.Status = memory.StatusCommitted
		require.NoError(t, s.InsertMemory(ctx, rec))
	}

	batchCalls := 0
	maxBatch := 0
	results, err := s.SearchByText(ctx, "needle", QueryOptions{
		TopK:         2,
		StatusFilter: "committed",
		CandidateBatchFilter: func(
			page []*memory.MemoryRecord,
		) ([]*memory.MemoryRecord, error) {
			batchCalls++
			if len(page) > maxBatch {
				maxBatch = len(page)
			}
			allowed := page[:0]
			for _, rec := range page {
				if strings.HasPrefix(rec.MemoryID, "zzz-allowed-") {
					allowed = append(allowed, rec)
				}
			}
			return allowed, nil
		},
	})
	require.NoError(t, err)
	require.Len(t, results, 2)
	require.Equal(t, 2, batchCalls,
		"140 denied hits require exactly two ranked SQL pages, not one policy call per record")
	require.Equal(t, 128, maxBatch)
	for _, rec := range results {
		require.True(t, strings.HasPrefix(rec.MemoryID, "zzz-allowed-"))
	}
}

func TestSQLiteHybridCandidateFilterLeafErrorCannotDegradeToPartialSuccess(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	textMatch := testMemory("text-match", "agent", "needle", "domain")
	textMatch.Status = memory.StatusCommitted
	textMatch.Embedding = []float32{1, 0}
	require.NoError(t, s.InsertMemory(ctx, textMatch))

	vectorOnly := testMemory("vector-policy-failure", "agent", "unrelated", "domain")
	vectorOnly.Status = memory.StatusCommitted
	vectorOnly.Embedding = []float32{1, 0}
	require.NoError(t, s.InsertMemory(ctx, vectorOnly))

	policyErr := errors.New("live authorization unavailable")
	_, err := s.SearchHybrid(ctx, "needle", []float32{1, 0}, QueryOptions{
		TopK:         10,
		StatusFilter: "committed",
		CandidateFilter: func(rec *memory.MemoryRecord) (bool, error) {
			if rec.MemoryID == vectorOnly.MemoryID {
				return false, policyErr
			}
			return true, nil
		},
	})
	require.ErrorIs(t, err, policyErr,
		"a successful text leaf must not hide a governed vector-leaf authorization failure")
}
