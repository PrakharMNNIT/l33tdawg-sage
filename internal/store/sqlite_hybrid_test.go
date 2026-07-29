package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedHybridCorpus inserts five committed memories where text content and
// embeddings are arranged so the BM25 and vector indexes return different
// top-1s for the same query. That divergence is what the RRF fusion has to
// resolve, so the hybrid path is exercised end-to-end against real SQLite.
func seedHybridCorpus(t *testing.T, s *SQLiteStore) {
	t.Helper()
	ctx := context.Background()

	corpus := []struct {
		id      string
		content string
		emb     []float32
	}{
		// "auth-jwt-keyword" is the strongest BM25 match for "jwt auth"
		{"auth-jwt-keyword", "jwt auth verification with jose middleware", []float32{0.1, 0.1, 0.9}},
		// "auth-cosine-near" has weaker BM25 (no exact terms) but its embedding
		// is closest to the query embedding we'll use below.
		{"auth-cosine-near", "authentication system identity check", []float32{0.95, 0.05, 0.0}},
		{"db-query-perf", "n+1 query database performance fix", []float32{0.2, 0.3, 0.4}},
		{"unrelated-cache", "redis cache invalidation strategy", []float32{0.1, 0.8, 0.1}},
		{"http-rate-limit", "rate limiting middleware per-tenant", []float32{0.3, 0.3, 0.3}},
	}

	for _, c := range corpus {
		rec := testMemory(c.id, "agent1", c.content, "general")
		rec.Embedding = c.emb
		rec.Status = memory.StatusCommitted
		require.NoError(t, s.InsertMemory(ctx, rec))
	}
}

func TestSearchHybrid_FusesBothStreams(t *testing.T) {
	s := newTestStore(t)
	seedHybridCorpus(t, s)
	ctx := context.Background()

	// Query: text matches "auth-jwt-keyword" strongly via BM25;
	// query embedding (1.0, 0.0, 0.0) is closest to "auth-cosine-near" via cosine.
	queryEmb := []float32{1.0, 0.0, 0.0}
	results, err := s.SearchHybrid(ctx, "jwt auth", queryEmb, QueryOptions{TopK: 5})
	require.NoError(t, err)
	require.NotEmpty(t, results)

	ids := make([]string, 0, len(results))
	for _, r := range results {
		ids = append(ids, r.MemoryID)
	}

	// Both auth-related memories should rank above unrelated ones — the whole
	// point of fusion is that we surface signal from both indexes, not just one.
	assert.Contains(t, ids, "auth-jwt-keyword", "BM25 winner must appear in fused results")
	assert.Contains(t, ids, "auth-cosine-near", "vector winner must appear in fused results")

	// "unrelated-cache" has neither textual nor semantic overlap and must NOT
	// outrank the auth pair.
	authMin := len(ids)
	for i, id := range ids {
		if id == "auth-jwt-keyword" || id == "auth-cosine-near" {
			if i < authMin {
				authMin = i
			}
		}
	}
	for i, id := range ids {
		if id == "unrelated-cache" {
			assert.Greater(t, i, authMin,
				"unrelated memory must rank below the auth memories")
		}
	}
}

func TestSearchHybrid_RequiresQueryOrEmbedding(t *testing.T) {
	s := newTestStore(t)
	_, err := s.SearchHybrid(context.Background(), "", nil, QueryOptions{TopK: 5})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires either a query or an embedding")
}

func TestSearchHybrid_VectorOnlyWhenQueryEmpty(t *testing.T) {
	s := newTestStore(t)
	seedHybridCorpus(t, s)

	results, err := s.SearchHybrid(context.Background(), "",
		[]float32{1.0, 0.0, 0.0}, QueryOptions{TopK: 3})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	// With BM25 disabled (empty query), the closest-by-cosine memory must rank first.
	assert.Equal(t, "auth-cosine-near", results[0].MemoryID)
}

func TestSearchHybrid_BM25OnlyWhenEmbeddingEmpty(t *testing.T) {
	s := newTestStore(t)
	seedHybridCorpus(t, s)

	results, err := s.SearchHybrid(context.Background(),
		"jwt", nil, QueryOptions{TopK: 3})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	// With vector disabled (no embedding), BM25 winner must rank first.
	assert.Equal(t, "auth-jwt-keyword", results[0].MemoryID)
}

func TestSearchHybrid_VaultActiveDegradesToVectorOnly(t *testing.T) {
	s := newTestStore(t)
	seedHybridCorpus(t, s)

	keyFile := filepath.Join(t.TempDir(), "vault.key")
	require.NoError(t, vault.Init(keyFile, "test-passphrase"))
	activeVault, err := vault.Open(keyFile, "test-passphrase")
	require.NoError(t, err)
	s.SetVault(activeVault)

	results, err := s.SearchHybrid(context.Background(),
		"jwt", []float32{1.0, 0.0, 0.0}, QueryOptions{TopK: 2})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "auth-cosine-near", results[0].MemoryID,
		"vector-only branch must return the cosine winner")

	results, err = s.SearchHybrid(context.Background(),
		"jwt", nil, QueryOptions{TopK: 2})
	require.Nil(t, results)
	require.Error(t, err,
		"vault-active query-only hybrid has no usable leaf and must not claim empty success")
	require.ErrorContains(t, err, ErrTextSearchVaultEncryptedMsg)
}

func TestSearchHybrid_RespectsTopK(t *testing.T) {
	s := newTestStore(t)
	seedHybridCorpus(t, s)

	results, err := s.SearchHybrid(context.Background(),
		"auth", []float32{0.5, 0.5, 0.5}, QueryOptions{TopK: 2})
	require.NoError(t, err)
	assert.LessOrEqual(t, len(results), 2, "TopK must cap the merged result count")
}

func TestSearchHybrid_HugeTopKAndOversampleCannotOverflow(t *testing.T) {
	s := newTestStore(t)
	seedHybridCorpus(t, s)
	maxInt := int(^uint(0) >> 1)
	t.Setenv("SAGE_HYBRID_OVERSAMPLE", fmt.Sprintf("%d", maxInt))

	results, err := s.SearchHybrid(
		context.Background(),
		"auth",
		[]float32{0.5, 0.5, 0.5},
		QueryOptions{TopK: maxInt},
	)
	require.NoError(t, err)
	require.Len(t, results, 5,
		"overflow-safe saturation must retain the bounded corpus instead of wrapping to a tiny leaf limit")
}

func TestSearchHybrid_DomainFilterAppliesToBothStreams(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Two memories in "security" domain, three in "general"
	for i := 0; i < 2; i++ {
		rec := testMemory(fmt.Sprintf("sec-%d", i), "agent1",
			fmt.Sprintf("security incident %d", i), "security")
		rec.Embedding = []float32{0.9, 0.1, 0.0}
		rec.Status = memory.StatusCommitted
		require.NoError(t, s.InsertMemory(ctx, rec))
	}
	for i := 0; i < 3; i++ {
		rec := testMemory(fmt.Sprintf("gen-%d", i), "agent1",
			fmt.Sprintf("security incident %d", i), "general")
		rec.Embedding = []float32{0.9, 0.1, 0.0}
		rec.Status = memory.StatusCommitted
		require.NoError(t, s.InsertMemory(ctx, rec))
	}

	results, err := s.SearchHybrid(ctx, "security incident",
		[]float32{0.9, 0.1, 0.0},
		QueryOptions{TopK: 10, DomainTag: "security"})
	require.NoError(t, err)
	for _, r := range results {
		assert.Equal(t, "security", r.DomainTag,
			"domain filter must apply to both BM25 and vector streams")
	}
	assert.LessOrEqual(t, len(results), 2,
		"only the two security-tagged memories should match")
}
