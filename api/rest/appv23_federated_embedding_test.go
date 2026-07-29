package rest

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/embedding"
	"github.com/l33tdawg/sage/internal/metrics"
)

func TestAppV23FederatedVectorRecallRequiresExactSignedEmbeddingProvider(t *testing.T) {
	memStore := newMockMemoryStore()
	health := metrics.NewHealthChecker()
	server := NewServer(
		"", memStore, newMockScoreStore(), nil, health, zerolog.Nop(),
		embedding.NewHashProvider(3),
	)
	server.SetPostV23ForNextTxAccessor(func() bool { return true })

	require.NoError(t, server.requireFederatedEmbeddingProvider(
		true, nil, []float32{0.1, 0.2, 0.3}, "hash:3",
	))
	require.ErrorContains(t, server.requireFederatedEmbeddingProvider(
		true, nil, []float32{0.1, 0.2, 0.3}, "",
	), "required")
	require.ErrorContains(t, server.requireFederatedEmbeddingProvider(
		true, nil, []float32{0.1, 0.2, 0.3}, "operator-substitution",
	), "does not match")
	require.NoError(t, server.requireFederatedEmbeddingProvider(
		false, nil, []float32{0.1, 0.2, 0.3}, "",
	), "local vector recall remains source-compatible")
	require.NoError(t, server.requireFederatedEmbeddingProvider(
		true, nil, nil, "",
	), "text-only hybrid recall has no vector-space selector to bind")

	server.SetPostV23ForNextTxAccessor(func() bool { return false })
	require.NoError(t, server.requireFederatedEmbeddingProvider(
		true, nil, []float32{0.1, 0.2, 0.3}, "",
	), "pre-v23 replay behavior remains unchanged")
}
