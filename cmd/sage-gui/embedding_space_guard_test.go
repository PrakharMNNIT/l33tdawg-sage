package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/embedding"
	"github.com/l33tdawg/sage/internal/metrics"
)

type fakeProviderCounter struct {
	counts map[string]int
	err    error
}

func (f fakeProviderCounter) CountMemoriesByProvider(_ context.Context) (map[string]int, error) {
	return f.counts, f.err
}

// readyBody drives the readiness handler on an otherwise-healthy node so the
// only thing that can move status is the embedding-space check under test.
func readyBody(t *testing.T, h *metrics.HealthChecker, target string) (int, map[string]any) {
	t.Helper()
	h.SetPostgresHealth(true)
	h.SetCometBFTHealth(true)
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	h.ReadinessHandler(rec, req)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return rec.Code, body
}

// A store written in a vector space the active embedder does not produce must be
// surfaced — loudly and queryably — but must NOT fail the boot: recall silently
// partitions by space, a quality loss rather than an outage, and refusing to
// start would brick a deliberate re-embed migration.
func TestCheckEmbeddingSpaceConsistency_ForeignSpaceIsDegradedNotFatal(t *testing.T) {
	h := metrics.NewHealthChecker()
	// Active embedder is hash@768; the store is full of semantic vectors, with a
	// handful of empty-provider rows (queued for re-embed — a different condition).
	counter := fakeProviderCounter{counts: map[string]int{
		"hash": 3,
		"openai-compatible:gte-Qwen2-1.5B-instruct:1536": 1659,
		"": 35,
	}}
	checkEmbeddingSpaceConsistency(context.Background(), counter, embedding.NewHashProvider(768), h, zerolog.Nop())

	code, body := readyBody(t, h, "/ready")
	assert.Equal(t, http.StatusOK, code, "a space mismatch is degraded, not an outage — the node still serves")
	assert.Equal(t, "degraded", body["status"])

	es, ok := body["embedding_space"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, es["checked"])
	assert.Equal(t, false, es["ok"])
	assert.Equal(t, "hash", es["active_space"])
	assert.EqualValues(t, 1659, es["foreign_rows"], "empty-provider rows are excluded; only the foreign non-empty space counts")
	foreign, ok := es["foreign_spaces"].(map[string]any)
	require.True(t, ok)
	assert.EqualValues(t, 1659, foreign["openai-compatible:gte-Qwen2-1.5B-instruct:1536"])
	_, hashCarried := foreign["hash"]
	assert.False(t, hashCarried, "the active space is not foreign to itself")

	// The disclosure is queryable, and strict readiness gates can act on it.
	strictCode, _ := readyBody(t, h, "/ready?strict=1")
	assert.Equal(t, http.StatusServiceUnavailable, strictCode)
}

// A store whose committed vectors all share the active space is healthy: no
// warning, no degraded status.
func TestCheckEmbeddingSpaceConsistency_MatchingSpaceIsOK(t *testing.T) {
	h := metrics.NewHealthChecker()
	counter := fakeProviderCounter{counts: map[string]int{"hash": 10, "": 2}}
	checkEmbeddingSpaceConsistency(context.Background(), counter, embedding.NewHashProvider(768), h, zerolog.Nop())

	code, body := readyBody(t, h, "/ready")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "ready", body["status"])
	es := body["embedding_space"].(map[string]any)
	assert.Equal(t, true, es["ok"])
	assert.Nil(t, es["foreign_spaces"])
}

// If the count query itself fails the check must not fabricate a verdict: it
// records nothing (status stays unchecked) rather than reporting a false OK or a
// false mismatch, and it never blocks the boot.
func TestCheckEmbeddingSpaceConsistency_CountErrorLeavesUnchecked(t *testing.T) {
	h := metrics.NewHealthChecker()
	counter := fakeProviderCounter{err: assert.AnError}
	checkEmbeddingSpaceConsistency(context.Background(), counter, embedding.NewHashProvider(768), h, zerolog.Nop())

	_, body := readyBody(t, h, "/ready")
	es := body["embedding_space"].(map[string]any)
	assert.Equal(t, false, es["checked"], "a failed count leaves the check unrun, not a fabricated OK")
}
