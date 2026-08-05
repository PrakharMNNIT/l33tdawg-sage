package rest

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

// vaultActiveMockStore wraps mockMemoryStore and implements VaultActive() to
// simulate a node where the synaptic-ledger vault is unlocked and content is
// AES-256-GCM encrypted at rest. This is the only condition the v6.6.10
// /v1/embed/info change cares about — it forces semantic=true regardless of
// the underlying embedder so MCP clients don't take the broken FTS5 path.
type vaultActiveMockStore struct {
	*mockMemoryStore
	vaultActive bool
}

func (v *vaultActiveMockStore) VaultActive() bool { return v.vaultActive }

// TestHandleEmbedInfo_VaultActiveForcesSemantic confirms that /v1/embed/info
// reports semantic=true whenever the store is vault-active, even when the
// configured embedder is the non-semantic HashProvider. This is the primary
// fix in v6.6.10 — without it, MCP isSemanticMode would route to FTS5 and
// SQLiteStore.SearchByText would return the cryptic vault-encrypted error.
func TestHandleEmbedInfo_VaultActiveForcesSemantic(t *testing.T) {
	hashEmbedder := embedding.NewHashProvider(768)
	require.False(t, hashEmbedder.Semantic(), "HashProvider must be non-semantic for this test to be meaningful")

	memStore := &vaultActiveMockStore{mockMemoryStore: newMockMemoryStore(), vaultActive: true}
	scoreStore := newMockScoreStore()
	health := metrics.NewHealthChecker()
	health.SetPostgresHealth(true)
	health.SetCometBFTHealth(true)

	srv := NewServer("", memStore, scoreStore, nil, health, zerolog.Nop(), hashEmbedder)

	req, _ := signedRequest(t, http.MethodGet, "/v1/embed/info", nil)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp EmbedInfoResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

	assert.True(t, resp.Semantic, "vault-active store must force semantic=true even with HashProvider embedder")
	assert.Equal(t, "vault-encrypted", resp.Provider, "provider should reflect the vault-encrypted state")
}

// TestHandleEmbedInfo_VaultInactiveHonorsEmbedder confirms the existing
// behavior is preserved when the vault is NOT active — the embedder's
// Semantic() flag is the source of truth, and FTS5 fallback is allowed
// because content is plaintext-indexable.
func TestHandleEmbedInfo_VaultInactiveHonorsEmbedder(t *testing.T) {
	hashEmbedder := embedding.NewHashProvider(768)

	memStore := &vaultActiveMockStore{mockMemoryStore: newMockMemoryStore(), vaultActive: false}
	scoreStore := newMockScoreStore()
	health := metrics.NewHealthChecker()
	health.SetPostgresHealth(true)
	health.SetCometBFTHealth(true)

	srv := NewServer("", memStore, scoreStore, nil, health, zerolog.Nop(), hashEmbedder)

	req, _ := signedRequest(t, http.MethodGet, "/v1/embed/info", nil)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp EmbedInfoResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

	assert.False(t, resp.Semantic, "vault-inactive store must honor the embedder's actual Semantic() value")
	assert.Equal(t, "hash", resp.Provider)
}

// TestHandleEmbedInfo_NoVaultAPIPreservesLegacyBehavior confirms that stores
// which don't implement VaultActive() (e.g. PostgresStore in the current
// codebase) get the legacy behavior unchanged — semantic flag tracks the
// embedder verbatim. Important: we must not break PostgresStore's existing
// semantic reporting.
func TestHandleEmbedInfo_NoVaultAPIPreservesLegacyBehavior(t *testing.T) {
	hashEmbedder := embedding.NewHashProvider(768)

	// Plain mockMemoryStore does NOT implement VaultActive().
	memStore := newMockMemoryStore()
	scoreStore := newMockScoreStore()
	health := metrics.NewHealthChecker()
	health.SetPostgresHealth(true)
	health.SetCometBFTHealth(true)

	srv := NewServer("", memStore, scoreStore, nil, health, zerolog.Nop(), hashEmbedder)

	req, _ := signedRequest(t, http.MethodGet, "/v1/embed/info", nil)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp EmbedInfoResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

	// HashProvider is non-semantic AND the store doesn't expose vault status,
	// so the response should reflect the embedder unchanged: semantic=false.
	assert.False(t, resp.Semantic)
	assert.Equal(t, "hash", resp.Provider)
}

// namedSemanticEmbedder is a minimal Provider that implements the optional
// embedding.Named interface so we can assert /v1/embed/info uses the embedder's
// own name rather than always reporting "ollama" for any semantic provider.
type namedSemanticEmbedder struct {
	name string
	dim  int
}

func (n *namedSemanticEmbedder) Embed(_ context.Context, _ string) ([]float32, error) {
	return make([]float32, n.dim), nil
}
func (n *namedSemanticEmbedder) Dimension() int { return n.dim }
func (n *namedSemanticEmbedder) Ready() bool    { return true }
func (n *namedSemanticEmbedder) Semantic() bool { return true }
func (n *namedSemanticEmbedder) Name() string   { return n.name }

// TestHandleEmbedInfo_NamedProviderOverridesOllama confirms that semantic
// providers other than the legacy Ollama client (e.g. the openai-compatible
// provider) report their own name through /v1/embed/info instead of being
// silently labeled "ollama".
func TestHandleEmbedInfo_NamedProviderOverridesOllama(t *testing.T) {
	emb := &namedSemanticEmbedder{name: "openai-compatible", dim: 1536}

	memStore := newMockMemoryStore()
	scoreStore := newMockScoreStore()
	health := metrics.NewHealthChecker()
	health.SetPostgresHealth(true)
	health.SetCometBFTHealth(true)

	srv := NewServer("", memStore, scoreStore, nil, health, zerolog.Nop(), emb)

	req, _ := signedRequest(t, http.MethodGet, "/v1/embed/info", nil)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp EmbedInfoResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

	assert.True(t, resp.Semantic)
	assert.Equal(t, "openai-compatible", resp.Provider)
	assert.True(t, resp.SubmitEmbeddingAuthoritative)
	assert.Equal(t, 1536, resp.Dimension)
}

// modeledEmbedder implements the optional embedding.Modeler interface so we
// can assert /v1/embed reports the model the embedding was actually produced
// with, rather than the hardcoded "nomic-embed-text" literal.
type modeledEmbedder struct {
	model string
	dim   int
}

func (m *modeledEmbedder) Embed(_ context.Context, _ string) ([]float32, error) {
	return make([]float32, m.dim), nil
}
func (m *modeledEmbedder) Dimension() int { return m.dim }
func (m *modeledEmbedder) Ready() bool    { return true }
func (m *modeledEmbedder) Semantic() bool { return true }
func (m *modeledEmbedder) Model() string  { return m.model }

// TestHandleEmbed_ModelerReportsActualModel confirms POST /v1/embed reports the
// provider's actual model (via the optional Modeler interface) instead of the
// hardcoded "nomic-embed-text". An openai-compatible node must not claim its
// gte-Qwen2 embeddings came from nomic-embed-text.
func TestHandleEmbed_ModelerReportsActualModel(t *testing.T) {
	emb := &modeledEmbedder{model: "Alibaba-NLP/gte-Qwen2-1.5B-instruct", dim: 1536}

	memStore := newMockMemoryStore()
	scoreStore := newMockScoreStore()
	health := metrics.NewHealthChecker()
	health.SetPostgresHealth(true)
	health.SetCometBFTHealth(true)

	srv := NewServer("", memStore, scoreStore, nil, health, zerolog.Nop(), emb)

	body := []byte(`{"text":"hello"}`)
	req, _ := signedRequest(t, http.MethodPost, "/v1/embed", body)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp EmbedResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

	assert.Equal(t, "Alibaba-NLP/gte-Qwen2-1.5B-instruct", resp.Model,
		"/v1/embed must report the provider's actual model, not the hardcoded default")
	assert.Equal(t, "ollama:Alibaba-NLP/gte-Qwen2-1.5B-instruct:1536", resp.EmbeddingProvider,
		"/v1/embed must report the exact vector-space identifier the caller signs")
	assert.Equal(t, 1536, resp.Dimension)
}

// TestHandleEmbed_FallsBackForNonModeler confirms a provider that does NOT
// implement Modeler (e.g. the hash provider) preserves the legacy default
// model string — the fix is additive and must not regress that path.
func TestHandleEmbed_FallsBackForNonModeler(t *testing.T) {
	hashEmbedder := embedding.NewHashProvider(768)

	memStore := newMockMemoryStore()
	scoreStore := newMockScoreStore()
	health := metrics.NewHealthChecker()
	health.SetPostgresHealth(true)
	health.SetCometBFTHealth(true)

	srv := NewServer("", memStore, scoreStore, nil, health, zerolog.Nop(), hashEmbedder)

	body := []byte(`{"text":"hello"}`)
	req, _ := signedRequest(t, http.MethodPost, "/v1/embed", body)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp EmbedResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

	assert.Equal(t, "nomic-embed-text", resp.Model,
		"non-Modeler provider must preserve the legacy default model string")
	assert.Equal(t, "hash", resp.EmbeddingProvider)
}
