package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/embedding"
)

func TestOllamaDimensionPropagatesFromEnvironmentToProvider(t *testing.T) {
	cfg := DefaultConfig(t.TempDir())
	cfg.Embedding.Provider = "ollama"
	t.Setenv("SAGE_EMBEDDING_MODEL", "all-minilm:l6-v2")
	t.Setenv("SAGE_EMBEDDING_DIMENSION", "384")

	applyEnvOverrides(cfg)
	provider := createEmbeddingProvider(cfg, zerolog.Nop())

	assert.Equal(t, 384, cfg.Embedding.Dimension)
	assert.Equal(t, 384, provider.Dimension())
	assert.Equal(t, "ollama:all-minilm:l6-v2:384", embedding.SpaceID(provider))
}

func TestInvalidEmbeddingDimensionOverridePreservesConfiguredValue(t *testing.T) {
	cfg := DefaultConfig(t.TempDir())
	cfg.Embedding.Dimension = 384
	t.Setenv("SAGE_EMBEDDING_DIMENSION", "not-a-positive-integer")

	applyEnvOverrides(cfg)

	assert.Equal(t, 384, cfg.Embedding.Dimension)
}

func TestEmbeddingProviderSelectionPreservesConfiguredOllamaSpace(t *testing.T) {
	cfg := DefaultConfig(t.TempDir())
	cfg.Embedding.Provider = "ollama"
	cfg.Embedding.BaseURL = "http://127.0.0.1:11434"
	cfg.Embedding.Model = "snowflake-arctic-embed:xs"
	cfg.Embedding.Dimension = 384

	applyEmbeddingProviderSelection(cfg, "ollama")

	assert.Equal(t, "http://127.0.0.1:11434", cfg.Embedding.BaseURL)
	assert.Equal(t, "snowflake-arctic-embed:xs", cfg.Embedding.Model)
	assert.Equal(t, 384, cfg.Embedding.Dimension)
}

func TestEmbeddingProviderSelectionUsesExplicitManagedDefaultFromHash(t *testing.T) {
	cfg := DefaultConfig(t.TempDir())
	cfg.Embedding.Provider = "hash"
	cfg.Embedding.Dimension = 384

	applyEmbeddingProviderSelection(cfg, "ollama")

	assert.Equal(t, "http://localhost:11434", cfg.Embedding.BaseURL)
	assert.Equal(t, "nomic-embed-text", cfg.Embedding.Model)
	assert.Equal(t, 768, cfg.Embedding.Dimension)
}

func TestWizardOllamaProbeHonorsRequestedModelAndDimension(t *testing.T) {
	var requestedModel string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model string `json:"model"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		requestedModel = body.Model
		_ = json.NewEncoder(w).Encode(map[string]any{
			"embeddings": [][]float64{{0.1, 0.2, 0.3}},
		})
	}))
	defer upstream.Close()

	body, err := json.Marshal(map[string]any{
		"provider": "ollama", "base_url": upstream.URL,
		"model": "snowflake-arctic-embed:xs", "dimension": 3,
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/test-provider", bytes.NewReader(body))
	recorder := httptest.NewRecorder()

	handleTestProvider(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)
	var response map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	assert.Equal(t, true, response["ok"])
	assert.Equal(t, float64(3), response["dimension"])
	assert.Equal(t, "snowflake-arctic-embed:xs", requestedModel)
}

func TestEmbeddingHTTPTimeoutEnvironmentContract(t *testing.T) {
	type constructor func(string) embedding.Provider
	constructors := map[string]constructor{
		"ollama": func(baseURL string) embedding.Provider {
			return embedding.NewClientWithDimension(baseURL, "small", 3)
		},
		"openai-compatible": func(baseURL string) embedding.Provider {
			return embedding.NewOpenAICompatibleClient(baseURL, "small", "", 3)
		},
	}

	for providerName, newProvider := range constructors {
		providerName, newProvider := providerName, newProvider
		t.Run(providerName, func(t *testing.T) {
			t.Run("canonical timeout", func(t *testing.T) {
				assertEmbeddingTimeout(t, newProvider, "15ms", "", 80*time.Millisecond, true)
			})
			t.Run("legacy alias", func(t *testing.T) {
				assertEmbeddingTimeout(t, newProvider, "", "15ms", 80*time.Millisecond, true)
			})
			t.Run("canonical wins over alias", func(t *testing.T) {
				assertEmbeddingTimeout(t, newProvider, "200ms", "1ms", 30*time.Millisecond, false)
			})
			t.Run("invalid canonical falls back safely", func(t *testing.T) {
				assertEmbeddingTimeout(t, newProvider, "invalid", "1ms", 30*time.Millisecond, false)
			})
			t.Run("default permits ordinary request", func(t *testing.T) {
				assertEmbeddingTimeout(t, newProvider, "", "", 30*time.Millisecond, false)
			})
		})
	}
}

func assertEmbeddingTimeout(
	t *testing.T,
	newProvider func(string) embedding.Provider,
	canonical, alias string,
	delay time.Duration,
	wantTimeout bool,
) {
	t.Helper()
	t.Setenv("SAGE_EMBEDDING_TIMEOUT", canonical)
	t.Setenv("SAGE_EMBED_TIMEOUT", alias)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		if r.URL.Path == "/v1/embeddings" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"embedding": []float64{0.1, 0.2, 0.3}, "index": 0}},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"embeddings": [][]float64{{0.1, 0.2, 0.3}},
		})
	}))
	defer upstream.Close()

	_, err := newProvider(upstream.URL).Embed(context.Background(), "timeout contract")
	if wantTimeout {
		require.Error(t, err)
		return
	}
	require.NoError(t, err)
}
