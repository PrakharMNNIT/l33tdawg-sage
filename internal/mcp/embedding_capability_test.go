package mcp

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type embeddingRequestCounts struct {
	info   int
	embed  int
	submit int
}

func writeEmbeddingCapability(w http.ResponseWriter, current bool) {
	body := map[string]any{"semantic": true, "ready": true}
	if current {
		body["submit_embedding_authoritative"] = true
	}
	_ = json.NewEncoder(w).Encode(body)
}

func assertCompatibilityEmbedding(t *testing.T, r *http.Request, current bool) {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
	if current {
		assert.Nil(t, body["embedding"], "current nodes mint the authoritative vector")
		return
	}
	assert.Equal(t, []any{0.1, 0.2, 0.3}, body["embedding"],
		"legacy nodes still receive the compatibility vector")
}

func TestStoreMemoryEmbeddingCapabilityRequestCounts(t *testing.T) {
	for _, current := range []bool{false, true} {
		current := current
		name := "legacy"
		if current {
			name = "current"
		}
		t.Run(name, func(t *testing.T) {
			var counts embeddingRequestCounts
			mux := http.NewServeMux()
			mux.HandleFunc("/v1/memory/pre-validate", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"accepted": true})
			})
			mux.HandleFunc("/v1/embed/info", func(w http.ResponseWriter, _ *http.Request) {
				counts.info++
				writeEmbeddingCapability(w, current)
			})
			mux.HandleFunc("/v1/embed", func(w http.ResponseWriter, _ *http.Request) {
				counts.embed++
				_ = json.NewEncoder(w).Encode(map[string]any{"embedding": []float32{0.1, 0.2, 0.3}})
			})
			mux.HandleFunc("/v1/memory/submit", func(w http.ResponseWriter, r *http.Request) {
				counts.submit++
				assertCompatibilityEmbedding(t, r, current)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"memory_id": "memory-1", "status": "proposed", "embedding_queued": false,
				})
			})
			ts := httptest.NewServer(mux)
			defer ts.Close()

			_, privateKey, err := ed25519.GenerateKey(nil)
			require.NoError(t, err)
			server := NewServer(ts.URL, privateKey)
			for i := 0; i < 2; i++ {
				degraded, storeErr := server.storeMemory(
					context.Background(), fmt.Sprintf("observation %d", i), "test", "observation", 0.8,
				)
				require.NoError(t, storeErr)
				assert.False(t, degraded)
			}

			wantInfo := 1
			if current {
				wantInfo = 2
			}
			assert.Equal(t, wantInfo, counts.info)
			assert.Equal(t, 2, counts.submit)
			if current {
				assert.Zero(t, counts.embed)
			} else {
				assert.Equal(t, 2, counts.embed)
			}
		})
	}
}

func TestToolRememberEmbeddingCapabilityRequestCounts(t *testing.T) {
	for _, current := range []bool{false, true} {
		current := current
		name := "legacy"
		if current {
			name = "current"
		}
		t.Run(name, func(t *testing.T) {
			var counts embeddingRequestCounts
			mux := http.NewServeMux()
			mux.HandleFunc("/v1/memory/list", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"memories": []any{}})
			})
			mux.HandleFunc("/v1/memory/pre-validate", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"accepted": true})
			})
			mux.HandleFunc("/v1/embed/info", func(w http.ResponseWriter, _ *http.Request) {
				counts.info++
				writeEmbeddingCapability(w, current)
			})
			mux.HandleFunc("/v1/embed", func(w http.ResponseWriter, _ *http.Request) {
				counts.embed++
				_ = json.NewEncoder(w).Encode(map[string]any{"embedding": []float32{0.1, 0.2, 0.3}})
			})
			mux.HandleFunc("/v1/memory/submit", func(w http.ResponseWriter, r *http.Request) {
				counts.submit++
				assertCompatibilityEmbedding(t, r, current)
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"memory_id": "memory-remember", "status": "proposed", "committed": true,
					"embedding_queued": current,
				})
			})
			ts := httptest.NewServer(mux)
			defer ts.Close()

			_, privateKey, err := ed25519.GenerateKey(nil)
			require.NoError(t, err)
			result, rememberErr := NewServer(ts.URL, privateKey).toolRemember(
				context.Background(), map[string]any{
					"content": "A sufficiently distinct compatibility observation", "domain": "test",
				},
			)
			require.NoError(t, rememberErr)
			assert.Equal(t, "memory-remember", result.(map[string]any)["memory_id"])
			if current {
				assert.Equal(t, true, result.(map[string]any)["embedding_queued"])
				assert.Equal(t, "no_vector", result.(map[string]any)["store_mode"])
				assert.Equal(t, true, result.(map[string]any)["semantic_degraded"])
				assert.Contains(t, result.(map[string]any)["degraded_reason"], "re-embed")
			} else {
				assert.NotContains(t, result.(map[string]any), "embedding_queued")
			}
			assert.Equal(t, 1, counts.info)
			assert.Equal(t, 1, counts.submit)
			if current {
				assert.Zero(t, counts.embed)
			} else {
				assert.Equal(t, 1, counts.embed)
			}
		})
	}
}

func TestToolTaskEmbeddingCapabilityRequestCounts(t *testing.T) {
	for _, current := range []bool{false, true} {
		current := current
		name := "legacy"
		if current {
			name = "current"
		}
		t.Run(name, func(t *testing.T) {
			var counts embeddingRequestCounts
			mux := http.NewServeMux()
			mux.HandleFunc("/v1/embed/info", func(w http.ResponseWriter, _ *http.Request) {
				counts.info++
				writeEmbeddingCapability(w, current)
			})
			mux.HandleFunc("/v1/embed", func(w http.ResponseWriter, _ *http.Request) {
				counts.embed++
				_ = json.NewEncoder(w).Encode(map[string]any{"embedding": []float32{0.1, 0.2, 0.3}})
			})
			mux.HandleFunc("/v1/memory/submit", func(w http.ResponseWriter, r *http.Request) {
				counts.submit++
				assertCompatibilityEmbedding(t, r, current)
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"memory_id": "task-1", "status": "proposed", "task_status": "planned",
					"committed": true, "committed_height": 7, "embedding_queued": current,
				})
			})
			mux.HandleFunc("/v1/memory/tasks", func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"tasks": []map[string]any{{
						"memory_id": "task-1", "domain_tag": "test", "task_status": "planned",
						"assignee": r.Header.Get("X-Agent-ID"),
					}},
					"total": 1,
				})
			})
			ts := httptest.NewServer(mux)
			defer ts.Close()

			_, privateKey, err := ed25519.GenerateKey(nil)
			require.NoError(t, err)
			result, taskErr := NewServer(ts.URL, privateKey).toolTask(
				context.Background(), map[string]any{
					"content": "Verify compatibility request counts", "domain": "test", "status": "planned",
				},
			)
			require.NoError(t, taskErr)
			assert.Equal(t, "task-1", result.(map[string]any)["memory_id"])
			if current {
				assert.Equal(t, true, result.(map[string]any)["embedding_queued"])
				assert.Equal(t, "no_vector", result.(map[string]any)["store_mode"])
				assert.Equal(t, true, result.(map[string]any)["semantic_degraded"])
				assert.Contains(t, result.(map[string]any)["degraded_reason"], "re-embed")
			} else {
				assert.NotContains(t, result.(map[string]any), "embedding_queued")
			}
			assert.Equal(t, 1, counts.info)
			assert.Equal(t, 1, counts.submit)
			if current {
				assert.Zero(t, counts.embed)
			} else {
				assert.Equal(t, 1, counts.embed)
			}
		})
	}
}

func TestToolInceptionEmbeddingCapabilityRequestCounts(t *testing.T) {
	for _, current := range []bool{false, true} {
		current := current
		name := "legacy"
		if current {
			name = "current"
		}
		t.Run(name, func(t *testing.T) {
			var counts embeddingRequestCounts
			mux := http.NewServeMux()
			mux.HandleFunc("/v1/agent/register", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"agent_id": "fresh-agent", "name": "fresh-agent", "status": "already_registered",
				})
			})
			mux.HandleFunc("/v1/memory/list", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"total": 0})
			})
			mux.HandleFunc("/v1/embed/info", func(w http.ResponseWriter, _ *http.Request) {
				counts.info++
				writeEmbeddingCapability(w, current)
			})
			mux.HandleFunc("/v1/embed", func(w http.ResponseWriter, _ *http.Request) {
				counts.embed++
				_ = json.NewEncoder(w).Encode(map[string]any{"embedding": []float32{0.1, 0.2, 0.3}})
			})
			mux.HandleFunc("/v1/memory/submit", func(w http.ResponseWriter, r *http.Request) {
				counts.submit++
				assertCompatibilityEmbedding(t, r, current)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"memory_id": fmt.Sprintf("seed-%d", counts.submit), "status": "proposed",
					"embedding_queued": current,
				})
			})
			ts := httptest.NewServer(mux)
			defer ts.Close()

			_, privateKey, err := ed25519.GenerateKey(nil)
			require.NoError(t, err)
			result, inceptionErr := NewServer(ts.URL, privateKey).toolInception(context.Background(), nil)
			require.NoError(t, inceptionErr)
			assert.Equal(t, "inception_complete", result.(map[string]any)["status"])
			assert.Equal(t, 5, counts.submit)
			if current {
				assert.Equal(t, 5, result.(map[string]any)["embeddings_queued"])
				assert.Equal(t, true, result.(map[string]any)["semantic_degraded"])
				assert.Contains(t, result.(map[string]any)["embedding_notice"], "queued")
			} else {
				assert.NotContains(t, result.(map[string]any), "embeddings_queued")
			}
			wantInfo := 1
			if current {
				wantInfo = 5
			}
			assert.Equal(t, wantInfo, counts.info)
			if current {
				assert.Zero(t, counts.embed)
			} else {
				assert.Equal(t, 5, counts.embed)
			}
		})
	}
}

func TestServerEmbedsSubmissionsDoesNotCacheUnsafePositive(t *testing.T) {
	var infoCalls int
	current := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/embed/info", r.URL.Path)
		infoCalls++
		writeEmbeddingCapability(w, current)
	}))
	defer srv.Close()

	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	server := NewServer(srv.URL, privateKey)
	assert.True(t, server.serverEmbedsSubmissions(context.Background()))
	current = false
	assert.False(t, server.serverEmbedsSubmissions(context.Background()))
	assert.Equal(t, 2, infoCalls)
}
