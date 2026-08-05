package embedding

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noEmbedBackoff makes the retry loop instantaneous for tests.
func noEmbedBackoff(t *testing.T) {
	t.Helper()
	orig := embedRetryBackoffs
	embedRetryBackoffs = []time.Duration{0, 0}
	t.Cleanup(func() { embedRetryBackoffs = orig })
}

// TestOllamaEmbed_RetriesTransientAndSendsKeepAlive is the core guard for the
// intermittent-embed-failure fix: a transient 503 (Ollama loading the model after an
// idle unload) is retried and succeeds, and every request carries keep_alive so the
// model stays resident between sage_turn calls.
func TestOllamaEmbed_RetriesTransientAndSendsKeepAlive(t *testing.T) {
	noEmbedBackoff(t)

	var calls int32
	var sawKeepAlive any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		body, _ := io.ReadAll(r.Body)
		var req embedRequest
		_ = json.Unmarshal(body, &req)
		if n == 1 {
			sawKeepAlive = req.KeepAlive
		}
		if n < 3 { // first two attempts: transient failure
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(embedResponse{Embeddings: [][]float64{make([]float64, Dimension)}})
	}))
	defer srv.Close()

	emb, err := NewClient(srv.URL, "nomic-embed-text").Embed(context.Background(), "hello")
	require.NoError(t, err, "must succeed after retrying the transient 503s")
	assert.Len(t, emb, Dimension)
	assert.Equal(t, int32(3), atomic.LoadInt32(&calls), "1 initial + 2 retries")
	assert.NotNil(t, sawKeepAlive, "keep_alive must be sent to keep the model resident")
}

// TestOllamaEmbed_KeepAliveGrammar guards the HIGH regression: Ollama's JSON keep_alive
// field accepts a duration STRING or a NUMBER, but an integer AS A STRING
// ({"keep_alive":"-1"}) 400s. Users commonly export OLLAMA_KEEP_ALIVE=-1 (the server env
// var accepts it), so an integer-form value must go on the wire as a JSON number, not a
// string, and an unparseable value must fall back to a valid duration.
func TestOllamaEmbed_KeepAliveGrammar(t *testing.T) {
	noEmbedBackoff(t)
	cases := []struct{ env, wantJSON string }{
		{"", `"30m"`},        // default → duration string
		{"-1", `-1`},         // pin → JSON number (NOT the string "-1")
		{"300", `300`},       // seconds → JSON number
		{"24h", `"24h"`},     // duration string passthrough
		{"garbage", `"30m"`}, // unparseable → fall back, never 400 every embed
	}
	for _, tc := range cases {
		t.Run("env="+tc.env, func(t *testing.T) {
			t.Setenv("OLLAMA_KEEP_ALIVE", tc.env)
			var gotKA json.RawMessage
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					KeepAlive json.RawMessage `json:"keep_alive"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				gotKA = req.KeepAlive
				_ = json.NewEncoder(w).Encode(embedResponse{Embeddings: [][]float64{make([]float64, Dimension)}})
			}))
			defer srv.Close()

			_, err := NewClient(srv.URL, "nomic-embed-text").Embed(context.Background(), "x")
			require.NoError(t, err)
			assert.JSONEq(t, tc.wantJSON, string(gotKA), "keep_alive wire form for OLLAMA_KEEP_ALIVE=%q", tc.env)
		})
	}
}

// TestOllamaEmbed_DoesNotRetry4xx: a 4xx is a real client error (bad model/request),
// not transient — it must fail fast, not burn the retry budget.
func TestOllamaEmbed_DoesNotRetry4xx(t *testing.T) {
	noEmbedBackoff(t)

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL, "nomic-embed-text").Embed(context.Background(), "hello")
	require.Error(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "4xx must not be retried")
}

// TestOllamaEmbed_TimeoutNotRetried: a hung/overloaded Ollama (request times out)
// must NOT be retried — retrying would just triple the wait (each attempt pays the
// full timeout). Connection blips retry; hangs fail fast.
func TestOllamaEmbed_TimeoutNotRetried(t *testing.T) {
	noEmbedBackoff(t)

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(200 * time.Millisecond) // hang past the caller's deadline
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := NewClient(srv.URL, "nomic-embed-text").Embed(ctx, "hello")
	require.Error(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "a timeout must not be retried")
}

// TestOllamaEmbed_PersistentTransientExhaustsRetries: a genuinely-down embedder fails
// after exhausting the bounded retry budget (it does not loop forever).
func TestOllamaEmbed_PersistentTransientExhaustsRetries(t *testing.T) {
	noEmbedBackoff(t)

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL, "nomic-embed-text").Embed(context.Background(), "hello")
	require.Error(t, err)
	assert.Equal(t, int32(3), atomic.LoadInt32(&calls), "1 initial + 2 retries, then give up")
}

func TestOllamaEmbed_ConfigurableDimensionAndBatch(t *testing.T) {
	const dimension = 3
	var input []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Input []string `json:"input"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		input = req.Input
		_ = json.NewEncoder(w).Encode(embedResponse{Embeddings: [][]float64{
			{1, 2, 3}, {4, 5, 6},
		}})
	}))
	defer srv.Close()

	client := NewClientWithDimension(srv.URL, "all-minilm:l6-v2", dimension)
	vectors, err := client.EmbedBatch(context.Background(), []string{"one", "two"})
	require.NoError(t, err)
	assert.Equal(t, []string{"one", "two"}, input)
	assert.Len(t, vectors, 2)
	assert.Len(t, vectors[0], dimension)
	assert.Equal(t, dimension, client.Dimension())
	assert.Equal(t, "ollama:all-minilm:l6-v2:3", SpaceID(client))
}

func TestOllamaEmbed_RejectsConfiguredDimensionMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(embedResponse{Embeddings: [][]float64{{1, 2}}})
	}))
	defer srv.Close()

	_, err := NewClientWithDimension(srv.URL, "small", 3).Embed(context.Background(), "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dimension mismatch")
}

func TestEmbeddingHTTPTimeoutConfiguration(t *testing.T) {
	t.Setenv("SAGE_EMBEDDING_TIMEOUT", "75s")
	ollama := NewClient("http://localhost", "")
	openAI := NewOpenAICompatibleClient("http://localhost", "m", "", 3)
	assert.Equal(t, 75*time.Second, ollama.httpClient.Timeout)
	assert.Equal(t, 75*time.Second, openAI.httpClient.Timeout)
}
