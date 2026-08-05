package ollamad

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModelReadyRequiresEmbeddingProbe(t *testing.T) {
	for _, tc := range []struct {
		name      string
		dim       int
		wantReady bool
	}{
		{name: "tag only is not enough", dim: 0, wantReady: false},
		{name: "wrong dimension is refused", dim: 12, wantReady: false},
		{name: "expected embedding dimension passes", dim: ModelDimension, wantReady: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/tags":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"models": []map[string]any{{"name": ModelName + ":latest"}},
					})
				case "/api/embed":
					if tc.dim == 0 {
						http.Error(w, "model not loadable", http.StatusInternalServerError)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"embeddings": [][]float32{make([]float32, tc.dim)},
					})
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			m := New(t.TempDir())
			m.port = testServerPort(t, srv)
			assert.Equal(t, tc.wantReady, m.ModelReady(context.Background()))
		})
	}
}

func TestConfiguredModelReadyUsesExactModelAndDimension(t *testing.T) {
	const model = "snowflake-arctic-embed:xs"
	const dimension = 384
	for _, tc := range []struct {
		name      string
		dim       int
		wantReady bool
	}{
		{name: "configured dimension passes", dim: dimension, wantReady: true},
		{name: "silent legacy dimension is refused", dim: ModelDimension, wantReady: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var probedModel string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/tags":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"models": []map[string]any{{"name": model}},
					})
				case "/api/embed":
					var request struct {
						Model string `json:"model"`
					}
					require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
					probedModel = request.Model
					_ = json.NewEncoder(w).Encode(map[string]any{
						"embeddings": [][]float32{make([]float32, tc.dim)},
					})
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			manager, err := NewConfigured(t.TempDir(), model, dimension)
			require.NoError(t, err)
			manager.port = testServerPort(t, srv)
			assert.Equal(t, tc.wantReady, manager.ModelReady(context.Background()))
			assert.Equal(t, model, probedModel)
		})
	}
}

func TestNewConfiguredRejectsAmbiguousVectorSpace(t *testing.T) {
	_, err := NewConfigured(t.TempDir(), "", 384)
	require.ErrorContains(t, err, "model is required")
	_, err = NewConfigured(t.TempDir(), "small", 0)
	require.ErrorContains(t, err, "dimension must be positive")
}

func testServerPort(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	n, err := strconv.Atoi(port)
	require.NoError(t, err)
	return n
}
