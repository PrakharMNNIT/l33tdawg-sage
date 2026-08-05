package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunBenchmarkOllamaContractAndRequestCounts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/embed", r.URL.Path)
		var request struct {
			Input any `json:"input"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		count := inputCount(request.Input)
		vectors := make([][]float64, count)
		for i := range vectors {
			vectors[i] = []float64{float64(i), 1, 2}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"embeddings": vectors})
	}))
	defer server.Close()

	result, err := runBenchmark(context.Background(), config{
		Provider: "ollama", BaseURL: server.URL, Model: "small", Dimension: 3,
		Timeout: time.Second, ScalarRuns: 3, BatchSize: 4,
	})
	require.NoError(t, err)
	require.Len(t, result.Phases, 3)
	assert.Equal(t, "cold_scalar", result.Phases[0].Name)
	assert.True(t, result.Phases[0].Controlled)
	assert.Equal(t, int64(1), result.Phases[0].Requests)
	assert.Equal(t, int64(3), result.Phases[1].Requests)
	assert.Equal(t, int64(1), result.Phases[2].Requests)
	assert.Equal(t, 4, result.Phases[2].Items)
}

func TestRunBenchmarkRejectsDimensionAndCardinalityMismatch(t *testing.T) {
	for _, test := range []struct {
		name      string
		handler   http.HandlerFunc
		wantError string
	}{
		{
			name: "dimension",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"embeddings": [][]float64{{1, 2}}})
			},
			wantError: "dimension mismatch",
		},
		{
			name: "batch_cardinality",
			handler: func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					Input any `json:"input"`
				}
				require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
				count := inputCount(request.Input)
				if count > 1 {
					count--
				}
				vectors := make([][]float64, count)
				for i := range vectors {
					vectors[i] = []float64{1, 2, 3}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"embeddings": vectors})
			},
			wantError: "cardinality mismatch",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			_, err := runBenchmark(context.Background(), config{
				Provider: "ollama", BaseURL: server.URL, Model: "small", Dimension: 3,
				Timeout: time.Second, ScalarRuns: 1, BatchSize: 3,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.wantError)
		})
	}
}

func TestRunBenchmarkOpenAIWithoutResetDoesNotClaimCold(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/embeddings", r.URL.Path)
		var request struct {
			Input any `json:"input"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		count := inputCount(request.Input)
		data := make([]map[string]any, count)
		for i := range data {
			data[i] = map[string]any{"index": i, "embedding": []float64{1, 2}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	defer server.Close()

	result, err := runBenchmark(context.Background(), config{
		Provider: "openai-compatible", BaseURL: server.URL, Model: "tei", Dimension: 2,
		Timeout: time.Second, ScalarRuns: 1, BatchSize: 2,
	})
	require.NoError(t, err)
	assert.Equal(t, "first_observed_scalar", result.Phases[0].Name)
	assert.False(t, result.Phases[0].Controlled)
	assert.Contains(t, result.Phases[0].ControlNote, "no standard unload API")
}

func TestRunBenchmarkProviderFailureReturnsNoResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	result, err := runBenchmark(context.Background(), config{
		Provider: "ollama", BaseURL: server.URL, Model: "small", Dimension: 3,
		Timeout: time.Second, ScalarRuns: 1, BatchSize: 2,
	})
	require.Error(t, err)
	assert.Nil(t, result, "failed runs must not expose partial benchmark measurements")
	assert.Contains(t, err.Error(), "HTTP 503")
}

func inputCount(input any) int {
	if values, ok := input.([]any); ok {
		return len(values)
	}
	return 1
}
