package mcp

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMCPFederatedRecallPlanExpandsAndSignsExactDestinationState(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	server := NewServer("http://localhost:8080", key)
	var finalBody map[string]any
	server.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, readErr := io.ReadAll(req.Body)
		require.NoError(t, readErr)
		switch req.URL.Path {
		case "/v1/federation/recall-plan":
			var preflight map[string]any
			require.NoError(t, json.Unmarshal(body, &preflight))
			require.Equal(t, "research", preflight["domain_tag"])
			return &http.Response{
				StatusCode: http.StatusOK, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{
					"protocol_version":23,
					"source_chain_id":"chain-local",
					"destinations":["chain-x"],
					"agreement_bindings":{"chain-x":"binding-x"},
					"query_challenges":{"chain-x":"challenge-x"},
					"authorization_models":{"chain-x":"peer-export-v1"},
					"authorization_attestations":{"chain-x":{"eligible":true,"max_classification":3}},
					"expires_at":{"chain-x":9999999999}
				}`)),
			}, nil
		case "/v1/memory/search":
			require.NoError(t, json.Unmarshal(body, &finalBody))
			return &http.Response{
				StatusCode: http.StatusOK, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{"results":[],"total_count":0}`)),
			}, nil
		default:
			t.Fatalf("unexpected path %s", req.URL.Path)
			return nil, nil
		}
	})}

	request := recallRequest{
		"query": "needle", "domain_tag": "research", "provider": "test",
	}
	require.NoError(t, server.applyRecallFederation(
		context.Background(), request,
		recallFederationOptions{Federated: true, Chains: []string{"*"}},
	))
	body, err := json.Marshal(request)
	require.NoError(t, err)
	var out recallResp
	require.NoError(t, server.doSignedJSON(
		context.Background(), http.MethodPost, "/v1/memory/search", body, &out,
	))
	require.Equal(t, []any{"chain-x"}, finalBody["federate_chains"])
	contextBody := finalBody["federation_context"].(map[string]any)
	require.Equal(t, "chain-local", contextBody["source_chain_id"])
	require.Equal(t, "binding-x", contextBody["agreement_bindings"].(map[string]any)["chain-x"])
	require.Equal(t, "challenge-x", contextBody["query_challenges"].(map[string]any)["chain-x"])
	require.Equal(t, "peer-export-v1", contextBody["authorization_models"].(map[string]any)["chain-x"])
	attestation := contextBody["authorization_attestations"].(map[string]any)["chain-x"].(map[string]any)
	require.Equal(t, true, attestation["eligible"])
	require.Equal(t, float64(3), attestation["max_classification"])
}

func TestMCPFederatedVectorRecallSignsDiscoveredEmbeddingProvider(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
		call func(*Server, *recallResp) error
	}{
		{
			name: "semantic",
			path: "/v1/memory/query",
			call: func(server *Server, out *recallResp) error {
				return server.recallSemantic(
					context.Background(), "needle", "research", 5, 0.3,
					recallFederationOptions{Federated: true, Chains: []string{"chain-x"}}, out,
				)
			},
		},
		{
			name: "hybrid",
			path: "/v1/memory/hybrid",
			call: func(server *Server, out *recallResp) error {
				return server.recallHybrid(
					context.Background(), "needle", "research", 5, 0.3,
					recallFederationOptions{Federated: true, Chains: []string{"chain-x"}}, out,
				)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, key, err := ed25519.GenerateKey(nil)
			require.NoError(t, err)
			server := NewServer("http://localhost:8080", key)
			var finalBody map[string]any
			server.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body, readErr := io.ReadAll(req.Body)
				require.NoError(t, readErr)
				response := func(payload string) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK, Header: make(http.Header),
						Body: io.NopCloser(strings.NewReader(payload)),
					}, nil
				}
				switch req.URL.Path {
				case "/v1/embed":
					return response(`{
						"embedding":[0.1,0.2,0.3],
						"model":"model-a",
						"embedding_provider":"ollama:model-a:3",
						"dimension":3
					}`)
				case "/v1/federation/recall-plan":
					return response(`{
						"protocol_version":23,
						"source_chain_id":"chain-local",
						"destinations":["chain-x"],
						"agreement_bindings":{"chain-x":"binding-x"},
						"query_challenges":{"chain-x":"challenge-x"},
						"authorization_models":{"chain-x":"peer-export-v1"},
						"authorization_attestations":{"chain-x":{"eligible":true,"max_classification":4}},
						"expires_at":{"chain-x":9999999999}
					}`)
				case test.path:
					require.NoError(t, json.Unmarshal(body, &finalBody))
					return response(`{"results":[],"total_count":0}`)
				default:
					t.Fatalf("unexpected path %s", req.URL.Path)
					return nil, nil
				}
			})}

			var out recallResp
			require.NoError(t, test.call(server, &out))
			require.Equal(t, "ollama:model-a:3", finalBody["embedding_provider"])
			require.Equal(t, true, finalBody["federated"])
			require.Equal(t, []any{"chain-x"}, finalBody["federate_chains"])
		})
	}
}
