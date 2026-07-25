package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleHealthPrefersLiveABCIAppVersionOverStaleHandshake(t *testing.T) {
	tests := []struct {
		name           string
		statusOK       bool
		abciStatus     int
		abciBody       string
		wantAppVersion string
	}{
		{
			name:           "live ABCI overrides stale handshake",
			statusOK:       true,
			abciStatus:     http.StatusOK,
			abciBody:       `{"result":{"response":{"app_version":"21"}}}`,
			wantAppVersion: "21",
		},
		{
			name:           "ABCI non-2xx keeps handshake fallback",
			statusOK:       true,
			abciStatus:     http.StatusBadGateway,
			abciBody:       `{"result":{"response":{"app_version":"21"}}}`,
			wantAppVersion: "20",
		},
		{
			name:           "malformed ABCI keeps handshake fallback",
			statusOK:       true,
			abciStatus:     http.StatusOK,
			abciBody:       `{not-json`,
			wantAppVersion: "20",
		},
		{
			name:           "empty ABCI version keeps handshake fallback",
			statusOK:       true,
			abciStatus:     http.StatusOK,
			abciBody:       `{"result":{"response":{"app_version":""}}}`,
			wantAppVersion: "20",
		},
		{
			name:           "valid ABCI still works when status fails",
			statusOK:       false,
			abciStatus:     http.StatusOK,
			abciBody:       `{"result":{"response":{"app_version":"21"}}}`,
			wantAppVersion: "21",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/status":
					if !tt.statusOK {
						http.Error(w, "status unavailable", http.StatusServiceUnavailable)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"result": map[string]any{
							"node_info": map[string]any{
								"network": "sage-test",
								"moniker": "test-node",
								"protocol_version": map[string]string{
									"app": "20",
								},
							},
							"sync_info": map[string]any{
								"latest_block_height": "19666",
								"latest_block_time":   time.Now().UTC().Format(time.RFC3339Nano),
								"latest_app_hash":     "ABC123",
								"catching_up":         false,
							},
							"validator_info": map[string]string{"voting_power": "10"},
						},
					})
				case "/abci_info":
					w.WriteHeader(tt.abciStatus)
					_, _ = w.Write([]byte(tt.abciBody))
				case "/num_unconfirmed_txs":
					_, _ = w.Write([]byte(`{"result":{"n_txs":"0","total_bytes":"0"}}`))
				case "/net_info":
					_, _ = w.Write([]byte(`{"result":{"n_peers":"0","peers":[]}}`))
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(rpc.Close)

			h, _ := newTestHandler(t)
			h.CometBFTRPC = rpc.URL
			h.SetEmbedder(hashOnlyEmbedder{})

			health := doHealth(t, h)
			chain, ok := health["chain"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, tt.wantAppVersion, chain["app_version"])
			if tt.statusOK {
				assert.Equal(t, "19666", chain["block_height"])
			}
		})
	}
}
