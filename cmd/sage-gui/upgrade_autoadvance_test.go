package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sageabci "github.com/l33tdawg/sage/internal/abci"
)

// TestPickAutoAdvanceTarget pins the ladder policy: below the frozen PoE
// target the auto-advance proposes the legacy skip-ahead (6, backfilled by
// reconcilePoEForkMonotonicity); from 6 upward the independent gates activate
// strictly one at a time; at the binary ceiling it stops.
func TestPickAutoAdvanceTarget(t *testing.T) {
	maxV := sageabci.MaxSupportedAppVersion()

	assert.Equal(t, uint64(6), pickAutoAdvanceTarget(1, maxV), "fresh chain skip-aheads to the PoE target")
	assert.Equal(t, uint64(6), pickAutoAdvanceTarget(5, maxV))
	assert.Equal(t, uint64(7), pickAutoAdvanceTarget(6, maxV), "independent gates walk one at a time")
	assert.Equal(t, uint64(12), pickAutoAdvanceTarget(11, maxV))
	assert.Equal(t, uint64(13), pickAutoAdvanceTarget(12, maxV))
	assert.Equal(t, uint64(0), pickAutoAdvanceTarget(maxV, maxV), "at the ceiling: done")
	assert.Equal(t, uint64(0), pickAutoAdvanceTarget(maxV+1, maxV), "past the ceiling (newer chain than binary): done, never regress")
}

func TestPersonalAutoAdvanceCeilingHonorsMandatoryFloor(t *testing.T) {
	const maxV = uint64(25)

	assert.Equal(t, uint64(0), personalAutoAdvanceCeiling(upgradeWatchdogConfig{
		PersonalMode: false, AutoAdvance: true, RequiredAppVersion: 24,
	}, maxV), "quorum networks never inherit personal-node forced activation")
	assert.Equal(t, maxV, personalAutoAdvanceCeiling(upgradeWatchdogConfig{
		PersonalMode: true, AutoAdvance: true, RequiredAppVersion: 24,
	}, maxV), "ordinary personal auto-advance reaches the binary ceiling")
	assert.Equal(t, maxV, personalAutoAdvanceCeiling(upgradeWatchdogConfig{
		PersonalMode: true, AutoAdvance: false, RequiredAppVersion: 24,
	}, maxV), "disable_auto_upgrade cannot suppress consensus migrations")
	assert.Equal(t, maxV, personalAutoAdvanceCeiling(upgradeWatchdogConfig{
		PersonalMode: true, AutoAdvance: false, RequiredAppVersion: 26,
	}, maxV), "personal nodes always stop at compiled support")
}

// scriptedCommitRPC scripts /broadcast_tx_commit responses for outcome
// classification tests.
func scriptedCommitRPC(t *testing.T, checkCode, txCode uint32, txLog string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := hex.DecodeString(strings.TrimPrefix(r.URL.Query().Get("tx"), "0x"))
		require.NoError(t, err)
		hash := sha256.Sum256(raw)
		resp := map[string]any{
			"result": map[string]any{
				"hash":   fmt.Sprintf("%X", hash),
				"height": "42",
				"check_tx": map[string]any{
					"code": checkCode,
					"log":  "",
				},
				"tx_result": map[string]any{
					"code": txCode,
					"log":  txLog,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func autoAdvanceTestCfg(t *testing.T, rpc string) upgradeWatchdogConfig {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return upgradeWatchdogConfig{
		BinaryVersion: "test",
		AgentKey:      priv,
		CometRPC:      rpc,
		Logger:        zerolog.Nop(),
	}
}

// TestProposeForAutoAdvance_OutcomeClassification pins the mapping from
// block-execution results to the auto-advance state machine: success →
// proposed, at-most-one-pending → pending, the admin gate (code 47, both the
// "not registered" and "not an admin" shapes) → terminal admin rejection
// with operator guidance, anything else → transient retry.
func TestProposeForAutoAdvance_OutcomeClassification(t *testing.T) {
	cases := []struct {
		name      string
		checkCode uint32
		txCode    uint32
		txLog     string
		want      autoAdvanceOutcome
	}{
		{"accepted", 0, 0, "upgrade plan accepted", autoAdvanceProposed},
		{"already pending", 0, 47, "an upgrade plan is already pending (at-most-one-pending invariant)", autoAdvancePending},
		{"admin gate: unregistered proposer", 0, 47, "upgrade propose: proposer not registered: Key not found", autoAdvanceAdminRejected},
		{"admin gate: non-admin proposer", 0, 47, "upgrade propose: proposer must be an admin agent", autoAdvanceAdminRejected},
		{"transient garbage", 0, 99, "some other rejection", autoAdvanceTransient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := scriptedCommitRPC(t, tc.checkCode, tc.txCode, tc.txLog)
			defer srv.Close()
			cfg := autoAdvanceTestCfg(t, srv.URL)
			got := proposeForAutoAdvance(context.Background(), cfg, 9)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestReadChainAppVersionAndHeight pins the string-serialized uint64 parsing
// of /abci_info (CometBFT JSON-RPC serializes both fields as strings).
func TestReadChainAppVersionAndHeight(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"result":{"response":{"app_version":"12","last_block_height":"1387575"}}}`)
	}))
	defer srv.Close()

	version, height, err := readChainAppVersionAndHeight(context.Background(), srv.URL)
	require.NoError(t, err)
	assert.Equal(t, uint64(12), version)
	assert.Equal(t, int64(1387575), height)
}
