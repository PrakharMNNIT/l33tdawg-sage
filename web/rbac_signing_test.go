package web

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/tx"
)

func TestLatestConsensusTimeWeb(t *testing.T) {
	want := time.Date(2026, 8, 5, 6, 14, 18, 0, time.UTC)
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/status", r.URL.Path)
		_, _ = fmt.Fprintf(w, `{"result":{"sync_info":{"latest_block_time":%q}}}`, want.Format(time.RFC3339Nano))
	}))
	t.Cleanup(rpc.Close)

	got, err := latestConsensusTimeWeb(rpc.URL)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestLatestConsensusTimeWebRejectsTrailingAndOversizedData(t *testing.T) {
	want := time.Date(2026, 8, 5, 6, 14, 18, 0, time.UTC)
	proof := fmt.Sprintf(`{"result":{"sync_info":{"latest_block_time":%q}}}`,
		want.Format(time.RFC3339Nano))
	for _, tc := range []struct {
		name   string
		suffix string
	}{
		{name: "second JSON document", suffix: `{}`},
		{name: "oversized whitespace suffix", suffix: strings.Repeat(" ", int(tx.CometRPCMaxResponseBytes)+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprint(w, proof+tc.suffix)
			}))
			t.Cleanup(rpc.Close)

			got, err := latestConsensusTimeWeb(rpc.URL)
			require.Error(t, err)
			assert.True(t, got.IsZero())
		})
	}
}

func TestFreshGovernanceProofTimeUsesWallClockAfterIdle(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 30, 0, 0, time.UTC)
	latest := now.Add(-6 * time.Minute)

	got, err := freshGovernanceProofTime(now, latest)
	require.NoError(t, err)
	assert.Equal(t, now, got,
		"a newly signed transfer proof must not inherit an idle chain's stale block time")
}

func TestFreshGovernanceProofTimeUsesNewerCommittedClockWithinWindow(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 30, 0, 0, time.UTC)
	latest := now.Add(4 * time.Minute)

	got, err := freshGovernanceProofTime(now, latest)
	require.NoError(t, err)
	assert.Equal(t, latest, got)
}

func TestFreshGovernanceProofTimeRejectsCommittedClockTooFarAhead(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 30, 0, 0, time.UTC)

	_, err := freshGovernanceProofTime(now, now.Add(governanceProofClockSkew+time.Second))
	require.ErrorContains(t, err, "ahead of host time")
}

func TestConsensusTimedGovernanceProofAfterIdleUsesFreshProof(t *testing.T) {
	idleBlockTime := time.Now().Add(-6 * time.Minute)
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"result":{"sync_info":{"latest_block_time":%q}}}`, idleBlockTime.Format(time.RFC3339Nano))
	}))
	t.Cleanup(rpc.Close)
	_, operatorKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	ptx := &tx.ParsedTx{Type: tx.TxTypeGovPropose, GovPropose: &tx.GovPropose{}}

	h := &DashboardHandler{CometBFTRPC: rpc.URL, ConsensusGovernanceClock: true}
	before := time.Now().Unix()
	require.NoError(t, h.embedConsensusTimedGovernanceProof(
		ptx, operatorKey, http.MethodPost, "/v1/governance/propose", []byte(`{}`),
	))
	after := time.Now().Unix()
	assert.GreaterOrEqual(t, ptx.AgentTimestamp, before)
	assert.LessOrEqual(t, ptx.AgentTimestamp, after)
	assert.NotEqual(t, idleBlockTime.Unix(), ptx.AgentTimestamp)
}

func TestConsensusTimedGovernanceProofFailsClosedWithoutCommittedClock(t *testing.T) {
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(rpc.Close)
	_, operatorKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	ptx := &tx.ParsedTx{Type: tx.TxTypeGovPropose, GovPropose: &tx.GovPropose{}}

	h := &DashboardHandler{CometBFTRPC: rpc.URL, ConsensusGovernanceClock: true}
	err = h.embedConsensusTimedGovernanceProof(
		ptx, operatorKey, http.MethodPost, "/v1/governance/propose", []byte(`{}`),
	)
	require.ErrorContains(t, err, "read committed consensus time")
	assert.Zero(t, ptx.AgentTimestamp)
}

func TestRetryGovernanceProofAtCommittedTimeAfterIdleRejection(t *testing.T) {
	want := time.Date(2026, 8, 6, 7, 42, 22, 0, time.UTC)
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/status", r.URL.Path)
		_, _ = fmt.Fprintf(w, `{"result":{"sync_info":{"latest_block_time":%q}}}`, want.Format(time.RFC3339Nano))
	}))
	t.Cleanup(rpc.Close)
	_, operatorKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	ptx := &tx.ParsedTx{Type: tx.TxTypeGovPropose, GovPropose: &tx.GovPropose{}}
	h := &DashboardHandler{CometBFTRPC: rpc.URL}

	retried, err := h.retryGovernanceProofAtCommittedTime(
		ptx,
		operatorKey,
		http.MethodPost,
		"/v1/governance/propose",
		[]byte(`{}`),
		fmt.Errorf("tx rejected in FinalizeBlock (code 109): agent proof rejected: %s", governanceProofAheadOfConsensus),
	)
	require.NoError(t, err)
	assert.True(t, retried)
	assert.Equal(t, want.Unix(), ptx.AgentTimestamp)
	assert.Len(t, ptx.AgentNonce, 8)
}

func TestRetryGovernanceProofAtCommittedTimeIgnoresOtherFailures(t *testing.T) {
	h := &DashboardHandler{CometBFTRPC: "http://unused.invalid"}
	retried, err := h.retryGovernanceProofAtCommittedTime(
		&tx.ParsedTx{}, nil, http.MethodPost, "/v1/governance/propose", nil,
		fmt.Errorf("governance propose failed: proposer is in cooldown"),
	)
	require.NoError(t, err)
	assert.False(t, retried)
}

func TestSignAndBroadcastCommitLeavesDirectGovernanceProofless(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	var captured *tx.ParsedTx
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.URL.Query().Get("tx"), "0x")
		encoded, decodeErr := hex.DecodeString(raw)
		require.NoError(t, decodeErr)
		captured, decodeErr = tx.DecodeTx(encoded)
		require.NoError(t, decodeErr)
		writeCommitOK(w, r)
	}))
	t.Cleanup(rpc.Close)

	h := &DashboardHandler{CometBFTRPC: rpc.URL}
	_, _, _, err = h.signAndBroadcastCommit(&tx.ParsedTx{
		Type: tx.TxTypeGovPropose,
		GovPropose: &tx.GovPropose{
			Operation: tx.GovOpDomainReassign,
			TargetID:  "quiettype-pages",
		},
	}, key)
	require.NoError(t, err)
	require.NotNil(t, captured)

	assert.NotEmpty(t, captured.PublicKey, "outer operator signature remains authoritative")
	assert.Equal(t, make([]byte, len(captured.AgentPubKey)), []byte(captured.AgentPubKey))
	assert.Equal(t, make([]byte, len(captured.AgentSig)), []byte(captured.AgentSig))
	assert.Equal(t, make([]byte, len(captured.AgentBodyHash)), captured.AgentBodyHash)
	assert.Empty(t, captured.AgentNonce)
	assert.Empty(t, captured.AgentRequest)
}

func TestSignAndBroadcastCommitKeepsAgentProofForAccessGrant(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	var captured *tx.ParsedTx
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.URL.Query().Get("tx"), "0x")
		encoded, decodeErr := hex.DecodeString(raw)
		require.NoError(t, decodeErr)
		captured, decodeErr = tx.DecodeTx(encoded)
		require.NoError(t, decodeErr)
		writeCommitOK(w, r)
	}))
	t.Cleanup(rpc.Close)

	h := &DashboardHandler{CometBFTRPC: rpc.URL}
	_, _, _, err = h.signAndBroadcastCommit(&tx.ParsedTx{
		Type: tx.TxTypeAccessGrant,
		AccessGrant: &tx.AccessGrant{
			GranterID: agentIDForKey(key),
			GranteeID: "agent-b",
			Domain:    "sage-rbac",
			Level:     2,
		},
	}, key)
	require.NoError(t, err)
	require.NotNil(t, captured)

	assert.NotEmpty(t, captured.AgentPubKey)
	assert.NotEmpty(t, captured.AgentSig)
	assert.NotEmpty(t, captured.AgentBodyHash)
}

func TestSignAndBroadcastCommitPreservesModernGovernanceProof(t *testing.T) {
	_, outerKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_, operatorKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	var captured *tx.ParsedTx
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.URL.Query().Get("tx"), "0x")
		encoded, decodeErr := hex.DecodeString(raw)
		require.NoError(t, decodeErr)
		captured, decodeErr = tx.DecodeTx(encoded)
		require.NoError(t, decodeErr)
		writeCommitOK(w, r)
	}))
	t.Cleanup(rpc.Close)

	ptx := &tx.ParsedTx{
		Type: tx.TxTypeGovPropose,
		GovPropose: &tx.GovPropose{
			Operation: tx.GovOpDomainReassign,
			TargetID:  "quiettype-pages",
			Reason:    "transfer to application identity",
			Payload:   []byte(`{"domain":"quiettype-pages"}`),
		},
	}
	proofBody := []byte(`{"validator_id":"validator","governance_domain":"domain","operation":"domain_reassign","target_id":"quiettype-pages","reason":"transfer to application identity","payload":"e30="}`)
	require.NoError(t, embedDashboardGovernanceProof(
		ptx,
		operatorKey,
		http.MethodPost,
		"/v1/governance/propose",
		proofBody,
	))

	h := &DashboardHandler{CometBFTRPC: rpc.URL}
	_, _, _, err = h.signAndBroadcastCommit(ptx, outerKey)
	require.NoError(t, err)
	require.NotNil(t, captured)

	assert.Equal(t, []byte(outerKey.Public().(ed25519.PublicKey)), []byte(captured.PublicKey))
	assert.Equal(t, []byte(operatorKey.Public().(ed25519.PublicKey)), []byte(captured.AgentPubKey))
	assert.Len(t, captured.AgentNonce, 8)
	assert.Equal(t, []byte("POST /v1/governance/propose\n"+string(proofBody)), captured.AgentRequest)
}
