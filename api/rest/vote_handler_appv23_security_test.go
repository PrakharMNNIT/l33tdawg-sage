package rest

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/auth"
	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/tx"
)

func TestAppV23MemoryVoteIsLocalOperatorOnlyAndValidatorBound(t *testing.T) {
	fixture := newAppV23RESTRouteFixture(t)

	_, validatorKey, err := auth.GenerateKeypair()
	require.NoError(t, err)
	require.NoError(t, fixture.server.SetValidatorSigningKey(validatorKey))

	var broadcasts atomic.Int32
	var captured []*tx.ParsedTx
	comet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		broadcasts.Add(1)
		raw, decodeErr := hex.DecodeString(strings.TrimPrefix(r.URL.Query().Get("tx"), "0x"))
		require.NoError(t, decodeErr)
		parsed, decodeErr := tx.DecodeTx(raw)
		require.NoError(t, decodeErr)
		captured = append(captured, parsed)
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"check_tx":  map[string]any{"code": 0},
				"tx_result": map[string]any{"code": 0},
				"hash":      "APPV23VOTE",
				"height":    "12",
			},
		}))
	}))
	t.Cleanup(comet.Close)
	fixture.server.cometbftRPC = comet.URL

	const memoryID = "app-v23-operator-vote-target"
	seedMemory(
		t, fixture.memories, memoryID, fixture.ids["member"],
		"member.home", "operator vote target",
	)
	fixture.memories.memories[memoryID].Status = memory.StatusProposed
	require.NoError(t, fixture.badger.SetMemoryHash(
		memoryID,
		fixture.memories.memories[memoryID].ContentHash,
		string(memory.StatusProposed),
	))

	body := []byte(`{"decision":"accept","rationale":"manual operator override"}`)
	for _, actor := range []string{"member", "manager"} {
		t.Run(actor+" cannot make the validator vote", func(t *testing.T) {
			req := appV23SignedRESTRouteRequest(
				t, fixture, actor, http.MethodPost,
				"/v1/memory/does-not-exist/vote", body, false,
			)
			rec := httptest.NewRecorder()
			fixture.server.Router().ServeHTTP(rec, req)
			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			require.Zero(t, broadcasts.Load())
		})
	}

	for _, actor := range []string{"current-root", "current-admin"} {
		t.Run(actor+" can authorize the local validator", func(t *testing.T) {
			before := broadcasts.Load()
			req := appV23SignedRESTRouteRequest(
				t, fixture, actor, http.MethodPost,
				"/v1/memory/"+memoryID+"/vote", body, true,
			)
			rec := httptest.NewRecorder()
			fixture.server.Router().ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.Equal(t, before+1, broadcasts.Load())
		})
	}

	require.Len(t, captured, 2)
	for _, parsed := range captured {
		require.Equal(t, tx.TxTypeMemoryVote, parsed.Type)
		require.NotNil(t, parsed.MemoryVote)
		require.Equal(t, memoryID, parsed.MemoryVote.MemoryID)
		require.Equal(t, make([]byte, ed25519.PublicKeySize), parsed.AgentPubKey)
		require.Equal(t, make([]byte, ed25519.SignatureSize), parsed.AgentSig)
		require.Empty(t, parsed.AgentRequest)
		require.Nil(t, parsed.LocalElevation)
	}
}
