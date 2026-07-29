package abci

import (
	"context"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/tx"
)

func TestPreAppV20DomainFinalizeWaitsBeforeTakingRuntimePublication(t *testing.T) {
	app := setupTestApp(t)
	agent := newAgentKey(t)
	blockTime := time.Unix(17_201, 0).UTC()
	parsed := makeDelegatedDomainRegisterTx(
		t,
		agent,
		agent,
		[]byte("pre-v20 ordered publication"),
		blockTime,
		"legacy-publication-domain",
		"",
		false,
	)
	raw, err := tx.EncodeTx(parsed)
	require.NoError(t, err)

	unlockOwnership := app.badgerStore.LockDomainOwnershipRead()
	type finalizeResult struct {
		response *abcitypes.ResponseFinalizeBlock
		err      error
	}
	finalized := make(chan finalizeResult, 1)
	go func() {
		response, finalizeErr := app.FinalizeBlock(
			context.Background(),
			&abcitypes.RequestFinalizeBlock{
				Height: 1,
				Time:   blockTime,
				Txs:    [][]byte{raw},
			},
		)
		finalized <- finalizeResult{response: response, err: finalizeErr}
	}()

	// Give FinalizeBlock time to reach the ownership barrier. It must wait there
	// without owning runtimeViewMu, because a federated reader may already hold
	// this domain lease and need one of the runtime gate accessors before it can
	// release.
	time.Sleep(100 * time.Millisecond)
	require.True(t, app.runtimeViewMu.TryRLock(),
		"pre-v20 FinalizeBlock took runtime publication before the domain lease")
	app.runtimeViewMu.RUnlock()

	unlockOwnership()
	select {
	case result := <-finalized:
		require.NoError(t, result.err)
		require.NotNil(t, result.response)
		require.Len(t, result.response.TxResults, 1)
		require.Zero(t, result.response.TxResults[0].Code,
			result.response.TxResults[0].Log)
	case <-time.After(5 * time.Second):
		t.Fatal("pre-v20 FinalizeBlock remained blocked after the domain lease released")
	}
	owner, err := app.badgerStore.GetDomainOwner("legacy-publication-domain")
	require.NoError(t, err)
	require.Equal(t, agent.id, owner)
}
