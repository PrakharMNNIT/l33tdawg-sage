//go:build v119testfixture

package abci

import (
	"context"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/tx"
)

func TestAppV20CommitAfterBadgerSyncReopensCompleteBeforePublish(t *testing.T) {
	h := newGovernanceReplayHarness(t)
	candidate := newAgentKey(t)
	parsed := makeAgentRegisterTx(t, candidate, "post-sync-agent", "member", "", "test", "")
	parsed.Nonce = 1
	require.NoError(t, tx.SignTx(parsed, candidate.priv))
	raw := encodeGovernanceReplayTx(t, parsed)
	finalized := finalizeGovernanceReplayBlock(t, h.app, &abcitypes.RequestFinalizeBlock{
		Height: 2, Time: time.Unix(16_002, 0).UTC(), Txs: [][]byte{raw},
	})
	require.Len(t, finalized.TxResults, 1)
	require.Zero(t, finalized.TxResults[0].Code, finalized.TxResults[0].Log)
	assert.False(t, h.app.badgerStore.IsAgentRegistered(candidate.id), "root graph remains speculative before Commit")

	restore := SetAppV20CommitBoundaryHookForTest(func(stage AppV20CommitBoundaryStage) {
		if stage == AppV20CommitAfterBadgerSync {
			panic("v11.9 crash after Badger sync")
		}
	})
	assert.PanicsWithValue(t, "v11.9 crash after Badger sync", func() {
		_, _ = h.app.Commit(context.Background(), &abcitypes.RequestCommit{})
	})
	restore()

	// The real multiprocess fixture stops at this hook with SIGKILL. Closing here
	// merely releases the test process's Badger lock; the hook has already crossed
	// Commit+Sync and deliberately ran before publishAppV20Finalize.
	h.crashAndReopen(t)
	info, err := h.app.Info(context.Background(), &abcitypes.RequestInfo{})
	require.NoError(t, err)
	assert.Equal(t, int64(2), info.LastBlockHeight)
	assert.Equal(t, finalized.AppHash, info.LastBlockAppHash)
	assert.True(t, h.app.badgerStore.IsAgentRegistered(candidate.id))
}

func TestAppV20CommitBadgerPublicationBlocksRuntimeReaders(t *testing.T) {
	h := newGovernanceReplayHarness(t)
	candidate := newAgentKey(t)
	parsed := makeAgentRegisterTx(t, candidate, "publication-lock-agent", "member", "", "test", "")
	parsed.Nonce = 1
	require.NoError(t, tx.SignTx(parsed, candidate.priv))
	raw := encodeGovernanceReplayTx(t, parsed)
	finalized := finalizeGovernanceReplayBlock(t, h.app, &abcitypes.RequestFinalizeBlock{
		Height: 2, Time: time.Unix(16_102, 0).UTC(), Txs: [][]byte{raw},
	})
	require.Len(t, finalized.TxResults, 1)
	require.Zero(t, finalized.TxResults[0].Code, finalized.TxResults[0].Log)

	afterBadgerSync := make(chan struct{})
	releasePublication := make(chan struct{})
	restore := SetAppV20CommitBoundaryHookForTest(func(stage AppV20CommitBoundaryStage) {
		if stage == AppV20CommitAfterBadgerSync {
			close(afterBadgerSync)
			<-releasePublication
		}
	})
	defer restore()

	commitDone := make(chan error, 1)
	go func() {
		_, err := h.app.Commit(context.Background(), &abcitypes.RequestCommit{})
		commitDone <- err
	}()

	select {
	case <-afterBadgerSync:
	case <-time.After(5 * time.Second):
		t.Fatal("Commit did not reach the after-Badger-sync boundary")
	}
	// The durable transaction is already visible at this hook. Runtime readers
	// must nevertheless wait until the matching height/fork graph is published.
	assert.True(t, h.app.badgerStore.IsAgentRegistered(candidate.id))

	infoDone := make(chan *abcitypes.ResponseInfo, 1)
	go func() {
		info, _ := h.app.Info(context.Background(), &abcitypes.RequestInfo{})
		infoDone <- info
	}()
	select {
	case info := <-infoDone:
		t.Fatalf("Info escaped the publication boundary with mixed state at height %d", info.LastBlockHeight)
	case <-time.After(100 * time.Millisecond):
	}

	close(releasePublication)
	require.NoError(t, <-commitDone)
	select {
	case info := <-infoDone:
		require.Equal(t, int64(2), info.LastBlockHeight)
		require.Equal(t, finalized.AppHash, info.LastBlockAppHash)
	case <-time.After(5 * time.Second):
		t.Fatal("Info remained blocked after atomic publication completed")
	}
}
