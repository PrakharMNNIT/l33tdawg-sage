package abci

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/taskidempotency"
	"github.com/l33tdawg/sage/internal/tx"
)

type appV23TaskTagFailingStore struct {
	store.OffchainStore
}

func (s *appV23TaskTagFailingStore) RunInTx(
	ctx context.Context,
	fn func(store.OffchainStore) error,
) error {
	return s.OffchainStore.RunInTx(ctx, func(transaction store.OffchainStore) error {
		return fn(&appV23TaskTagFailingStore{OffchainStore: transaction})
	})
}

func (s *appV23TaskTagFailingStore) SetTags(
	context.Context,
	string,
	[]string,
) error {
	return errors.New("injected keyed task tag projection failure")
}

func appV23KeyedTaskTx(
	t *testing.T,
	signer agentKey,
	key string,
	tags []string,
	nonce uint64,
	blockTime time.Time,
) ([]byte, string) {
	t.Helper()
	const content = "[TASK] Check the HDMI port"
	const domain = "voice-interface"
	memoryID, err := taskidempotency.MemoryID(signer.id, key)
	require.NoError(t, err)
	request := canonicalAgentRequest(t, "POST", "/v1/memory/submit", map[string]any{
		"content":          content,
		"memory_type":      "task",
		"domain_tag":       domain,
		"confidence_score": 0.9,
		"classification":   1,
		"task_status":      "planned",
		"tags":             tags,
		"idempotency_key":  key,
	})
	agentPub, agentSig, bodyHash, proofTime := signAgentProof(t, signer, request)
	contentHash := sha256.Sum256([]byte(content))
	parsed := &tx.ParsedTx{
		Type:      tx.TxTypeMemorySubmit,
		Nonce:     nonce,
		Timestamp: blockTime,
		MemorySubmit: &tx.MemorySubmit{
			MemoryID: memoryID, ContentHash: contentHash[:],
			MemoryType: tx.MemoryTypeTask, DomainTag: domain,
			ConfidenceScore: 0.9, Content: content,
			Classification: tx.ClearanceInternal,
			TaskStatus:     "planned",
			Tags:           append([]string(nil), tags...),
		},
		AgentPubKey: agentPub, AgentSig: agentSig,
		AgentBodyHash: bodyHash, AgentTimestamp: proofTime,
		AgentRequest: append([]byte(nil), request...),
	}
	require.NoError(t, tx.SignTx(parsed, signer.priv))
	raw, err := tx.EncodeTx(parsed)
	require.NoError(t, err)
	return raw, memoryID
}

func TestAppV23KeyedTaskTagsRollbackAndReplayWithCommitBatch(t *testing.T) {
	app, _, companion := directAppV23GenesisTestApp(t)
	sqlite, ok := app.offchainStore.(*store.SQLiteStore)
	require.True(t, ok)
	blockTime := time.Now().UTC().Truncate(time.Second)
	raw, memoryID := appV23KeyedTaskTx(
		t, companion, "task-tags-crash-v1",
		[]string{"hardware", "urgent"}, 1, blockTime,
	)
	block := &abcitypes.RequestFinalizeBlock{
		Height: 1, Time: blockTime, Txs: [][]byte{raw},
	}

	// Inject failure at SetTags inside the projection transaction. If keyed
	// task tags were still a post-Commit REST write, Commit would succeed and
	// leave a durable untagged task. Instead the entire memory batch rolls back
	// and persisted consensus height stays behind for exact block replay.
	app.offchainStore = &appV23TaskTagFailingStore{OffchainStore: sqlite}
	finalized, err := app.FinalizeBlock(context.Background(), block)
	require.NoError(t, err)
	require.Len(t, finalized.TxResults, 1)
	require.Zero(t, finalized.TxResults[0].Code, finalized.TxResults[0].Log)
	require.NotNil(t, app.pendingAppV20Finalize)
	tagWrites := 0
	for _, pending := range app.pendingAppV20Finalize.app.pendingWrites {
		if pending.writeType != "memory_tags" {
			continue
		}
		tagWrites++
		payload, valid := pending.data.(*memoryTagsData)
		require.True(t, valid)
		require.Equal(t, memoryID, payload.MemoryID)
		require.Equal(t, []string{"hardware", "urgent"}, payload.Tags)
	}
	require.Equal(t, 1, tagWrites)
	requireCommitPanicV20(t, app)
	_, err = sqlite.GetMemory(context.Background(), memoryID)
	require.Error(t, err, "failed tag projection must roll back the memory row")
	tags, err := sqlite.GetTags(context.Background(), memoryID)
	require.NoError(t, err)
	require.Empty(t, tags)
	persisted, err := LoadState(app.badgerStore)
	require.NoError(t, err)
	require.Zero(t, persisted.Height)

	// Model restart recovery by restoring the healthy projection and replaying
	// the exact block CometBFT still owes the app. Memory, assignment, receipt,
	// and canonical tags become durable together.
	app.offchainStore = sqlite
	replayed, err := app.FinalizeBlock(context.Background(), block)
	require.NoError(t, err)
	require.Equal(t, finalized.AppHash, replayed.AppHash)
	require.Equal(t, finalized.TxResults[0].Data, replayed.TxResults[0].Data)
	require.Zero(t, replayed.TxResults[0].Code, replayed.TxResults[0].Log)
	_, err = app.Commit(context.Background(), &abcitypes.RequestCommit{})
	require.NoError(t, err)
	projected, err := sqlite.GetMemory(context.Background(), memoryID)
	require.NoError(t, err)
	require.Equal(t, companion.id, projected.Assignee)
	tags, err = sqlite.GetTags(context.Background(), memoryID)
	require.NoError(t, err)
	require.Equal(t, []string{"hardware", "urgent"}, tags)
}
