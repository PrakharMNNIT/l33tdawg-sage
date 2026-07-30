package abci

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/taskidempotency"
	"github.com/l33tdawg/sage/internal/tx"
)

func rawAppV23TaskTx(
	t *testing.T,
	signer agentKey,
	principalID, key string,
	includeAgentRequest bool,
) *tx.ParsedTx {
	t.Helper()
	content := "[TASK] Raw consensus task"
	contentHash := sha256.Sum256([]byte(content))
	memoryID := "00000000-0000-4000-8000-000000000023"
	if key != "" {
		var err error
		memoryID, err = taskidempotency.MemoryID(principalID, key)
		require.NoError(t, err)
	} else if includeAgentRequest {
		var err error
		key, err = taskidempotency.SemanticKey(
			signer.id, "voice-interface", content,
		)
		require.NoError(t, err)
		memoryID, err = taskidempotency.MemoryID(principalID, key)
		require.NoError(t, err)
	}
	body := map[string]any{
		"content":          content,
		"memory_type":      "task",
		"domain_tag":       "voice-interface",
		"confidence_score": 0.9,
		"task_status":      "planned",
	}
	if key != "" {
		body["idempotency_key"] = key
	}
	request := canonicalAgentRequest(t, "POST", "/v1/memory/submit", body)
	proofBody := []byte("proofless raw task")
	if includeAgentRequest {
		proofBody = request
	}
	pub, sig, bodyHash, timestamp := signAgentProof(t, signer, proofBody)
	parsed := &tx.ParsedTx{
		Type: tx.TxTypeMemorySubmit,
		MemorySubmit: &tx.MemorySubmit{
			MemoryID: memoryID, ContentHash: contentHash[:],
			MemoryType: tx.MemoryTypeTask, DomainTag: "voice-interface",
			ConfidenceScore: 0.9, Content: content, TaskStatus: "planned",
		},
		AgentPubKey: pub, AgentSig: sig, AgentBodyHash: bodyHash,
		AgentTimestamp: timestamp, Nonce: 1, Timestamp: time.Unix(timestamp, 0),
	}
	if includeAgentRequest {
		parsed.AgentRequest = request
	}
	require.NoError(t, tx.SignTx(parsed, signer.priv))
	return parsed
}

func TestAppV23RawOrdinaryTaskRequiresDurableAssignmentIntent(t *testing.T) {
	app, _, companion := directAppV23GenesisTestApp(t)
	height := activateDirectAppV24ForTest(t, app, time.Now().UTC().Add(-time.Minute))
	parsed := rawAppV23TaskTx(t, companion, companion.id, "", false)

	result := app.processTx(parsed, height, time.Unix(parsed.AgentTimestamp, 0))
	require.Equal(t, uint32(17), result.Code, result.Log)
	require.Contains(t, result.Log, "idempotency assignment intent")
	_, _, err := app.badgerStore.GetMemoryHash(parsed.MemorySubmit.MemoryID)
	require.Error(t, err, "rejected raw task must not create consensus memory state")
	require.Empty(t, app.pendingWrites, "rejected raw task must not stage an invisible projection")
}

func TestAppV23SignedOrdinaryTaskDerivesDurableAssignmentIntent(t *testing.T) {
	app, _, companion := directAppV23GenesisTestApp(t)
	height := activateDirectAppV24ForTest(t, app, time.Now().UTC().Add(-time.Minute))
	parsed := rawAppV23TaskTx(t, companion, companion.id, "", true)

	result := app.processTx(parsed, height, time.Unix(parsed.AgentTimestamp, 0))
	require.Zero(t, result.Code, result.Log)
	key, err := taskidempotency.SemanticKey(
		companion.id,
		parsed.MemorySubmit.DomainTag,
		parsed.MemorySubmit.Content,
	)
	require.NoError(t, err)
	binding, err := app.badgerStore.GetAppV23TaskIdempotencyBinding(
		companion.id, key,
	)
	require.NoError(t, err)
	require.NotNil(t, binding)
	require.Equal(t, parsed.MemorySubmit.MemoryID, binding.MemoryID)
	require.Equal(t, companion.id, binding.AssigneeID)
}

func TestAppV23RawOrdinaryKeyedTaskBindsExactAssignee(t *testing.T) {
	app, _, companion := directAppV23GenesisTestApp(t)
	height := activateDirectAppV24ForTest(t, app, time.Now().UTC().Add(-time.Minute))
	const key = "raw-companion-task-v1"
	parsed := rawAppV23TaskTx(t, companion, companion.id, key, true)

	result := app.processTx(parsed, height, time.Unix(parsed.AgentTimestamp, 0))
	require.Zero(t, result.Code, result.Log)
	binding, err := app.badgerStore.GetAppV23TaskIdempotencyBinding(companion.id, key)
	require.NoError(t, err)
	require.NotNil(t, binding)
	require.Equal(t, companion.id, binding.AssigneeID)

	var projected *memory.MemoryRecord
	for _, pending := range app.pendingWrites {
		if record, ok := pending.data.(*memory.MemoryRecord); ok {
			projected = record
			break
		}
	}
	require.NotNil(t, projected)
	require.Equal(t, companion.id, projected.Assignee)
}

func TestAppV23RawRootTaskCannotBecomeOrdinaryAssignee(t *testing.T) {
	t.Run("keyed agent request rejected", func(t *testing.T) {
		app, root, _ := directAppV23GenesisTestApp(t)
		const key = "root-must-not-be-assignee"
		parsed := rawAppV23TaskTx(t, root, root.id, key, true)

		result := app.processTx(parsed, 1, time.Unix(parsed.AgentTimestamp, 0))
		require.Equal(t, uint32(17), result.Code, result.Log)
		require.Contains(t, result.Log, "Root tasks must remain unassigned")
		binding, err := app.badgerStore.GetAppV23TaskIdempotencyBinding(root.id, key)
		require.NoError(t, err)
		require.Nil(t, binding)
		require.Empty(t, app.pendingWrites)
	})

	t.Run("localhost CEREBRUM unassigned task remains valid", func(t *testing.T) {
		app, root, _ := directAppV23GenesisTestApp(t)
		parsed := rawAppV23TaskTx(t, root, root.id, "", false)

		result := app.processTx(parsed, 1, time.Unix(parsed.AgentTimestamp, 0))
		require.Zero(t, result.Code, result.Log)
		var projected *memory.MemoryRecord
		for _, pending := range app.pendingWrites {
			if record, ok := pending.data.(*memory.MemoryRecord); ok {
				projected = record
				break
			}
		}
		require.NotNil(t, projected)
		require.Empty(t, projected.Assignee)
	})
}
