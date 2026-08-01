package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/memory"
)

func TestCanonicalMemoryProjectionRevisionIgnoresUnrelatedState(t *testing.T) {
	canonical, err := NewBadgerStore(filepath.Join(t.TempDir(), "badger"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, canonical.CloseBadger()) })

	initial := canonical.CanonicalMemoryProjectionRevision()
	for i := 0; i < 100; i++ {
		require.NoError(t, canonical.SetNonce(fmt.Sprintf("agent-%03d", i), uint64(i+1)))
	}
	require.Equal(t, initial, canonical.CanonicalMemoryProjectionRevision())
	unrelatedTransaction := canonical.BeginConsensusTransaction(nil)
	for i := 0; i < 100; i++ {
		require.NoError(t, unrelatedTransaction.SetNonce(
			fmt.Sprintf("transaction-agent-%03d", i), uint64(i+1),
		))
	}
	require.NoError(t, unrelatedTransaction.CommitConsensusTransaction())
	require.Equal(t, initial, canonical.CanonicalMemoryProjectionRevision(),
		"unrelated and empty-style consensus commits stay off the memory token")

	contentHash := sha256.Sum256([]byte("projection revision"))
	require.NoError(t, canonical.SetMemoryHash(
		"memory-revision", contentHash[:], string(memory.StatusCommitted),
	))
	require.Greater(t, canonical.CanonicalMemoryProjectionRevision(), initial)
	for name, mutate := range map[string]func() error{
		"domain": func() error {
			return canonical.SetMemoryDomain("memory-revision", "revision-domain")
		},
		"author": func() error {
			return canonical.SetMemoryAuthor("memory-revision", "revision-agent")
		},
		"principal": func() error {
			return canonical.SetMemoryAuthorPrincipal("memory-revision", "revision-principal")
		},
		"classification": func() error {
			return canonical.SetMemoryClassification("memory-revision", 2)
		},
		"co-commit core": func() error {
			return canonical.SetCoCommitCore("memory-revision", contentHash[:])
		},
		"co-commit shared": func() error {
			return canonical.SetCoCommitShared("memory-revision", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			before := canonical.CanonicalMemoryProjectionRevision()
			require.NoError(t, mutate())
			require.Greater(t, canonical.CanonicalMemoryProjectionRevision(), before)
		})
	}

	beforeTransaction := canonical.CanonicalMemoryProjectionRevision()
	transaction := canonical.BeginConsensusTransaction(nil)
	require.NoError(t, transaction.SetNonce("unrelated-in-transaction", 1))
	require.NoError(t, transaction.SetMemoryDomain("memory-revision", "revision-domain"))
	require.NoError(t, transaction.SetMemoryAuthor("memory-revision", "revision-agent"))
	require.Equal(t, beforeTransaction, canonical.CanonicalMemoryProjectionRevision(),
		"speculative memory writes must not invalidate the published snapshot")
	require.NoError(t, transaction.CommitConsensusTransaction())
	require.Equal(t, beforeTransaction+1, canonical.CanonicalMemoryProjectionRevision(),
		"one committed consensus transaction advances one projection generation")

	beforeDiscard := canonical.CanonicalMemoryProjectionRevision()
	discarded := canonical.BeginConsensusTransaction(nil)
	require.NoError(t, discarded.SetMemoryDomain("memory-revision", "discarded-domain"))
	discarded.DiscardConsensusTransaction()
	require.Equal(t, beforeDiscard, canonical.CanonicalMemoryProjectionRevision())

	beforeFailedStandalone := canonical.CanonicalMemoryProjectionRevision()
	err = canonical.update(func(txn *badger.Txn) error {
		require.NoError(t, canonical.txnSet(
			txn, memoryDomainKey("memory-revision"), []byte("rolled-back-domain"),
		))
		return errors.New("force standalone rollback")
	})
	require.ErrorContains(t, err, "force standalone rollback")
	require.Equal(t, beforeFailedStandalone,
		canonical.CanonicalMemoryProjectionRevision(),
		"a failed standalone commit must not publish a revision")

	beforeConcurrent := canonical.CanonicalMemoryProjectionRevision()
	const writers = 12
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			require.NoError(t, canonical.SetMemoryDomain(
				fmt.Sprintf("concurrent-memory-%d", index), "revision-domain",
			))
		}(i)
	}
	wg.Wait()
	require.Equal(t, beforeConcurrent+writers,
		canonical.CanonicalMemoryProjectionRevision(),
		"the shared standalone publication gate must not lose increments")
}

func TestSQLiteMemoryProjectionRevisionTracksRawMemoryMutations(t *testing.T) {
	ctx := context.Background()
	sqlStore, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "sage.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlStore.Close()) })

	initial, err := sqlStore.MemoryProjectionRevision(ctx)
	require.NoError(t, err)

	contentHash := sha256.Sum256([]byte("sql projection revision"))
	record := &memory.MemoryRecord{
		MemoryID:        "sql-projection-revision",
		SubmittingAgent: "revision-agent",
		Content:         "sql projection revision",
		ContentHash:     contentHash[:],
		MemoryType:      memory.TypeFact,
		DomainTag:       "revision-domain",
		ConfidenceScore: 0.9,
		Status:          memory.StatusCommitted,
	}
	require.NoError(t, sqlStore.InsertMemory(ctx, record))
	afterInsert, err := sqlStore.MemoryProjectionRevision(ctx)
	require.NoError(t, err)
	require.Greater(t, afterInsert, initial)

	_, err = sqlStore.conn.ExecContext(ctx,
		`UPDATE memories SET domain_tag = ? WHERE memory_id = ?`,
		"raw-tamper-domain", record.MemoryID)
	require.NoError(t, err)
	afterRawUpdate, err := sqlStore.MemoryProjectionRevision(ctx)
	require.NoError(t, err)
	require.Equal(t, afterInsert+1, afterRawUpdate)

	_, err = sqlStore.conn.ExecContext(ctx,
		`UPDATE memories
		 SET embedding = ?, embedding_hash = ?, embedding_provider = ?
		 WHERE memory_id = ?`,
		[]byte{1, 2, 3}, []byte{4, 5, 6}, "revision-embedder",
		record.MemoryID,
	)
	require.NoError(t, err)
	afterEmbedding, err := sqlStore.MemoryProjectionRevision(ctx)
	require.NoError(t, err)
	require.Equal(t, afterRawUpdate, afterEmbedding,
		"embedding maintenance must not invalidate canonical disclosure audits")
	graphAfterEmbedding, err := sqlStore.GraphProjectionRevision(ctx)
	require.NoError(t, err)

	_, err = sqlStore.conn.ExecContext(ctx,
		`UPDATE memories SET confidence_score = ? WHERE memory_id = ?`,
		0.8, record.MemoryID,
	)
	require.NoError(t, err)
	afterGraphOnly, err := sqlStore.MemoryProjectionRevision(ctx)
	require.NoError(t, err)
	require.Equal(t, afterEmbedding, afterGraphOnly,
		"render-only metadata must not invalidate canonical disclosure audits")
	graphAfterConfidence, err := sqlStore.GraphProjectionRevision(ctx)
	require.NoError(t, err)
	require.Equal(t, graphAfterEmbedding+1, graphAfterConfidence,
		"rendered confidence changes must invalidate graph bytes")

	_, err = sqlStore.conn.ExecContext(ctx,
		`INSERT INTO preferences(key, value) VALUES (?, ?)`,
		"projection-revision-control", "unrelated")
	require.NoError(t, err)
	afterUnrelated, err := sqlStore.MemoryProjectionRevision(ctx)
	require.NoError(t, err)
	require.Equal(t, afterGraphOnly, afterUnrelated)

	vaultGeneration := sqlStore.VaultGeneration()
	sqlStore.SetVault(nil)
	require.Equal(t, vaultGeneration+1, sqlStore.VaultGeneration())
	sqlStore.SetVaultExpected(true)
	require.Equal(t, vaultGeneration+2, sqlStore.VaultGeneration())
	sqlStore.SetVaultExpected(true)
	require.Equal(t, vaultGeneration+2, sqlStore.VaultGeneration(),
		"reasserting the same expected state is not a publication")
	sqlStore.SetVault(nil)
	require.Equal(t, vaultGeneration+3, sqlStore.VaultGeneration(),
		"same-state vault publication still defeats ABA/key rotation")
}

func TestGraphProjectionRevisionTracksOnlyRenderedMetadata(t *testing.T) {
	ctx := context.Background()
	sqlStore, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "sage.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlStore.Close()) })

	initial, err := sqlStore.GraphProjectionRevision(ctx)
	require.NoError(t, err)
	for _, memoryID := range []string{"graph-memory", "graph-target"} {
		hash := sha256.Sum256([]byte(memoryID))
		require.NoError(t, sqlStore.InsertMemory(ctx, &memory.MemoryRecord{
			MemoryID: memoryID, SubmittingAgent: "graph-agent",
			Content: memoryID, ContentHash: hash[:],
			MemoryType: memory.TypeFact, DomainTag: "graph-domain",
			ConfidenceScore: 0.9, Status: memory.StatusCommitted,
		}))
	}
	for _, statement := range []string{
		`INSERT INTO memory_tags(memory_id, tag) VALUES ('graph-memory', 'tag')`,
		`INSERT INTO corroborations(memory_id, agent_id) VALUES ('graph-memory', 'agent')`,
		`INSERT INTO memory_links(source_id, target_id, link_type)
		 VALUES ('graph-memory', 'graph-target', 'related')`,
	} {
		_, err = sqlStore.conn.ExecContext(ctx, statement)
		require.NoError(t, err)
	}
	afterMetadata, err := sqlStore.GraphProjectionRevision(ctx)
	require.NoError(t, err)
	require.Equal(t, initial+3, afterMetadata)

	_, err = sqlStore.conn.ExecContext(ctx,
		`INSERT INTO preferences(key, value) VALUES ('graph-control', 'value')`)
	require.NoError(t, err)
	afterUnrelated, err := sqlStore.GraphProjectionRevision(ctx)
	require.NoError(t, err)
	require.Equal(t, afterMetadata, afterUnrelated)
}

func TestGraphAuthorizationRevisionTracksRootAndRBACState(t *testing.T) {
	canonical, err := NewBadgerStore(filepath.Join(t.TempDir(), "badger"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, canonical.CloseBadger()) })

	initial := canonical.GraphAuthorizationRevision()
	require.NoError(t, canonical.SetNonce("graph-control", 1))
	require.Equal(t, initial, canonical.GraphAuthorizationRevision())
	require.NoError(t, canonical.SetRawForTest(
		[]byte("appv23:root_credential:test"), []byte{1},
	))
	require.Equal(t, initial+1, canonical.GraphAuthorizationRevision())
	require.NoError(t, canonical.SetRawForTest(
		[]byte("grant:graph-domain:test"), []byte{1},
	))
	require.Equal(t, initial+2, canonical.GraphAuthorizationRevision())
	require.NoError(t, canonical.SetRawForTest(
		[]byte("state:shared_domain:graph-domain"), []byte{1},
	))
	require.Equal(t, initial+3, canonical.GraphAuthorizationRevision(),
		"dynamic shared-domain promotion changes caller scope and must invalidate cached graph bytes")
	require.NoError(t, canonical.SetRawForTest(
		[]byte("appv25:domain_continuity_grant:agent:domain"), []byte{1},
	))
	require.Equal(t, initial+4, canonical.GraphAuthorizationRevision(),
		"continuity repair can change authority without touching app-v23 state")
}
