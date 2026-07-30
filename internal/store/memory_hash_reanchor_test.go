package store

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func eligibleHashlessReanchorMemory(
	t *testing.T,
	store *BadgerStore,
	memoryID string,
	status string,
) {
	t.Helper()
	require.NoError(t, store.SetMemoryHash(memoryID, nil, status))
	require.NoError(t, store.SetMemoryDomain(memoryID, "repair/domain"))
	require.NoError(t, store.SetMemoryAuthor(memoryID, strings.Repeat("a", 64)))
	require.NoError(t, store.SetMemoryAuthorPrincipal(memoryID, "agent:"+strings.Repeat("a", 64)))
	require.NoError(t, store.SetMemoryClassification(memoryID, uint8(ClearanceInternal)))
}

func reanchorTestHash(memoryID string) []byte {
	hash := sha256.Sum256([]byte("canonical projection content for " + memoryID))
	return hash[:]
}

func reanchorTestEntry(memoryID, status string) MemoryHashReanchorEntry {
	return MemoryHashReanchorEntry{
		MemoryID:       memoryID,
		ExpectedStatus: status,
		ContentHash:    reanchorTestHash(memoryID),
	}
}

func setRawReanchorTestKey(t *testing.T, store *BadgerStore, key, value []byte) {
	t.Helper()
	require.NoError(t, store.db.Update(func(txn *badger.Txn) error {
		return txn.Set(append([]byte(nil), key...), append([]byte(nil), value...))
	}))
}

func deleteRawReanchorTestKey(t *testing.T, store *BadgerStore, key []byte) {
	t.Helper()
	require.NoError(t, store.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(append([]byte(nil), key...))
	}))
}

func snapshotReanchorTestState(t *testing.T, store *BadgerStore) map[string][]byte {
	t.Helper()
	snapshot := make(map[string][]byte)
	require.NoError(t, store.db.View(func(txn *badger.Txn) error {
		iterator := txn.NewIterator(badger.DefaultIteratorOptions)
		defer iterator.Close()
		for iterator.Rewind(); iterator.Valid(); iterator.Next() {
			item := iterator.Item()
			key := string(item.KeyCopy(nil))
			if err := item.Value(func(value []byte) error {
				snapshot[key] = append([]byte(nil), value...)
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}))
	return snapshot
}

func TestReanchorMemoryHashesRepairsBoundedChunkAndOnlyMemoryKeys(t *testing.T) {
	store := newTestBadger(t)
	eligibleHashlessReanchorMemory(t, store, "memory-a", "committed")
	eligibleHashlessReanchorMemory(t, store, "memory-b", "deprecated")
	before := snapshotReanchorTestState(t, store)

	entries := []MemoryHashReanchorEntry{
		reanchorTestEntry("memory-a", "committed"),
		reanchorTestEntry("memory-b", "deprecated"),
	}
	require.NoError(t, store.ReanchorMemoryHashes(entries))

	for _, entry := range entries {
		contentHash, status, err := store.GetMemoryHash(entry.MemoryID)
		require.NoError(t, err)
		assert.Equal(t, entry.ContentHash, contentHash)
		assert.Equal(t, entry.ExpectedStatus, status)
	}

	after := snapshotReanchorTestState(t, store)
	var changed []string
	for key, beforeValue := range before {
		if !bytes.Equal(beforeValue, after[key]) {
			changed = append(changed, key)
		}
	}
	for key := range after {
		if _, existed := before[key]; !existed {
			changed = append(changed, key)
		}
	}
	sort.Strings(changed)
	assert.Equal(t, []string{"memory:memory-a", "memory:memory-b"}, changed)
}

func TestReanchorMemoryHashesIsIdempotentForExactHash(t *testing.T) {
	store := newTestBadger(t)
	eligibleHashlessReanchorMemory(t, store, "memory-a", "committed")
	eligibleHashlessReanchorMemory(t, store, "memory-b", "deprecated")
	entries := []MemoryHashReanchorEntry{
		reanchorTestEntry("memory-a", "committed"),
		reanchorTestEntry("memory-b", "deprecated"),
	}

	require.NoError(t, store.ReanchorMemoryHashes(entries))
	afterFirst := snapshotReanchorTestState(t, store)
	require.NoError(t, store.ReanchorMemoryHashes(entries))
	assert.Equal(t, afterFirst, snapshotReanchorTestState(t, store))
}

func TestReanchorMemoryHashesValidatesWholeChunkBeforeMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *BadgerStore, *MemoryHashReanchorEntry)
	}{
		{"missing memory", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			deleteRawReanchorTestKey(t, store, memoryKey("memory-b"))
		}},
		{"malformed memory encoding", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			setRawMemoryEntry(t, store, "memory-b", []byte{0, 0, 0})
		}},
		{"short nonzero hash", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			setRawMemoryEntry(
				t, store, "memory-b",
				encodeMemoryHashEntry(bytes.Repeat([]byte{1}, sha256.Size-1), "committed"),
			)
		}},
		{"different canonical hash", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			setRawMemoryEntry(
				t, store, "memory-b",
				encodeMemoryHashEntry(bytes.Repeat([]byte{0xff}, sha256.Size), "committed"),
			)
		}},
		{"nonterminal status", func(t *testing.T, store *BadgerStore, entry *MemoryHashReanchorEntry) {
			setRawMemoryEntry(t, store, "memory-b", encodeMemoryHashEntry(nil, "proposed"))
			entry.ExpectedStatus = "committed"
		}},
		{"status mismatch", func(_ *testing.T, _ *BadgerStore, entry *MemoryHashReanchorEntry) {
			entry.ExpectedStatus = "deprecated"
		}},
		{"missing domain", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			deleteRawReanchorTestKey(t, store, memoryDomainKey("memory-b"))
		}},
		{"empty domain", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			setRawReanchorTestKey(t, store, memoryDomainKey("memory-b"), nil)
		}},
		{"missing author", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			deleteRawReanchorTestKey(t, store, memoryAuthorKey("memory-b"))
		}},
		{"empty author", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			setRawReanchorTestKey(t, store, memoryAuthorKey("memory-b"), nil)
		}},
		{"missing app-v23 principal marker", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			deleteRawReanchorTestKey(t, store, memoryAuthorPrincipalKey("memory-b"))
		}},
		{"empty app-v23 principal marker", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			setRawReanchorTestKey(t, store, memoryAuthorPrincipalKey("memory-b"), nil)
		}},
		{"missing classification", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			deleteRawReanchorTestKey(t, store, memClassKey("memory-b"))
		}},
		{"empty classification", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			setRawReanchorTestKey(t, store, memClassKey("memory-b"), nil)
		}},
		{"wide classification", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			setRawReanchorTestKey(t, store, memClassKey("memory-b"), []byte{1, 2})
		}},
		{"invalid classification", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			setRawReanchorTestKey(t, store, memClassKey("memory-b"), []byte{5})
		}},
		{"co-commit core marker", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			setRawReanchorTestKey(t, store, cocommitCoreKey("memory-b"), bytes.Repeat([]byte{1}, sha256.Size))
		}},
		{"co-commit shared marker", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			setRawReanchorTestKey(t, store, cocommitSharedKey("memory-b"), []byte{0, 0, 0, 1})
		}},
		{"scoped ballot marker", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			setRawReanchorTestKey(t, store, scopeBallotKey("memory-b"), []byte("marker"))
		}},
		{"scoped content marker", func(t *testing.T, store *BadgerStore, _ *MemoryHashReanchorEntry) {
			setRawReanchorTestKey(t, store, scopedContentKey("memory-b"), []byte("marker"))
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newTestBadger(t)
			eligibleHashlessReanchorMemory(t, store, "memory-a", "committed")
			eligibleHashlessReanchorMemory(t, store, "memory-b", "committed")
			firstBefore := rawMemoryEntry(t, store, "memory-a")
			second := reanchorTestEntry("memory-b", "committed")
			test.mutate(t, store, &second)

			err := store.ReanchorMemoryHashes([]MemoryHashReanchorEntry{
				reanchorTestEntry("memory-a", "committed"),
				second,
			})
			require.Error(t, err)
			assert.Equal(t, firstBefore, rawMemoryEntry(t, store, "memory-a"))
			firstHash, firstStatus, getErr := store.GetMemoryHash("memory-a")
			require.NoError(t, getErr)
			assert.Empty(t, firstHash, "the earlier valid entry must not be partially repaired")
			assert.Equal(t, "committed", firstStatus)
		})
	}
}

func TestMemoryHashReanchorSeparatesMutableDriftFromCanonicalCorruption(t *testing.T) {
	t.Run("status transition is terminal business drift", func(t *testing.T) {
		store := newTestBadger(t)
		eligibleHashlessReanchorMemory(t, store, "memory-a", "committed")
		entry := reanchorTestEntry("memory-a", "deprecated")
		err := store.ValidateMemoryHashReanchors([]MemoryHashReanchorEntry{entry})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMemoryHashReanchorStateDrift)
	})

	t.Run("missing disclosure projection remains fatal corruption", func(t *testing.T) {
		store := newTestBadger(t)
		eligibleHashlessReanchorMemory(t, store, "memory-a", "committed")
		deleteRawReanchorTestKey(t, store, memoryDomainKey("memory-a"))
		err := store.ValidateMemoryHashReanchors([]MemoryHashReanchorEntry{
			reanchorTestEntry("memory-a", "committed"),
		})
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrMemoryHashReanchorStateDrift)
	})

	t.Run("missing canonical memory remains fatal corruption", func(t *testing.T) {
		store := newTestBadger(t)
		eligibleHashlessReanchorMemory(t, store, "memory-a", "committed")
		deleteRawReanchorTestKey(t, store, memoryKey("memory-a"))
		err := store.ValidateMemoryHashReanchors([]MemoryHashReanchorEntry{
			reanchorTestEntry("memory-a", "committed"),
		})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMemoryNotFound)
		require.NotErrorIs(t, err, ErrMemoryHashReanchorStateDrift)
	})

	t.Run("malformed canonical hash remains fatal corruption", func(t *testing.T) {
		store := newTestBadger(t)
		eligibleHashlessReanchorMemory(t, store, "memory-a", "committed")
		setRawMemoryEntry(t, store, "memory-a", []byte{0, 0, 0})
		err := store.ValidateMemoryHashReanchors([]MemoryHashReanchorEntry{
			reanchorTestEntry("memory-a", "committed"),
		})
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrMemoryHashReanchorStateDrift)
	})

	for _, status := range []string{"", "garbage"} {
		t.Run("invalid canonical status "+status+" remains fatal corruption", func(t *testing.T) {
			store := newTestBadger(t)
			eligibleHashlessReanchorMemory(t, store, "memory-a", "committed")
			setRawMemoryEntry(t, store, "memory-a", encodeMemoryHashEntry(nil, status))
			err := store.ValidateMemoryHashReanchors([]MemoryHashReanchorEntry{
				reanchorTestEntry("memory-a", "committed"),
			})
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrMemoryHashReanchorStateDrift)
		})
	}

	t.Run("partial scoped marker remains fatal corruption", func(t *testing.T) {
		store := newTestBadger(t)
		eligibleHashlessReanchorMemory(t, store, "memory-a", "committed")
		setRawReanchorTestKey(t, store, scopeBallotKey("memory-a"), []byte("partial"))
		err := store.ValidateMemoryHashReanchors([]MemoryHashReanchorEntry{
			reanchorTestEntry("memory-a", "committed"),
		})
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrMemoryHashReanchorStateDrift)
	})

	t.Run("different canonical hash remains fatal conflict", func(t *testing.T) {
		store := newTestBadger(t)
		eligibleHashlessReanchorMemory(t, store, "memory-a", "committed")
		setRawMemoryEntry(
			t,
			store,
			"memory-a",
			encodeMemoryHashEntry(bytes.Repeat([]byte{0xff}, sha256.Size), "committed"),
		)
		err := store.ValidateMemoryHashReanchors([]MemoryHashReanchorEntry{
			reanchorTestEntry("memory-a", "committed"),
		})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMemoryHashReanchorConflict)
		require.NotErrorIs(t, err, ErrMemoryHashReanchorStateDrift)
	})
}

func TestReanchorMemoryHashesRejectsInvalidInputBeforeStateAccess(t *testing.T) {
	hash := reanchorTestHash("a")
	tests := []struct {
		name    string
		entries []MemoryHashReanchorEntry
	}{
		{"empty", nil},
		{"too many", func() []MemoryHashReanchorEntry {
			entries := make([]MemoryHashReanchorEntry, maxMemoryHashReanchorEntries+1)
			for i := range entries {
				entries[i] = MemoryHashReanchorEntry{
					MemoryID:       fmt.Sprintf("%04d", i),
					ExpectedStatus: "committed",
					ContentHash:    hash,
				}
			}
			return entries
		}()},
		{"empty ID", []MemoryHashReanchorEntry{{
			ExpectedStatus: "committed", ContentHash: hash,
		}}},
		{"oversized ID", []MemoryHashReanchorEntry{{
			MemoryID: strings.Repeat("m", maxMemoryHashReanchorIDBytes+1), ExpectedStatus: "committed", ContentHash: hash,
		}}},
		{"nonterminal status", []MemoryHashReanchorEntry{{
			MemoryID: "a", ExpectedStatus: "proposed", ContentHash: hash,
		}}},
		{"short hash", []MemoryHashReanchorEntry{{
			MemoryID: "a", ExpectedStatus: "committed", ContentHash: hash[:sha256.Size-1],
		}}},
		{"unsorted", []MemoryHashReanchorEntry{
			{MemoryID: "b", ExpectedStatus: "committed", ContentHash: hash},
			{MemoryID: "a", ExpectedStatus: "committed", ContentHash: hash},
		}},
		{"duplicate", []MemoryHashReanchorEntry{
			{MemoryID: "a", ExpectedStatus: "committed", ContentHash: hash},
			{MemoryID: "a", ExpectedStatus: "committed", ContentHash: hash},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newTestBadger(t)
			before := snapshotReanchorTestState(t, store)
			require.Error(t, store.ReanchorMemoryHashes(test.entries))
			assert.Equal(t, before, snapshotReanchorTestState(t, store))
		})
	}
}

func TestValidateMemoryHashReanchorEntriesAcceptsExactBoundaries(t *testing.T) {
	entries := make([]MemoryHashReanchorEntry, maxMemoryHashReanchorEntries)
	for i := range entries {
		entries[i] = MemoryHashReanchorEntry{
			MemoryID:       fmt.Sprintf("%03d", i),
			ExpectedStatus: "committed",
			ContentHash:    reanchorTestHash(fmt.Sprintf("%03d", i)),
		}
	}
	entries[len(entries)-1].MemoryID = strings.Repeat("z", maxMemoryHashReanchorIDBytes)
	require.NoError(t, validateMemoryHashReanchorEntries(entries))
}

func TestReanchorMemoryHashesStagesInConsensusTransaction(t *testing.T) {
	store := newTestBadger(t)
	eligibleHashlessReanchorMemory(t, store, "memory-a", "committed")
	entry := reanchorTestEntry("memory-a", "committed")

	scoped := store.BeginConsensusTransaction(nil)
	require.NoError(t, scoped.ReanchorMemoryHashes([]MemoryHashReanchorEntry{entry}))
	stagedHash, stagedStatus, err := scoped.GetMemoryHash(entry.MemoryID)
	require.NoError(t, err)
	assert.Equal(t, entry.ContentHash, stagedHash)
	assert.Equal(t, entry.ExpectedStatus, stagedStatus)

	baseHash, baseStatus, err := store.GetMemoryHash(entry.MemoryID)
	require.NoError(t, err)
	assert.Empty(t, baseHash)
	assert.Equal(t, entry.ExpectedStatus, baseStatus)

	require.NoError(t, scoped.CommitConsensusTransaction())
	baseHash, baseStatus, err = store.GetMemoryHash(entry.MemoryID)
	require.NoError(t, err)
	assert.Equal(t, entry.ContentHash, baseHash)
	assert.Equal(t, entry.ExpectedStatus, baseStatus)
}

func TestReanchorMemoryHashesWriteFailurePoisonsAndRollsBackWholeConsensusChunk(t *testing.T) {
	store := newTestBadger(t)
	eligibleHashlessReanchorMemory(t, store, "memory-a", "committed")
	eligibleHashlessReanchorMemory(t, store, "memory-b", "committed")
	before := snapshotReanchorTestState(t, store)

	scoped := store.BeginConsensusTransaction(nil)
	scoped.writeFaultHook = func(attempt int) error {
		if attempt == 2 {
			return errors.New("injected second reanchor write failure")
		}
		return nil
	}
	err := scoped.ReanchorMemoryHashes([]MemoryHashReanchorEntry{
		reanchorTestEntry("memory-a", "committed"),
		reanchorTestEntry("memory-b", "committed"),
	})
	require.ErrorContains(t, err, "injected second reanchor write failure")
	require.Error(t, scoped.ConsensusTransactionError())
	require.Error(t, scoped.CommitConsensusTransaction())
	assert.Equal(t, before, snapshotReanchorTestState(t, store))
}
