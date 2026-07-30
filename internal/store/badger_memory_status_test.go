package store

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func rawMemoryEntry(t *testing.T, store *BadgerStore, memoryID string) []byte {
	t.Helper()
	var raw []byte
	require.NoError(t, store.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(memoryKey(memoryID))
		if err != nil {
			return err
		}
		return item.Value(func(value []byte) error {
			raw = append([]byte(nil), value...)
			return nil
		})
	}))
	return raw
}

func setRawMemoryEntry(t *testing.T, store *BadgerStore, memoryID string, raw []byte) {
	t.Helper()
	require.NoError(t, store.db.Update(func(txn *badger.Txn) error {
		return txn.Set(memoryKey(memoryID), append([]byte(nil), raw...))
	}))
}

func TestSetMemoryStatusPreservingHashRetainsExactSHA256(t *testing.T) {
	store := newTestBadger(t)
	memoryID := "future-safe-status"
	contentHash := sha256.Sum256([]byte("exact canonical memory content"))
	require.NoError(t, store.SetMemoryHash(memoryID, contentHash[:], "proposed"))

	require.NoError(t, store.SetMemoryStatusPreservingHash(memoryID, "committed"))

	gotHash, gotStatus, err := store.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, contentHash[:], gotHash)
	assert.Equal(t, "committed", gotStatus)
	assert.Equal(
		t,
		encodeMemoryHashEntry(contentHash[:], "committed"),
		rawMemoryEntry(t, store, memoryID),
		"the status-only transition must preserve the exact hash bytes",
	)

	require.NoError(t, store.SetMemoryStatusPreservingHash(memoryID, "deprecated"))
	gotHash, gotStatus, err = store.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, contentHash[:], gotHash)
	assert.Equal(t, "deprecated", gotStatus)
}

func TestSetMemoryStatusPreservingHashStagesInsideConsensusTransaction(t *testing.T) {
	store := newTestBadger(t)
	memoryID := "future-safe-consensus-status"
	contentHash := sha256.Sum256([]byte("consensus transaction memory"))
	require.NoError(t, store.SetMemoryHash(memoryID, contentHash[:], "proposed"))

	scoped := store.BeginConsensusTransaction(nil)
	require.NoError(t, scoped.SetMemoryStatusPreservingHash(memoryID, "committed"))

	scopedHash, scopedStatus, err := scoped.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, contentHash[:], scopedHash)
	assert.Equal(t, "committed", scopedStatus)
	baseHash, baseStatus, err := store.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, contentHash[:], baseHash)
	assert.Equal(t, "proposed", baseStatus, "the status update must remain staged before Commit")

	require.NoError(t, scoped.CommitConsensusTransaction())
	baseHash, baseStatus, err = store.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, contentHash[:], baseHash)
	assert.Equal(t, "committed", baseStatus)
}

func TestSetMemoryStatusPreservingHashRefusesMissingAndEmptyHash(t *testing.T) {
	store := newTestBadger(t)

	err := store.SetMemoryStatusPreservingHash("does-not-exist", "committed")
	require.ErrorIs(t, err, ErrMemoryNotFound)

	const legacyID = "legacy-empty-hash"
	require.NoError(t, store.SetMemoryHash(legacyID, nil, "proposed"))
	before := rawMemoryEntry(t, store, legacyID)

	err = store.SetMemoryStatusPreservingHash(legacyID, "committed")
	require.ErrorIs(t, err, ErrMemoryHashUnavailable)
	assert.Equal(t, before, rawMemoryEntry(t, store, legacyID))
	hash, status, getErr := store.GetMemoryHash(legacyID)
	require.NoError(t, getErr)
	assert.Empty(t, hash)
	assert.Equal(t, "proposed", status, "a refused transition must leave status unchanged")
}

func TestSetMemoryStatusPreservingHashRefusesMalformedOrNonCanonicalHash(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "truncated header", raw: []byte{0, 0, 0}},
		{name: "declared hash overruns value", raw: []byte{0, 0, 0, 32, 1, 2, 3}},
		{name: "short decoded hash", raw: encodeMemoryHashEntry(bytes.Repeat([]byte{0x11}, sha256.Size-1), "proposed")},
		{name: "long decoded hash", raw: encodeMemoryHashEntry(bytes.Repeat([]byte{0x22}, sha256.Size+1), "proposed")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newTestBadger(t)
			memoryID := "malformed-" + test.name
			setRawMemoryEntry(t, store, memoryID, test.raw)

			err := store.SetMemoryStatusPreservingHash(memoryID, "committed")
			require.ErrorIs(t, err, ErrMemoryHashMalformed)
			assert.Equal(
				t,
				test.raw,
				rawMemoryEntry(t, store, memoryID),
				"a refused transition must leave malformed state byte-identical",
			)
		})
	}
}

func TestSetMemoryStatusPreservingHashValidatesArgumentsBeforeMutation(t *testing.T) {
	store := newTestBadger(t)
	contentHash := sha256.Sum256([]byte("argument validation"))
	require.NoError(t, store.SetMemoryHash("argument-memory", contentHash[:], "proposed"))
	before := rawMemoryEntry(t, store, "argument-memory")

	require.ErrorContains(t, store.SetMemoryStatusPreservingHash("", "committed"), "memory id is required")
	require.ErrorContains(t, store.SetMemoryStatusPreservingHash("argument-memory", " \t"), "memory status is required")
	assert.Equal(t, before, rawMemoryEntry(t, store, "argument-memory"))
}

func TestSetMemoryHashNilLegacyEncodingRemainsByteIdentical(t *testing.T) {
	store := newTestBadger(t)
	const memoryID = "legacy-nil-encoding"
	const status = "committed"

	require.NoError(t, store.SetMemoryHash(memoryID, nil, status))

	want := append([]byte{0, 0, 0, 0}, []byte(status)...)
	assert.Equal(
		t,
		want,
		rawMemoryEntry(t, store, memoryID),
		"legacy SetMemoryHash(nil) must retain its zero-length-hash wire encoding",
	)
	hash, gotStatus, err := store.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Nil(t, hash)
	assert.Equal(t, status, gotStatus)

	err = store.SetMemoryStatusPreservingHash(memoryID, "deprecated")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMemoryHashUnavailable))
	assert.Equal(t, want, rawMemoryEntry(t, store, memoryID))
}
