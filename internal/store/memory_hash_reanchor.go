package store

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	badger "github.com/dgraph-io/badger/v4"
)

const (
	maxMemoryHashReanchorEntries = 256
	maxMemoryHashReanchorIDBytes = 512
)

var (
	// ErrMemoryHashReanchorIneligible marks a record that is outside the
	// deliberately narrow app-v24 repair population.
	ErrMemoryHashReanchorIneligible = errors.New("memory is ineligible for hash reanchor")

	// ErrMemoryHashReanchorStateDrift marks an expected lifecycle transition
	// that can make an otherwise valid proposal permanently stale.
	// Malformed canonical encoding and missing disclosure projections never
	// wrap this sentinel; those are invariant failures that consensus must keep
	// fatal instead of clearing as ordinary proposal drift.
	ErrMemoryHashReanchorStateDrift = errors.New("memory hash reanchor target state changed")

	// ErrMemoryHashReanchorConflict marks a replay whose requested evidence
	// differs from an already canonical 32-byte hash.
	ErrMemoryHashReanchorConflict = errors.New("memory hash reanchor conflicts with canonical evidence")
)

// MemoryHashReanchorEntry is the typed Badger input for one app-v24 repair.
// The governance/ABCI layer is responsible for authenticating the payload and
// translating its transaction-level entry into this storage type.
type MemoryHashReanchorEntry struct {
	MemoryID       string
	ExpectedStatus string
	ContentHash    []byte
}

type validatedMemoryHashReanchor struct {
	entry       MemoryHashReanchorEntry
	needsRepair bool
}

// ValidateMemoryHashReanchors performs the same complete-snapshot eligibility
// check as ReanchorMemoryHashes without writing. ABCI uses it immediately
// before governance execution is marked successful, then calls
// ReanchorMemoryHashes from the apply phase in the same outer consensus
// transaction.
func (s *BadgerStore) ValidateMemoryHashReanchors(entries []MemoryHashReanchorEntry) error {
	if s == nil {
		return errors.New("memory hash reanchor requires a store")
	}
	ownedEntries, err := ownMemoryHashReanchorEntries(entries)
	if err != nil {
		return err
	}
	return s.view(func(txn *badger.Txn) error {
		for _, entry := range ownedEntries {
			if _, err := validateMemoryHashReanchorState(txn, entry); err != nil {
				return err
			}
		}
		return nil
	})
}

// ReanchorMemoryHashes validates and applies one bounded repair chunk in one
// Badger transaction. The first pass validates every entry and stages no
// mutation. Only after the complete chunk is proven eligible does the second
// pass rewrite memory:<id>, retaining the exact terminal status.
//
// A canonical record that already contains the requested 32-byte hash is an
// idempotent no-op. A different non-zero hash, malformed record, missing
// envelope field, co-commit/scoped marker, or status mismatch fails the whole
// chunk. No SQL projection participates in this consensus mutation.
func (s *BadgerStore) ReanchorMemoryHashes(entries []MemoryHashReanchorEntry) error {
	if s == nil {
		return errors.New("memory hash reanchor requires a store")
	}
	ownedEntries, err := ownMemoryHashReanchorEntries(entries)
	if err != nil {
		return err
	}

	return s.update(func(txn *badger.Txn) error {
		validated := make([]validatedMemoryHashReanchor, 0, len(ownedEntries))

		// Pass 1: validate the complete chunk against one transaction snapshot.
		for _, entry := range ownedEntries {
			needsRepair, err := validateMemoryHashReanchorState(txn, entry)
			if err != nil {
				return err
			}
			validated = append(validated, validatedMemoryHashReanchor{
				entry:       entry,
				needsRepair: needsRepair,
			})
		}

		// Pass 2: change only memory:<id>. Exact-hash entries are replay-safe
		// no-ops and deliberately consume no write budget.
		for _, item := range validated {
			if !item.needsRepair {
				continue
			}
			if err := s.txnSet(
				txn,
				memoryKey(item.entry.MemoryID),
				encodeMemoryHashEntry(item.entry.ContentHash, item.entry.ExpectedStatus),
			); err != nil {
				return fmt.Errorf(
					"reanchor memory hash for %s: %w", item.entry.MemoryID, err,
				)
			}
		}
		return nil
	})
}

func ownMemoryHashReanchorEntries(entries []MemoryHashReanchorEntry) ([]MemoryHashReanchorEntry, error) {
	// Own the exact evidence bytes used by validation and persistence.
	// Consensus callers are synchronous, but a defensive copy keeps these
	// primitives immune to a caller mutating a reused hash buffer.
	ownedEntries := make([]MemoryHashReanchorEntry, len(entries))
	for i, entry := range entries {
		ownedEntries[i] = entry
		ownedEntries[i].ContentHash = append([]byte(nil), entry.ContentHash...)
	}
	if err := validateMemoryHashReanchorEntries(ownedEntries); err != nil {
		return nil, err
	}
	return ownedEntries, nil
}

func validateMemoryHashReanchorEntries(entries []MemoryHashReanchorEntry) error {
	if len(entries) == 0 || len(entries) > maxMemoryHashReanchorEntries {
		return fmt.Errorf(
			"memory hash reanchor entry count %d is outside 1..%d",
			len(entries), maxMemoryHashReanchorEntries,
		)
	}
	var previous []byte
	for i, entry := range entries {
		memoryID := []byte(entry.MemoryID)
		if len(memoryID) == 0 || len(memoryID) > maxMemoryHashReanchorIDBytes {
			return fmt.Errorf(
				"memory hash reanchor entry %d ID length %d is outside 1..%d",
				i, len(memoryID), maxMemoryHashReanchorIDBytes,
			)
		}
		if i > 0 && bytes.Compare(previous, memoryID) >= 0 {
			return fmt.Errorf(
				"memory hash reanchor entry %d ID is not strictly raw-byte sorted and unique", i,
			)
		}
		switch entry.ExpectedStatus {
		case "committed", "deprecated":
		default:
			return fmt.Errorf(
				"memory hash reanchor entry %d expected status %q is not terminal",
				i, entry.ExpectedStatus,
			)
		}
		if len(entry.ContentHash) != sha256.Size {
			return fmt.Errorf(
				"memory hash reanchor entry %d content hash length %d, want %d",
				i, len(entry.ContentHash), sha256.Size,
			)
		}
		previous = memoryID
	}
	return nil
}

func validateMemoryHashReanchorState(
	txn *badger.Txn,
	entry MemoryHashReanchorEntry,
) (bool, error) {
	item, err := txn.Get(memoryKey(entry.MemoryID))
	if errors.Is(err, badger.ErrKeyNotFound) {
		return false, fmt.Errorf(
			"%w: %w: %s",
			ErrMemoryHashReanchorIneligible,
			ErrMemoryNotFound,
			entry.MemoryID,
		)
	}
	if err != nil {
		return false, fmt.Errorf("read memory %s for hash reanchor: %w", entry.MemoryID, err)
	}

	var canonicalHash []byte
	var canonicalStatus string
	if err := item.Value(func(value []byte) error {
		var decodeErr error
		canonicalHash, canonicalStatus, decodeErr = decodeMemoryHashEntry(value)
		return decodeErr
	}); err != nil {
		return false, fmt.Errorf(
			"%w: %w for %s: %v",
			ErrMemoryHashReanchorIneligible, ErrMemoryHashMalformed, entry.MemoryID, err,
		)
	}
	// decodeMemoryHashEntry only establishes framing. Validate the lifecycle
	// enum before treating a mismatch as ordinary mutable drift; an arbitrary
	// or empty status byte sequence is canonical corruption and must remain
	// fatal to consensus.
	switch canonicalStatus {
	case "proposed", "validated", "committed", "challenged", "deprecated":
	default:
		return false, fmt.Errorf(
			"%w: memory %s has invalid status %q",
			ErrMemoryHashReanchorIneligible,
			entry.MemoryID,
			canonicalStatus,
		)
	}
	if canonicalStatus != entry.ExpectedStatus {
		return false, fmt.Errorf(
			"%w: %w: status mismatch for %s: got %q, expected %q",
			ErrMemoryHashReanchorIneligible,
			ErrMemoryHashReanchorStateDrift,
			entry.MemoryID,
			canonicalStatus,
			entry.ExpectedStatus,
		)
	}
	switch canonicalStatus {
	case "committed", "deprecated":
	default:
		return false, fmt.Errorf(
			"%w: %w: memory %s status %q is not terminal",
			ErrMemoryHashReanchorIneligible,
			ErrMemoryHashReanchorStateDrift,
			entry.MemoryID,
			canonicalStatus,
		)
	}

	// These exact projections constitute the complete ordinary app-v23
	// disclosure envelope. The principal key is the app-v23 provenance marker;
	// pre-v23 hashless records intentionally lack it and remain outside repair.
	if err := requireNonEmptyMemoryHashReanchorValue(
		txn, memoryDomainKey(entry.MemoryID), entry.MemoryID, "domain",
	); err != nil {
		return false, err
	}
	if err := requireNonEmptyMemoryHashReanchorValue(
		txn, memoryAuthorKey(entry.MemoryID), entry.MemoryID, "author",
	); err != nil {
		return false, err
	}
	if err := requireNonEmptyMemoryHashReanchorValue(
		txn, memoryAuthorPrincipalKey(entry.MemoryID), entry.MemoryID, "author principal",
	); err != nil {
		return false, err
	}
	if err := requireMemoryHashReanchorClassification(txn, entry.MemoryID); err != nil {
		return false, err
	}

	// Co-commits and scoped memories retain their hash through their own
	// lifecycle machinery. A terminal ordinary repair target cannot legitimately
	// acquire either marker after the proposal snapshot: scoped submission starts
	// from proposed state, while this operation accepts only committed/deprecated
	// records. Treat any marker here as invariant corruption, including a partial
	// marker set, so consensus never clears the proposal as ordinary drift.
	for _, marker := range []struct {
		key  []byte
		kind string
	}{
		{cocommitCoreKey(entry.MemoryID), "co-commit core"},
		{cocommitSharedKey(entry.MemoryID), "co-commit schema"},
		{scopeBallotKey(entry.MemoryID), "scoped ballot"},
		{scopedContentKey(entry.MemoryID), "scoped content"},
	} {
		if _, getErr := txn.Get(marker.key); getErr == nil {
			return false, fmt.Errorf(
				"%w: memory %s has %s state",
				ErrMemoryHashReanchorIneligible,
				entry.MemoryID,
				marker.kind,
			)
		} else if !errors.Is(getErr, badger.ErrKeyNotFound) {
			return false, fmt.Errorf(
				"read memory %s %s marker: %w", entry.MemoryID, marker.kind, getErr,
			)
		}
	}

	switch len(canonicalHash) {
	case 0:
		return true, nil
	case sha256.Size:
		if bytes.Equal(canonicalHash, entry.ContentHash) {
			return false, nil
		}
		return false, fmt.Errorf(
			"%w: memory %s already has a different canonical hash",
			ErrMemoryHashReanchorConflict, entry.MemoryID,
		)
	default:
		return false, fmt.Errorf(
			"%w: %w for %s: got %d bytes, want zero or %d",
			ErrMemoryHashReanchorIneligible,
			ErrMemoryHashMalformed,
			entry.MemoryID,
			len(canonicalHash),
			sha256.Size,
		)
	}
}

func requireNonEmptyMemoryHashReanchorValue(
	txn *badger.Txn,
	key []byte,
	memoryID string,
	field string,
) error {
	item, err := txn.Get(key)
	if errors.Is(err, badger.ErrKeyNotFound) {
		return fmt.Errorf(
			"%w: memory %s is missing %s projection",
			ErrMemoryHashReanchorIneligible, memoryID, field,
		)
	}
	if err != nil {
		return fmt.Errorf("read memory %s %s projection: %w", memoryID, field, err)
	}
	return item.Value(func(value []byte) error {
		if len(value) == 0 {
			return fmt.Errorf(
				"%w: memory %s has empty %s projection",
				ErrMemoryHashReanchorIneligible, memoryID, field,
			)
		}
		return nil
	})
}

func requireMemoryHashReanchorClassification(txn *badger.Txn, memoryID string) error {
	item, err := txn.Get(memClassKey(memoryID))
	if errors.Is(err, badger.ErrKeyNotFound) {
		return fmt.Errorf(
			"%w: memory %s is missing classification projection",
			ErrMemoryHashReanchorIneligible, memoryID,
		)
	}
	if err != nil {
		return fmt.Errorf("read memory %s classification projection: %w", memoryID, err)
	}
	return item.Value(func(value []byte) error {
		if len(value) != 1 || value[0] > uint8(ClearanceTopSecret) {
			return fmt.Errorf(
				"%w: memory %s has malformed classification projection",
				ErrMemoryHashReanchorIneligible, memoryID,
			)
		}
		return nil
	})
}
