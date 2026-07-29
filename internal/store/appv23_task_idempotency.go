package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	badger "github.com/dgraph-io/badger/v4"

	"github.com/l33tdawg/sage/internal/taskidempotency"
)

var ErrAppV23TaskIdempotencyConflict = errors.New("task idempotency key is already bound to a different payload")

// AppV23TaskIdempotencyBinding is consensus state. PayloadDigest commits to the
// exact task fields and assignee; MemoryID/height/tx hash make a retry response
// reconstructible after an HTTP disconnect or process restart.
type AppV23TaskIdempotencyBinding struct {
	Version          uint8  `json:"version"`
	PrincipalID      string `json:"principal_id"`
	BindingKeyDigest string `json:"binding_key_digest"`
	PayloadDigest    string `json:"payload_digest"`
	MemoryID         string `json:"memory_id"`
	AssigneeID       string `json:"assignee_id"`
	CommittedHeight  int64  `json:"committed_height"`
	TxHash           string `json:"tx_hash"`
}

func appV23TaskIdempotencyKey(principalID, key string) ([]byte, string, error) {
	sum, err := taskidempotency.BindingKeyDigest(principalID, key)
	if err != nil {
		return nil, "", err
	}
	digest := taskidempotency.Hex(sum)
	return []byte("appv23:task-idempotency:" + digest), digest, nil
}

func validateAppV23TaskIdempotencyBinding(binding *AppV23TaskIdempotencyBinding) error {
	if binding == nil || binding.Version != 1 ||
		!isCanonicalAgentID(binding.PrincipalID) ||
		!isCanonicalAgentID(binding.AssigneeID) ||
		!canonicalLowerHex(binding.BindingKeyDigest, 64) ||
		!canonicalLowerHex(binding.PayloadDigest, 64) ||
		!canonicalUpperHex(binding.TxHash, 64) ||
		!canonicalUUIDv4(binding.MemoryID) ||
		binding.CommittedHeight <= 0 || binding.TxHash == "" {
		return errors.New("invalid app-v23 task idempotency binding")
	}
	return nil
}

func decodeAppV23TaskIdempotencyBinding(
	value []byte,
) (*AppV23TaskIdempotencyBinding, error) {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	var binding AppV23TaskIdempotencyBinding
	if err := decoder.Decode(&binding); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("app-v23 task idempotency binding has trailing JSON")
		}
		return nil, err
	}
	if err := validateAppV23TaskIdempotencyBinding(&binding); err != nil {
		return nil, err
	}
	return &binding, nil
}

func canonicalLowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for i := range value {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}

func canonicalUpperHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for i := range value {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'A' || value[i] > 'F') {
			return false
		}
	}
	return true
}

func canonicalUUIDv4(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' ||
		value[18] != '-' || value[23] != '-' || value[14] != '4' ||
		(value[19] != '8' && value[19] != '9' && value[19] != 'a' && value[19] != 'b') {
		return false
	}
	for i := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}

func (s *BadgerStore) GetAppV23TaskIdempotencyBinding(
	principalID, key string,
) (*AppV23TaskIdempotencyBinding, error) {
	stateKey, keyDigest, err := appV23TaskIdempotencyKey(principalID, key)
	if err != nil {
		return nil, err
	}
	var binding *AppV23TaskIdempotencyBinding
	err = s.view(func(txn *badger.Txn) error {
		item, getErr := txn.Get(stateKey)
		if getErr != nil {
			return getErr
		}
		return item.Value(func(value []byte) error {
			var decodeErr error
			binding, decodeErr = decodeAppV23TaskIdempotencyBinding(value)
			return decodeErr
		})
	})
	if errors.Is(err, badger.ErrKeyNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read app-v23 task idempotency binding: %w", err)
	}
	if binding.PrincipalID != principalID {
		return nil, errors.New("app-v23 task idempotency binding principal mismatch")
	}
	if binding.BindingKeyDigest != keyDigest {
		return nil, errors.New("app-v23 task idempotency binding key mismatch")
	}
	return binding, nil
}

func validateAppV23TaskIdempotencyStateTxn(txn *badger.Txn) error {
	prefix := []byte("appv23:task-idempotency:")
	opts := badger.DefaultIteratorOptions
	opts.Prefix = prefix
	it := txn.NewIterator(opts)
	defer it.Close()
	for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
		key := it.Item().KeyCopy(nil)
		suffix := string(key[len(prefix):])
		if !canonicalLowerHex(suffix, 64) {
			return errors.New("app-v23 task idempotency key suffix is malformed")
		}
		var binding *AppV23TaskIdempotencyBinding
		if err := it.Item().Value(func(value []byte) error {
			var decodeErr error
			binding, decodeErr = decodeAppV23TaskIdempotencyBinding(value)
			return decodeErr
		}); err != nil {
			return fmt.Errorf("invalid app-v23 task idempotency binding: %w", err)
		}
		if binding.BindingKeyDigest != suffix {
			return errors.New("app-v23 task idempotency key/value invariant failed")
		}
		memoryItem, err := txn.Get(memoryKey(binding.MemoryID))
		if err != nil {
			return errors.New("app-v23 task idempotency binding references missing memory")
		}
		if valueErr := memoryItem.Value(func(value []byte) error {
			_, _, decodeErr := decodeMemoryHashEntry(value)
			return decodeErr
		}); valueErr != nil {
			return errors.New("app-v23 task idempotency binding references malformed memory")
		}
		if _, domainErr := txn.Get(memoryDomainKey(binding.MemoryID)); domainErr != nil {
			return errors.New("app-v23 task idempotency binding references missing memory domain")
		}
		classItem, err := txn.Get(memClassKey(binding.MemoryID))
		if err != nil {
			return errors.New("app-v23 task idempotency binding references missing memory classification")
		}
		if classErr := classItem.Value(func(value []byte) error {
			if len(value) != 1 {
				return errors.New("malformed memory classification")
			}
			return nil
		}); classErr != nil {
			return errors.New("app-v23 task idempotency binding references malformed memory classification")
		}
		authorItem, err := txn.Get(memoryAuthorPrincipalKey(binding.MemoryID))
		if err != nil {
			return errors.New("app-v23 task idempotency binding references missing memory principal")
		}
		if err := authorItem.Value(func(value []byte) error {
			if string(value) != binding.PrincipalID {
				return errors.New("memory principal mismatch")
			}
			return nil
		}); err != nil {
			return errors.New("app-v23 task idempotency binding memory principal mismatch")
		}
	}
	return nil
}

// SetAppV23TaskIdempotencyBinding is first-write-wins. An identical replay is
// a deterministic no-op; reusing the token for any other payload is a conflict.
func (s *BadgerStore) SetAppV23TaskIdempotencyBinding(
	principalID, key string,
	binding *AppV23TaskIdempotencyBinding,
) error {
	stateKey, keyDigest, err := appV23TaskIdempotencyKey(principalID, key)
	if err != nil {
		return err
	}
	if validationErr := validateAppV23TaskIdempotencyBinding(binding); validationErr != nil {
		return validationErr
	}
	if binding.PrincipalID != principalID {
		return errors.New("app-v23 task idempotency binding principal mismatch")
	}
	if binding.BindingKeyDigest != keyDigest {
		return errors.New("app-v23 task idempotency binding key mismatch")
	}
	encoded, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	return s.update(func(txn *badger.Txn) error {
		item, getErr := txn.Get(stateKey)
		if getErr == nil {
			var existing []byte
			if valueErr := item.Value(func(value []byte) error {
				existing = append([]byte(nil), value...)
				return nil
			}); valueErr != nil {
				return valueErr
			}
			if bytes.Equal(existing, encoded) {
				return nil
			}
			return ErrAppV23TaskIdempotencyConflict
		}
		if !errors.Is(getErr, badger.ErrKeyNotFound) {
			return getErr
		}
		return s.txnSet(txn, stateKey, encoded)
	})
}
