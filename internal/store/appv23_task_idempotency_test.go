package store

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/taskidempotency"
)

func TestAppV23TaskIdempotencyBindingPersistsAndConflicts(t *testing.T) {
	path := t.TempDir()
	s, err := NewBadgerStore(path)
	require.NoError(t, err)
	principal := strings.Repeat("ab", 32)
	keyDigest, err := taskidempotency.BindingKeyDigest(principal, "request-1")
	require.NoError(t, err)
	binding := &AppV23TaskIdempotencyBinding{
		Version: 1, PrincipalID: principal,
		BindingKeyDigest: taskidempotency.Hex(keyDigest),
		PayloadDigest:    strings.Repeat("cd", 32),
		MemoryID:         "00000000-0000-4000-8000-000000000001",
		AssigneeID:       principal, CommittedHeight: 23,
		TxHash: strings.Repeat("EF", 32),
	}
	require.NoError(t, s.SetAppV23TaskIdempotencyBinding(principal, "request-1", binding))
	require.NoError(t, s.SetAppV23TaskIdempotencyBinding(principal, "request-1", binding),
		"identical consensus replay is a no-op")
	require.NoError(t, s.db.Close())

	s, err = NewBadgerStore(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.db.Close() })
	got, err := s.GetAppV23TaskIdempotencyBinding(principal, "request-1")
	require.NoError(t, err)
	require.Equal(t, binding, got)

	conflict := *binding
	conflict.PayloadDigest = strings.Repeat("ee", 32)
	err = s.SetAppV23TaskIdempotencyBinding(principal, "request-1", &conflict)
	require.True(t, errors.Is(err, ErrAppV23TaskIdempotencyConflict))
}

func TestValidateAppV23StateRejectsMalformedTaskIdempotencyBinding(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
	root := appV23Register(t, s, "task-receipt-root", AppV23RoleAdmin, 1, 0)
	agent := appV23Register(t, s, "task-receipt-agent", AppV23RoleMember, 2, 0)
	require.NotEqual(t, root, agent)
	require.NoError(t, s.EnsureAppV23Root("task-receipt-scope", 10))

	key := "request-state-validation"
	memoryID, err := taskidempotency.MemoryID(agent, key)
	require.NoError(t, err)
	keyDigest, err := taskidempotency.BindingKeyDigest(agent, key)
	require.NoError(t, err)
	contentHash := sha256.Sum256([]byte("[TASK] state validation"))
	require.NoError(t, s.SetMemoryHash(memoryID, contentHash[:], "proposed"))
	require.NoError(t, s.SetMemoryDomain(memoryID, "task-receipt-agent"))
	require.NoError(t, s.SetMemoryClassification(memoryID, 0))
	require.NoError(t, s.SetMemoryAuthorPrincipal(memoryID, agent))
	binding := &AppV23TaskIdempotencyBinding{
		Version: 1, PrincipalID: agent,
		BindingKeyDigest: taskidempotency.Hex(keyDigest),
		PayloadDigest:    strings.Repeat("cd", 32),
		MemoryID:         memoryID,
		AssigneeID:       agent,
		CommittedHeight:  11,
		TxHash:           strings.Repeat("EF", 32),
	}
	require.NoError(t, s.SetAppV23TaskIdempotencyBinding(agent, key, binding))
	require.NoError(t, s.ValidateAppV23State())

	raw, err := json.Marshal(binding)
	require.NoError(t, err)
	var object map[string]any
	require.NoError(t, json.Unmarshal(raw, &object))
	object["unexpected"] = true
	malformed, err := json.Marshal(object)
	require.NoError(t, err)
	stateKey, _, err := appV23TaskIdempotencyKey(agent, key)
	require.NoError(t, err)
	require.NoError(t, s.SetRawForTest(stateKey, malformed))
	require.ErrorContains(t, s.ValidateAppV23State(), "invalid app-v23 task idempotency binding")
}
