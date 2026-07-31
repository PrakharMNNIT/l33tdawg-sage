package store

import (
	"crypto/sha256"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppV25DomainContinuityV2BatchReplicaDeterminismAndReplay(t *testing.T) {
	build := func(path string) (*BadgerStore, []AppV25DomainContinuityBatchEntry) {
		s, err := NewBadgerStore(path)
		require.NoError(t, err)
		rootID := appV23Register(t, s, "continuity-v2-replay-root", AppV23RoleAdmin, 1, 0)
		writerA := appV23Register(t, s, "continuity-v2-replay-a", AppV23RoleMember, 2, DefaultSelfRegisteredAgentCapabilities)
		writerB := appV23Register(t, s, "continuity-v2-replay-b", AppV23RoleMember, 3, DefaultSelfRegisteredAgentCapabilities)
		require.NoError(t, s.RegisterDomain("v2-replay-a", rootID, "", 4))
		require.NoError(t, s.RegisterDomain("v2-replay-b", rootID, "", 5))
		require.NoError(t, s.EnsureAppV23Root("continuity-v2-replay", 100))
		sharedWriters := []string{writerA, writerB}
		sort.Strings(sharedWriters)
		return s, []AppV25DomainContinuityBatchEntry{
			{Domain: "v2-replay-a", Owner: writerA, Writers: sharedWriters},
			{Domain: "v2-replay-b", Owner: writerA, Writers: []string{writerA}},
		}
	}

	left, leftEntries := build(t.TempDir())
	defer func() { require.NoError(t, left.CloseBadger()) }()
	right, rightEntries := build(t.TempDir())
	defer func() { require.NoError(t, right.CloseBadger()) }()
	require.Equal(t, leftEntries, rightEntries)
	plan := sha256.Sum256([]byte("v2-replica-determinism"))

	require.NoError(t, left.ApplyAppV25DomainContinuityBatch(leftEntries, plan[:], 1, 120))
	require.NoError(t, right.ApplyAppV25DomainContinuityBatch(rightEntries, plan[:], 1, 120))
	leftHash, err := left.ComputeAppHash()
	require.NoError(t, err)
	rightHash, err := right.ComputeAppHash()
	require.NoError(t, err)
	require.Equal(t, leftHash, rightHash,
		"map iteration and write order must not affect replicated app state")

	require.NoError(t, left.ApplyAppV25DomainContinuityBatch(leftEntries, plan[:], 1, 120))
	replayedHash, err := left.ComputeAppHash()
	require.NoError(t, err)
	require.Equal(t, leftHash, replayedHash,
		"exact v2 execution replay must be idempotent")
}
