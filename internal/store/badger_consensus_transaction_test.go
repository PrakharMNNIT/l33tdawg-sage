package store

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConsensusOwnerCommitWaitsForOwnershipReaders(t *testing.T) {
	base, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, base.CloseBadger()) })
	require.NoError(t, base.RegisterDomain("research", "owner-a", "", 1))
	scoped := base.BeginConsensusTransaction(nil)
	require.NoError(t, scoped.TransferDomain("research", "owner-b", "", 2))

	unlock := base.LockDomainOwnershipRead()
	committed := make(chan error, 1)
	go func() { committed <- scoped.CommitConsensusTransaction() }()
	select {
	case commitErr := <-committed:
		t.Fatalf("ownership-changing consensus commit bypassed an active reader: %v", commitErr)
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	require.NoError(t, <-committed)
	owner, err := base.GetDomainOwner("research")
	require.NoError(t, err)
	require.Equal(t, "owner-b", owner)
}

func TestConsensusPublicationUsesOwnershipThenRuntimeLockOrder(t *testing.T) {
	base, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, base.CloseBadger()) })
	require.NoError(t, base.RegisterDomain("research", "owner-a", "", 1))
	scoped := base.BeginConsensusTransaction(nil)
	require.NoError(t, scoped.TransferDomain("research", "owner-b", "", 2))

	var runtime sync.RWMutex
	unlockOwnership := base.LockDomainOwnershipRead()
	runtimeAcquired := make(chan struct{})
	committed := make(chan error, 1)
	go func() {
		committed <- scoped.CommitConsensusTransactionWithPublication(
			func() func() {
				runtime.Lock()
				close(runtimeAcquired)
				return runtime.Unlock
			},
			nil,
			func() {},
		)
	}()

	// A federated reader already holding the domain lease must still be able to
	// enter the runtime read view. Commit cannot own runtime while it waits for
	// that reader's domain lease, or the two sides deadlock permanently.
	runtime.RLock()
	select {
	case <-runtimeAcquired:
		runtime.RUnlock()
		t.Fatal("Commit acquired runtime publication before the domain reader released")
	case <-time.After(100 * time.Millisecond):
	}
	runtime.RUnlock()

	unlockOwnership()
	require.NoError(t, <-committed)
	select {
	case <-runtimeAcquired:
	case <-time.After(2 * time.Second):
		t.Fatal("Commit did not acquire runtime publication after the domain lease released")
	}
}

func TestConsensusPublicationLocksRuntimeBeforeDurableKeysBecomeVisible(t *testing.T) {
	base, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, base.CloseBadger()) })
	require.NoError(t, base.RegisterDomain("research", "owner-a", "", 1))
	scoped := base.BeginConsensusTransaction(nil)
	require.NoError(t, scoped.TransferDomain("research", "owner-b", "", 2))

	var runtime sync.RWMutex
	runtime.RLock()
	runtimeAttempted := make(chan struct{})
	published := make(chan struct{})
	committed := make(chan error, 1)
	go func() {
		committed <- scoped.CommitConsensusTransactionWithPublication(
			func() func() {
				close(runtimeAttempted)
				runtime.Lock()
				return runtime.Unlock
			},
			nil,
			func() { close(published) },
		)
	}()

	select {
	case <-runtimeAttempted:
	case <-time.After(2 * time.Second):
		t.Fatal("Commit did not reach the runtime publication gate")
	}
	owner, err := base.GetDomainOwner("research")
	require.NoError(t, err)
	require.Equal(t, "owner-a", owner,
		"staged keys became visible before Commit acquired runtime publication")
	select {
	case <-published:
		t.Fatal("runtime view published while its write gate was held by a reader")
	default:
	}

	runtime.RUnlock()
	require.NoError(t, <-committed)
	select {
	case <-published:
	case <-time.After(2 * time.Second):
		t.Fatal("runtime publication callback did not run after durable commit")
	}
	owner, err = base.GetDomainOwner("research")
	require.NoError(t, err)
	require.Equal(t, "owner-b", owner)
}

func TestOrderedPublicationBarrierLetsDomainReaderFinishBeforeRuntimeWriter(t *testing.T) {
	base, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, base.CloseBadger()) })
	require.NoError(t, base.RegisterDomain("legacy-research", "owner-a", "", 1))

	var runtime sync.RWMutex
	unlockOwnership := base.LockDomainOwnershipRead()
	runtimeAcquired := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- base.WithOrderedPublicationBarrier(
			func() func() {
				runtime.Lock()
				close(runtimeAcquired)
				return runtime.Unlock
			},
			func(scoped *BadgerStore) error {
				return scoped.TransferDomain("legacy-research", "owner-b", "", 2)
			},
		)
	}()

	runtime.RLock()
	select {
	case <-runtimeAcquired:
		runtime.RUnlock()
		t.Fatal("legacy publication acquired runtime before the domain reader released")
	case <-time.After(100 * time.Millisecond):
	}
	runtime.RUnlock()
	unlockOwnership()
	require.NoError(t, <-finished)

	owner, err := base.GetDomainOwner("legacy-research")
	require.NoError(t, err)
	require.Equal(t, "owner-b", owner,
		"nested mutation on the barrier-scoped handle did not publish")
}

func TestConsensusCloneUsesAuthorizationHookInstalledAfterClone(t *testing.T) {
	base, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, base.CloseBadger()) })
	require.NoError(t, base.SetCrossFed(
		"peer-late-hook", "https://peer.invalid", []byte("peer-key"),
		4, 0, []string{"*"}, nil, "active",
	))

	scoped := base.BeginConsensusTransaction(nil)
	require.NoError(t, scoped.UpdateCrossFedStatus(
		"peer-late-hook", "revoked",
	))
	var acquiredChain string
	var releases int
	base.SetAuthorizationMutationHook(func(remoteChainID string) func() {
		acquiredChain = remoteChainID
		return func() { releases++ }
	})
	require.NoError(t, scoped.CommitConsensusTransaction())
	require.Equal(t, "peer-late-hook", acquiredChain,
		"a clone opened before startup wiring must resolve the live hook at commit")
	require.Equal(t, 1, releases)
}

func TestAuthorizationHookInstallWaitsForPreHookConsensusCommit(t *testing.T) {
	base, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, base.CloseBadger()) })
	require.NoError(t, base.SetCrossFed(
		"peer-startup", "https://peer.invalid", []byte("peer-key"),
		4, 0, []string{"*"}, nil, "active",
	))
	scoped := base.BeginConsensusTransaction(nil)
	require.NoError(t, scoped.UpdateCrossFedStatus("peer-startup", "revoked"))

	unlockOwnership := base.LockDomainOwnershipRead()
	commitDone := make(chan error, 1)
	go func() { commitDone <- scoped.CommitConsensusTransaction() }()
	require.Eventually(t, func() bool {
		if base.authorizationMutationHooks.mu.TryLock() {
			base.authorizationMutationHooks.mu.Unlock()
			return false
		}
		return true
	}, 2*time.Second, time.Millisecond,
		"pre-hook authorization commit did not acquire startup barrier")

	installed := make(chan struct{})
	go func() {
		base.SetAuthorizationMutationHook(func(string) func() {
			return func() {}
		})
		close(installed)
	}()
	select {
	case <-installed:
		t.Fatal("hook installation bypassed a pre-hook authorization commit")
	case <-time.After(100 * time.Millisecond):
	}
	unlockOwnership()
	require.NoError(t, <-commitDone)
	select {
	case <-installed:
	case <-time.After(2 * time.Second):
		t.Fatal("hook installation did not finish after old commit published")
	}
}

func TestSetSharedDomainWaitsForOwnershipReaders(t *testing.T) {
	base, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, base.CloseBadger()) })

	unlock := base.LockDomainOwnershipRead()
	shared := make(chan error, 1)
	go func() { shared <- base.SetSharedDomain("open.shared") }()
	select {
	case shareErr := <-shared:
		t.Fatalf("shared-domain publication bypassed an active owner reader: %v", shareErr)
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	require.NoError(t, <-shared)
	marker, err := base.GetState("shared_domain:open.shared")
	require.NoError(t, err)
	require.Equal(t, []byte{1}, marker)
}

func TestAccessGrantRevokeWaitsForOwnershipReaders(t *testing.T) {
	base, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, base.CloseBadger()) })
	require.NoError(t, base.SetAccessGrant("research", "reader", 1, 0, "owner"))

	unlock := base.LockDomainOwnershipRead()
	revoked := make(chan error, 1)
	go func() { revoked <- base.DeleteAccessGrant("research", "reader") }()
	select {
	case revokeErr := <-revoked:
		t.Fatalf("access revoke bypassed an active federated authorization reader: %v", revokeErr)
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	require.NoError(t, <-revoked)
	_, _, _, err = base.GetAccessGrant("research", "reader")
	require.ErrorIs(t, err, ErrAccessGrantNotFound)
}

func TestConsensusTransactionPreWriteSentinelDoesNotPoison(t *testing.T) {
	base, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, base.CloseBadger()) })

	scoped := base.BeginConsensusTransaction(nil)
	require.NoError(t, scoped.RegisterDomain("bounded.example", "owner", "", 1))
	require.ErrorIs(t, scoped.RegisterDomain("bounded.example", "attacker", "", 2), ErrDomainAlreadyRegistered)
	assert.NoError(t, scoped.ConsensusTransactionError(), "a validation sentinel before mutation is an ordinary invalid tx")
	require.NoError(t, scoped.SetState("after-sentinel", []byte("committed")))
	require.NoError(t, scoped.CommitConsensusTransaction())

	owner, err := base.GetDomainOwner("bounded.example")
	require.NoError(t, err)
	assert.Equal(t, "owner", owner)
	value, err := base.GetState("after-sentinel")
	require.NoError(t, err)
	assert.Equal(t, []byte("committed"), value)
}

func TestConsensusTransactionFailedFirstOrMidWriteDiscardsWholeBoundary(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(fmt.Sprintf("write-%d", failAt), func(t *testing.T) {
			base, err := NewBadgerStore(t.TempDir())
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, base.CloseBadger()) })

			scoped := base.BeginConsensusTransaction(nil)
			scoped.writeFaultHook = func(attempt int) error {
				if attempt == failAt {
					return errors.New("injected staged-write failure")
				}
				return nil
			}
			err = scoped.SetStatesAtomic([]StateWrite{
				{Key: "a", Value: []byte("one")},
				{Key: "b", Value: []byte("two")},
				{Key: "c", Value: []byte("three")},
			})
			require.ErrorContains(t, err, "injected staged-write failure")
			require.Error(t, scoped.ConsensusTransactionError())
			require.Error(t, scoped.CommitConsensusTransaction(), "a poisoned transaction must never publish earlier staged writes")

			for _, key := range []string{"a", "b", "c"} {
				value, getErr := base.GetState(key)
				require.NoError(t, getErr)
				assert.Empty(t, value, "state %q survived a failed atomic boundary", key)
			}
		})
	}
}

func TestConsensusTransactionProofReplayDoesNotPruneExpiredMarkers(t *testing.T) {
	base, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, base.CloseBadger()) })

	now := time.Unix(50_000, 0).UTC()
	duplicate := sha256.Sum256([]byte("duplicate"))
	require.NoError(t, base.ClaimAgentProof(duplicate[:], now, now.Unix()+300))
	expired := make([][sha256.Size]byte, 12)
	for i := range expired {
		expired[i] = sha256.Sum256([]byte(fmt.Sprintf("expired-%d", i)))
		require.NoError(t, base.ClaimAgentProof(expired[i][:], now.Add(-time.Hour), now.Unix()-1))
	}

	scoped := base.BeginConsensusTransaction(nil)
	require.ErrorIs(t, scoped.ClaimAgentProof(duplicate[:], now, now.Unix()+300), ErrAgentProofReplayed)
	assert.NoError(t, scoped.ConsensusTransactionError(), "proof replay is rejected before opportunistic GC mutates")
	require.NoError(t, scoped.SetState("valid-after-replay", []byte("yes")))
	require.NoError(t, scoped.CommitConsensusTransaction())

	for i := range expired {
		exists, hasErr := base.HasAgentProof(expired[i][:], now.Add(-2*time.Second), now.Unix()-1)
		require.NoError(t, hasErr)
		assert.True(t, exists, "rejected replay pruned expired marker %d", i)
	}
}

func TestValidateAppV20ResourceBoundsRejectsOversizedLegacyFullRecord(t *testing.T) {
	bs, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, bs.CloseBadger()) })

	const recordLimit = 64 << 10
	require.NoError(t, bs.SetRawForTest([]byte("federation:legacy"), make([]byte, recordLimit+1)))
	err = bs.ValidateAppV20ResourceBounds(512, recordLimit, recordLimit, 100)
	require.ErrorContains(t, err, "legacy consensus record")
}

func TestValidateAppV20ResourceBoundsRejectsStaleValidatorAmplification(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed func(*testing.T, *BadgerStore, map[string]int64)
		want string
	}{
		{
			name: "persisted validator keys",
			seed: func(t *testing.T, bs *BadgerStore, validators map[string]int64) {
				require.NoError(t, bs.SaveValidators(validators))
			},
			want: "persisted validator set",
		},
		{
			name: "persisted PoE weight keys",
			seed: func(t *testing.T, bs *BadgerStore, validators map[string]int64) {
				weights := make(map[string]float64, len(validators))
				for id := range validators {
					weights[id] = 1
				}
				require.NoError(t, bs.SetEpochWeights(1, weights))
			},
			want: "persisted PoE weight set",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bs, err := NewBadgerStore(t.TempDir())
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, bs.CloseBadger()) })
			validators := make(map[string]int64, 101)
			for i := 0; i < 101; i++ {
				validators[fmt.Sprintf("%064x", i)] = 1
			}
			tc.seed(t, bs, validators)
			err = bs.ValidateAppV20ResourceBounds(512, 64<<10, 64<<10, 100)
			require.ErrorContains(t, err, tc.want)
		})
	}
}
