package store

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRoutineAgentActivityDoesNotPublishLinkedAuthorizationInvalidation(
	t *testing.T,
) {
	ctx := context.Background()
	s, err := NewSQLiteStore(ctx, ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	var invalidations atomic.Int32
	s.SetFederationAuthorizationMutationHook(func(string) func() {
		invalidations.Add(1)
		return func() {}
	})

	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	agentID := hex.EncodeToString(pub)
	agent := &AgentEntry{
		AgentID: agentID, Name: "active-agent",
		RegisteredName: "active-agent", Status: "active",
	}
	require.NoError(t, s.CreateAgent(ctx, agent))
	for i := 0; i < 128; i++ {
		require.NoError(t, s.UpdateAgentLastSeen(
			ctx, agentID, time.Unix(int64(i+1), 0),
		))
	}
	agent.Name = "renamed-active-agent"
	require.NoError(t, s.UpdateAgent(ctx, agent))
	require.NoError(t, s.UpdateAgentStatus(ctx, agentID, "active"))
	require.Zero(t, invalidations.Load(),
		"routine liveness and metadata churn must not cancel linked delivery")

	require.NoError(t, s.UpdateAgentStatus(ctx, agentID, "inactive"))
	require.EqualValues(t, 1, invalidations.Load())
	require.NoError(t, s.UpdateAgentStatus(ctx, agentID, "active"))
	require.EqualValues(t, 1, invalidations.Load(),
		"authorization-enabling activity cannot disclose stale payload")
	require.NoError(t, s.RemoveAgent(ctx, agentID))
	require.EqualValues(t, 2, invalidations.Load())
}

func TestSQLiteTransactionsRejectLinkedAuthorizationInvalidation(
	t *testing.T,
) {
	ctx := context.Background()
	s, err := NewSQLiteStore(ctx, ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	require.NoError(t, s.CreateAgent(ctx, &AgentEntry{
		AgentID: "contact-agent", Name: "active-agent", Status: "active",
	}))

	var invalidations atomic.Int32
	s.SetFederationAuthorizationMutationHook(func(string) func() {
		invalidations.Add(1)
		return func() {}
	})
	transactions := []struct {
		name string
		run  func(func(OffchainStore) error) error
	}{
		{
			name: "ordinary",
			run: func(fn func(OffchainStore) error) error {
				return s.RunInTx(ctx, fn)
			},
		},
		{
			name: "agent-contact",
			run: func(fn func(OffchainStore) error) error {
				return s.RunInAgentContactTx(ctx, fn)
			},
		},
	}
	mutations := []struct {
		name string
		run  func(OffchainStore) error
	}{
		{
			name: "inactive",
			run: func(tx OffchainStore) error {
				return tx.UpdateAgentStatus(ctx, "contact-agent", "inactive")
			},
		},
		{
			name: "remove",
			run: func(tx OffchainStore) error {
				return tx.RemoveAgent(ctx, "contact-agent")
			},
		},
		{
			name: "rotate",
			run: func(tx OffchainStore) error {
				_, _, rotateErr := tx.RotateAgentKey(ctx, "contact-agent")
				return rotateErr
			},
		},
		{
			name: "federated-guest",
			run: func(tx OffchainStore) error {
				return tx.(*SQLiteStore).PutFederatedGroupGuest(
					ctx, FederatedGroupGuest{},
				)
			},
		},
	}
	for _, transaction := range transactions {
		t.Run(transaction.name, func(t *testing.T) {
			for _, mutation := range mutations {
				t.Run(mutation.name, func(t *testing.T) {
					err := transaction.run(mutation.run)
					require.ErrorContains(t, err,
						"not permitted inside SQLite transaction")
					require.Zero(t, invalidations.Load(),
						"transaction must reject before waiting on delivery")
				})
			}
		})
	}
}

func TestSQLiteTransactionCloneUsesAuthorizationHookInstalledAfterClone(
	t *testing.T,
) {
	ctx := context.Background()
	s, err := NewSQLiteStore(ctx, ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	cloneReady := make(chan struct{})
	useClone := make(chan struct{})
	txDone := make(chan error, 1)
	go func() {
		txDone <- s.RunInTx(ctx, func(tx OffchainStore) error {
			close(cloneReady)
			<-useClone
			release := tx.(*SQLiteStore).
				beginFederationAuthorizationMutation("peer-late-hook")
			release()
			return nil
		})
	}()
	select {
	case <-cloneReady:
	case <-time.After(2 * time.Second):
		t.Fatal("transaction clone was not created")
	}

	var acquired atomic.Int32
	var released atomic.Int32
	var acquiredChain atomic.Value
	s.SetFederationAuthorizationMutationHook(
		func(remoteChainID string) func() {
			acquiredChain.Store(remoteChainID)
			acquired.Add(1)
			return func() { released.Add(1) }
		},
	)
	close(useClone)
	require.NoError(t, <-txDone)
	require.EqualValues(t, 1, acquired.Load(),
		"a clone opened before startup wiring must resolve the live hook")
	require.EqualValues(t, 1, released.Load())
	require.Equal(t, "peer-late-hook", acquiredChain.Load())
}

func TestSQLiteHookInstallWaitsForPreHookAuthorizationMutation(
	t *testing.T,
) {
	ctx := context.Background()
	s, err := NewSQLiteStore(ctx, ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	mutationStarted := make(chan struct{})
	releaseMutation := make(chan struct{})
	txDone := make(chan error, 1)
	go func() {
		txDone <- s.RunInTx(ctx, func(tx OffchainStore) error {
			release := tx.(*SQLiteStore).
				beginFederationAuthorizationMutation("peer-startup")
			close(mutationStarted)
			<-releaseMutation
			release()
			return nil
		})
	}()
	select {
	case <-mutationStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("pre-hook authorization mutation did not start")
	}

	installed := make(chan struct{})
	go func() {
		s.SetFederationAuthorizationMutationHook(func(string) func() {
			return func() {}
		})
		close(installed)
	}()
	select {
	case <-installed:
		t.Fatal("hook installation bypassed a pre-hook SQLite mutation")
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseMutation)
	require.NoError(t, <-txDone)
	select {
	case <-installed:
	case <-time.After(2 * time.Second):
		t.Fatal("hook installation did not finish after old mutation")
	}
}
