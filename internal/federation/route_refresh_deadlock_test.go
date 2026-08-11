package federation

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/store"
)

// R1 regression. maybeTriggerRouteRefresh is called from INSIDE
// doPeerRequestWithHeaders, and several callers hold the sync-policy READ lease
// across that peer request. Resolving the agreement/binding also takes that
// read lease, so doing it on the caller's goroutine is a recursive RLock.
//
// Go's sync.RWMutex blocks new readers the moment a writer queues, so the
// recursive acquisition deadlocks against a writer that is itself waiting for
// the caller's RUnlock. LockSyncPolicyRead is a bare RLock with no context and
// no try-variant, so nothing times out and nothing can cancel it: both
// goroutines hang for the life of the process and the gate is wedged for every
// other reader, including all inbound federation handlers.
//
// These tests fail by TIMING OUT rather than by asserting, which is the only
// honest way to test a deadlock — so every one of them is bounded.

func policyGateStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	sqlite, err := store.NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "policy-gate.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sqlite.Close() })
	return sqlite
}

// The core invariant, tested deterministically with no race window: while a
// policy WRITER holds the gate, maybeTriggerRouteRefresh must still return
// promptly on the calling goroutine. Before the fix it blocked here forever,
// because its first statement acquired the read lease.
func TestMaybeTriggerRouteRefreshDoesNotBlockCallerOnPolicyGate(t *testing.T) {
	sqlite := policyGateStore(t)
	m := &Manager{memStore: sqlite}

	unlockWriter := sqlite.LockSyncPolicyWrite()
	defer unlockWriter()

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		m.maybeTriggerRouteRefresh("peer-chain-a")
	}()

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("maybeTriggerRouteRefresh blocked on the caller's goroutine while a policy writer " +
			"held the gate: it is acquiring the sync-policy read lease inline, which deadlocks " +
			"when the caller already holds that lease across the peer request")
	}
}

// The full interleaving the audit described, end to end: a reader holds the
// lease across a simulated peer request, a writer queues behind it, and the
// post-request refresh fires. All three must complete.
func TestRouteRefreshSurvivesWriterQueuedBehindRequestHoldingReader(t *testing.T) {
	sqlite := policyGateStore(t)
	m := &Manager{memStore: sqlite}

	writerQueued := make(chan struct{})
	writerDone := make(chan struct{})
	readerDone := make(chan struct{})

	// Goroutine A: the request-holding reader, e.g. AvailableRecallDomains.
	go func() {
		defer close(readerDone)
		readerUnlock := sqlite.LockSyncPolicyRead()

		// The writer queues while A still holds the read lease. From here on,
		// Go's RWMutex refuses every new reader — including a recursive one.
		<-writerQueued
		time.Sleep(50 * time.Millisecond)

		// This is the call that used to deadlock, made while the lease is held.
		m.maybeTriggerRouteRefresh("peer-chain-b")

		readerUnlock()
	}()

	// Goroutine B: a policy writer, e.g. an automatic journal-pull ingest.
	go func() {
		defer close(writerDone)
		close(writerQueued)
		unlock := sqlite.LockSyncPolicyWrite()
		unlock()
	}()

	for name, done := range map[string]chan struct{}{"reader": readerDone, "writer": writerDone} {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s goroutine never completed: the sync-policy gate is wedged, which is the "+
				"federation-wide deadlock this regression exists to prevent", name)
		}
	}
}

// Both trigger sites in doPeerRequestWithHeaders must be safe, not just the one
// a reviewer happened to look at: the transport-failure path and the
// Direct-route success path.
func TestBothRouteRefreshTriggerSitesAreCallerSafe(t *testing.T) {
	sqlite := policyGateStore(t)
	m := &Manager{memStore: sqlite}

	unlockWriter := sqlite.LockSyncPolicyWrite()
	defer unlockWriter()

	// Both sites reach the same entry point; calling it repeatedly under a held
	// writer proves neither can block the request goroutine.
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.maybeTriggerRouteRefresh("peer-failure-path")
		m.maybeTriggerRouteRefresh("peer-direct-success-path")
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a route-refresh trigger site blocked the caller while a policy writer held the gate")
	}
}

// The per-peer admission guard must bound pending refreshes to one goroutine
// per peer, so a stalled gate cannot accumulate goroutines under request load.
// Without it, moving the work off-thread would trade a deadlock for a leak.
func TestRouteRefreshSchedulesAtMostOnePendingRefreshPerPeer(t *testing.T) {
	sqlite := policyGateStore(t)
	m := &Manager{memStore: sqlite}

	// Hold the gate so every scheduled goroutine parks inside the lease and the
	// pending set cannot drain while we measure it.
	unlockWriter := sqlite.LockSyncPolicyWrite()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.maybeTriggerRouteRefresh("same-peer")
		}()
	}
	wg.Wait()

	m.routeRefreshMu.Lock()
	pending := len(m.routeRefreshPending)
	m.routeRefreshMu.Unlock()

	if pending > 1 {
		t.Fatalf("50 concurrent triggers for one peer scheduled %d pending refreshes, want at most 1", pending)
	}

	unlockWriter()
}

// The remediation must be CENTRAL, not caller-specific. Four production chains
// hold the sync-policy read lease across a peer request and therefore reach the
// inline refresh:
//
//	client.go:447  /fed/v1/query        (also holds the Badger lease)
//	client.go:525  /fed/v1/query/available
//	client.go:658  /fed/v1/query/plan
//	sync_outbox.go:955 -> push at :1087 -> SyncPush -> doPeerRequest
//
// The last one is the sync OUTBOX: it runs on a background cadence rather than
// a user query, and it holds the domain-ownership lease alongside the policy
// lease. A fix applied at any single call site would have left the other three
// deadlocking, which is why the guard lives in maybeTriggerRouteRefresh itself.
//
// This test pins that property at the shared entry point: with a policy writer
// queued, the refresh trigger must not block ANY caller, whatever lease that
// caller happens to be holding.
func TestRouteRefreshRemediationIsCentralNotCallerSpecific(t *testing.T) {
	sqlite := policyGateStore(t)
	m := &Manager{memStore: sqlite}

	unlockWriter := sqlite.LockSyncPolicyWrite()
	defer unlockWriter()

	// One goroutine per known lock-holding chain, all hitting the shared entry
	// point while the writer holds the gate.
	chains := []string{
		"query-chain",           // client.go:447
		"query-available-chain", // client.go:525
		"query-plan-chain",      // client.go:658
		"sync-outbox-chain",     // sync_outbox.go:955 -> SyncPush
	}
	done := make(chan string, len(chains))
	for _, chain := range chains {
		go func(c string) {
			m.maybeTriggerRouteRefresh(c)
			done <- c
		}(chain)
	}

	for range chains {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("a lock-holding caller blocked on the route-refresh trigger: the remediation is " +
				"not central, so at least one of the four known chains can still deadlock")
		}
	}
}
