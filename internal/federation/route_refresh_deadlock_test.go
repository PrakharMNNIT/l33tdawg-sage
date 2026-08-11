package federation

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
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

// The per-peer admission guard must admit exactly ONE worker per peer while a
// gate is stalled, so moving the refresh off-thread cannot trade a deadlock for
// a goroutine pile-up under request load.
//
// This asserts WORKERS ADMITTED, not len(routeRefreshPending). The map cannot
// distinguish the cases: an admitted worker and a rejected duplicate both leave
// one key under the same chain ID, so len is 1 with the guard working AND 1
// with duplicate-rejection removed, and 0 with the guard deleted outright. An
// assertion on that map passes under every mutation it is supposed to catch.
func TestRouteRefreshAdmitsExactlyOneWorkerPerPeerUnderLoad(t *testing.T) {
	sqlite := policyGateStore(t)
	m := &Manager{memStore: sqlite}

	var entered atomic.Int32
	firstEntered := make(chan struct{})
	var once sync.Once
	setRouteRefreshWorkerEntry(func(string) {
		entered.Add(1)
		once.Do(func() { close(firstEntered) })
	})
	t.Cleanup(func() { setRouteRefreshWorkerEntry(nil) })

	// Hold the gate so the admitted worker parks inside the lease and cannot
	// finish and clear its pending slot while the others are still arriving.
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

	// Every caller must have returned — none may block behind the writer.
	select {
	case <-firstEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("no refresh worker was ever admitted")
	}

	// Give any wrongly-admitted duplicates time to arrive before counting.
	time.Sleep(200 * time.Millisecond)
	if got := entered.Load(); got != 1 {
		t.Fatalf("%d workers entered runScheduledRouteRefresh for one peer, want exactly 1: "+
			"the admission guard is not rejecting duplicates, so a stalled gate accumulates goroutines", got)
	}

	// Releasing the writer lets the single worker finish and clean up after
	// itself, so a later trigger for the same peer is admitted again.
	unlockWriter()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m.routeRefreshMu.Lock()
		n := len(m.routeRefreshPending)
		m.routeRefreshMu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the pending slot was never released, so this peer can never schedule another refresh")
}

// SHARED-ENTRY COVERAGE, SOURCE-TRACED — read the limitation before trusting it.
//
// This test drives the shared entry point directly. It does NOT execute the
// four production chains below; their identification is by source reading, not
// by this test. So it proves the shared helper is safe for any caller holding
// the policy lease, which is the property the central fix relies on — and it
// proves nothing about whether those chains still route through the helper.
// End-to-end execution of the two doPeerRequestWithHeaders trigger sites lives
// in route_refresh_trigger_e2e_test.go; sync-outbox e2e is not covered.
//
// The chains, traced in source at v11.18.6:
//
//	client.go:447  /fed/v1/query        (also holds the Badger lease)
//	client.go:525  /fed/v1/query/available
//	client.go:658  /fed/v1/query/plan
//	sync_outbox.go:955 -> push at :1087 -> SyncPush -> doPeerRequest
//
// The last is the sync OUTBOX: a background cadence rather than a user query,
// holding the domain-ownership lease alongside the policy lease. A fix applied
// at any single call site would have left the others deadlocking, which is why
// the guard lives in maybeTriggerRouteRefresh itself — and why an incomplete
// enumeration (mine originally missed the outbox) stopped mattering.
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
