package federation

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/stretchr/testify/require"
)

// R1 end-to-end trigger coverage.
//
// The earlier tests called maybeTriggerRouteRefresh directly, which proves the
// shared helper is safe but proves NOTHING about the two production call sites:
// delete either trigger from doPeerRequestWithHeaders and a helper-level test
// stays green. These drive real requests through doPeerRequestWithHeaders with
// a policy writer holding the gate, and assert both that the request completes
// bounded and that a refresh worker was actually admitted.
//
// Deleting either production trigger makes the corresponding test fail.

// watchRouteRefreshWorkers installs the worker-entry seam and returns a counter
// plus a channel closed on the first admission.
func watchRouteRefreshWorkers(t *testing.T) (*atomic.Int32, chan struct{}) {
	t.Helper()
	var entered atomic.Int32
	first := make(chan struct{})
	var closeOnce atomic.Bool
	setRouteRefreshWorkerEntry(func(string) {
		entered.Add(1)
		if closeOnce.CompareAndSwap(false, true) {
			close(first)
		}
	})
	t.Cleanup(func() { setRouteRefreshWorkerEntry(nil) })
	return &entered, first
}

func chainPolicyStore(t *testing.T, c *testChain) *store.SQLiteStore {
	t.Helper()
	ss, ok := c.mem.(*store.SQLiteStore)
	require.True(t, ok, "test chain's MemStore must be a SQLiteStore to hold its policy gate")
	return ss
}

// TRIGGER SITE (a): the non-security transport-error path in
// doPeerRequestWithHeaders. An unreachable peer produces a plain dial failure,
// which is not a security failure, so the refresh trigger fires.
func TestTransportErrorTriggerAdmitsRefreshWorkerWithWriterHeld(t *testing.T) {
	a := newTestChain(t, "trigger-transport-a")
	b := newTestChain(t, "trigger-transport-b")
	// Deliberately unreachable: a closed port on loopback gives a prompt
	// connection-refused rather than a slow timeout.
	federate(t, a, b, "https://127.0.0.1:1", nil, 4, 0)
	federate(t, b, a, "https://unused.invalid", nil, 4, 0)

	entered, firstEntry := watchRouteRefreshWorkers(t)

	// A policy writer holds the gate for the whole request. Before R1 this is
	// precisely the state in which the inline refresh deadlocked.
	unlockWriter := chainPolicyStore(t, a).LockSyncPolicyWrite()
	defer unlockWriter()

	agreement, err := a.mgr.ActiveAgreement(b.chainID)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _, _ = a.mgr.doPeerRequest(ctx, agreement, http.MethodPost, "/fed/v1/query", map[string]any{})
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the request never completed while a policy writer held the gate: the transport-error " +
			"trigger is still doing policy work on the request goroutine")
	}

	select {
	case <-firstEntry:
	case <-time.After(5 * time.Second):
		t.Fatalf("no refresh worker was admitted from the transport-error path (entered=%d): the "+
			"trigger at that call site is missing", entered.Load())
	}
}

// TRIGGER SITE (b): the Direct-route success path. Requires a REACHABLE peer so
// the direct candidate wins, and a non-nil route dialer, because the trigger is
// guarded on `chosen.Kind == RouteKindDirect && routeDial != nil`.
func TestDirectSuccessTriggerAdmitsRefreshWorkerWithWriterHeld(t *testing.T) {
	a := newTestChain(t, "trigger-direct-a")
	b := newTestChain(t, "trigger-direct-b")
	var served atomic.Int32
	server := startCountedFederationServer(t, b, &served)
	federate(t, a, b, server.URL, nil, 4, 0)
	federate(t, b, a, "https://unused.invalid", nil, 4, 0)

	// Non-nil dialer that always fails, so the reachable Direct candidate wins
	// the race while routeDial stays non-nil — exactly the trigger's condition.
	a.mgr.SetPeerRouteDialFunc(func(ctx context.Context, chain string, _ []string, _ PeerRouteAuthenticator) (PeerRouteDialResult, bool, error) {
		return PeerRouteDialResult{}, true, context.DeadlineExceeded
	})

	entered, firstEntry := watchRouteRefreshWorkers(t)

	unlockWriter := chainPolicyStore(t, a).LockSyncPolicyWrite()
	defer unlockWriter()

	agreement, err := a.mgr.ActiveAgreement(b.chainID)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_, _, _ = a.mgr.doPeerRequest(ctx, agreement, http.MethodPost, "/fed/v1/query", map[string]any{})
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the request never completed while a policy writer held the gate: the Direct-success " +
			"trigger is still doing policy work on the request goroutine")
	}

	require.Positive(t, served.Load(), "the peer never served the request, so Direct did not win and "+
		"this test is not exercising the Direct-success trigger at all")

	select {
	case <-firstEntry:
	case <-time.After(5 * time.Second):
		t.Fatalf("no refresh worker was admitted from the Direct-success path (entered=%d): the "+
			"trigger at that call site is missing", entered.Load())
	}
}

// watchRouteRefreshWorkersForChain is the zero-assertion counterpart of
// watchRouteRefreshWorkers: it counts admissions for ONE remote chain only.
//
// The filter is load-bearing for a "must stay zero" test. The seam is a package
// global, so with a reachable peer BOTH chains' managers report through it, and
// an unrelated admission on the serving side would read as the defect. Scoping
// to the requesting side's remote chain ID keeps the assertion about the guard
// under test and nothing else.
func watchRouteRefreshWorkersForChain(t *testing.T, remoteChainID string) *atomic.Int32 {
	t.Helper()
	var entered atomic.Int32
	setRouteRefreshWorkerEntry(func(chainID string) {
		if chainID == remoteChainID {
			entered.Add(1)
		}
	})
	t.Cleanup(func() { setRouteRefreshWorkerEntry(nil) })
	return &entered
}

// The route-exchange path must NOT self-trigger a refresh, or an exchange would
// schedule another exchange. Both production triggers guard on
// `path != p2pRoutesExchangePath`; this pins the TRANSPORT-ERROR one.
//
// It cannot pin the other: an unreachable peer never reaches the Direct-success
// trigger at all, so deleting that guard leaves this test green. The
// Direct-success half is covered by the reachable-peer test below.
func TestRouteExchangePathDoesNotSelfTriggerRefresh(t *testing.T) {
	a := newTestChain(t, "trigger-noself-a")
	b := newTestChain(t, "trigger-noself-b")
	federate(t, a, b, "https://127.0.0.1:1", nil, 4, 0)
	federate(t, b, a, "https://unused.invalid", nil, 4, 0)

	entered, _ := watchRouteRefreshWorkers(t)

	agreement, err := a.mgr.ActiveAgreement(b.chainID)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, _ = a.mgr.doPeerRequest(ctx, agreement, http.MethodPost, p2pRoutesExchangePath, map[string]any{})

	time.Sleep(300 * time.Millisecond)
	require.Zero(t, entered.Load(), "the route exchange scheduled its own refresh, which recurses")
}

// The Direct-success half of the no-self-trigger guard (client.go: the
// `chosen.Kind == RouteKindDirect && routeDial != nil && path !=
// p2pRoutesExchangePath` branch). This needs the SAME fixture shape as
// TestDirectSuccessTriggerAdmitsRefreshWorkerWithWriterHeld — a reachable peer
// so Direct wins, and a non-nil dialer so the branch is entered — but drives
// the exchange path and asserts the refresh is NOT scheduled.
//
// Deleting `&& path != p2pRoutesExchangePath` from the Direct-success trigger
// makes this test fail; the unreachable-peer test above stays green under that
// same mutation, which is why both are needed.
func TestDirectSuccessRouteExchangeDoesNotSelfTriggerRefresh(t *testing.T) {
	a := newTestChain(t, "trigger-noself-direct-a")
	b := newTestChain(t, "trigger-noself-direct-b")
	var served atomic.Int32
	server := startCountedFederationServer(t, b, &served)
	federate(t, a, b, server.URL, nil, 4, 0)
	federate(t, b, a, "https://unused.invalid", nil, 4, 0)

	// Non-nil but always-failing, exactly as in the Direct-success trigger test:
	// the reachable Direct candidate wins the race while routeDial stays non-nil.
	a.mgr.SetPeerRouteDialFunc(func(ctx context.Context, chain string, _ []string, _ PeerRouteAuthenticator) (PeerRouteDialResult, bool, error) {
		return PeerRouteDialResult{}, true, context.DeadlineExceeded
	})

	entered := watchRouteRefreshWorkersForChain(t, b.chainID)

	agreement, err := a.mgr.ActiveAgreement(b.chainID)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, _, _ = a.mgr.doPeerRequest(ctx, agreement, http.MethodPost, p2pRoutesExchangePath, map[string]any{})

	// Without this the test is vacuous: if Direct never won, the guarded branch
	// was never reached and zero admissions proves nothing. The exchange
	// handler's own status code is irrelevant — the trigger sits before the
	// response body is read, so being served at all is what matters.
	require.Positive(t, served.Load(), "the peer never served the exchange request, so the Direct-success "+
		"branch was never reached and this test is not exercising its guard")

	time.Sleep(300 * time.Millisecond)
	require.Zero(t, entered.Load(), "a successful Direct route exchange scheduled another refresh, "+
		"which schedules another exchange")
}
