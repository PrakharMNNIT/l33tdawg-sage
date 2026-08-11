package federation

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// R2 regression. A P2P-only agreement's endpoint is the joinP2POnlyEndpoint
// sentinel, which join_routes.go documents as never to be attempted as a TCP
// fallback. So when generation pinning nulls routeDial, the comment's promise
// that "Direct HTTPS remains available" is false for this class: there is no
// transport left at all, and the request falls through to a plain dial of an
// unroutable address.
//
// That also blocked the authenticated route exchange, which is the only thing
// that can replace the stale snapshot — so the peer could never reach the
// current generation and stayed unreachable until it was paired again.
//
// The rule these tests must NOT let regress: no route learned under another
// trust generation may enter a PROTECTED request. Only the exchange that
// upgrades the generation may use the stale snapshot as a bootstrap hint, and
// even then the connection is still completed through the pinned mTLS
// handshake bound to the current agreement.

// p2pOnlyGenerationFixture federates a -> b over the P2P-only sentinel endpoint
// and installs a snapshot whose generation deliberately differs from the one
// the request will require.
func p2pOnlyGenerationFixture(t *testing.T) (*testChain, *testChain, *atomic.Int32, *atomic.Value) {
	t.Helper()
	a := newTestChain(t, "p2p-only-a")
	b := newTestChain(t, "p2p-only-b")
	federate(t, a, b, joinP2POnlyEndpoint, nil, 4, 0)
	federate(t, b, a, "https://unused.invalid", nil, 4, 0)

	var dials atomic.Int32
	var sawTargets atomic.Value
	sawTargets.Store([]string{})

	a.mgr.SetJoinP2PHooks(JoinP2PHooks{
		LoadSnapshot: func(string) (RouteSnapshot, bool) {
			return RouteSnapshot{
				PeerID:     "peer-b",
				Addrs:      []string{"/dns4/relay.example/tcp/4001/p2p/peer-b"},
				Generation: "generation-OLD",
				Revision:   7,
			}, true
		},
	})
	a.mgr.SetPeerRouteDialFunc(func(ctx context.Context, chain string, frozen []string, authenticate PeerRouteAuthenticator) (PeerRouteDialResult, bool, error) {
		dials.Add(1)
		sawTargets.Store(append([]string{}, frozen...))
		// Refuse the dial: this test is about WHETHER the route layer is
		// consulted and with which targets, not about completing a handshake.
		return PeerRouteDialResult{}, true, assert.AnError
	})
	return a, b, &dials, &sawTargets
}

// The recovery path: a P2P-only peer whose snapshot is stuck on an old
// generation must still be able to run the route exchange that upgrades it.
func TestP2POnlyPeerCanAttemptRouteExchangeAcrossGenerations(t *testing.T) {
	a, b, dials, sawTargets := p2pOnlyGenerationFixture(t)

	agreement, err := a.mgr.ActiveAgreement(b.chainID)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = withRouteGeneration(ctx, "generation-NEW")

	_, _, reqErr := a.mgr.doPeerRequest(ctx, agreement, http.MethodPost, p2pRoutesExchangePath, map[string]any{})
	require.Error(t, reqErr, "the stub dialer refuses, so the request must fail")

	require.Equal(t, int32(1), dials.Load(),
		"the route exchange was never offered a transport: a p2p-only peer whose snapshot is on an "+
			"older generation can never upgrade it, so it is bricked until re-paired")

	targets, _ := sawTargets.Load().([]string)
	assert.Equal(t, []string{"/dns4/relay.example/tcp/4001/p2p/peer-b"}, targets,
		"the exchange must receive the stale snapshot as a bootstrap hint")
}

// The rule that must survive the fix: a PROTECTED request still refuses a
// cross-generation route.
func TestP2POnlyProtectedRequestStillRefusesCrossGenerationRoute(t *testing.T) {
	a, b, dials, _ := p2pOnlyGenerationFixture(t)

	agreement, err := a.mgr.ActiveAgreement(b.chainID)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = withRouteGeneration(ctx, "generation-NEW")

	_, _, reqErr := a.mgr.doPeerRequest(ctx, agreement, http.MethodPost, "/fed/v1/query", map[string]any{})
	require.Error(t, reqErr)

	assert.Equal(t, int32(0), dials.Load(),
		"a protected request used a route learned under a different trust generation")
}

// The failure must name the actual cause.
//
// CORRECTION TO MY EARLIER CLAIM, recorded here because the frozen R2 commit
// message and its code comment both overstate the mechanism and cannot be
// amended: the pre-fix path did NOT literally open a TCP connection to
// 127.0.0.1:65535. client.go installs an erroring DialTLSContext for the
// p2p-only-without-dialer case, which returns ErrPeerOffline "has no p2p
// dialer" without dialing; the sentinel appears only because net/http wraps
// that error with the request URL. The defect — the peer is unreachable and
// cannot recover its generation — is unchanged, but the operator-facing symptom
// was a peer-offline error carrying the sentinel, not a dial attempt against it.
// Caught by codex in review. The assertion below is about what the error
// SURFACES, which is what was always actually wrong with it.
func TestP2POnlyGenerationMismatchReportsTrustGenerationNotOffline(t *testing.T) {
	a, b, _, _ := p2pOnlyGenerationFixture(t)

	agreement, err := a.mgr.ActiveAgreement(b.chainID)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = withRouteGeneration(ctx, "generation-NEW")

	_, _, reqErr := a.mgr.doPeerRequest(ctx, agreement, http.MethodPost, "/fed/v1/query", map[string]any{})
	require.Error(t, reqErr)

	assert.Equal(t, RouteRecoveryTrustGenerationMismatch, RouteRecoveryFailureCode(reqErr),
		"expected a trust-generation recovery code, got: %v", reqErr)
	assert.NotContains(t, reqErr.Error(), "65535",
		"the p2p-only sentinel address must never be surfaced as the failure: it tells an operator "+
			"to look at the network when the trust generation is what needs repairing")
}

// A matching-generation snapshot is unaffected by the fix: it still pins the
// exact frozen target set for every path, exchange or not.
func TestP2POnlyMatchingGenerationStillPinsFrozenTargets(t *testing.T) {
	a := newTestChain(t, "p2p-only-match-a")
	b := newTestChain(t, "p2p-only-match-b")
	federate(t, a, b, joinP2POnlyEndpoint, nil, 4, 0)
	federate(t, b, a, "https://unused.invalid", nil, 4, 0)

	var sawTargets atomic.Value
	sawTargets.Store([]string{})
	a.mgr.SetJoinP2PHooks(JoinP2PHooks{
		LoadSnapshot: func(string) (RouteSnapshot, bool) {
			return RouteSnapshot{Addrs: []string{"/dns4/current.example/tcp/4001"}, Generation: "generation-NOW"}, true
		},
	})
	a.mgr.SetPeerRouteDialFunc(func(ctx context.Context, chain string, frozen []string, _ PeerRouteAuthenticator) (PeerRouteDialResult, bool, error) {
		sawTargets.Store(append([]string{}, frozen...))
		return PeerRouteDialResult{}, true, assert.AnError
	})

	agreement, err := a.mgr.ActiveAgreement(b.chainID)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = withRouteGeneration(ctx, "generation-NOW")

	_, _, _ = a.mgr.doPeerRequest(ctx, agreement, http.MethodPost, "/fed/v1/query", map[string]any{})

	targets, _ := sawTargets.Load().([]string)
	assert.Equal(t, []string{"/dns4/current.example/tcp/4001"}, targets,
		"a matching generation must still pin the exact frozen target set")
}

// A P2P-only peer with NO snapshot at all must still be able to reach the
// bootstrap exchange. There is no stale snapshot to hint with, so the dialer is
// left to load its current configuration — that is the only route material
// available, and it is still authenticated by the pinned handshake bound to the
// current agreement.
func TestP2POnlyMissingSnapshotCanStillReachBootstrapExchange(t *testing.T) {
	a := newTestChain(t, "p2p-only-missing-a")
	b := newTestChain(t, "p2p-only-missing-b")
	federate(t, a, b, joinP2POnlyEndpoint, nil, 4, 0)
	federate(t, b, a, "https://unused.invalid", nil, 4, 0)

	var dials atomic.Int32
	var frozenWasNil atomic.Bool
	a.mgr.SetJoinP2PHooks(JoinP2PHooks{
		LoadSnapshot: func(string) (RouteSnapshot, bool) { return RouteSnapshot{}, false },
	})
	a.mgr.SetPeerRouteDialFunc(func(ctx context.Context, chain string, frozen []string, _ PeerRouteAuthenticator) (PeerRouteDialResult, bool, error) {
		dials.Add(1)
		frozenWasNil.Store(frozen == nil)
		return PeerRouteDialResult{}, true, assert.AnError
	})

	agreement, err := a.mgr.ActiveAgreement(b.chainID)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = withRouteGeneration(ctx, "generation-NEW")

	_, _, _ = a.mgr.doPeerRequest(ctx, agreement, http.MethodPost, p2pRoutesExchangePath, map[string]any{})

	require.Equal(t, int32(1), dials.Load(),
		"a p2p-only peer with no snapshot could not reach the bootstrap exchange, so it can never "+
			"acquire one and is permanently unreachable")
	assert.True(t, frozenWasNil.Load(),
		"with no snapshot the dialer must receive nil frozen targets, meaning it may load current config")
}

// The same peer, same missing snapshot, on a PROTECTED path: still refused.
// Relaxing the bootstrap exchange must not relax anything else.
func TestP2POnlyMissingSnapshotStillRefusesProtectedRequest(t *testing.T) {
	a := newTestChain(t, "p2p-only-missing-prot-a")
	b := newTestChain(t, "p2p-only-missing-prot-b")
	federate(t, a, b, joinP2POnlyEndpoint, nil, 4, 0)
	federate(t, b, a, "https://unused.invalid", nil, 4, 0)

	var dials atomic.Int32
	a.mgr.SetJoinP2PHooks(JoinP2PHooks{
		LoadSnapshot: func(string) (RouteSnapshot, bool) { return RouteSnapshot{}, false },
	})
	a.mgr.SetPeerRouteDialFunc(func(ctx context.Context, chain string, _ []string, _ PeerRouteAuthenticator) (PeerRouteDialResult, bool, error) {
		dials.Add(1)
		return PeerRouteDialResult{}, true, assert.AnError
	})

	agreement, err := a.mgr.ActiveAgreement(b.chainID)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = withRouteGeneration(ctx, "generation-NEW")

	_, _, reqErr := a.mgr.doPeerRequest(ctx, agreement, http.MethodPost, "/fed/v1/status", map[string]any{})
	require.Error(t, reqErr)
	assert.Equal(t, int32(0), dials.Load(), "a protected path must not receive current/bootstrap targets")
	assert.Equal(t, RouteRecoveryTrustGenerationMismatch, RouteRecoveryFailureCode(reqErr))
}

// The non-nil-empty frozen slice invariant: a MATCHING generation whose
// snapshot has no addresses must still pin an empty-but-non-nil set, so the
// dialer stays pinned to exactly G rather than falling back to current config.
func TestMatchingGenerationWithNoAddrsStillPinsNonNilEmptyTargets(t *testing.T) {
	a := newTestChain(t, "frozen-empty-a")
	b := newTestChain(t, "frozen-empty-b")
	federate(t, a, b, joinP2POnlyEndpoint, nil, 4, 0)
	federate(t, b, a, "https://unused.invalid", nil, 4, 0)

	var sawNil atomic.Bool
	sawNil.Store(true)
	a.mgr.SetJoinP2PHooks(JoinP2PHooks{
		LoadSnapshot: func(string) (RouteSnapshot, bool) {
			return RouteSnapshot{Addrs: nil, Generation: "generation-NOW"}, true
		},
	})
	a.mgr.SetPeerRouteDialFunc(func(ctx context.Context, chain string, frozen []string, _ PeerRouteAuthenticator) (PeerRouteDialResult, bool, error) {
		sawNil.Store(frozen == nil)
		return PeerRouteDialResult{}, true, assert.AnError
	})

	agreement, err := a.mgr.ActiveAgreement(b.chainID)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = withRouteGeneration(ctx, "generation-NOW")

	_, _, _ = a.mgr.doPeerRequest(ctx, agreement, http.MethodPost, "/fed/v1/status", map[string]any{})

	assert.False(t, sawNil.Load(),
		"an exact-generation dial with no targets must pass a non-nil empty slice, not nil: nil would "+
			"let the dialer load current config and escape the generation pin")
}
