package tx

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"
)

// nonceMu guards lastNonce and seeded. nonce allocation is process-global because
// a single signing key (notably the node priv-validator key) is shared by every
// REST and web handler in the process; they must draw from one strictly-increasing
// sequence per key.
var (
	nonceMu   sync.Mutex
	lastNonce = make(map[string]uint64)
	seeded    = make(map[string]bool) // keys whose on-chain floor we've already consulted
)

// nonceFloorMu guards nonceFloor, installed once at boot and read on first use of
// each key.
var (
	nonceFloorMu sync.RWMutex
	nonceFloor   func(pub ed25519.PublicKey) (uint64, bool)
)

// SetNonceFloorFunc installs the on-chain committed-nonce lookup used to SEED the
// allocator the first time each signing key is used in this process. f reports the
// highest nonce already committed on-chain for pub (ok=false when unknown / not
// yet committed for that key).
//
// Wire it ONCE at boot, before any signing, with a CHEAP, non-blocking source — a
// local store read (e.g. badgerStore.GetNonce(hex(pub))). It is consulted at most
// once per key and the allocator mutex is held across the call, so a slow or
// remote source would stall concurrent allocations for that instant; wrap any such
// source in a short timeout. Passing nil clears the hook (restores pure-clock
// behavior). See MonotonicNonce for why this exists.
func SetNonceFloorFunc(f func(pub ed25519.PublicKey) (uint64, bool)) {
	nonceFloorMu.Lock()
	nonceFloor = f
	nonceFloorMu.Unlock()
}

// nonceFloorFor returns the wired floor for pub, or (0,false) when no hook is
// installed or the hook reports no committed nonce.
func nonceFloorFor(pub ed25519.PublicKey) (uint64, bool) {
	nonceFloorMu.RLock()
	f := nonceFloor
	nonceFloorMu.RUnlock()
	if f == nil {
		return 0, false
	}
	return f(pub)
}

// MonotonicNonce returns a strictly-increasing replay nonce for transactions
// signed by sk.
//
// Why this exists: app-v9 enforces nonce/replay protection in the CONSENSUS path
// (a tx is rejected when its nonce <= the signer's highest committed nonce). So
// every producer signing with a given key MUST emit strictly-increasing nonces,
// or a colliding/out-of-order tx is silently dropped (Code 4). Raw
// time.Now().UnixNano() is NOT safe for this: it can repeat on coarse-resolution
// clocks (notably darwin) and it races across the many concurrent producers that
// share the node signing key, so two txs in one block can carry equal or
// descending nonces and the second is rejected.
//
// This allocator is keyed by the signer's public key and returns
// max(UnixNano, lastForKey+1): it guarantees strict per-key monotonicity within
// the process regardless of clock resolution or producer concurrency, and never
// returns 0 (so it never trips app-v9's nonce-0 rejection).
//
// ALLOCATION ORDER IS NOT ARRIVAL ORDER — use WithNonceLease when several
// goroutines can submit for one key at once. This function releases nonceMu the
// instant it returns, so concurrent callers can allocate N and N+1 and then
// reach CometBFT in either order; the late-arriving N is rejected Code 4.
// Calling MonotonicNonce directly is only safe where a key has a single
// submitter, or where submissions for that key are already serialized.
//
// SEEDING (lifts both limits below when a floor hook is wired via
// SetNonceFloorFunc): the FIRST allocation for a key seeds the in-process sequence
// from the highest nonce already committed on-chain for that key, via max() — it
// can only RAISE the starting floor, never lower a value already set. So a fresh
// process, or a node that just restarted, resumes ABOVE the chain's last committed
// nonce instead of trusting the wall clock to exceed it. With no hook wired the
// seed is a no-op and behavior is exactly as before.
//
// SCOPE / KNOWN LIMITS (both are liveness-only — the consensus verdict is always
// deterministic, never a fork — and both are LIFTED once a floor hook is wired):
//   - One process per signing key. Without a seed hook the map is process-global
//     and NOT initialized from the committed on-chain nonce, so two processes
//     signing with the SAME key against the SAME chain can allocate
//     colliding/descending nonces and app-v9 drops the loser (Code 4). A wired
//     floor hook makes a newly-started process resume above the chain. (Truly
//     simultaneous same-key signing across processes is independently a CometBFT
//     equivocation/double-sign hazard — don't do it.)
//   - Cross-restart relies on a forward wall clock when no hook is wired: on
//     restart the map is empty and the first allocation is raw UnixNano, which
//     under NORMAL forward time exceeds the prior process's last committed nonce. A
//     BACKWARD clock step (NTP correction, manual set, VM snapshot restore) past
//     the committed nonce temporarily stalls that key (Code 4) until the clock
//     catches up. A wired floor hook removes this dependence on the clock entirely
//     by seeding from the committed nonce on first use.
func MonotonicNonce(sk ed25519.PrivateKey) uint64 {
	pub, ok := sk.Public().(ed25519.PublicKey)
	if !ok {
		// Unreachable for an ed25519 private key; fail safe to a positive value.
		return uint64(time.Now().UnixNano()) // #nosec G115 -- UnixNano is positive
	}
	key := string(pub)

	nonceMu.Lock()
	defer nonceMu.Unlock()

	// First use of this key in this process: seed the sequence from the highest
	// nonce already committed on-chain so a fresh / post-restart producer resumes
	// above the chain. Consulted at most once per key (guarded by seeded), and
	// applied with max() so it can only raise the floor — never regress a value an
	// allocation in this process already established.
	if !seeded[key] {
		seeded[key] = true
		if floor, ok := nonceFloorFor(pub); ok && floor > lastNonce[key] {
			lastNonce[key] = floor
		}
	}

	n := uint64(time.Now().UnixNano()) // #nosec G115 -- UnixNano is positive
	if n <= lastNonce[key] {
		n = lastNonce[key] + 1
	}
	lastNonce[key] = n
	return n
}

// nonceLease is the per-signing-key submission slot handed out by
// WithNonceLease. ch is a capacity-1 semaphore rather than a sync.Mutex because
// a waiter must be able to abandon the queue when its request context dies, and
// a mutex cannot be acquired selectably.
//
// holders counts the current holder plus everyone queued behind it, so the map
// entry can be dropped the moment a key goes idle. See leases for why that
// matters.
type nonceLease struct {
	ch      chan struct{}
	holders int
}

// leaseMu guards leases. leases is deliberately SPARSE — an entry exists only
// while a key has an in-flight or queued submission, and the last participant
// deletes it on the way out. A permanently-growing map[pubkey]*mutex would be a
// slow leak on a long-lived node that signs for many agents (every registered
// agent key, every federation peer key), and nothing would ever reclaim it. The
// cost of this choice is one small allocation per idle->busy transition, which
// is noise next to the commit-confirmed broadcast the lease wraps.
var (
	leaseMu sync.Mutex
	leases  = make(map[string]*nonceLease)
)

// WithNonceLease allocates a nonce for sk and runs submit while holding a
// per-public-key lock, so no other holder of the SAME key can interleave.
//
// Why this is not just MonotonicNonce: MonotonicNonce guarantees allocation
// ORDER, not ARRIVAL order. It holds nonceMu only across the increment, so two
// goroutines signing with one key can allocate N and N+1 and then race to
// CometBFT in either order. app-v9's replay gate is strictly ">" against the
// highest COMMITTED nonce (internal/abci/app.go, both the CheckTx and the
// consensus path), so gaps are harmless but a DESCENDING arrival is fatal: the
// N tx that lands after N+1 is rejected Code 4 "nonce too low". That is exactly
// what a dashboard fan-out (clearing a board column, bulk-forgetting memories)
// produced — a subset of the batch failing for no operator-visible reason.
// Holding the lock across allocation AND submission makes a nonce valid only
// inside the lease, which is the invariant the consensus gate actually wants.
//
// Distinct keys never contend: unrelated signers stay fully concurrent, so this
// serializes only what correctness requires.
//
// ctx bounds the WAIT, not submit: a request whose context is already dead never
// allocates a nonce and never takes a slot. Note that skipping an allocation is
// harmless on its own — the consensus gate tests `>`, not `== last+1`, so gaps
// in the sequence cost nothing. The reason to check early is simply that a dead
// request must not hold the slot other callers are queued on.
//
// SUBMIT MUST NOT RETURN UNTIL THE OUTCOME IS DEFINITIVE. This is the contract
// the whole primitive rests on, and it is the one way a correct-looking adopter
// can still lose transactions. If submit gives up on a timeout while its
// transaction is still in flight, the lease releases, the next caller allocates
// a HIGHER nonce and submits, and the abandoned LOWER nonce can still arrive
// afterwards — rejected Code 4, which is exactly the failure this exists to
// prevent. An adopter that cannot guarantee a definitive outcome must reconcile
// the indeterminate case before releasing the lease. web/rbac_signing.go does
// this by waiting for commit and classifying transport faults through
// isIndeterminateCommitError instead of treating them as clean failures.
//
// Once the lease is held, submit owns cancellation. Errors from submit are
// returned unwrapped so callers can keep matching on them.
//
// DEADLOCK: the lock is taken and released entirely inside this function and
// never spans a return, so the only way to deadlock is for submit to reach back
// into WithNonceLease with the same key. Callers must not do that. The one
// adopter today (web.DashboardHandler.signAndBroadcastCommitContext) submits via
// CometBFT's HTTP RPC, and internal/abci does not import web, so the
// FinalizeBlock work that /broadcast_tx_commit waits on cannot call back into a
// lease. Do NOT "fix" a future re-entrancy report with a reentrant lock — a
// reentrant lease would silently re-permit the interleaving this exists to stop.
func WithNonceLease(ctx context.Context, sk ed25519.PrivateKey, submit func(nonce uint64) error) error {
	if submit == nil {
		// A nil submit cannot be "success": nothing was allocated and nothing was
		// sent. Returning nil here would let a caller that lost its closure to a
		// refactor report a committed transaction that never existed.
		return errors.New("nonce lease: submit must not be nil")
	}
	// Length MUST be checked before Public(). ed25519.PrivateKey.Public() slices
	// sk[32:64] with no bounds guard, so a nil or short key panics
	// ("slice bounds out of range [32:0]") rather than returning a bad value —
	// a type-assertion fallback below would be dead code guarding a crash that
	// already happened.
	if len(sk) != ed25519.PrivateKeySize {
		return errors.New("nonce lease: invalid ed25519 private key length")
	}
	pub, ok := sk.Public().(ed25519.PublicKey)
	if !ok {
		// Genuinely unreachable now that the length is validated, but a wrong
		// public-key type leaves nothing to serialize on, and silently dropping
		// to unserialized allocation would reintroduce the exact race this
		// primitive exists to prevent. Fail closed instead.
		return errors.New("nonce lease: ed25519 private key yielded a non-ed25519 public key")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	key := string(pub)

	lease, err := acquireNonceLease(ctx, key)
	if err != nil {
		return err
	}
	defer releaseNonceLease(key, lease)

	return submit(MonotonicNonce(sk))
}

// acquireNonceLease blocks until this goroutine owns key's submission slot, or
// ctx dies first. On error nothing is held and the caller must not release.
func acquireNonceLease(ctx context.Context, key string) (*nonceLease, error) {
	// Check before queueing: an already-cancelled request must not take a slot
	// ahead of live ones only to drop it again.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	leaseMu.Lock()
	lease := leases[key]
	if lease == nil {
		lease = &nonceLease{ch: make(chan struct{}, 1)}
		leases[key] = lease
	}
	lease.holders++
	leaseMu.Unlock()

	select {
	case lease.ch <- struct{}{}:
	case <-ctx.Done():
		// Abandon the queue. dropNonceLeaseRef, not releaseNonceLease: the
		// semaphore was never taken, and draining it here would hand a phantom
		// release to whichever goroutine actually holds it.
		dropNonceLeaseRef(key, lease)
		return nil, ctx.Err()
	}

	// The wait may have outlived the request. Give the slot straight back rather
	// than consuming a nonce nobody will broadcast.
	if err := ctx.Err(); err != nil {
		releaseNonceLease(key, lease)
		return nil, err
	}
	return lease, nil
}

// releaseNonceLease frees key's submission slot and then drops this goroutine's
// reference to the lease.
func releaseNonceLease(key string, lease *nonceLease) {
	<-lease.ch
	dropNonceLeaseRef(key, lease)
}

// dropNonceLeaseRef removes this goroutine from lease's participant count and
// evicts the map entry once nobody holds or wants it.
//
// The eviction is safe against a concurrent arrival because both sides take
// leaseMu: an arrival that read this lease out of the map has ALREADY
// incremented holders under the same lock, so holders cannot be zero while any
// goroutine still believes it is queueing on this object. An arrival that
// misses the entry allocates a fresh one, and the evicted object is by then
// unreferenced and unheld.
func dropNonceLeaseRef(key string, lease *nonceLease) {
	leaseMu.Lock()
	lease.holders--
	if lease.holders <= 0 && leases[key] == lease {
		delete(leases, key)
	}
	leaseMu.Unlock()
}
