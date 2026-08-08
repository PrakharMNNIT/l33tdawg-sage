package tx

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"
)

// leaseTestTimeout bounds every "must not hang" assertion below. A deadlocked
// lease would otherwise present as the whole package timing out ten minutes
// later with no indication of which invariant broke, so each test that could
// hang waits on its own channel and names the invariant it was waiting for.
const leaseTestTimeout = 10 * time.Second

func newLeaseTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

// leaseKeyFor mirrors WithNonceLease's map key so a test can assert the sparse
// leases map actually drained for the key it exercised, rather than relying on
// a global "map is empty" check that a sibling test could satisfy by accident.
func leaseKeyFor(t *testing.T, sk ed25519.PrivateKey) string {
	t.Helper()
	pub, ok := sk.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("test key has no ed25519 public key")
	}
	return string(pub)
}

func leaseEntryExists(key string) bool {
	leaseMu.Lock()
	defer leaseMu.Unlock()
	_, ok := leases[key]
	return ok
}

// waitFor blocks until done closes, failing with what the test was waiting for
// instead of hanging until the package deadline.
func waitFor(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(leaseTestTimeout):
		t.Fatalf("timed out waiting for %s: the lease deadlocked", what)
	}
}

// assertKeyStillGrantable proves the previous holder gave the slot back. Every
// error path in WithNonceLease is a candidate lock leak, and a leak is invisible
// until the NEXT submission for that key blocks forever — which in production is
// a dashboard action that never returns, not a test failure.
func assertKeyStillGrantable(t *testing.T, sk ed25519.PrivateKey, after string) uint64 {
	t.Helper()
	var nonce uint64
	granted := make(chan struct{})
	go func() {
		defer close(granted)
		if err := WithNonceLease(context.Background(), sk, func(n uint64) error {
			nonce = n
			return nil
		}); err != nil {
			t.Errorf("lease after %s: %v", after, err)
		}
	}()
	waitFor(t, granted, "a fresh lease on the same key after "+after)
	return nonce
}

// TestWithNonceLease_ArrivalOrderMatchesNonceOrder is the assertion that must
// fail if the lease is reverted to a bare MonotonicNonce call.
//
// It differs from the sibling ordering test by recording an explicit ARRIVAL
// SEQUENCE alongside the nonce and comparing the two orderings, which is the
// shape of the production defect: app-v9's replay gate compares each tx against
// the highest COMMITTED nonce, so what matters is not that the allocator counted
// up but that the transactions reached consensus in that same order. Reverted,
// each goroutine allocates under nonceMu and then races through sign/encode/HTTP
// unsynchronized, so arrival index i routinely carries a nonce allocated before
// arrival index i-1 — exactly the descending arrival that earns Code 4
// "nonce too low ... (rejected in consensus path)".
func TestWithNonceLease_ArrivalOrderMatchesNonceOrder(t *testing.T) {
	sk := newLeaseTestKey(t)

	type arrival struct {
		seq   int
		nonce uint64
	}
	var (
		mu       sync.Mutex
		arrivals []arrival
		next     int
	)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 48; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release every goroutine into the allocator at once
			if err := WithNonceLease(context.Background(), sk, func(nonce uint64) error {
				// Yield between "allocate" and "arrive". Without the lease this
				// is the window the racing goroutines reorder in; with it, no
				// other holder of this key can be here at all.
				time.Sleep(time.Millisecond)
				mu.Lock()
				arrivals = append(arrivals, arrival{seq: next, nonce: nonce})
				next++
				mu.Unlock()
				return nil
			}); err != nil {
				t.Errorf("WithNonceLease: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(arrivals) != 48 {
		t.Fatalf("recorded %d arrivals, want 48", len(arrivals))
	}
	for i := 1; i < len(arrivals); i++ {
		if arrivals[i].nonce <= arrivals[i-1].nonce {
			t.Fatalf("arrival %d carried nonce %d after arrival %d carried %d: "+
				"a lower nonce reaching consensus later is rejected Code 4 'nonce too low'",
				arrivals[i].seq, arrivals[i].nonce, arrivals[i-1].seq, arrivals[i-1].nonce)
		}
	}
}

// TestWithNonceLease_KeysCanBlockOnEachOther proves genuine overlap rather than
// measuring elapsed time, which would flake on a loaded CI runner. Key A's lease
// cannot finish until key B's lease runs, so if the two keys shared a lock this
// test deadlocks and reports which key never got in.
func TestWithNonceLease_KeysCanBlockOnEachOther(t *testing.T) {
	keyA := newLeaseTestKey(t)
	keyB := newLeaseTestKey(t)

	aInside := make(chan struct{})
	bInside := make(chan struct{})
	aDone := make(chan struct{})
	bDone := make(chan struct{})

	go func() {
		defer close(aDone)
		_ = WithNonceLease(context.Background(), keyA, func(uint64) error {
			close(aInside)
			// Only B, holding a DIFFERENT key, can unblock A. Give up strictly
			// sooner than the waitFor below so that a REGRESSION fails cleanly:
			// A releases first, B then drains from behind it, and the test
			// reports this assertion instead of the two timers racing and
			// logging after the test has already been failed.
			select {
			case <-bInside:
			case <-time.After(leaseTestTimeout / 2):
				t.Error("key B never entered its lease while key A held one: distinct keys are serialized")
			}
			return nil
		})
	}()

	waitFor(t, aInside, "key A to enter its lease")

	go func() {
		defer close(bDone)
		_ = WithNonceLease(context.Background(), keyB, func(uint64) error {
			close(bInside)
			return nil
		})
	}()

	waitFor(t, bDone, "key B's lease to complete while key A holds its own")
	waitFor(t, aDone, "key A's lease to complete")
}

// TestWithNonceLease_SequentialSameKeyLeasesComplete covers the ordinary
// single-goroutine path: taking the same key's lease again after releasing it
// must not block, and the nonces must keep climbing across leases.
func TestWithNonceLease_SequentialSameKeyLeasesComplete(t *testing.T) {
	sk := newLeaseTestKey(t)

	done := make(chan struct{})
	nonces := make([]uint64, 0, 16)
	go func() {
		defer close(done)
		for i := 0; i < 16; i++ {
			if err := WithNonceLease(context.Background(), sk, func(nonce uint64) error {
				nonces = append(nonces, nonce)
				return nil
			}); err != nil {
				t.Errorf("lease %d: %v", i, err)
				return
			}
		}
	}()
	waitFor(t, done, "16 back-to-back leases on one key in one goroutine")

	if len(nonces) != 16 {
		t.Fatalf("got %d nonces, want 16", len(nonces))
	}
	for i := 1; i < len(nonces); i++ {
		if nonces[i] <= nonces[i-1] {
			t.Fatalf("lease %d reused or regressed the nonce: %d after %d", i, nonces[i], nonces[i-1])
		}
	}
	if leaseEntryExists(leaseKeyFor(t, sk)) {
		t.Fatal("an idle key kept its lease entry: the sparse map is not draining")
	}
}

// TestWithNonceLease_NestedDistinctKeysComplete exercises the one nesting shape
// the deadlock audit declared safe: a lease taken for key A while key B's lease
// is held. This is the shape a future caller is most likely to introduce (a
// handler that signs with an agent key inside an operator-signed flow), so pin
// it as supported.
//
// The UNSAFE shape — re-entering with the SAME key — is intentionally not
// exercised: the lease is a non-reentrant capacity-1 semaphore, so that shape
// self-deadlocks by design, and a test for it could only hang. The prohibition
// is documented on WithNonceLease and enforced by review, not by a test that
// would have to reproduce a hang to pass.
func TestWithNonceLease_NestedDistinctKeysComplete(t *testing.T) {
	outer := newLeaseTestKey(t)
	inner := newLeaseTestKey(t)

	done := make(chan struct{})
	var outerNonce, innerNonce uint64
	go func() {
		defer close(done)
		err := WithNonceLease(context.Background(), outer, func(n uint64) error {
			outerNonce = n
			return WithNonceLease(context.Background(), inner, func(m uint64) error {
				innerNonce = m
				return nil
			})
		})
		if err != nil {
			t.Errorf("nested distinct-key leases: %v", err)
		}
	}()
	waitFor(t, done, "a lease on key B taken while key A's lease is held")

	if outerNonce == 0 || innerNonce == 0 {
		t.Fatalf("nested leases did not both allocate: outer=%d inner=%d", outerNonce, innerNonce)
	}
	if leaseEntryExists(leaseKeyFor(t, outer)) || leaseEntryExists(leaseKeyFor(t, inner)) {
		t.Fatal("a nested lease left an entry behind")
	}
}

// TestWithNonceLease_CancelledWaitersDoNotLeakTheSlot is the other half of the
// context contract. The queue-abandon path takes a different exit than the
// normal release (the semaphore was never acquired, so it must NOT be drained),
// and getting that wrong hands a phantom release to the real holder or strands
// the slot forever. Assert the key is still usable and the map entry is gone.
func TestWithNonceLease_CancelledWaitersDoNotLeakTheSlot(t *testing.T) {
	sk := newLeaseTestKey(t)

	held := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan struct{})
	var holderNonce uint64
	go func() {
		defer close(holderDone)
		_ = WithNonceLease(context.Background(), sk, func(n uint64) error {
			holderNonce = n
			close(held)
			<-release
			return nil
		})
	}()
	waitFor(t, held, "the holder to enter its lease")

	// Queue several waiters behind the holder, then kill all of them.
	const waiters = 4
	errs := make(chan error, waiters)
	ran := make(chan struct{}, waiters)
	cancels := make([]context.CancelFunc, 0, waiters)
	for i := 0; i < waiters; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancels = append(cancels, cancel)
		go func() {
			errs <- WithNonceLease(ctx, sk, func(uint64) error {
				ran <- struct{}{}
				return nil
			})
		}()
	}
	// Let the waiters actually reach the semaphore before cancelling; a waiter
	// killed before it queues exercises the cheap pre-check instead.
	time.Sleep(100 * time.Millisecond)
	for _, cancel := range cancels {
		cancel()
	}
	for i := 0; i < waiters; i++ {
		select {
		case err := <-errs:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled waiter: got %v, want context.Canceled", err)
			}
		case <-time.After(leaseTestTimeout):
			t.Fatal("a cancelled waiter never left the queue")
		}
	}
	select {
	case <-ran:
		t.Fatal("a cancelled waiter still allocated a nonce; a burned nonce makes a later honest tx look like a replay")
	default:
	}

	close(release)
	waitFor(t, holderDone, "the holder to release")

	if next := assertKeyStillGrantable(t, sk, "cancelled waiters"); next <= holderNonce {
		t.Fatalf("nonce regressed after the cancelled waiters: %d after %d", next, holderNonce)
	}
	if leaseEntryExists(leaseKeyFor(t, sk)) {
		t.Fatal("cancelled waiters left the lease entry behind")
	}
}

// TestWithNonceLease_SubmitErrorReleasesTheSlot pins that a failed broadcast —
// by far the most common outcome after a node restart or an RPC hiccup — does
// not wedge the key for every later request.
func TestWithNonceLease_SubmitErrorReleasesTheSlot(t *testing.T) {
	sk := newLeaseTestKey(t)

	boom := errors.New("broadcast tx commit: connection refused")
	if err := WithNonceLease(context.Background(), sk, func(uint64) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("got %v, want the submit error", err)
	}
	assertKeyStillGrantable(t, sk, "a failing submit")
	if leaseEntryExists(leaseKeyFor(t, sk)) {
		t.Fatal("a failing submit left the lease entry behind")
	}
}

// TestWithNonceLease_FailsClosedOnUnusableInput pins the three guards that run
// BEFORE any lease is taken.
//
// Each must return an error rather than succeed quietly: a nil error from this
// primitive means "your transaction was submitted under a held lease", and a
// caller that lost its closure or passed a zero-value key would otherwise be
// told a transaction committed that was never even allocated. The key-length
// guard also has to come before sk.Public(), which slices sk[32:64] with no
// bounds check and panics on a short key. None of these may leave a lease entry
// behind, since nothing was ever acquired.
func TestWithNonceLease_FailsClosedOnUnusableInput(t *testing.T) {
	valid := newLeaseTestKey(t)

	t.Run("nil submit", func(t *testing.T) {
		err := WithNonceLease(context.Background(), valid, nil)
		if err == nil {
			t.Fatal("a nil submit reported success: nothing was allocated or sent")
		}
		if leaseEntryExists(leaseKeyFor(t, valid)) {
			t.Fatal("a rejected call created a lease entry")
		}
	})

	for _, tc := range []struct {
		name string
		key  ed25519.PrivateKey
	}{
		{"nil key", nil},
		{"short key", make(ed25519.PrivateKey, ed25519.PrivateKeySize-1)},
		{"long key", make(ed25519.PrivateKey, ed25519.PrivateKeySize+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ran bool
			// Must return an error, not panic: sk.Public() would slice out of
			// range on anything shorter than a full private key.
			err := WithNonceLease(context.Background(), tc.key, func(uint64) error {
				ran = true
				return nil
			})
			if err == nil {
				t.Fatal("an unusable signing key reported success")
			}
			if ran {
				t.Fatal("submit ran for a key that cannot be serialized on")
			}
		})
	}

	// The guards must not have disturbed the allocator for a real key.
	assertKeyStillGrantable(t, valid, "rejected unusable input")
}

// TestWithNonceLease_PanicInSubmitReleasesTheSlot covers the path a plain
// `release()` at the end of the body would miss. The lease wraps handler code
// that can panic (a nil map, a nil RPC client); if the panic unwound past the
// semaphore without draining it, the node would keep serving every other key
// while silently refusing to ever sign again with this one.
func TestWithNonceLease_PanicInSubmitReleasesTheSlot(t *testing.T) {
	sk := newLeaseTestKey(t)

	func() {
		defer func() {
			if recovered := recover(); recovered == nil {
				t.Fatal("expected the panic to propagate out of WithNonceLease")
			}
		}()
		_ = WithNonceLease(context.Background(), sk, func(uint64) error {
			panic("submit exploded")
		})
	}()

	assertKeyStillGrantable(t, sk, "a panicking submit")
	if leaseEntryExists(leaseKeyFor(t, sk)) {
		t.Fatal("a panicking submit left the lease entry behind")
	}
}
