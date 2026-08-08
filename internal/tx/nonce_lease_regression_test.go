package tx

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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

// setFenceTimingsForTest shrinks the fence's production timers so a test can
// exercise real reconciliation in milliseconds. It goes through fenceTimingMu
// because reconciliation reads these from a background goroutine.
//
// None of these timers can LIFT a fence — that is the invariant under test — so
// shrinking them only changes how fast reconciliation asks, never what it
// concludes.
func setFenceTimingsForTest(t *testing.T, timings fenceTimings) {
	t.Helper()
	fenceTimingMu.Lock()
	previous := fenceTiming
	fenceTiming = timings
	fenceTimingMu.Unlock()
	t.Cleanup(func() {
		fenceTimingMu.Lock()
		fenceTiming = previous
		fenceTimingMu.Unlock()
	})
}

func fastFenceTimings() fenceTimings {
	return fenceTimings{
		// Deliberately SHORT: an attempt that runs out of time is one of the
		// four fail-open lifts this rework removed, so the tests want it to
		// happen often rather than rarely.
		attempt:  25 * time.Millisecond,
		retry:    time.Millisecond,
		retryMax: 5 * time.Millisecond,
		// Long enough that the held-fence alarm never fires during a test. The
		// alarm is asserted through FencedSigners, which is inspectable;
		// scraping stderr would be asserting a log format.
		report: time.Hour,
	}
}

// waitUntil polls cond until it holds, failing with what never became true
// rather than hanging. Used for state that a background goroutine flips.
func waitUntil(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(leaseTestTimeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// assertStaysFenced is the shape of nearly every assertion in this file's second
// half: prove the fence did NOT lift while something that is not proof kept
// happening. A lifted fence lets the next caller allocate past an abandoned
// nonce, which is the silent Code 4 loss the fence exists to prevent.
func assertStaysFenced(t *testing.T, key string, d time.Duration, why string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !keyIsFenced(key) {
			t.Fatalf("the fence lifted without proof of the transaction's fate: %s", why)
		}
		time.Sleep(time.Millisecond)
	}
}

// fencedSignerFor finds a key in the FencedSigners diagnostic snapshot. A held
// fence is only a defensible design if it is INSPECTABLE, so the snapshot is
// part of the contract, not a debugging convenience.
func fencedSignerFor(t *testing.T, sk ed25519.PrivateKey) (FencedSigner, bool) {
	t.Helper()
	want := hex.EncodeToString([]byte(leaseKeyFor(t, sk)))
	for _, held := range FencedSigners() {
		if held.SignerPubKeyHex == want {
			return held, true
		}
	}
	return FencedSigner{}, false
}

// TestWithNonceLease_DefinitiveSubmitErrorReleasesTheSlot pins the half of the
// contract that must stay cheap: a submission that FAILED DEFINITIVELY — a
// consensus rejection, a sign or encode fault — leaves nothing in flight, so it
// releases the slot immediately and must not fence anything.
//
// This direction matters as much as the fencing one. If an ordinary rejected
// transaction fenced its signing key, one bad request would stall every later
// request for that signer: a validation failure would become an outage. With
// fences now held until PROVEN, getting this backwards would be permanent.
func TestWithNonceLease_DefinitiveSubmitErrorReleasesTheSlot(t *testing.T) {
	sk := newLeaseTestKey(t)

	// The shape CometBFT returns when consensus has actually spoken.
	boom := errors.New("tx rejected in CheckTx (code 4): nonce too low")
	if err := WithNonceLease(context.Background(), sk, func(uint64) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("got %v, want the submit error", err)
	}
	if keyIsFenced(leaseKeyFor(t, sk)) {
		t.Fatal("a definitive rejection fenced the key: every ordinary validation failure would become an outage for this signer")
	}
	assertKeyStillGrantable(t, sk, "a definitively failing submit")
	if leaseEntryExists(leaseKeyFor(t, sk)) {
		t.Fatal("a failing submit left the lease entry behind")
	}
}

// TestWithNonceLease_IndeterminateSubmitFencesUntilProven is the regression this
// whole mechanism exists for, and it also pins the corrected invariant: ONLY A
// PROVEN FATE LIFTS.
//
// A broadcast that ends in a transport fault is NOT a failed broadcast — the
// transaction carrying that nonce may still be in flight. Releasing the slot
// there let the next caller allocate a HIGHER nonce and commit it, so when the
// abandoned LOWER nonce finally arrived app-v9 rejected it Code 4 "nonce too
// low": the lease reintroducing, through its own error path, the exact loss it
// was built to prevent.
//
// So the key stays CLOSED across the uncertainty, a caller that cannot wait is
// refused rather than allowed past, reconciliation attempts that TIME OUT do not
// count as an answer, and only the exact transaction turning up committed
// reopens it.
func TestWithNonceLease_IndeterminateSubmitFencesUntilProven(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	sent := []byte("encoded-transaction-bytes")
	resolve := make(chan struct{})
	var (
		probeMu   sync.Mutex
		probedTxs [][]byte
	)
	resolver := func(ctx context.Context, encoded []byte) (TxOutcome, error) {
		probeMu.Lock()
		probedTxs = append(probedTxs, encoded)
		probeMu.Unlock()
		select {
		case <-resolve:
			return TxOutcome{Verdict: TxVerdictCommitted, Detail: "committed at height 41"}, nil
		case <-ctx.Done():
			// The per-attempt deadline expiring is NOT an answer. Reconciliation
			// must keep the fence up and ask again; ending on a clock is the
			// fail-open this rework removed.
			return TxOutcome{}, ctx.Err()
		}
	}

	boom := errors.New("broadcast tx commit: connection refused")
	var fencedNonce uint64
	err := WithNonceLease(context.Background(), sk, func(n uint64) error {
		fencedNonce = n
		return Indeterminate(boom, sent, resolver)
	})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want the submit error to survive the indeterminate wrapper", err)
	}
	if !errors.Is(err, ErrSubmitIndeterminate) {
		t.Fatal("the indeterminate marker did not survive back to the caller")
	}
	if err.Error() != boom.Error() {
		t.Fatalf("the indeterminate wrapper rewrote the submit message to %q", err.Error())
	}
	if !keyIsFenced(key) {
		t.Fatal("an indeterminate submit did not fence the key: the next caller can allocate a higher nonce " +
			"and overtake a transaction that may still be in flight")
	}

	// Several attempts run out of time back to back. The fence must survive all
	// of them: a timed-out probe is the absence of an answer, not an answer.
	assertStaysFenced(t, key, 120*time.Millisecond, "reconciliation attempts kept timing out")
	if held, ok := fencedSignerFor(t, sk); !ok || held.Attempts == 0 {
		t.Fatalf("a held fence reported no reconciliation attempts: %+v (present=%v)", held, ok)
	}

	// A caller that arrives while the key is fenced blocks on the same per-key
	// gate. When its own deadline expires it must be REFUSED — never allowed to
	// allocate past the fence — and the fence must survive the refusal.
	fencedCtx, cancelFenced := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelFenced()
	var allocated bool
	blockedErr := WithNonceLease(fencedCtx, sk, func(uint64) error {
		allocated = true
		return nil
	})
	if allocated {
		t.Fatal("a caller allocated a nonce past the fence; that nonce is what kills the abandoned transaction")
	}
	if !errors.Is(blockedErr, ErrSignerFenced) {
		t.Fatalf("blocked caller got %v, want ErrSignerFenced so it is never retried as a consensus rejection", blockedErr)
	}
	if !errors.Is(blockedErr, context.DeadlineExceeded) {
		t.Fatalf("blocked caller lost its context cause: %v", blockedErr)
	}
	if !keyIsFenced(key) {
		t.Fatal("a waiter giving up lifted the fence: the fence must outlive the callers waiting on it")
	}

	// Proof — and only proof — opens the key again.
	close(resolve)
	waitUntil(t, func() bool { return !keyIsFenced(key) }, "a proven commit to lift the fence")

	probeMu.Lock()
	probes := len(probedTxs)
	var exact bool
	if probes > 0 {
		exact = string(probedTxs[0]) == string(sent)
	}
	probeMu.Unlock()
	if probes == 0 {
		t.Fatal("the fence lifted without reconciling anything")
	}
	if !exact {
		t.Fatal("reconciliation was not given the exact bytes that were broadcast; " +
			"any other identifier can neither find the abandoned transaction nor re-submit it idempotently")
	}

	if next := assertKeyStillGrantable(t, sk, "a proven indeterminate submit"); next <= fencedNonce {
		t.Fatalf("nonce regressed after the fence lifted: %d after %d", next, fencedNonce)
	}
	if leaseEntryExists(key) {
		t.Fatal("a fenced submit left the lease entry behind")
	}
}

// TestWithNonceLease_FenceLiftsOnDefinitiveRejection covers the other proof.
// The rule is deliberately NARROW — see checkTxRefusalIsPermanent and
// cometResubmitOutcome: an indexed FinalizeBlock result for the exact hash
// lifts, and a re-submission refused by the code-4 committed-nonce gate lifts
// (the gate is monotone, so those bytes can never commit AGAIN). Every OTHER
// non-zero CheckTx code is evidence about the re-submit only — a nonce-lookup
// fault, backpressure, an authorization change can all un-happen — and must
// leave the fence UP; TestCometTxResolver_TransientCheckTxRefusalNeverLifts
// pins that side. Here the resolver hands back a definitive verdict, and the
// lease must honor it by reopening the key.
//
// This is the outcome the re-submission engine is built to produce: rather than
// waiting for a lookup to resolve itself, reconciliation re-broadcasts the
// identical bytes precisely so consensus is forced to say yes or no.
func TestWithNonceLease_FenceLiftsOnDefinitiveRejection(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	resolver := func(context.Context, []byte) (TxOutcome, error) {
		return TxOutcome{
			Verdict: TxVerdictRejected,
			Detail:  "re-submit refused by the committed-nonce gate (CheckTx code 4): nonce too low",
		}, nil
	}
	err := WithNonceLease(context.Background(), sk, func(uint64) error {
		return Indeterminate(errors.New("decode broadcast commit response: unexpected EOF"), []byte("tx"), resolver)
	})
	if !errors.Is(err, ErrSubmitIndeterminate) {
		t.Fatalf("got %v, want an indeterminate submit error", err)
	}
	waitUntil(t, func() bool { return !keyIsFenced(key) }, "a proven consensus rejection to lift the fence")
	assertKeyStillGrantable(t, sk, "a transaction proven rejected")
}

// TestWithNonceLease_UnresolvedProbesNeverLift is the direct regression for the
// removed fail-open. "Not found" is NOT absence: CometBFT indexes a transaction
// only once it is in a block, so a transaction sitting unindexed in a mempool
// one moment before it commits answers exactly like one that never arrived.
// Neither that answer, nor a probe fault, nor any number of them accumulating,
// may reopen the key.
func TestWithNonceLease_UnresolvedProbesNeverLift(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	var proven atomic.Bool
	resolver := func(context.Context, []byte) (TxOutcome, error) {
		if proven.Load() {
			return TxOutcome{Verdict: TxVerdictCommitted, Detail: "committed at height 7"}, nil
		}
		// Exactly what a CometBFT node says about a transaction it has not put
		// in a block yet, whether or not it is about to.
		return TxOutcome{Verdict: TxVerdictUnresolved, Detail: "tx not found"}, nil
	}
	err := WithNonceLease(context.Background(), sk, func(uint64) error {
		return Indeterminate(errors.New("broadcast error: connection reset"), []byte("tx"), resolver)
	})
	if !errors.Is(err, ErrSubmitIndeterminate) {
		t.Fatalf("got %v, want an indeterminate submit error", err)
	}
	assertStaysFenced(t, key, 200*time.Millisecond,
		"a transaction reported not-found is indistinguishable from one in a mempool about to commit")

	proven.Store(true)
	waitUntil(t, func() bool { return !keyIsFenced(key) }, "the eventual proof to lift the fence")
	assertKeyStillGrantable(t, sk, "a fence that outlasted many unresolved probes")
}

// TestWithNonceLease_ResolverErrorWithVerdictNeverLifts pins the belt-and-braces
// rule in resolveOnce: a resolver that returns a definitive verdict ALONGSIDE an
// error is treated as unresolved. A failed attempt cannot also be a verdict, and
// this stops a buggy adopter from lifting a fence by accident — the one bug class
// whose cost is a silently lost transaction.
func TestWithNonceLease_ResolverErrorWithVerdictNeverLifts(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	var honest atomic.Bool
	resolver := func(context.Context, []byte) (TxOutcome, error) {
		if honest.Load() {
			return TxOutcome{Verdict: TxVerdictCommitted}, nil
		}
		return TxOutcome{Verdict: TxVerdictCommitted}, errors.New("dial tcp 127.0.0.1:26657: connect: connection refused")
	}
	if err := WithNonceLease(context.Background(), sk, func(uint64) error {
		return Indeterminate(errors.New("broadcast tx commit: EOF"), []byte("tx"), resolver)
	}); !errors.Is(err, ErrSubmitIndeterminate) {
		t.Fatalf("got %v, want an indeterminate submit error", err)
	}
	assertStaysFenced(t, key, 100*time.Millisecond, "the resolver reported a verdict it could not have observed")

	honest.Store(true)
	waitUntil(t, func() bool { return !keyIsFenced(key) }, "an unqualified verdict to lift the fence")
}

// TestWithNonceLease_ResolverPanicKeepsTheFenceAndRetries replaces the behavior a
// cross-review rejected. The superseded implementation wrapped reconciliation in
// `defer liftFence(...)`, so a panic in caller-supplied resolver code REOPENED
// the signing key.
//
// A panic says nothing about the transaction: the bytes may be in a mempool
// about to commit, and reopening lets the next caller allocate a higher nonce and
// kill them — the silent Code 4 loss the fence exists to prevent. So the panic is
// recovered (the node must survive a bad resolver), the fence is KEPT, and the
// loop retries, which matters because a panic is often transient (a nil client
// during a reconnect).
func TestWithNonceLease_ResolverPanicKeepsTheFenceAndRetries(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	var panics atomic.Int32
	resolver := func(context.Context, []byte) (TxOutcome, error) {
		if panics.Add(1) <= 5 {
			panic("resolver exploded")
		}
		return TxOutcome{Verdict: TxVerdictCommitted, Detail: "committed at height 12"}, nil
	}
	if err := WithNonceLease(context.Background(), sk, func(uint64) error {
		return Indeterminate(errors.New("broadcast tx commit: connection reset by peer"), []byte("tx"), resolver)
	}); !errors.Is(err, ErrSubmitIndeterminate) {
		t.Fatalf("got %v, want an indeterminate submit error", err)
	}

	waitUntil(t, func() bool { return panics.Load() >= 5 }, "the resolver to panic repeatedly")
	// It must have kept retrying THROUGH the panics rather than having lifted on
	// the first one; the retry count above is the proof it kept going, and the
	// fence must still be up while it does.
	waitUntil(t, func() bool { return !keyIsFenced(key) }, "the fence to lift once the resolver stopped panicking")
	if got := panics.Load(); got <= 5 {
		t.Fatalf("the fence lifted after %d resolver calls: a panic must not end reconciliation", got)
	}
	assertKeyStillGrantable(t, sk, "a resolver that panicked before answering")
}

// TestWithNonceLease_FenceIsHeldWithoutAResolver pins the inverse of what this
// file used to assert. The superseded behavior released the key on a blind timer
// when no resolver was available; a timer is not evidence, and "we have no way to
// check" is not evidence either, so the fence is HELD.
//
// Held is not wedged-with-no-way-out, and that is the point of the second half of
// this test: the process-wide resolver is re-read on EVERY attempt, so installing
// one later rescues fences that are already up.
//
// A RESTART IS NOT THE OTHER WAY OUT, and an earlier version of this comment said
// it was. Restarting drops the fence without resolving anything and re-seeds the
// allocator from the highest COMMITTED nonce, which is below the abandoned one —
// so the next allocation overtakes a transaction that may still be in flight, and
// the loss the fence exists to prevent happens anyway, untraceably.
func TestWithNonceLease_FenceIsHeldWithoutAResolver(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	t.Cleanup(func() { SetTxResolverFunc(nil) })
	SetTxResolverFunc(nil)

	err := WithNonceLease(context.Background(), sk, func(uint64) error {
		return Indeterminate(errors.New("broadcast error: connection reset"), []byte("tx"), nil)
	})
	if !errors.Is(err, ErrSubmitIndeterminate) {
		t.Fatalf("got %v, want an indeterminate submit error", err)
	}
	if !keyIsFenced(key) {
		t.Fatal("an unreconcilable indeterminate submit failed open")
	}
	assertStaysFenced(t, key, 200*time.Millisecond,
		"having no way to check a transaction is not evidence that it is gone")

	// A late install must rescue the held fence rather than only helping the
	// next one; otherwise a misordered boot would cost a signing key until
	// restart.
	SetTxResolverFunc(func(context.Context, []byte) (TxOutcome, error) {
		return TxOutcome{Verdict: TxVerdictCommitted, Detail: "committed at height 3"}, nil
	})
	waitUntil(t, func() bool { return !keyIsFenced(key) }, "a late-installed resolver to rescue the held fence")
	assertKeyStillGrantable(t, sk, "a fence rescued by a late resolver")
}

// TestWithNonceLease_HeldFenceIsObservable is the other half of the argument for
// holding rather than conceding. A held fence refuses every request for its key,
// possibly until restart; that is only defensible because the failure is loud and
// attributable. FencedSigners is the inspectable side of that: which key, which
// transaction, since when, and what the last attempt reported.
func TestWithNonceLease_HeldFenceIsObservable(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	sent := []byte("observable-transaction-bytes")
	wantHash := strings.ToUpper(hex.EncodeToString(func() []byte { h := CometTxHash(sent); return h[:] }()))

	var proven atomic.Bool
	resolver := func(context.Context, []byte) (TxOutcome, error) {
		if proven.Load() {
			return TxOutcome{Verdict: TxVerdictCommitted}, nil
		}
		return TxOutcome{Verdict: TxVerdictUnresolved, Detail: "comet re-submit: Internal error: tx already exists in cache"}, nil
	}
	cause := fmt.Errorf("broadcast tx commit: %w", context.DeadlineExceeded)
	if err := WithNonceLease(context.Background(), sk, func(uint64) error {
		return Indeterminate(cause, sent, resolver)
	}); !errors.Is(err, ErrSubmitIndeterminate) {
		t.Fatalf("got %v, want an indeterminate submit error", err)
	}

	waitUntil(t, func() bool {
		held, ok := fencedSignerFor(t, sk)
		return ok && held.Attempts > 0 && held.LastDetail != ""
	}, "the held fence to report a reconciliation attempt")

	held, ok := fencedSignerFor(t, sk)
	if !ok {
		t.Fatal("a held fence is invisible to FencedSigners: a stuck signing key would be a mystery hang")
	}
	if held.TxHash != wantHash {
		t.Fatalf("held fence names tx %q, want the hash of the exact bytes sent (%q)", held.TxHash, wantHash)
	}
	// The cause is a CATEGORY, and the assertion is deliberately that the
	// message did NOT survive. The submit error is the broadcast error, and a
	// broadcast URL is /broadcast_tx_commit?tx=0x<the whole signed transaction>
	// which net/http embeds verbatim in the error it returns — so storing the
	// message here would put signed bytes in the fence record, in every "still
	// held" line, and in any support bundle, repeating for as long as the fence
	// stands. See TestFenceNeverStoresOrLogsTheSignedTransaction.
	if held.Cause != string(fenceCauseTimeout) {
		t.Fatalf("held fence cause = %q, want the typed category %q", held.Cause, fenceCauseTimeout)
	}
	if strings.Contains(held.Cause, "broadcast tx commit") {
		t.Fatalf("held fence stored the raw submit error message (%q); it can contain the signed transaction", held.Cause)
	}
	if held.LastCause == "" {
		t.Fatal("held fence reported no typed cause for its last attempt")
	}
	if held.Since.IsZero() || held.HeldFor <= 0 {
		t.Fatalf("held fence reported no age: %+v", held)
	}
	if !strings.Contains(held.LastDetail, "already exists in cache") {
		t.Fatalf("held fence lost the last attempt's detail: %q", held.LastDetail)
	}

	proven.Store(true)
	waitUntil(t, func() bool { return !keyIsFenced(key) }, "the fence to lift once proven")
	if _, still := fencedSignerFor(t, sk); still {
		t.Fatal("a lifted fence is still reported as held")
	}
}

// TestWithNonceLease_FenceOnOneKeyDoesNotBlockAnother pins the concurrency
// boundary, which matters far more now that a fence can be held indefinitely: if
// a fence took anything global, one unreachable transaction would stop the whole
// node from signing instead of stopping one signer.
func TestWithNonceLease_FenceOnOneKeyDoesNotBlockAnother(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	fenced := newLeaseTestKey(t)
	other := newLeaseTestKey(t)
	fencedKey := leaseKeyFor(t, fenced)

	var proven atomic.Bool
	resolver := func(context.Context, []byte) (TxOutcome, error) {
		if proven.Load() {
			return TxOutcome{Verdict: TxVerdictCommitted}, nil
		}
		return TxOutcome{Verdict: TxVerdictUnresolved, Detail: "still pending"}, nil
	}
	if err := WithNonceLease(context.Background(), fenced, func(uint64) error {
		return Indeterminate(errors.New("broadcast tx commit: EOF"), []byte("tx"), resolver)
	}); !errors.Is(err, ErrSubmitIndeterminate) {
		t.Fatalf("got %v, want an indeterminate submit error", err)
	}
	if !keyIsFenced(fencedKey) {
		t.Fatal("the indeterminate submit did not fence its key")
	}

	// The unrelated key must sign normally, repeatedly, while the first is held.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 8; i++ {
			if err := WithNonceLease(context.Background(), other, func(uint64) error { return nil }); err != nil {
				t.Errorf("unrelated key %d: %v", i, err)
				return
			}
		}
	}()
	waitFor(t, done, "an unrelated signing key to keep working while another key is fenced")
	if !keyIsFenced(fencedKey) {
		t.Fatal("the unrelated key's traffic lifted somebody else's fence")
	}

	proven.Store(true)
	waitUntil(t, func() bool { return !keyIsFenced(fencedKey) }, "the fence to lift once proven")
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
