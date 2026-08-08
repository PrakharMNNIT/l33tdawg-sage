package tx

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

// This file pins the LIFECYCLE half of the fence's contract: reconciliation has
// no budget of any kind, a waiter parked on a fence proceeds the moment fate is
// proven, the goroutines and map entries a fence creates all drain when it
// lifts, and the bytes reconciliation re-submits are immune to the caller
// reusing its encode buffer.
//
// Everything here is sequenced structurally — attempt ordinals, channels and
// polls-until-condition — never by asserting that something did or did not
// happen within a wall-clock window, because a loaded CI runner makes every
// such window a coin flip.

// TestWithNonceLease_NoBudgetEndsReconciliation targets the second fail-open
// lift the superseded implementation shipped: reconciliation ran under one
// overall context.WithTimeout budget (SAGE_TX_FENCE_BUDGET_MS), and the budget
// expiring ENDED reconciliation and lifted the fence. A budget expiring says
// nothing about where the transaction is, so the reworked loop has no budget
// field at all — its per-attempt deadline expiring produces another attempt,
// never a lift.
//
// The assertion is by ATTEMPT ORDINAL, not wall clock: every one of a dozen
// consecutive attempts exhausts its own deadline, and the fence must still be
// standing after the twelfth — far past any bounded retry schedule — and must
// then lift on the first attempt that returns proof. Against the superseded
// build this fails whenever its budget expired inside the observed attempts;
// with the budget at its default the discrimination is the type system's
// (fenceTimings no longer has a budget to exhaust), and this test pins the
// contract so one cannot be reintroduced quietly.
func TestWithNonceLease_NoBudgetEndsReconciliation(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	// Attempts past which "some bounded schedule was still running" stops being
	// a plausible explanation for the fence surviving. Well past the verbose
	// window and the backoff ceiling, and cheap at test timings.
	const attemptsToOutlive = 12

	var attempts atomic.Int32
	var proven atomic.Bool
	resolver := func(ctx context.Context, _ []byte) (TxOutcome, error) {
		attempts.Add(1)
		if proven.Load() {
			return TxOutcome{Verdict: TxVerdictCommitted, Detail: "committed at height 99"}, nil
		}
		// Burn the WHOLE per-attempt deadline, the way a hung node does. The
		// superseded budget counted exactly this kind of time.
		<-ctx.Done()
		return TxOutcome{}, ctx.Err()
	}

	if err := WithNonceLease(context.Background(), sk, func(uint64) error {
		return Indeterminate(errors.New("broadcast tx commit: connection reset"), []byte("tx"), resolver)
	}); !errors.Is(err, ErrSubmitIndeterminate) {
		t.Fatalf("got %v, want an indeterminate submit error", err)
	}

	waitUntil(t, func() bool { return attempts.Load() >= attemptsToOutlive },
		"reconciliation to keep attempting past any bounded schedule")
	if !keyIsFenced(key) {
		t.Fatalf("the fence lifted somewhere inside %d deadline-exhausted attempts: an expired clock is not "+
			"evidence of the transaction's fate", attemptsToOutlive)
	}
	// The diagnostics must agree that all that retrying belonged to a HELD
	// fence — a fence that lifted and was re-raised would also satisfy the
	// counter above.
	if held, ok := fencedSignerFor(t, sk); !ok || held.Attempts < 2 {
		t.Fatalf("held fence does not account for the attempts made: %+v (present=%v)", held, ok)
	}

	proven.Store(true)
	waitUntil(t, func() bool { return !keyIsFenced(key) }, "proof to lift the fence after the deadline storm")
	assertKeyStillGrantable(t, sk, "a fence that outlived every exhausted attempt deadline")
}

// TestWithNonceLease_BlockedWaiterProceedsOnceFateIsProven covers the waiter's
// success path, which no other test exercises end to end: a caller parked on a
// held fence — not refused, because its context is still alive — must go
// through the moment the fate is proven, and the nonce it then allocates must
// be ABOVE the fenced one. That ordering is the entire point of parking the
// waiter: had it been allowed past the fence, its lower-or-equal nonce would be
// the one that kills the abandoned transaction.
func TestWithNonceLease_BlockedWaiterProceedsOnceFateIsProven(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	var attempts atomic.Int32
	var proven atomic.Bool
	resolver := func(context.Context, []byte) (TxOutcome, error) {
		attempts.Add(1)
		if proven.Load() {
			return TxOutcome{Verdict: TxVerdictCommitted, Detail: "committed at height 8"}, nil
		}
		return TxOutcome{Verdict: TxVerdictUnresolved, Detail: "tx not found"}, nil
	}

	var fencedNonce uint64
	if err := WithNonceLease(context.Background(), sk, func(n uint64) error {
		fencedNonce = n
		return Indeterminate(errors.New("broadcast tx commit: EOF"), []byte("tx"), resolver)
	}); !errors.Is(err, ErrSubmitIndeterminate) {
		t.Fatalf("got %v, want an indeterminate submit error", err)
	}
	if !keyIsFenced(key) {
		t.Fatal("the indeterminate submit did not fence the key")
	}

	var queued atomic.Bool
	var waiterNonce uint64
	waiterDone := make(chan struct{})
	go func() {
		defer close(waiterDone)
		queued.Store(true)
		if err := WithNonceLease(context.Background(), sk, func(n uint64) error {
			waiterNonce = n
			return nil
		}); err != nil {
			t.Errorf("the parked waiter failed instead of proceeding once the fence lifted: %v", err)
		}
	}()

	// Sequence structurally: the waiter is queued, and reconciliation has since
	// completed several more attempts with the waiter still parked. Attempt
	// ordinals stand in for "real time passed", so a loaded runner cannot turn
	// this into a flake.
	waitUntil(t, func() bool { return queued.Load() }, "the waiter to reach the lease")
	attemptsWhenQueued := attempts.Load()
	waitUntil(t, func() bool { return attempts.Load() >= attemptsWhenQueued+3 },
		"reconciliation to keep running with a waiter parked on the fence")
	select {
	case <-waiterDone:
		t.Fatal("the waiter completed while the fence was still held: it allocated a nonce past an " +
			"abandoned transaction, which is the exact move that kills it")
	default:
	}

	proven.Store(true)
	waitFor(t, waiterDone, "the parked waiter to proceed once the transaction's fate was proven")
	if waiterNonce <= fencedNonce {
		t.Fatalf("the waiter allocated nonce %d, at or below the fenced nonce %d: the fence held the slot "+
			"precisely so every later allocation lands above the abandoned one", waiterNonce, fencedNonce)
	}
	if leaseEntryExists(key) {
		t.Fatal("the waiter's release left the lease entry behind")
	}
}

// TestFenceLifecycleLeavesNoGoroutineOrLeaseBehind is the drain half of "never
// leak the lease, the fence, or a goroutine on any path". Every fence starts
// two goroutines — the reconciler and the held-fence alarm — and both are
// specified to live exactly as long as the fence. A version that leaked either
// would accumulate one hot loop per indeterminate submission for the life of
// the node, and nothing else in the suite would notice.
//
// The check is amplified rather than timed: run several full fence lifecycles
// and require the goroutine count to come back to (near) where it started.
// A per-fence leak of even one goroutine shows up multiplied by the cycle
// count, while the small tolerance absorbs unrelated runtime churn. The map
// entries are asserted exactly, because they are exact.
func TestFenceLifecycleLeavesNoGoroutineOrLeaseBehind(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	const cycles = 8
	baseline := runtime.NumGoroutine()

	for i := 0; i < cycles; i++ {
		var proven atomic.Bool
		resolver := func(context.Context, []byte) (TxOutcome, error) {
			if proven.Load() {
				return TxOutcome{Verdict: TxVerdictCommitted, Detail: "committed"}, nil
			}
			return TxOutcome{Verdict: TxVerdictUnresolved, Detail: "still pending"}, nil
		}
		if err := WithNonceLease(context.Background(), sk, func(uint64) error {
			return Indeterminate(errors.New("broadcast tx commit: EOF"), []byte("tx"), resolver)
		}); !errors.Is(err, ErrSubmitIndeterminate) {
			t.Fatalf("cycle %d: got %v, want an indeterminate submit error", i, err)
		}
		// Hold each fence across at least one recorded attempt so the alarm and
		// reconciler goroutines are genuinely running before being asked to
		// drain, rather than winning a race with their own startup.
		waitUntil(t, func() bool {
			held, ok := fencedSignerFor(t, sk)
			return ok && held.Attempts >= 1
		}, "the fence to make an attempt before being proven")
		proven.Store(true)
		waitUntil(t, func() bool { return !keyIsFenced(key) }, "the fence to lift")
	}

	// Both per-fence goroutines exit strictly after the lift is observable, so
	// poll rather than snapshot. The tolerance covers unrelated churn (an idle
	// HTTP connection from an earlier test winding down, a finalizer); a real
	// per-fence leak would sit cycles*1 or cycles*2 above baseline and can
	// never satisfy this.
	waitUntil(t, func() bool { return runtime.NumGoroutine() <= baseline+2 },
		"the reconciler and alarm goroutines of every lifted fence to exit")

	if leaseEntryExists(key) {
		t.Fatal("the lease map kept an entry for an idle key")
	}
	if keyIsFenced(key) {
		t.Fatal("the fence map kept an entry after its fence lifted")
	}
	assertKeyStillGrantable(t, sk, "eight full fence lifecycles")
}

// TestIndeterminateIsImmuneToTheCallersBufferBeingReused pins the copy in
// Indeterminate, which is the quiet half of the exact-bytes guarantee. The loud
// half — reconciliation re-submitting byte-identical payloads — is asserted at
// the resolver and adopter layers; this is the way it would break WITHOUT any
// of those tests noticing: an adopter reuses its encode buffer for the NEXT
// transaction, and if the fence had aliased that buffer rather than copying it,
// reconciliation would re-broadcast whatever the buffer holds now. Different
// bytes are a different hash and a different nonce, so CometBFT would not
// de-dupe them — the re-submission would be a second real transaction racing
// the first, turning the safety mechanism itself into the double-send.
func TestIndeterminateIsImmuneToTheCallersBufferBeingReused(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	original := []byte("first-encoded-transaction")
	buf := append([]byte(nil), original...)

	var (
		probeMu sync.Mutex
		probes  [][]byte
	)
	var proven atomic.Bool
	resolver := func(_ context.Context, encoded []byte) (TxOutcome, error) {
		probeMu.Lock()
		probes = append(probes, append([]byte(nil), encoded...))
		probeMu.Unlock()
		if proven.Load() {
			return TxOutcome{Verdict: TxVerdictCommitted, Detail: "committed"}, nil
		}
		return TxOutcome{Verdict: TxVerdictUnresolved, Detail: "tx not found"}, nil
	}

	if err := WithNonceLease(context.Background(), sk, func(uint64) error {
		return Indeterminate(errors.New("broadcast tx commit: connection reset"), buf, resolver)
	}); !errors.Is(err, ErrSubmitIndeterminate) {
		t.Fatalf("got %v, want an indeterminate submit error", err)
	}

	// The caller moves on and reuses its buffer, exactly as a pooled or
	// stack-allocated encode buffer would be. Everything reconciliation probes
	// from here on must still be the ORIGINAL bytes. (Had Indeterminate aliased
	// the buffer, this write would also race the resolver's read, so -race
	// catches the regression even if the assertion below happens to miss it.)
	probeMu.Lock()
	probesBeforeReuse := len(probes)
	probeMu.Unlock()
	for i := range buf {
		buf[i] = 'X'
	}
	waitUntil(t, func() bool {
		probeMu.Lock()
		defer probeMu.Unlock()
		return len(probes) >= probesBeforeReuse+2
	}, "reconciliation to probe again after the caller reused its buffer")

	proven.Store(true)
	waitUntil(t, func() bool { return !keyIsFenced(key) }, "the fence to lift once proven")

	probeMu.Lock()
	defer probeMu.Unlock()
	if len(probes) == 0 {
		t.Fatal("the fence lifted without reconciling anything")
	}
	for i, probe := range probes {
		if string(probe) != string(original) {
			t.Fatalf("probe %d reconciled %q, want the original bytes %q: an aliased buffer makes "+
				"re-submission broadcast a DIFFERENT transaction, which is a genuine double-send",
				i, probe, original)
		}
	}
}
