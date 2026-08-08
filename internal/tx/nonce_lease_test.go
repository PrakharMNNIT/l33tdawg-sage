package tx

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestWithNonceLease_SubmissionOrderMatchesAllocationOrder is the defect this
// exists for. MonotonicNonce alone guarantees allocation order, not arrival
// order: a dashboard fan-out (clear a Done column, bulk-forget memories) could
// allocate N then N+1 and submit them in either order, and app-v9's strictly-">"
// replay gate rejects the late lower nonce with Code 4. The lease must make the
// observed submission sequence ascending for a single key.
func TestWithNonceLease_SubmissionOrderMatchesAllocationOrder(t *testing.T) {
	_, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu        sync.Mutex
		submitted []uint64
	)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			leaseErr := WithNonceLease(context.Background(), sk, func(nonce uint64) error {
				// Widen the window the old code raced in: allocation and the
				// recorded "submission" are separated by a real scheduling point.
				time.Sleep(time.Millisecond)
				mu.Lock()
				submitted = append(submitted, nonce)
				mu.Unlock()
				return nil
			})
			if leaseErr != nil {
				t.Errorf("WithNonceLease: %v", leaseErr)
			}
		}()
	}
	wg.Wait()

	if len(submitted) != 64 {
		t.Fatalf("got %d submissions, want 64", len(submitted))
	}
	for i := 1; i < len(submitted); i++ {
		if submitted[i] <= submitted[i-1] {
			t.Fatalf("submission %d carried nonce %d after %d: a descending arrival is Code 4 'nonce too low'",
				i, submitted[i], submitted[i-1])
		}
	}
}

// TestWithNonceLease_DistinctKeysStayConcurrent guards the silent throughput
// cliff: serializing unrelated signing keys would still pass every correctness
// test above while turning every concurrent signer in the process into a queue.
func TestWithNonceLease_DistinctKeysStayConcurrent(t *testing.T) {
	const keys = 8
	var (
		inside  sync.WaitGroup
		release = make(chan struct{})
		done    sync.WaitGroup
	)
	inside.Add(keys)
	done.Add(keys)

	for i := 0; i < keys; i++ {
		_, sk, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			defer done.Done()
			_ = WithNonceLease(context.Background(), sk, func(uint64) error {
				// Every key must be able to be inside its lease at the same
				// time; if leases were global this blocks forever.
				inside.Done()
				<-release
				return nil
			})
		}()
	}

	entered := make(chan struct{})
	go func() { inside.Wait(); close(entered) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("distinct keys did not hold their leases concurrently")
	}
	close(release)
	done.Wait()
}

// TestWithNonceLease_CancelledContextAllocatesNothing covers both halves of the
// context contract: an already-dead request never enters the lease, and a
// request whose context dies while it is QUEUED gives the slot up instead of
// burning a nonce nobody will broadcast.
func TestWithNonceLease_CancelledContextAllocatesNothing(t *testing.T) {
	_, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	deadCtx, cancelDead := context.WithCancel(context.Background())
	cancelDead()
	var ran atomic.Bool
	if leaseErr := WithNonceLease(deadCtx, sk, func(uint64) error {
		ran.Store(true)
		return nil
	}); !errors.Is(leaseErr, context.Canceled) {
		t.Fatalf("dead context: got %v, want context.Canceled", leaseErr)
	}
	if ran.Load() {
		t.Fatal("a request whose context was already dead allocated a nonce")
	}

	// Hold the key, then queue a waiter behind it and cancel the waiter.
	held := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan struct{})
	go func() {
		defer close(holderDone)
		_ = WithNonceLease(context.Background(), sk, func(uint64) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	waiterErr := make(chan error, 1)
	go func() {
		waiterErr <- WithNonceLease(waiterCtx, sk, func(uint64) error {
			ran.Store(true)
			return nil
		})
	}()
	// Give the waiter time to actually reach the queue before cancelling it.
	time.Sleep(50 * time.Millisecond)
	cancelWaiter()
	select {
	case queuedErr := <-waiterErr:
		if !errors.Is(queuedErr, context.Canceled) {
			t.Fatalf("cancelled waiter: got %v, want context.Canceled", queuedErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cancelled waiter stayed queued")
	}
	if ran.Load() {
		t.Fatal("a cancelled waiter allocated a nonce")
	}

	close(release)
	<-holderDone
}

// TestWithNonceLease_LeaseMapDrainsWhenIdle pins the deliberate memory bound: a
// per-key lock map that only grows leaks on a long-lived node that signs for
// many agent and federation-peer keys, so the last participant must evict the
// entry.
func TestWithNonceLease_LeaseMapDrainsWhenIdle(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		_, sk, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				_ = WithNonceLease(context.Background(), sk, func(uint64) error { return nil })
			}
		}()
	}
	wg.Wait()

	leaseMu.Lock()
	remaining := len(leases)
	leaseMu.Unlock()
	if remaining != 0 {
		t.Fatalf("%d lease entries survived an idle key set; the map is leaking", remaining)
	}
}

// TestWithNonceLease_ReturnsSubmitErrorUnwrapped keeps callers able to classify
// broadcast failures (web's isIndeterminateCommitError matches on error text),
// so the lease must not decorate what submit returned.
func TestWithNonceLease_ReturnsSubmitErrorUnwrapped(t *testing.T) {
	_, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("broadcast tx commit: connection refused")
	got := WithNonceLease(context.Background(), sk, func(uint64) error { return sentinel })
	if !errors.Is(got, sentinel) {
		t.Fatalf("got %v, want the submit error itself", got)
	}
	if got.Error() != sentinel.Error() {
		t.Fatalf("lease rewrote the submit error to %q", got.Error())
	}
}

// TestWithNonceLease_RejectsUnusableKeyWithoutPanicking pins the ORDER of the
// entry guards, not just their presence. ed25519.PrivateKey.Public() slices
// sk[32:64] with no bounds check, so consulting it before validating the length
// panics ("slice bounds out of range [32:0]") on a nil or short key — and a
// type-assertion fallback written after that call is dead code guarding a crash
// that already happened. If anyone reorders these guards, this test crashes
// rather than fails, which is the point.
func TestWithNonceLease_RejectsUnusableKeyWithoutPanicking(t *testing.T) {
	for name, sk := range map[string]ed25519.PrivateKey{
		"nil":   nil,
		"empty": {},
		"short": make(ed25519.PrivateKey, ed25519.PrivateKeySize-1),
		"long":  make(ed25519.PrivateKey, ed25519.PrivateKeySize+1),
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			err := WithNonceLease(context.Background(), sk, func(uint64) error {
				called = true
				return nil
			})
			if err == nil {
				t.Fatal("an unusable key must be a definitive error, not a silent success")
			}
			if called {
				// Falling back to unserialized allocation here would quietly
				// reintroduce the very interleaving the lease exists to stop.
				t.Fatal("submit ran for a key the lease could not serialize on")
			}
		})
	}
}

// TestWithNonceLease_NilSubmitIsAnError guards against reporting success for a
// transaction that was never allocated and never sent. Returning nil here would
// let a caller that lost its closure to a refactor believe it committed.
func TestWithNonceLease_NilSubmitIsAnError(t *testing.T) {
	_, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if leaseErr := WithNonceLease(context.Background(), sk, nil); leaseErr == nil {
		t.Fatal("a nil submit must not be reported as a committed transaction")
	}
}
