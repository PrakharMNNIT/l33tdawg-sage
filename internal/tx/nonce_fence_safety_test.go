package tx

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file holds the three properties a cross-review found the first fence
// implementation getting wrong, plus the threat model that justifies the restart
// veto. Each is a correctness property with a silent, untraceable failure mode,
// so each gets an explicit test rather than being left to inspection.

// captureFenceLog redirects fence events into a buffer for the duration of a
// test. Fence events are the operator's only window into a hold that can now
// last indefinitely, so what they contain — and what they must never contain —
// is part of the contract, not a formatting detail.
func captureFenceLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	fenceLogMu.Lock()
	previous := fenceLogW
	fenceLogW = buf
	fenceLogMu.Unlock()
	t.Cleanup(func() {
		fenceLogMu.Lock()
		fenceLogW = previous
		fenceLogMu.Unlock()
	})
	return buf
}

// syncBuffer is a bytes.Buffer that survives the reconciliation goroutines
// writing to it while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestFenceNeverStoresOrLogsTheSignedTransaction is the regression for the
// worst defect the first implementation shipped with.
//
// THE LEAK: every CometBFT broadcaster in this repo issues
// GET /broadcast_tx_commit?tx=0x<the entire signed transaction>, and net/http
// embeds the full request URL in the *url.Error it returns. The first fence
// stored that error as its Cause and printed it on every "still held" line —
// and because reconciliation now retries for as long as the fence stands, that
// repeated forever, into the log, into FencedSigners(), and into any support
// bundle an operator sent us.
//
// The assertion is blunt on purpose: the hex of the transaction must not appear
// ANYWHERE in the fence's diagnostics or in anything the fence wrote. This
// exercises both leak paths at once — the submit error handed to Indeterminate,
// and the resolver's own error, which this package does not control.
func TestFenceNeverStoresOrLogsTheSignedTransaction(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	logged := captureFenceLog(t)
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	// Not a real encoded transaction, just a byte string whose hex is
	// unmistakable if any of it survives into a diagnostic.
	sent := []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04}
	sentHex := hex.EncodeToString(sent)
	leakyURL := "http://127.0.0.1:26657/broadcast_tx_commit?tx=0x" + sentHex

	var proven bool
	var provenMu sync.Mutex
	resolver := func(context.Context, []byte) (TxOutcome, error) {
		provenMu.Lock()
		done := proven
		provenMu.Unlock()
		if done {
			return TxOutcome{Verdict: TxVerdictCommitted, Detail: "committed at height 5"}, nil
		}
		// Exactly the shape net/http produces, including for a resolver an
		// adopter wrote and this package never sees.
		return TxOutcome{Verdict: TxVerdictUnresolved, Detail: `Get "` + leakyURL + `": EOF`},
			fmt.Errorf(`Get %q: read: connection reset by peer`, leakyURL)
	}

	// The submit error carries the same URL, which is how the real
	// broadcastTxCommitWebContext failure looks.
	submitErr := fmt.Errorf(`broadcast tx commit: Get %q: EOF`, leakyURL)
	if err := WithNonceLease(context.Background(), sk, func(uint64) error {
		return Indeterminate(submitErr, sent, resolver)
	}); !errors.Is(err, ErrSubmitIndeterminate) {
		t.Fatalf("got %v, want an indeterminate submit error", err)
	}

	// The message must still reach the CALLER verbatim — the lease's contract is
	// that submit's error comes back undecorated, and handlers surface it. Only
	// the fence's own retained copy is sanitized.
	waitUntil(t, func() bool {
		held, ok := fencedSignerFor(t, sk)
		return ok && held.Attempts >= 3
	}, "the fence to make several reconciliation attempts")

	held, ok := fencedSignerFor(t, sk)
	if !ok {
		t.Fatal("the fence lifted before the leak could be checked")
	}
	for field, value := range map[string]string{
		"Cause":      held.Cause,
		"LastDetail": held.LastDetail,
		"LastCause":  held.LastCause,
	} {
		if strings.Contains(strings.ToLower(value), sentHex) {
			t.Fatalf("FencedSigner.%s contains the signed transaction: %q", field, value)
		}
		if carriesTxPayload(value) {
			t.Fatalf("FencedSigner.%s still carries a tx= payload, which is a signed transaction "+
				"(possibly a truncated one, which is no better): %q", field, value)
		}
	}
	if held.Cause != string(fenceCauseTransport) && held.Cause != string(fenceCauseRPC) {
		t.Fatalf("fence cause %q is not one of the typed categories", held.Cause)
	}

	provenMu.Lock()
	proven = true
	provenMu.Unlock()
	waitUntil(t, func() bool { return !keyIsFenced(key) }, "the fence to lift once proven")

	out := logged.String()
	if strings.Contains(strings.ToLower(out), sentHex) {
		t.Fatalf("a fence event printed the signed transaction:\n%s", out)
	}
	if carriesTxPayload(out) {
		t.Fatalf("a fence event printed a tx= payload, which is a signed transaction:\n%s", out)
	}
	// The events themselves must still be there — sanitizing by printing nothing
	// would trade a leak for a mystery hang.
	for _, want := range []string{"event=fence_set", "event=reconcile_retry", "event=fence_lift"} {
		if !strings.Contains(out, want) {
			t.Fatalf("fence log lost %q; a held fence that says nothing is undiagnosable:\n%s", want, out)
		}
	}
}

// carriesTxPayload reports whether text still contains a CometBFT broadcast
// query parameter with any hex payload behind it.
//
// The bar is "any hex at all", not "a whole transaction": a truncated encoded
// transaction in a log is not meaningfully safer than a complete one, and
// tolerating short ones is exactly how the original leak would come back through
// a message that was clipped somewhere upstream.
func carriesTxPayload(text string) bool {
	lower := strings.ToLower(text)
	for i := 0; ; {
		idx := strings.Index(lower[i:], "tx=0x")
		if idx < 0 {
			return false
		}
		after := i + idx + len("tx=0x")
		if after < len(lower) && strings.ContainsRune("0123456789abcdef", rune(lower[after])) {
			return true
		}
		i = after
	}
}

// TestCometTxResolver_TransientCheckTxRefusalNeverLifts is the P0-B regression.
//
// The first implementation mapped EVERY non-zero CheckTx code to a definitive
// rejection. That is unsound, and the reason is worth restating because it is
// easy to talk yourself back out of: a re-submission is judged against the state
// that exists NOW at the node we are talking to, while the older copy — the one
// the fence is actually about — will be judged wherever and whenever IT arrives.
// A refusal that can un-happen therefore proves nothing about the original.
//
// SAGE has plenty of those: code 3 is a nonce LOOKUP failure (a local store
// fault), code 112 is admission backpressure, and every authorization code is
// ordinary mutable state. Lifting on any of them reopens the key while a
// transaction may still be in flight, which is the silent Code 4 loss.
func TestCometTxResolver_TransientCheckTxRefusalNeverLifts(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		log  string
	}{
		{name: "nonce lookup failure", code: 3, log: "nonce lookup error: db closed"},
		{name: "admission backpressure", code: 112, log: "resource temporarily unavailable"},
		{name: "app-v20 resource limit", code: 111, log: "app-v20 resource limit: payload too large"},
		{name: "authorization refused", code: 45, log: "access denied: agent cannot write domain"},
		{name: "signature invalid", code: 2, log: "invalid signature"},
		{name: "undecodable for this binary", code: 1, log: "failed to decode transaction"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, endpoint := newFakeComet(t)
			fake.setHandlers(
				func(string) (int, string) { return 500, cometNotFound },
				func(string) (int, string) {
					return 200, fmt.Sprintf(
						`{"result":{"check_tx":{"code":%d,"log":%q},"tx_result":{"code":0},"hash":"ABC","height":"0"}}`,
						tc.code, tc.log)
				})

			outcome, err := resolveWithFake(t, endpoint, []byte("still-maybe-in-flight"))
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if outcome.Verdict != TxVerdictUnresolved {
				t.Fatalf("CheckTx code %d produced %v; refusing THIS submission does not prove the "+
					"older copy cannot still arrive and commit", tc.code, outcome.Verdict)
			}
			if !strings.Contains(outcome.Detail, "not a permanent class") {
				t.Fatalf("detail %q does not explain why the fence is still held", outcome.Detail)
			}
		})
	}
}

// TestWithNonceLease_TransientCheckTxRefusalLeavesTheFenceSet is the same
// property one level up, through the real lease: the required end-to-end
// assertion is that the SIGNING KEY stays closed, not merely that a helper
// returned a particular enum.
func TestWithNonceLease_TransientCheckTxRefusalLeavesTheFenceSet(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	var superseded bool
	var mu sync.Mutex
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tx" {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(cometNotFound))
			return
		}
		mu.Lock()
		done := superseded
		mu.Unlock()
		if done {
			// The one CheckTx code that IS proof: the committed nonce for this
			// key is at or above this one, so these bytes can never commit
			// AGAIN (here genuinely superseded — the gate saw a higher nonce).
			_, _ = fmt.Fprint(w, `{"result":{"check_tx":{"code":4,"log":"nonce too low: got 7, expected > 9"},`+
				`"tx_result":{"code":0},"hash":"ABC","height":"0"}}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"result":{"check_tx":{"code":3,"log":"nonce lookup error"},`+
			`"tx_result":{"code":0},"hash":"ABC","height":"0"}}`)
	}))
	defer rpc.Close()

	if err := WithNonceLease(context.Background(), sk, func(uint64) error {
		return Indeterminate(errors.New("broadcast tx commit: EOF"), []byte("in-flight"), CometTxResolver(rpc.URL))
	}); !errors.Is(err, ErrSubmitIndeterminate) {
		t.Fatalf("got %v, want an indeterminate submit error", err)
	}

	assertStaysFenced(t, key, 200*time.Millisecond,
		"a transient CheckTx refusal (code 3) is evidence about the re-submission, not about the original copy")

	mu.Lock()
	superseded = true
	mu.Unlock()
	waitUntil(t, func() bool { return !keyIsFenced(key) },
		"the committed-nonce supersession (CheckTx code 4) to prove the abandoned transaction is dead")
	assertKeyStillGrantable(t, sk, "a transaction proven superseded")
}

// TestRestartWhileFencedLosesTheTransaction is the THREAT MODEL, written as an
// executable statement of the residual this release ships with rather than as
// prose that could quietly stop being true.
//
// The sequence, which is exactly what a coordinated restart does today:
//
//	nonce N is emitted and its fate is never observed
//	-> the process restarts, so the in-memory fence is GONE
//	-> the allocator re-seeds from the highest COMMITTED nonce, still BELOW N
//	-> it issues M in the gap, M commits
//	-> the late N arrives and app-v9 rejects it Code 4.
//
// The test simulates the restart by clearing the process state the way a fresh
// process would have it. What it proves is the uncomfortable half: seeding from
// the committed floor does NOT protect the abandoned nonce, because the floor
// knows only what committed and the fence is about what is still in flight.
//
// This is why RestartVetoReason exists, and why the fix is not "restart to clear
// a fence" but durable pre-broadcast intent in a later release.
func TestRestartWhileFencedLosesTheTransaction(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	// The chain has committed up to this nonce for the key. The abandoned
	// transaction is ABOVE it — that is what "still in flight" means.
	const committedFloor = uint64(1_000)
	SetNonceFloorFunc(func(ed25519.PublicKey) (uint64, bool) { return committedFloor, true })
	t.Cleanup(func() { SetNonceFloorFunc(nil) })

	blocked := make(chan struct{})
	resolver := func(ctx context.Context, _ []byte) (TxOutcome, error) {
		select {
		case <-blocked:
			// Teardown only. Reconciliation exits solely on a verdict, so a
			// resolver that stayed unresolved after the test would leave its
			// goroutine spinning for the rest of the package run; liftFence's
			// double-lift guard makes this safe even though the restart
			// simulation already evicted the fence.
			return TxOutcome{Verdict: TxVerdictCommitted, Detail: "test teardown"}, nil
		case <-ctx.Done():
		}
		return TxOutcome{Verdict: TxVerdictUnresolved, Detail: "still unproven"}, nil
	}

	var abandoned uint64
	if err := WithNonceLease(context.Background(), sk, func(n uint64) error {
		abandoned = n
		return Indeterminate(errors.New("broadcast tx commit: connection reset"), []byte("abandoned"), resolver)
	}); !errors.Is(err, ErrSubmitIndeterminate) {
		t.Fatalf("got %v, want an indeterminate submit error", err)
	}
	if !keyIsFenced(key) {
		t.Fatal("the indeterminate submit did not fence the key")
	}
	if abandoned <= committedFloor {
		t.Fatalf("test setup is wrong: the abandoned nonce %d must be above the committed floor %d",
			abandoned, committedFloor)
	}

	// While the process lives, the veto is the thing standing between this fence
	// and the loss below.
	if RestartVetoReason() == "" {
		t.Fatal("a held fence did not veto a coordinated restart; the updater would restart straight into the loss")
	}

	// --- simulate the restart -------------------------------------------------
	// A new process has: no fences (memory only), and no allocator history. All
	// it can do is re-seed from what the CHAIN committed.
	simulateProcessRestartForTest(t, key)

	if keyIsFenced(key) {
		t.Fatal("test setup is wrong: a restart must leave no fence behind")
	}
	if RestartVetoReason() != "" {
		t.Fatal("test setup is wrong: a restarted process has no fence to veto on")
	}

	var afterRestart uint64
	if err := WithNonceLease(context.Background(), sk, func(n uint64) error {
		afterRestart = n
		return nil
	}); err != nil {
		t.Fatalf("post-restart allocation: %v", err)
	}

	// THE RESIDUAL, ASSERTED. The restarted process allocated a nonce with no
	// knowledge of the abandoned one. It happens to be higher here (the clock
	// runs forward), and that is precisely the problem: this nonce will commit,
	// and when the abandoned transaction finally lands it is a replay.
	if afterRestart <= committedFloor {
		t.Fatalf("post-restart nonce %d did not even clear the committed floor %d", afterRestart, committedFloor)
	}
	if keyIsFenced(key) {
		t.Fatal("a restart must not resurrect the fence; if it could, this residual would not exist")
	}
	// State the invariant that is NOT restored, so this test fails loudly the day
	// durable broadcast intent lands and the residual is finally closed.
	if afterRestart == abandoned {
		t.Fatal("post-restart allocation collided with the abandoned nonce")
	}
	t.Logf("KNOWN RESIDUAL (v11.18.3): abandoned nonce %d was never proven; after a restart the "+
		"allocator seeded from committed floor %d and issued %d with no knowledge of it. If %d "+
		"commits first, the abandoned transaction is rejected Code 4. Closing this needs durable "+
		"pre-broadcast intent (11.18.4); until then RestartVetoReason blocks the restarts we schedule.",
		abandoned, committedFloor, afterRestart, afterRestart)

	close(blocked)
}

// simulateProcessRestartForTest drops exactly the state a real restart drops:
// EVERY fence (the map is memory only) and the allocator's history for the key
// under test. It deliberately does NOT touch the nonce floor hook, because a
// real restart re-installs that from the chain — which is the whole point of
// the test.
//
// It clears every fence rather than only this test's, because that is what a
// restart does and because the fences map is process-global: a fence another
// test left standing would otherwise make "a restarted process has no fence"
// false for reasons that have nothing to do with the property under test.
// Marking each fence lifted before closing its channel is what liftFence does,
// so a reconciliation goroutine still running from an earlier test cannot
// double-close.
func simulateProcessRestartForTest(t *testing.T, key string) {
	t.Helper()
	clearAllFencesForTest(t)

	nonceMu.Lock()
	delete(lastNonce, key)
	delete(seeded, key)
	nonceMu.Unlock()
}

// clearAllFencesForTest empties the process-global fence map. Used by tests
// whose subject is the map as a whole (the restart veto reads all of it), so
// they assert their own property instead of whatever an earlier test left
// behind.
func clearAllFencesForTest(t *testing.T) {
	t.Helper()
	fenceMu.Lock()
	for k, fence := range fences {
		if !fence.lifted {
			fence.lifted = true
			close(fence.ch)
		}
		delete(fences, k)
	}
	fenceMu.Unlock()
	publishFenceGauges()
}

// TestReportFencesDroppedAtShutdownEmitsATerminalRecord covers the last line of
// the fence's audit trail. A plain SIGTERM/SIGINT or serve-error exit is not a
// coordinated restart — no veto can apply to a shutdown the operator ordered —
// so the fence map simply dies with the process. Without a terminal record the
// freshest evidence is a fence_held line up to a full report interval old, and
// the Code 4 loss that may follow on the next start has no traceable cause. The
// record must name the fence (signer prefix, hash, age, attempts) under the
// same redaction rules as every other event, and must not pretend the exit is
// safe or advise one.
func TestReportFencesDroppedAtShutdownEmitsATerminalRecord(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	logged := captureFenceLog(t)
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	// With no fence held there must be no event: an unconditional terminal line
	// would train operators to ignore it.
	clearAllFencesForTest(t)
	ReportFencesDroppedAtShutdown("process exit (signal or serve error)")
	if strings.Contains(logged.String(), "fence_dropped_at_shutdown") {
		t.Fatal("a shutdown with nothing held still reported dropped fences")
	}

	sent := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x10, 0x20, 0x30, 0x40}
	blocked := make(chan struct{})
	resolver := func(ctx context.Context, _ []byte) (TxOutcome, error) {
		select {
		case <-blocked:
			// Teardown only — lets the reconciliation goroutine exit; see the
			// restart-residual test's resolver for why.
			return TxOutcome{Verdict: TxVerdictCommitted, Detail: "test teardown"}, nil
		case <-ctx.Done():
		}
		return TxOutcome{Verdict: TxVerdictUnresolved}, nil
	}
	if err := WithNonceLease(context.Background(), sk, func(uint64) error {
		return Indeterminate(errors.New("broadcast tx commit: connection reset"), sent, resolver)
	}); !errors.Is(err, ErrSubmitIndeterminate) {
		t.Fatalf("got %v, want an indeterminate submit error", err)
	}
	t.Cleanup(func() {
		close(blocked)
		simulateProcessRestartForTest(t, key)
	})

	ReportFencesDroppedAtShutdown("process exit (signal or serve error)")

	out := logged.String()
	if !strings.Contains(out, "event=fence_dropped_at_shutdown") {
		t.Fatalf("no terminal record was emitted for the held fence:\n%s", out)
	}
	if !strings.Contains(out, signerPrefix(key)) {
		t.Fatalf("the terminal record does not name the fenced signer:\n%s", out)
	}
	hash := CometTxHash(sent)
	if !strings.Contains(out, strings.ToUpper(hex.EncodeToString(hash[:]))) {
		t.Fatalf("the terminal record does not carry the abandoned transaction's hash:\n%s", out)
	}
	if carriesTxPayload(out) {
		t.Fatalf("the terminal record carries a tx= payload, which is a signed transaction:\n%s", out)
	}
	lowered := strings.ToLower(out)
	for _, forbidden := range []string{"restart to", "restart clears", "safe to restart", "safely"} {
		if strings.Contains(lowered, forbidden) {
			t.Fatalf("the terminal record claims the exit is safe (%q), the exact overstatement this "+
				"workstream removes:\n%s", forbidden, out)
		}
	}
	if !strings.Contains(lowered, "does not survive") {
		t.Fatalf("the terminal record does not state the residual — that this record dies with the "+
			"process:\n%s", out)
	}
}

// TestRestartVetoReasonIsSilentWhenNothingIsHeld pins the other direction: the
// veto must not stand in the way of ordinary restarts, or operators will learn
// to work around it and it will be worthless when it matters.
func TestRestartVetoReasonIsSilentWhenNothingIsHeld(t *testing.T) {
	clearAllFencesForTest(t)
	if reason := RestartVetoReason(); reason != "" {
		t.Fatalf("a node with no fenced key vetoed a restart: %q", reason)
	}
}

// TestRestartVetoReasonNeverAdvisesARestart guards the specific false claim this
// whole workstream exists because of. Operator-facing text must never suggest
// that restarting clears a fence: it does not, it discards the fence without
// resolving anything, and the transaction is then lost untraceably.
func TestRestartVetoReasonNeverAdvisesARestart(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	blocked := make(chan struct{})
	resolver := func(ctx context.Context, _ []byte) (TxOutcome, error) {
		select {
		case <-blocked:
			// Teardown only — lets the reconciliation goroutine exit; see the
			// restart-residual test's resolver for why.
			return TxOutcome{Verdict: TxVerdictCommitted, Detail: "test teardown"}, nil
		case <-ctx.Done():
		}
		return TxOutcome{Verdict: TxVerdictUnresolved}, nil
	}
	if err := WithNonceLease(context.Background(), sk, func(uint64) error {
		return Indeterminate(errors.New("broadcast tx commit: EOF"), []byte("held"), resolver)
	}); !errors.Is(err, ErrSubmitIndeterminate) {
		t.Fatalf("got %v, want an indeterminate submit error", err)
	}
	t.Cleanup(func() {
		close(blocked)
		simulateProcessRestartForTest(t, key)
	})

	reason := RestartVetoReason()
	if reason == "" {
		t.Fatal("a held fence must veto a coordinated restart")
	}
	for _, forbidden := range []string{"restart to", "restarting will", "restart the node", "restart clears", "just restart"} {
		if strings.Contains(strings.ToLower(reason), forbidden) {
			t.Fatalf("the veto reason advises a restart (%q), which is the action that loses the transaction: %q",
				forbidden, reason)
		}
	}
	if !strings.Contains(reason, "may still be in flight") {
		t.Fatalf("the veto reason does not say WHY it is vetoing: %q", reason)
	}
}

// TestQuiesceSigningForRestartRefusesNewSigningWithoutBurningANonce covers the
// other half of the restart condition. Once a coordinated restart is committed,
// no new transaction may be signed into the teardown: such a transaction is the
// likeliest of any to end with an unobserved fate, and an unobserved fate at
// that exact moment is the one the in-process fence cannot carry across.
//
// The refusal must be typed and must not consume a nonce — a burned nonce makes
// a later honest transaction look like a replay — and it must be reversible, or
// an abandoned restart would leave the node silently unable to sign.
func TestQuiesceSigningForRestartRefusesNewSigningWithoutBurningANonce(t *testing.T) {
	sk := newLeaseTestKey(t)
	before := assertKeyStillGrantable(t, sk, "a node that has not been quiesced")

	resume := QuiesceSigningForRestart()
	var ran bool
	err := WithNonceLease(context.Background(), sk, func(uint64) error {
		ran = true
		return nil
	})
	if !errors.Is(err, ErrSigningQuiesced) {
		t.Fatalf("got %v, want ErrSigningQuiesced", err)
	}
	if ran {
		t.Fatal("a quiesced node still signed; that transaction would be broadcast into a teardown")
	}
	if errors.Is(err, ErrSignerFenced) {
		t.Fatal("ErrSigningQuiesced must not be mistakable for a fence: nothing is being reconciled")
	}
	if leaseEntryExists(leaseKeyFor(t, sk)) {
		t.Fatal("a quiesced refusal took a lease slot")
	}

	resume()
	after := assertKeyStillGrantable(t, sk, "a node whose restart was abandoned")
	if after <= before {
		t.Fatalf("nonce regressed across quiesce/resume: %d after %d", after, before)
	}
	// Resuming twice must not be an error; the restart path can unwind through
	// more than one cleanup.
	resume()
}

// TestQuiesceRefusesCallersAlreadyQueuedOnASlot pins the re-check a cross-review
// found missing. Checking signingQuiesced only at WithNonceLease entry left a
// hole exactly where the quiesce matters most: a caller that passed the entry
// check minutes ago and parked in the queue behind a slow commit would, when the
// slot finally freed AFTER quiesce flipped, allocate a nonce and broadcast
// straight into the teardown — the transaction likeliest to end with an
// unobserved fate, raising a fence AFTER the restart veto had already been
// evaluated. The refusal must be typed, must not run submit, and must not burn a
// nonce.
func TestQuiesceRefusesCallersAlreadyQueuedOnASlot(t *testing.T) {
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	holderEntered := make(chan struct{})
	releaseHolder := make(chan struct{})
	holderDone := make(chan struct{})
	go func() {
		defer close(holderDone)
		if err := WithNonceLease(context.Background(), sk, func(uint64) error {
			close(holderEntered)
			<-releaseHolder
			return nil
		}); err != nil {
			t.Errorf("holder lease failed: %v", err)
		}
	}()
	waitFor(t, holderEntered, "the first caller to take the slot")

	// The second caller passes the entry check (nothing is quiesced yet) and
	// queues behind the held slot.
	queuedResult := make(chan error, 1)
	queuedRan := false
	go func() {
		queuedResult <- WithNonceLease(context.Background(), sk, func(uint64) error {
			queuedRan = true
			return nil
		})
	}()
	waitUntil(t, func() bool {
		leaseMu.Lock()
		defer leaseMu.Unlock()
		lease := leases[key]
		return lease != nil && lease.holders >= 2
	}, "the second caller to queue behind the held slot")

	// Quiesce flips while the second caller is parked, THEN the slot frees.
	resume := QuiesceSigningForRestart()
	t.Cleanup(resume)
	close(releaseHolder)
	waitFor(t, holderDone, "the holder to release the slot")

	var err error
	select {
	case err = <-queuedResult:
	case <-time.After(leaseTestTimeout):
		t.Fatal("the queued caller never returned after quiesce")
	}
	if !errors.Is(err, ErrSigningQuiesced) {
		t.Fatalf("queued caller after quiesce: got %v, want ErrSigningQuiesced", err)
	}
	if queuedRan {
		t.Fatal("a caller queued before quiesce still signed after it; that transaction would be broadcast into a teardown")
	}
	waitUntil(t, func() bool { return !leaseEntryExists(key) }, "the lease map to drain after the refusal")

	resume()
	assertKeyStillGrantable(t, sk, "a queued caller was refused by quiesce")
}

// TestWaitForSigningIdleTracksInFlightSubmissions covers the ordering guarantee
// the restart path builds on: WaitForSigningIdle must not report idle while any
// submission is in flight or queued (that submission may yet raise a fence), and
// must report idle promptly once the last participant lets go.
func TestWaitForSigningIdleTracksInFlightSubmissions(t *testing.T) {
	sk := newLeaseTestKey(t)
	key := leaseKeyFor(t, sk)

	holderEntered := make(chan struct{})
	releaseHolder := make(chan struct{})
	holderDone := make(chan struct{})
	go func() {
		defer close(holderDone)
		if err := WithNonceLease(context.Background(), sk, func(uint64) error {
			close(holderEntered)
			<-releaseHolder
			return nil
		}); err != nil {
			t.Errorf("holder lease failed: %v", err)
		}
	}()
	waitFor(t, holderEntered, "the submission to take the slot")

	busyCtx, cancelBusy := context.WithTimeout(context.Background(), 100*time.Millisecond)
	err := WaitForSigningIdle(busyCtx)
	cancelBusy()
	if err == nil {
		t.Fatal("WaitForSigningIdle reported idle while a submission held the slot; " +
			"a restart drain starting now could sever that submission and raise a fence after the veto ran")
	}

	close(releaseHolder)
	waitFor(t, holderDone, "the submission to finish")

	idleCtx, cancelIdle := context.WithTimeout(context.Background(), leaseTestTimeout)
	defer cancelIdle()
	if err := WaitForSigningIdle(idleCtx); err != nil {
		t.Fatalf("WaitForSigningIdle after the slot drained: %v", err)
	}
	if leaseEntryExists(key) {
		t.Fatal("lease entry survived the idle wait")
	}
}

// TestQuiesceIsGlobalButFencingStaysPerKey pins the boundary between the two
// gates, which are easy to confuse because both refuse to sign.
//
// A FENCE is per key and is the correctness mechanism: one signer's unresolved
// transaction must never stop another signer, or one unreachable RPC would take
// the whole node down. QUIESCE is global and is a lifecycle mechanism: the
// process is going away, so nobody should be starting anything.
func TestQuiesceIsGlobalButFencingStaysPerKey(t *testing.T) {
	setFenceTimingsForTest(t, fastFenceTimings())
	fenced := newLeaseTestKey(t)
	other := newLeaseTestKey(t)
	fencedKey := leaseKeyFor(t, fenced)

	blocked := make(chan struct{})
	resolver := func(ctx context.Context, _ []byte) (TxOutcome, error) {
		select {
		case <-blocked:
			// Teardown only — lets the reconciliation goroutine exit; see the
			// restart-residual test's resolver for why.
			return TxOutcome{Verdict: TxVerdictCommitted, Detail: "test teardown"}, nil
		case <-ctx.Done():
		}
		return TxOutcome{Verdict: TxVerdictUnresolved}, nil
	}
	if err := WithNonceLease(context.Background(), fenced, func(uint64) error {
		return Indeterminate(errors.New("broadcast tx commit: EOF"), []byte("held"), resolver)
	}); !errors.Is(err, ErrSubmitIndeterminate) {
		t.Fatalf("got %v, want an indeterminate submit error", err)
	}
	t.Cleanup(func() {
		close(blocked)
		simulateProcessRestartForTest(t, fencedKey)
	})

	// A fence on one key leaves every other key signing normally.
	assertKeyStillGrantable(t, other, "an unrelated key while another is fenced")

	// Quiescing closes everything, including the keys that were fine.
	resume := QuiesceSigningForRestart()
	if err := WithNonceLease(context.Background(), other, func(uint64) error { return nil }); !errors.Is(err, ErrSigningQuiesced) {
		t.Fatalf("unrelated key during quiesce: got %v, want ErrSigningQuiesced", err)
	}
	resume()
	assertKeyStillGrantable(t, other, "an unrelated key after the restart was abandoned")
}
