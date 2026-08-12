package federation

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/tx"
)

// A3: a nil CometCommitResult must never be classified as a retryable
// consensus verdict.
//
// This condition is unreachable today — BroadcastCometCommit never returns
// (nil, nil), so the caller returns on the error before classification. The
// test exists precisely because that is a property of ANOTHER package's
// contract, not of this one. If the broadcaster ever gains a path that returns
// no result and no error, the old behavior would have released the signing key
// on an outcome nothing observed, silently. This fails instead.
func TestClassifySyncBroadcastNilResultIsIndeterminateNotRetry(t *testing.T) {
	got := classifySyncBroadcast(nil)

	if got == syncBcastRetry {
		t.Fatal("nil result classified as syncBcastRetry: the caller's default arm treats that " +
			"as exact-hash-bound with the registration already retired, and releases the signer. " +
			"A nil result satisfies none of those conditions.")
	}
	if got != syncBcastIndeterminate {
		t.Fatalf("nil result classified as %v, want syncBcastIndeterminate", got)
	}
}

func TestNilSyncBroadcastResultFencesExactSignerAndBytes(t *testing.T) {
	m, _ := newSyncTestManager(t, &scriptedComet{responses: []string{cometOK}})
	// Keep reconciliation unable to manufacture proof while the assertions run.
	m.cometRPC = "http://127.0.0.1:1"
	var submittedKey ed25519.PrivateKey
	var submittedBytes []byte
	m.syncBroadcastCommitFn = func(
		_ context.Context,
		_ string,
		key ed25519.PrivateKey,
		encoded []byte,
	) (*tx.CometCommitResult, error) {
		submittedKey = append(ed25519.PrivateKey(nil), key...)
		submittedBytes = append([]byte(nil), encoded...)
		return nil, nil
	}

	item := syncItem("nil-result", "hr", "fence the exact impossible-result submission")
	outcome, hash := m.broadcastSyncSubmit(syncMemoryID("chain-b", item.OriginMemoryID), &item)
	if outcome != SyncOutcomeRetry || hash != "" {
		t.Fatalf("nil result returned outcome=%q hash=%q, want retry with no hash", outcome, hash)
	}
	if !submittedKey.Equal(m.agentKey) {
		t.Fatal("test seam did not receive the manager's exact signing key")
	}
	if len(submittedBytes) == 0 {
		t.Fatal("test seam received no encoded transaction bytes")
	}
	wantHash := tx.CometTxHash(submittedBytes)
	wantSigner := hex.EncodeToString(m.agentPub)
	found := false
	for _, held := range tx.FencedSigners() {
		if held.SignerPubKeyHex == wantSigner {
			found = true
			if held.TxHash != strings.ToUpper(hex.EncodeToString(wantHash[:])) {
				t.Fatalf("fenced tx hash=%q, want exact submitted bytes hash %X", held.TxHash, wantHash)
			}
		}
	}
	if !found {
		t.Fatalf("nil result released signer %s instead of fencing it", wantSigner)
	}

	waitCtx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	allocated := false
	err := tx.WithNonceLease(waitCtx, m.agentKey, func(uint64) error {
		allocated = true
		return nil
	})
	if allocated {
		t.Fatal("same-key waiter allocated past the nil-result fence")
	}
	if !errors.Is(err, tx.ErrSignerFenced) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("same-key waiter got %v, want ErrSignerFenced with deadline cause", err)
	}
}

// The classes that DO represent a real verdict must stay distinct from the
// indeterminate one, so a future edit cannot quietly fold "no proof" into any
// of them.
func TestSyncBroadcastIndeterminateIsDistinctFromEveryVerdictClass(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  syncBcastClass
	}{
		{"committed", classifySyncBroadcast(&tx.CometCommitResult{})},
		{"checktx nonce race", classifySyncBroadcast(&tx.CometCommitResult{CheckTxCode: 4})},
		{"checktx other refusal", classifySyncBroadcast(&tx.CometCommitResult{CheckTxCode: 9})},
		{"finalize nonce race", classifySyncBroadcast(&tx.CometCommitResult{TxResultCode: 4})},
		{"finalize other refusal", classifySyncBroadcast(&tx.CometCommitResult{TxResultCode: 9})},
		{"finalize duplicate", classifySyncBroadcast(&tx.CometCommitResult{
			TxResultCode: 11, TxResultLog: "already reached terminal status",
		})},
		{"finalize scope reject", classifySyncBroadcast(&tx.CometCommitResult{
			TxResultCode: 11, TxResultLog: "no write access to domain",
		})},
		{"finalize unrecognised code 11", classifySyncBroadcast(&tx.CometCommitResult{
			TxResultCode: 11, TxResultLog: "something new nobody has seen",
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got == syncBcastIndeterminate {
				t.Fatalf("a non-nil hash-bound result was classified indeterminate, "+
					"which now fences the signing key: %v", tc.got)
			}
		})
	}
}
