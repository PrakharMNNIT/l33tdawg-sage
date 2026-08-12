package federation

import (
	"testing"

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
