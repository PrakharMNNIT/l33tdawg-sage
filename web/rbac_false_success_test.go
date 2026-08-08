package web

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/tx"
)

// This file pins the FALSE-SUCCESS class in broadcastTxCommitWebContext: every
// commit response that does not positively prove THIS transaction landed must
// come back indeterminate — which is what raises the fence — never as a
// success and never as a definitive rejection. The worst member of the class
// was a syntactically valid but EMPTY body ("{}"): every field zero-values, so
// CheckTx.Code == 0 and TxResult.Code == 0 held and the caller was told the
// transaction COMMITTED with an empty hash at height 0. The fence never
// engaged because there was no error; the write was simply lost behind a
// success message.

// falseSuccessKey builds a signing key for direct broadcast calls. The key is
// only used for RegisterSubmittedTx bookkeeping inside the broadcast helper;
// these tests call the helper directly, outside any lease.
func falseSuccessKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return key
}

// TestBroadcastTxCommit_FalseSuccessShapesAreIndeterminate sweeps every
// no-proof shape. The uniform assertion is the contract: an error that
// isIndeterminateCommitError — the exact predicate signAndBroadcastCommitPrepared
// uses to decide a fence goes up — and no hash, height or log handed to the
// caller, because a caller holding any of them will report a commit that was
// never proven.
func TestBroadcastTxCommit_FalseSuccessShapesAreIndeterminate(t *testing.T) {
	signed := []byte("false-success-probe")
	sum := tx.CometTxHash(signed)
	boundHash := strings.ToUpper(hex.EncodeToString(sum[:]))
	wrongSum := tx.CometTxHash([]byte("someone-else-entirely"))
	wrongHash := strings.ToUpper(hex.EncodeToString(wrongSum[:]))

	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{
			// THE WORST CASE: nothing in this body says anything about any
			// transaction, and it used to be reported as a committed success.
			name:   "syntactically valid but empty body",
			status: 200,
			body:   `{}`,
		},
		{
			// A 500 whose body happens to parse — a proxy artifact. Nothing
			// below the status line examined the code, so this fell through to
			// whatever the body claimed. The bytes may well be in a mempool:
			// indeterminate, not a success and not a rejection.
			name:   "http 500 with a parseable success body",
			status: 500,
			body: `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` +
				boundHash + `","height":"12"}}`,
		},
		{
			name:   "success envelope with no hash",
			status: 200,
			body:   `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"","height":"12"}}`,
		},
		{
			name:   "bound success envelope missing both nested verdicts",
			status: 200,
			body:   `{"result":{"hash":"` + boundHash + `","height":"12"}}`,
		},
		{
			name:   "bound success envelope with null checktx",
			status: 200,
			body:   `{"result":{"check_tx":null,"tx_result":{"code":0},"hash":"` + boundHash + `","height":"12"}}`,
		},
		{
			name:   "bound success envelope with null txresult",
			status: 200,
			body:   `{"result":{"check_tx":{"code":0},"tx_result":null,"hash":"` + boundHash + `","height":"12"}}`,
		},
		{
			// A perfectly-formed envelope about a DIFFERENT transaction — the
			// replayed-proxy shape. Accepting it reports this transaction
			// committed on the strength of someone else's fate.
			name:   "success envelope with the wrong hash",
			status: 200,
			body: `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` +
				wrongHash + `","height":"12"}}`,
		},
		{
			// Bound hash but no block: "committed" with no height is not a
			// claim that can be checked.
			name:   "success envelope with height zero",
			status: 200,
			body: `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` +
				boundHash + `","height":"0"}}`,
		},
		{
			// REJECTIONS MUST BE BOUND TOO. A replaying proxy answering with an
			// EARLIER transaction's CheckTx refusal — while our bytes reached
			// the real mempool — used to be adopted as a definitive verdict,
			// releasing the lease over in-flight bytes. Someone else's refusal
			// is silence about ours.
			name:   "checktx rejection with the wrong hash",
			status: 200,
			body: `{"result":{"check_tx":{"code":2,"log":"unauthorized"},"tx_result":{"code":0},"hash":"` +
				wrongHash + `","height":"0"}}`,
		},
		{
			// The same replay with the hash simply absent. A real CometBFT
			// refusal always carries our hash (the node computes it locally
			// from the submitted bytes), so "no hash" is never a real verdict.
			name:   "checktx rejection with no hash",
			status: 200,
			body:   `{"result":{"check_tx":{"code":2,"log":"unauthorized"},"tx_result":{"code":0},"hash":"","height":"0"}}`,
		},
		{
			name:   "finalizeblock rejection with the wrong hash",
			status: 200,
			body: `{"result":{"check_tx":{"code":0},"tx_result":{"code":5,"log":"refused"},"hash":"` +
				wrongHash + `","height":"12"}}`,
		},
		{
			// Bound hash but height zero: a FinalizeBlock verdict IS inclusion
			// in a block, so a heightless one is a shape no real node produces
			// — silence, not a rejection to release on.
			name:   "finalizeblock rejection without a block height",
			status: 200,
			body: `{"result":{"check_tx":{"code":0},"tx_result":{"code":5,"log":"refused"},"hash":"` +
				boundHash + `","height":"0"}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			}))
			t.Cleanup(rpc.Close)

			hash, height, txLog, err := broadcastTxCommitWebContext(
				context.Background(), rpc.URL, falseSuccessKey(t), signed)
			require.Error(t, err,
				"a response that proves nothing was reported as a successful commit")
			assert.True(t, isIndeterminateCommitError(err),
				"no-proof must be INDETERMINATE (which fences), not a definitive failure: %v", err)
			assert.Empty(t, hash, "no proof, so no hash may reach the caller")
			assert.Zero(t, height)
			assert.Empty(t, txLog)
		})
	}
}

// TestBroadcastTxCommit_EmptyBodyFencesTheSigningKey is the worst case driven
// end to end: through signAndBroadcastCommitContext, an empty "{}" commit
// response must leave the signing key FENCED — proof that the indeterminate
// classification above actually engages the machinery that protects the nonce,
// rather than surfacing as a plain error someone downstream can shrug off.
func TestBroadcastTxCommit_EmptyBodyFencesTheSigningKey(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// fenceResolvingRPC guarantees the fence this test raises is RESOLVED with
	// proof at teardown, so it cannot leak into the package's restart tests.
	rpc := fenceResolvingRPC(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{}`)
	})

	h := &DashboardHandler{CometBFTRPC: rpc.URL}
	hash, height, _, err := h.signAndBroadcastCommitContext(
		context.Background(), accessGrantTx(agentIDForKey(key), "agent-empty-body"), key)
	require.Error(t, err, "an empty commit body was reported as a successful commit")
	assert.Empty(t, hash)
	assert.Zero(t, height)

	require.Eventually(t, func() bool { return fencedSignerPresent(key) },
		5*time.Second, 10*time.Millisecond,
		"the empty-body false success did not fence its signing key; the nonce above it is unprotected")
}

// TestBroadcastTxCommit_BoundSuccessStillSucceeds is the guard against fixing
// the false-success class by breaking the true one: a 200 whose envelope
// carries the EXACT hash of the bytes sent and a positive height is proof, and
// must still be reported as the commit it is.
//
// NOTE: this test also passed against the superseded implementation — that
// code accepted everything, including this. It is here so the sweep above can
// never be "fixed" by rejecting all responses.
func TestBroadcastTxCommit_BoundSuccessStillSucceeds(t *testing.T) {
	signed := []byte("genuinely-committed")
	sum := tx.CometTxHash(signed)
	wantHash := strings.ToUpper(hex.EncodeToString(sum[:]))

	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeCommitOKAt(w, r, 42, "applied")
	}))
	t.Cleanup(rpc.Close)

	hash, height, txLog, err := broadcastTxCommitWebContext(
		context.Background(), rpc.URL, falseSuccessKey(t), signed)
	require.NoError(t, err, "a fully-proven commit must not be refused")
	assert.Equal(t, wantHash, hash,
		"the reported hash must be the canonical rendering of the PROVEN hash")
	assert.Equal(t, int64(42), height)
	assert.Equal(t, "applied", txLog)
}

// TestBroadcastTxCommit_NonstandardHashPrefixStillBinds pins the shared
// normalization (tx.NormalizeCometHash / tx.CometReportedHashMatches): an
// envelope rendering the CORRECT hash with a nonstandard uppercase "0X" prefix
// is still OUR hash and must bind as proof. The web helper used to re-implement
// the normalization locally with the steps in the opposite order (prefix strip
// before lowercasing), so exactly this rendering read as a different
// transaction here while internal/tx's reconciler accepted it — fail-closed,
// but the two proof surfaces had diverged on the formatting variance the
// normalization exists to absorb. This test fails against that local copy.
func TestBroadcastTxCommit_NonstandardHashPrefixStillBinds(t *testing.T) {
	signed := []byte("bound-with-0X-prefix")
	sum := tx.CometTxHash(signed)
	wantHash := strings.ToUpper(hex.EncodeToString(sum[:]))

	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"0X`+
			wantHash+`","height":"7"}}`)
	}))
	t.Cleanup(rpc.Close)

	hash, height, _, err := broadcastTxCommitWebContext(
		context.Background(), rpc.URL, falseSuccessKey(t), signed)
	require.NoError(t, err,
		"a '0X'-prefixed rendering of OUR hash is a formatting variance, not a different transaction")
	assert.Equal(t, wantHash, hash)
	assert.Equal(t, int64(7), height)
}

// TestBroadcastTxCommit_BoundRejectionsStayDefinitive is the guard on the
// other side of the rejection binding: requiring the hash must not reclassify
// GENUINE rejections as indeterminate, or every ordinary validation failure
// would fence the signing key and turn one refused transaction into an outage
// for that signer. A real CometBFT rejection always carries our hash — the
// node computes it locally from the submitted bytes on every return — so a
// bound CheckTx refusal (height 0) and a bound in-block rejection (positive
// height) must both stay plain, definitive, lease-releasing errors.
//
// NOTE: like its success-side sibling above, this test also passed against the
// superseded implementation — that code adopted every rejection, bound or not.
// It does NOT prove the rejection binding exists; the pinning tests for that
// are the wrong-hash/no-hash rejection cases in
// TestBroadcastTxCommit_FalseSuccessShapesAreIndeterminate. This one exists
// only so the binding can never be "fixed" by reclassifying genuine rejections
// as indeterminate.
func TestBroadcastTxCommit_BoundRejectionsStayDefinitive(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answer  func(w http.ResponseWriter, r *http.Request)
		wantMsg string
	}{
		{
			name: "bound checktx refusal at height zero",
			answer: func(w http.ResponseWriter, r *http.Request) {
				writeCommitCheckTxRejected(w, r, 2, "unauthorized")
			},
			wantMsg: "tx rejected in CheckTx (code 2)",
		},
		{
			name: "bound finalizeblock rejection in its block",
			answer: func(w http.ResponseWriter, r *http.Request) {
				writeCommitTxRejected(w, r, 5, "refused", 12)
			},
			wantMsg: "tx rejected in FinalizeBlock (code 5)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rpc := httptest.NewServer(http.HandlerFunc(tc.answer))
			t.Cleanup(rpc.Close)

			hash, height, txLog, err := broadcastTxCommitWebContext(
				context.Background(), rpc.URL, falseSuccessKey(t), []byte("genuinely-refused"))
			require.Error(t, err)
			assert.False(t, isIndeterminateCommitError(err),
				"a hash-bound consensus rejection is a definitive verdict and must release, not fence: %v", err)
			assert.Contains(t, err.Error(), tc.wantMsg)
			assert.Empty(t, hash)
			assert.Zero(t, height)
			assert.Empty(t, txLog)
		})
	}
}

// TestBroadcastTxCommit_Oversized500BodyIsIndeterminate is the web half of the
// oversized-body hazard on the 500 side (the 200 side is pinned in
// signer_fence_surface_test.go). Before the status check and the body cap, a
// 500 carrying a huge parseable success envelope was fully read, decoded, and
// reported as a committed success — an allocation amplifier AND a false commit
// in one response. It must be indeterminate: fence, re-ask, never trust.
func TestBroadcastTxCommit_Oversized500BodyIsIndeterminate(t *testing.T) {
	signed := []byte("oversized-500-commit-answer")
	sum := tx.CometTxHash(signed)
	boundHash := strings.ToUpper(hex.EncodeToString(sum[:]))
	pad := strings.Repeat("a", int(tx.CometRPCMaxResponseBytes)+(1<<20))

	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, `{"pad":"`+pad+`","result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"`+
			boundHash+`","height":"7"}}`)
	}))
	t.Cleanup(rpc.Close)

	hash, height, txLog, err := broadcastTxCommitWebContext(
		context.Background(), rpc.URL, falseSuccessKey(t), signed)
	require.Error(t, err)
	assert.True(t, isIndeterminateCommitError(err),
		"an oversized 500 proves nothing: it must fence, not succeed and not reject definitively")
	assert.Empty(t, hash)
	assert.Zero(t, height)
	assert.Empty(t, txLog)
}

// TestBroadcastTxCommit_SuccessPathLogIsScrubbed pins B6's blind spot: the
// SUCCESS path. A committed transaction's tx_result.log is exactly as
// remote-controlled as a failed one's — a proxy can append the echoed
// broadcast URL (the whole signed transaction) or terminal control sequences —
// and the success log is the one that flows into activity events and operator
// responses without anyone thinking to check it.
func TestBroadcastTxCommit_SuccessPathLogIsScrubbed(t *testing.T) {
	signed := []byte("committed-with-hostile-log")
	signedHex := hex.EncodeToString(signed)

	hostileLog := "applied; upstream echo GET /broadcast_tx_commit?tx=0x" + signedHex +
		"\rforged-terminal-rewind\x1b[2K\x7f"
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeCommitOKAt(w, r, 42, hostileLog)
	}))
	t.Cleanup(rpc.Close)

	hash, height, txLog, err := broadcastTxCommitWebContext(
		context.Background(), rpc.URL, falseSuccessKey(t), signed)
	require.NoError(t, err, "a proven commit with a hostile log is still a commit")
	assert.NotEmpty(t, hash)
	assert.Equal(t, int64(42), height)
	assert.NotContains(t, strings.ToLower(txLog), signedHex,
		"the success-path log carries the signed transaction's hex")
	assert.Contains(t, txLog, "[redacted",
		"the payload must be visibly redacted, not silently dropped")
	for i := 0; i < len(txLog); i++ {
		if b := txLog[i]; b < 0x20 || b == 0x7f {
			t.Fatalf("the success-path log carries raw control byte %#x at offset %d; any surface "+
				"rendering it is forgeable: %q", b, i, txLog)
		}
	}
}
