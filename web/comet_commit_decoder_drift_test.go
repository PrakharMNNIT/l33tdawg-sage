package web

import (
	"context"
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

// A/B COMMIT-DECODER DRIFT CONTRACT
//
// Two independent decoders read the SAME /broadcast_tx_commit envelope:
//
//	A = tx.BroadcastCometCommit          (internal/tx/comet_commit.go)
//	B = broadcastTxCommitWebContext      (web/rbac_signing.go)
//
// They are NOT redundant and must never be merged. A DESCRIBES what a node
// said: a hash-bound non-zero verdict code comes back as a *value* and the
// caller decides what it means. B returns a VERDICT that five handlers act on
// directly: the same envelope comes back as a definitive error, and everything
// short of proof comes back typed indeterminate so the signer fence engages.
// That split is the whole reason both exist.
//
// What they DO share is the HTTP prologue — status, content bounds, JSON
// framing, the JSON-RPC error envelope, structural completeness — and that
// shared region drifted apart once already: web/ formatted the raw error
// envelope while internal/tx scrubbed the identical surface, and the closed
// signed-transaction leak came back at the second origin. Nothing in either
// package's existing tests pins a single prologue message on either side
// (internal/tx/comet_commit_test.go asserts only `err != nil`;
// web/rbac_false_success_test.go asserts only `isIndeterminateCommitError`), so
// a rewording on one side is invisible to CI today. This file is that pin.
//
// It has exactly two kinds of assertion, and the second is as load-bearing as
// the first:
//
//  1. AGREEMENT. For the shapes both decoders classify identically today, the
//     rendered message is pinned as a literal AND compared A-to-B. Rewording
//     either side, or deleting a check from either side, fails here.
//  2. RECORDED DIFFERENCE. For every shape where the two legitimately differ,
//     BOTH strings are pinned as literals. Widening the gap fails (the changed
//     literal). Silently CLOSING the gap also fails (the other literal, plus an
//     explicit NotEqual). These rows are not bugs waiting to be fixed — they
//     are the contract. If a production change deliberately converges a pair,
//     the row must be updated in that same commit, which is precisely the
//     review event this file exists to force.
//
// PACKAGE CHOICE. B is unexported, so a test that drives B through its real
// entry point must live in package web. A is exported and web already depends
// on internal/tx, so package web is the only place BOTH decoders can be driven
// honestly, through their real entry points, with no re-implementation and no
// widening of B's visibility. The cost is that `go test ./internal/tx` alone
// does not run this file; a change to A is caught by `go test ./web`. That is
// the right trade: exporting B, or copying either decoder's branch ladder into
// a helper here, would make the test agree with a copy instead of with the code.
//
// NIL SIGNING KEY. Every call below passes a nil signing key. tx.Register-
// SubmittedTx and tx.ClearSubmittedTx are no-ops for a key that is not
// ed25519.PrivateKeySize (internal/tx/nonce.go:480, :527), so this file
// exercises only the decode/classification path and leaves NOTHING in
// internal/tx's process-global registration map — no fence is raised, so
// fenceResolvingRPC's drain is neither needed nor appropriate here. That the
// classifications actually engage the fence is already covered end to end by
// web/rbac_false_success_test.go, web/signer_fence_surface_test.go and
// internal/tx/comet_commit_test.go, and is deliberately not re-asserted here.
// The same nil-key idiom is already used by both sides' delivery tests
// (internal/tx/comet_commit_test.go:62, web/comet_submit_delivery_test.go:107).

// commitDecoderOutcome is one wire response as seen by BOTH decoders. Their
// return shapes differ on purpose (A hands back a *tx.CometCommitResult it
// makes no judgement about; B hands back the three fields a handler reports),
// so the outcome carries both rather than flattening them into a common shape
// that would quietly assert they are the same kind of answer.
type commitDecoderOutcome struct {
	aResult *tx.CometCommitResult
	aErr    error

	bHash   string
	bHeight int64
	bLog    string
	bErr    error
}

// driveBothCommitDecoders answers A and B from ONE stub, so the comparison is
// against byte-identical wire input rather than two fixtures that merely look
// alike. body receives the request because the bound-hash fixtures
// (commit_commit_stub_test.go's commitEnvelope family) derive the hash from the
// tx=0x bytes actually submitted, and both decoders send the same small-tx GET.
//
// contentType is set verbatim when non-empty; passing "" leaves Go to sniff,
// which is a different case entirely and is exercised on its own below.
func driveBothCommitDecoders(t *testing.T, signed []byte, status int, contentType string, body func(*http.Request) string) commitDecoderOutcome {
	t.Helper()
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
		}
		_, _ = fmt.Fprint(w, body(r))
	}))
	t.Cleanup(rpc.Close)

	var out commitDecoderOutcome
	out.aResult, out.aErr = tx.BroadcastCometCommit(context.Background(), rpc.URL, nil, signed)
	out.bHash, out.bHeight, out.bLog, out.bErr = broadcastTxCommitWebContext(
		context.Background(), rpc.URL, nil, signed)
	return out
}

// staticBody adapts a fixed body to driveBothCommitDecoders' request-aware
// signature for the majority of rows that do not need the submitted bytes.
func staticBody(body string) func(*http.Request) string {
	return func(*http.Request) string { return body }
}

func commitDecoderErrText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestCometCommitDecoderDrift_SharedShapesStayByteIdentical pins the prologue
// region where the two decoders are genuinely one contract expressed twice.
//
// Each row asserts the message TWICE over: as a literal (so rewording either
// side fails, even if both are reworded together) and as an A==B equality (so
// rewording exactly one side fails with a message that names the drift). A row
// also fails if either decoder stops classifying the shape at all, because the
// nil-error case renders as "" and cannot match the literal.
//
// The rows are ordered as the two ladders evaluate them, which is itself part
// of the contract: status, then framing, then the RPC error envelope. Both
// files check them in that order today, and a reordering that moved, say, the
// oversize check above the trailing-data check would change which message a
// body-with-both-faults produces on one side only.
func TestCometCommitDecoderDrift_SharedShapesStayByteIdentical(t *testing.T) {
	signed := []byte("a2a-prologue-contract")
	signedHex := hex.EncodeToString(signed)
	sum := tx.CometTxHash(signed)
	bound := strings.ToUpper(hex.EncodeToString(sum[:]))
	valid := `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` + bound + `","height":"7"}}`

	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{
			// A NON-200 IS NEVER PROOF, on either side, no matter how good the
			// body looks. Both decoders read resp.Status (not just the code)
			// through the same scrubber, so the rendered message is identical
			// down to the reason phrase. Only the Go TYPE differs — B wraps it
			// in commitIndeterminateError — and that wrapper is deliberately
			// message-invisible, which is exactly why a string pin is needed
			// here rather than a type assertion.
			name:   "non-200 with a parseable success body",
			status: 500,
			body:   valid,
			want:   "broadcast tx commit: unexpected status 500 Internal Server Error",
		},
		{
			// Single-document framing. A second value means something between
			// the node and us is concatenating responses; neither decoder may
			// adopt the first one.
			name:   "second empty JSON document",
			status: 200,
			body:   valid + ` {}`,
			want:   "decode broadcast commit response: multiple JSON values",
		},
		{
			name:   "second complete Comet envelope",
			status: 200,
			body:   valid + ` ` + valid,
			want:   "decode broadcast commit response: multiple JSON values",
		},
		{
			// Both decode the TRAILER into &struct{}{} — the same target type
			// — which is why even the substituted stdlib text matches. Change
			// either target and this row diverges immediately.
			name:   "trailing garbage after a complete envelope",
			status: 200,
			body:   valid + ` garbage`,
			want:   "decode broadcast commit response: trailing data: invalid character 'g' looking for beginning of value",
		},
		{
			name:   "trailing JSON array after a complete envelope",
			status: 200,
			body:   valid + ` [1,2]`,
			want:   "decode broadcast commit response: trailing data: json: cannot unmarshal array into Go value of type struct {}",
		},
		{
			// Truncation mid-document. Note this is ALSO how an oversized body
			// cut off mid-document reports on both sides — the oversize branch
			// is reachable only when the document parses cleanly and the reader
			// still drained cap+1 bytes.
			name:   "truncated document",
			status: 200,
			body:   `{"result":`,
			want:   "decode broadcast commit response: unexpected EOF",
		},
		{
			name:   "empty body",
			status: 200,
			body:   ``,
			want:   "decode broadcast commit response: EOF",
		},
		{
			// A proxy's plain-text error page. Both reach the decoder because
			// text/plain is an accepted content type on A's side; the HTML
			// variant is where the two ladders split and is asserted
			// separately.
			name:   "non-JSON prose body",
			status: 200,
			body:   `oops: gateway timeout`,
			want:   "decode broadcast commit response: invalid character 'o' looking for beginning of value",
		},
		{
			name:   "rpc error envelope with data",
			status: 200,
			body:   `{"error":{"message":"request failed","data":"untrusted"}}`,
			want:   "broadcast error: request failed: untrusted",
		},
		{
			name:   "rpc error envelope without data",
			status: 200,
			body:   `{"error":{"message":"request failed"}}`,
			want:   "broadcast error: request failed",
		},
		{
			// THE REGRESSION THIS WHOLE FILE DESCENDS FROM. Message and Data
			// are remote-controlled: a reverse proxy in front of CometBFT can
			// answer 200 with an envelope echoing the request line, which on
			// this endpoint IS the entire signed transaction. web/ once
			// formatted that verbatim while internal/tx scrubbed it. Both must
			// redact, and must redact to the same text — an asymmetry here is
			// how the closed leak returns at one origin only.
			name:   "rpc error envelope echoing the signed transaction",
			status: 200,
			body:   `{"error":{"message":"GET /broadcast_tx_commit?tx=0x` + signedHex + `"}}`,
			want:   "broadcast error: GET /broadcast_tx_commit?tx=0x[redacted signed tx]",
		},
		{
			// The one place the two ladders are structurally different yet
			// observably identical, so it is pinned rather than trusted: A
			// branches on the POST-scrub data (comet_commit.go:285), B on the
			// RAW data (rbac_signing.go:311). They agree only because no
			// scrubbing pass can empty a non-empty string — the control-rune
			// pass maps to a space rather than deleting. A U+0001 data field is
			// the minimal witness: raw non-empty, scrubbed to a single space,
			// so both must take the with-data branch. If scrubbing ever starts
			// trimming, A silently drops to the no-data branch while B does
			// not, and this row is the only thing that notices.
			//
			// The want ends in two spaces: one from the ": " separator, one
			// from the scrubbed control rune.
			name:   "rpc error envelope whose data scrubs to whitespace",
			status: 200,
			body:   `{"error":{"message":"boom","data":"\u0001"}}`,
			want:   "broadcast error: boom:  ",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := driveBothCommitDecoders(t, signed, tc.status, "application/json", staticBody(tc.body))

			require.Error(t, out.aErr, "internal/tx stopped classifying a shape web/ still refuses")
			require.Error(t, out.bErr, "web/ stopped classifying a shape internal/tx still refuses")
			assert.Nil(t, out.aResult, "a refused shape must hand internal/tx's caller no result")
			assert.Empty(t, out.bHash, "a refused shape must hand web/'s caller no hash")
			assert.Zero(t, out.bHeight, "a refused shape must hand web/'s caller no height")
			assert.Empty(t, out.bLog, "a refused shape must hand web/'s caller no log")

			assert.Equal(t, tc.want, out.aErr.Error(),
				"internal/tx reworded a shared prologue message; the two decoders now describe "+
					"the same wire response differently")
			assert.Equal(t, tc.want, out.bErr.Error(),
				"web/ reworded a shared prologue message; the two decoders now describe "+
					"the same wire response differently")
			assert.Equal(t, out.aErr.Error(), out.bErr.Error(),
				"the shared prologue drifted: same bytes, two different messages")

			// B types every prologue refusal indeterminate even with this nil-key
			// fixture. Production A also returns a typed ErrSubmitIndeterminate
			// when given a valid signing key; its exact RegisterSubmittedTx guard
			// deliberately leaves nil-key calls bare. This cross-decoder test
			// therefore asserts B's marker only. A's valid-key typing is pinned in
			// internal/tx/comet_commit_indeterminate_test.go.
			assert.True(t, isIndeterminateCommitError(out.bErr),
				"a prologue refusal proves nothing about the transaction's fate and must stay "+
					"indeterminate so the signer fence engages: %v", out.bErr)
		})
	}
}

// TestCometCommitDecoderDrift_RecordedStringAsymmetries pins the shapes both
// decoders classify with DELIBERATELY different words.
//
// Read this as a ledger, not a defect list. Every pair here is intentional: B
// speaks to an operator through a 502 body, A speaks to an adopter's fence
// logic. What must not happen is silent movement — a reword that makes the two
// converge is as much a signal as one that makes them diverge further, because
// convergence usually means someone "fixed" one side by copying the other and
// took its epistemics along with the text.
//
// Two rows here are structural rather than cosmetic and matter most:
// "CheckTx rejection with the wrong hash" and "FinalizeBlock rejection with a
// bound hash but no height" pin the single largest asymmetry between the two —
// A binds the reported hash ONCE, up front, before any verdict code is read
// (comet_commit.go:295), so an unbound envelope can never reach a code branch;
// B computes `bound` and consults it separately inside each verdict branch
// (rbac_signing.go:352). Moving A's gate below its code reads, or hoisting B's
// above them, changes which message these rows produce.
func TestCometCommitDecoderDrift_RecordedStringAsymmetries(t *testing.T) {
	signed := []byte("a2a-prologue-contract")
	sum := tx.CometTxHash(signed)
	bound := strings.ToUpper(hex.EncodeToString(sum[:]))
	wantPrefix := hex.EncodeToString(sum[:])[:8]

	wrongSum := tx.CometTxHash([]byte("someone-else-entirely"))
	wrongHash := strings.ToUpper(hex.EncodeToString(wrongSum[:]))
	wrongPrefix := hex.EncodeToString(wrongSum[:])[:8]

	valid := `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` + bound + `","height":"7"}}`

	for _, tc := range []struct {
		name  string
		body  string
		wantA string
		wantB string
	}{
		{
			// Same trigger, same cap, same position in the ladder (after the
			// trailing-data check on both sides); B appends a clause naming
			// what it refuses to do. Recorded so that a change to the cap or to
			// the phrasing on one side is visible.
			name:  "oversized body",
			body:  valid + strings.Repeat(" ", tx.CometRPCMaxResponseBytes+1),
			wantA: fmt.Sprintf("broadcast commit response body exceeded %d bytes", tx.CometRPCMaxResponseBytes),
			wantB: fmt.Sprintf("broadcast commit response body exceeded %d bytes; refusing to treat it "+
				"as a CometBFT envelope", tx.CometRPCMaxResponseBytes),
		},
		{
			// A's envelope models result as a POINTER, so "no result at all" is
			// a condition it can name; B's is a VALUE struct, so it can only
			// speak about the nested verdicts. A's message therefore lists
			// `result` and B's does not — a difference in what each decoder is
			// physically able to observe, not a difference in taste.
			name:  "envelope missing both nested verdicts",
			body:  `{"result":{"hash":"` + bound + `","height":"7"}}`,
			wantA: "broadcast commit response omitted result, check_tx, tx_result, or verdict code",
			wantB: "broadcast commit response omitted check_tx, tx_result, or verdict code: " +
				"cannot prove this transaction's fate",
		},
		{
			// The same pair for an explicitly null result. This row exists to
			// record that B CANNOT distinguish `"result":null` from `{}` from a
			// present-but-empty result: its value struct collapses all three
			// into one branch. If B ever grows a *struct here, its message will
			// change and this row will say so.
			name:  "explicitly null result",
			body:  `{"result":null}`,
			wantA: "broadcast commit response omitted result, check_tx, tx_result, or verdict code",
			wantB: "broadcast commit response omitted check_tx, tx_result, or verdict code: " +
				"cannot prove this transaction's fate",
		},
		{
			// The replayed-proxy success. Both refuse; A phrases it as "a
			// different transaction" through the shared fence diagnostic
			// (cometHashMismatchDetail), B as "does not match the transaction
			// sent". Both render `want` and `got` through the SAME exported
			// helpers, so the two eight-character prefixes must agree even
			// though the sentences do not — that shared rendering is asserted
			// implicitly by both literals carrying identical prefixes.
			name: "success envelope about a different transaction",
			body: `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` + wrongHash + `","height":"7"}}`,
			wantA: "broadcast commit answered about a different transaction (want " + wantPrefix +
				"…, got " + wrongPrefix + "…): not proof of this one's fate",
			wantB: "broadcast commit response hash does not match the transaction sent (want " +
				wantPrefix + "…, got " + wrongPrefix + "…)",
		},
		{
			// An absent hash is its own shape in B and folds into the single
			// hash gate in A, where HexHashPrefix renders the empty value as
			// "(no hex characters)". Two different decompositions of the same
			// fact; both must keep refusing it.
			name:  "success envelope carrying no hash",
			body:  `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"","height":"7"}}`,
			wantA: "broadcast commit answered about a different transaction (want " + wantPrefix + "…, got (no hex characters)…): not proof of this one's fate",
			wantB: "broadcast commit response carried no transaction hash: cannot prove this transaction committed",
		},
		{
			// SUB-DIVERGENCE IN THE `got` RENDERING, and the only row where the
			// two prefixes legitimately differ. A passes the RAW reported hash
			// to HexHashPrefix; B passes the already-NormalizeCometHash'd
			// value, and NormalizeCometHash strips exactly one 0x prefix. So a
			// doubly-prefixed hash renders as 0abcd123 for A (the surviving
			// "0" of the second prefix, then the hex) and abcd1234 for B.
			//
			// Recorded rather than fixed: both are honest hex-filtered prefixes
			// of remote text, neither is used for comparison (the binding
			// predicate is shared and normalizes identically on both sides),
			// and pinning it is how a future change to either the normalizer or
			// to which value gets handed to the renderer becomes visible.
			name:  "doubly 0x-prefixed hash renders differently on each side",
			body:  `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"0x0xABCD1234","height":"7"}}`,
			wantA: "broadcast commit answered about a different transaction (want " + wantPrefix + "…, got 0abcd123…): not proof of this one's fate",
			wantB: "broadcast commit response hash does not match the transaction sent (want " + wantPrefix + "…, got abcd1234…)",
		},
		{
			// Bound hash, zero codes, no block. Same refusal, different words;
			// B's names what it cannot prove because its string reaches an
			// operator.
			name:  "bound success envelope at height zero",
			body:  `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` + bound + `","height":"0"}}`,
			wantA: "broadcast commit response reported no committed height",
			wantB: "broadcast commit response reported no block height: cannot prove this transaction committed",
		},
		{
			// STRUCTURAL. A's hash gate runs before any code is read, so this
			// replayed CheckTx refusal is refused as a hash mismatch and A never
			// learns there was a rejection in it at all. B reaches its CheckTx
			// branch first and refuses it there, with a message that names the
			// rejection. Same safety outcome by two different routes — and the
			// route is the thing being pinned. If A's gate ever moved below the
			// code reads, A would adopt someone else's refusal as definitive,
			// clear the registration, and release the lease over bytes still in
			// flight: the exact silent Code 4 loss both files exist to prevent.
			name: "CheckTx rejection about a different transaction",
			body: `{"result":{"check_tx":{"code":2,"log":"unauthorized"},"tx_result":{"code":0},"hash":"` + wrongHash + `","height":"0"}}`,
			wantA: "broadcast commit answered about a different transaction (want " + wantPrefix +
				"…, got " + wrongPrefix + "…): not proof of this one's fate",
			wantB: "broadcast commit response reported a CheckTx rejection for a different transaction (want " +
				wantPrefix + "…, got " + wrongPrefix + "…): not proof of this one's fate",
		},
		{
			// STRUCTURAL, the other direction. Bound hash, so A gets past its
			// gate, sees checkCode == 0, and refuses on the missing height with
			// its generic no-height message — it never reaches the FinalizeBlock
			// code. B folds the binding and the height into one predicate
			// inside the FinalizeBlock branch and reports both facts. A
			// FinalizeBlock verdict IS inclusion in a block, so height 0 is a
			// shape no real node produces; both must refuse it, and each does so
			// from a different position in its ladder.
			name:  "FinalizeBlock rejection with a bound hash but no block height",
			body:  `{"result":{"check_tx":{"code":0},"tx_result":{"code":5,"log":"refused"},"hash":"` + bound + `","height":"0"}}`,
			wantA: "broadcast commit response reported no committed height",
			wantB: "broadcast commit response reported a FinalizeBlock rejection that is not bound to this " +
				"transaction (hash match true, height 0): not proof of its fate",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := driveBothCommitDecoders(t, signed, http.StatusOK, "application/json", staticBody(tc.body))

			require.Error(t, out.aErr, "internal/tx stopped refusing a shape it must still refuse")
			require.Error(t, out.bErr, "web/ stopped refusing a shape it must still refuse")
			assert.Nil(t, out.aResult)
			assert.Empty(t, out.bHash)
			assert.Zero(t, out.bHeight)

			assert.Equal(t, tc.wantA, out.aErr.Error(),
				"internal/tx's half of a RECORDED difference moved. If this was intentional, update "+
					"this row in the same commit; if it was a copy from web/, the two decoders are "+
					"being merged and must not be")
			assert.Equal(t, tc.wantB, out.bErr.Error(),
				"web/'s half of a RECORDED difference moved. If this was intentional, update this row "+
					"in the same commit; if it was a copy from internal/tx, the two decoders are being "+
					"merged and must not be")
			assert.NotEqual(t, out.aErr.Error(), out.bErr.Error(),
				"these two messages are deliberately different — they became identical, which means "+
					"one decoder's wording (and possibly its epistemics) was pulled into the other")

			assert.True(t, isIndeterminateCommitError(out.bErr),
				"an unproven commit must stay indeterminate on web/'s side so the fence engages: %v", out.bErr)
		})
	}
}

// TestCometCommitDecoderDrift_EnvelopeTypeDivergenceIsRecorded pins the drift
// that lives in the STRUCT DEFINITIONS rather than in any branch: identical
// bytes on the wire, and one decoder errors where the other succeeds.
//
//	A: Height tx.CometHeight  (JSON string OR number, rejects null)
//	   Code   *uint32         (rejects negatives and >2^32-1 at decode)
//	B: Height int64 `json:"height,string"` (JSON string ONLY, tolerates null)
//	   Code   *int            (accepts both)
//
// None of these are currently reachable from a real CometBFT node, which always
// quotes height and always reports codes in uint32 range. They are reachable
// from a proxy, a mock, or a future node version — and the point of pinning
// them is that the decoders' TOLERANCE for each other's inputs is a real
// property that must not shift unnoticed. If someone "aligns" B's height tag to
// accept numbers, the numeric row's wantB stops being an error and this test
// says so; the fix is to decide whether A and B should converge here and record
// it, not to let CI stay silent.
func TestCometCommitDecoderDrift_EnvelopeTypeDivergenceIsRecorded(t *testing.T) {
	signed := []byte("a2a-prologue-contract")
	sum := tx.CometTxHash(signed)
	bound := strings.ToUpper(hex.EncodeToString(sum[:]))

	for _, tc := range []struct {
		name string
		body string
		// wantAErr == "" means A must SUCCEED; wantAHeight is then checked.
		wantAErr    string
		wantAHeight int64
		// wantBErr is always non-empty here: every row is a shape B refuses,
		// though not always at the same stage as A.
		wantBErr string
		// bDefinitive marks the one row where B's refusal is a real consensus
		// verdict rather than "we cannot tell" — it must NOT fence.
		bDefinitive bool
	}{
		{
			// A accepts an unquoted height because tx.CometHeight takes either
			// encoding; B's ,string tag refuses it before any verdict is read.
			// Not a defect on either side: A widened deliberately for adopters
			// whose proxy re-serializes, B stayed narrow. It is a divergence in
			// what counts as a well-formed envelope, so it is recorded.
			name:        "unquoted numeric height",
			body:        `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` + bound + `","height":7}}`,
			wantAErr:    "",
			wantAHeight: 7,
			wantBErr: "decode broadcast commit response: json: invalid use of ,string struct tag, " +
				"trying to unmarshal unquoted value into int64",
		},
		{
			// The mirror image, and the more interesting one: a null height is
			// a DECODE failure for A and decodes cleanly to 0 for B, which then
			// refuses it two branches later on the height check. Same final
			// safety outcome, reached at completely different points in the
			// ladder — which is why the messages are pinned rather than a
			// shared "both errored" assertion.
			name:     "explicitly null height",
			body:     `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` + bound + `","height":null}}`,
			wantAErr: `decode broadcast commit response: decode Comet height "null": strconv.ParseInt: parsing "null": invalid syntax`,
			wantBErr: "broadcast commit response reported no block height: cannot prove this transaction committed",
		},
		{
			// THE SHARPEST ROW. A's *uint32 makes a negative code a decode
			// failure — an unreadable answer, so production A returns a typed
			// indeterminate error and leaves the registration live as an
			// independent backstop. B's *int accepts -1 as a genuine rejection
			// code and returns a DEFINITIVE error that retires the
			// registration. Identical bytes, opposite consequences for the
			// signing key.
			//
			// This is recorded, not reconciled, because the two are answering
			// different questions: A is asked "is this a well-formed CometBFT
			// envelope", B is asked "what do I tell the operator". But it is
			// exactly the kind of asymmetry that should never move by accident,
			// because tightening B here would turn ordinary rejections into
			// fences and loosening A would let a malformed envelope through.
			name:        "negative CheckTx code",
			body:        `{"result":{"check_tx":{"code":-1,"log":"denied"},"tx_result":{"code":0},"hash":"` + bound + `","height":"7"}}`,
			wantAErr:    "decode broadcast commit response: json: cannot unmarshal number -1 into Go struct field .result.check_tx.code of type uint32",
			wantBErr:    "tx rejected in CheckTx (code -1): denied",
			bDefinitive: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := driveBothCommitDecoders(t, signed, http.StatusOK, "application/json", staticBody(tc.body))

			if tc.wantAErr == "" {
				require.NoError(t, out.aErr,
					"internal/tx stopped accepting an envelope encoding it deliberately tolerates")
				require.NotNil(t, out.aResult)
				assert.Equal(t, tc.wantAHeight, out.aResult.Height)
				assert.Equal(t, bound, out.aResult.Hash,
					"the returned hash must be the locally derived one, never the reported field")
			} else {
				require.Error(t, out.aErr,
					"internal/tx started accepting an envelope encoding it deliberately refuses")
				assert.Nil(t, out.aResult)
				assert.Equal(t, tc.wantAErr, commitDecoderErrText(out.aErr),
					"internal/tx's envelope tolerance changed; A and B now disagree differently about "+
						"the same bytes than this row records")
			}

			require.Error(t, out.bErr, "web/ started accepting an envelope encoding it refuses today")
			assert.Empty(t, out.bHash)
			assert.Zero(t, out.bHeight)
			assert.Equal(t, tc.wantBErr, commitDecoderErrText(out.bErr),
				"web/'s envelope tolerance changed; A and B now disagree differently about the same "+
					"bytes than this row records")

			assert.Equal(t, !tc.bDefinitive, isIndeterminateCommitError(out.bErr),
				"web/ changed whether this shape fences the signing key, which is a far larger change "+
					"than the message it reports: %v", out.bErr)
		})
	}
}

// TestCometCommitDecoderDrift_ContentTypeValidationIsDecoderAOnly records the
// single asymmetry that can flip the OUTCOME rather than just the wording.
//
// A calls validateCometJSONResponse (comet_commit.go:262): an empty
// Content-Type passes for older proxies, application/json and text/plain pass,
// and everything else — including an unparseable header — is refused before the
// body is touched. B has no counterpart anywhere: `mime` is not imported by any
// file in web/, and mime.ParseMediaType occurs exactly once in the repo.
//
// So for one class of response — an HTTP 200 carrying a perfectly valid,
// hash-bound, positive-height commit envelope under a non-JSON Content-Type — A
// errors and fences while B reports a SUCCESSFUL COMMIT. That is asserted here
// literally, including B's success, because pretending otherwise would make the
// test a wish rather than a record.
//
// If this test starts failing because B grew a content-type check, that is a
// deliberate production change and this file must be updated in the same
// commit. If it starts failing because A's check was removed or loosened, that
// is a regression: A's gate is what stops an intermediary's HTML error page
// served at 200 from being handed to a JSON decoder in the first place.
func TestCometCommitDecoderDrift_ContentTypeValidationIsDecoderAOnly(t *testing.T) {
	signed := []byte("a2a-prologue-contract")
	sum := tx.CometTxHash(signed)
	bound := strings.ToUpper(hex.EncodeToString(sum[:]))
	valid := `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` + bound + `","height":"7"}}`

	for _, tc := range []struct {
		name        string
		contentType string
		body        string
		wantAErr    string
		// wantBErr == "" means B must return a SUCCESSFUL commit for these bytes.
		wantBErr string
	}{
		{
			// THE OUTCOME FLIP. Same bytes, same status: A refuses, B commits.
			name:        "valid envelope served as text/html",
			contentType: "text/html; charset=utf-8",
			body:        valid,
			wantAErr:    `broadcast tx commit: comet RPC returned non-JSON content type "text/html; charset=utf-8"`,
			wantBErr:    "",
		},
		{
			// An unparseable header is refused by A on the ParseMediaType error
			// leg, not the media-type comparison. B never looks.
			name:        "valid envelope served under an unparseable content type",
			contentType: "application/json;;",
			body:        valid,
			wantAErr:    `broadcast tx commit: comet RPC returned non-JSON content type "application/json;;"`,
			wantBErr:    "",
		},
		{
			// The common case: an intermediary's HTML error page at 200. Both
			// refuse — but as DIFFERENT SHAPES, which is the observable
			// consequence of the missing gate. A never reads the body; B
			// reports a JSON syntax error. Recorded so that a change to either
			// ladder that made these converge is visible.
			name:        "html error page served as text/html",
			contentType: "text/html; charset=utf-8",
			body:        `<html>oops</html>`,
			wantAErr:    `broadcast tx commit: comet RPC returned non-JSON content type "text/html; charset=utf-8"`,
			wantBErr:    "decode broadcast commit response: invalid character '<' looking for beginning of value",
		},
		{
			// CONTROL ROW. With the header a real node sends, the gate is
			// invisible and both decoders commit the same transaction. Without
			// this row a change that made A refuse EVERYTHING would still pass
			// the rows above.
			name:        "valid envelope served as application/json",
			contentType: "application/json",
			body:        valid,
			wantAErr:    "",
			wantBErr:    "",
		},
		{
			// Empty Content-Type is explicitly tolerated by A for older
			// Comet/proxy deployments, so this must also commit on both sides.
			// (Go's httptest sniffs a JSON body to text/plain when the handler
			// sets nothing, which A also accepts — hence the header is cleared
			// here by serving a body Go sniffs as text/plain either way; the
			// assertion is that A does not refuse it.)
			name:        "valid envelope with a sniffed content type",
			contentType: "",
			body:        valid,
			wantAErr:    "",
			wantBErr:    "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := driveBothCommitDecoders(t, signed, http.StatusOK, tc.contentType, staticBody(tc.body))

			if tc.wantAErr == "" {
				require.NoError(t, out.aErr, "internal/tx refused a content type it must accept")
				require.NotNil(t, out.aResult)
				assert.Equal(t, bound, out.aResult.Hash)
				assert.Equal(t, int64(7), out.aResult.Height)
			} else {
				require.Error(t, out.aErr,
					"internal/tx's content-type gate is gone; an intermediary's non-JSON page at 200 "+
						"now reaches the JSON decoder")
				assert.Nil(t, out.aResult)
				assert.Equal(t, tc.wantAErr, out.aErr.Error())
			}

			if tc.wantBErr == "" {
				require.NoError(t, out.bErr,
					"web/ grew a content-type check. That may be the right change, but it closes a "+
						"RECORDED gap between the two decoders and this row must be updated with it")
				assert.Equal(t, bound, out.bHash)
				assert.Equal(t, int64(7), out.bHeight)
			} else {
				require.Error(t, out.bErr)
				assert.Equal(t, tc.wantBErr, out.bErr.Error())
				assert.Empty(t, out.bHash)
			}
		})
	}
}

// TestCometCommitDecoderDrift_TransportCauseVocabulariesStayDisjoint pins the
// prologue's other recorded difference: both decoders classify a transport
// failure by TYPE, in the same order, from the same shared transport
// (tx.DoCometSubmission) — and then render the result through two vocabularies
// that share no word.
//
//	classifyFenceCause  -> "timeout" | "canceled" | "transport" | "decode" | "rpc"
//	commitTransportCause-> "timed out waiting for commit" | "the request was canceled" |
//	                       "the connection to the node failed" | "the request to the node failed"
//
// This is deliberate and must stay: A's value is a typed fenceCause that drives
// fence logic, B's is prose for an operator-facing 502. The danger is not the
// difference, it is that both messages carry the IDENTICAL prefix
// "broadcast tx commit: " that the non-200 shape also uses — so anything
// downstream matching on that prefix cannot tell a status from a transport
// failure, and a reword on one side is undetectable without a pin like this.
//
// Only the two deterministic buckets are driven here (deadline, cancel). The
// "connection failed" bucket is exercised through the reset-before-headers
// case; A's `decode` bucket has no counterpart in B at all and is unreachable
// from Do in practice (net/http returns *url.Error, which satisfies net.Error,
// and the net check runs first on both sides), so it is deliberately not
// asserted — see the report accompanying this file.
func TestCometCommitDecoderDrift_TransportCauseVocabulariesStayDisjoint(t *testing.T) {
	signed := []byte("a2a-prologue-transport")

	t.Run("expired deadline", func(t *testing.T) {
		rpc := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done() // never answer; let the client's deadline decide
		}))
		t.Cleanup(rpc.Close)

		ctxA, cancelA := context.WithTimeout(context.Background(), 75*time.Millisecond)
		defer cancelA()
		_, aErr := tx.BroadcastCometCommit(ctxA, rpc.URL, nil, signed)

		ctxB, cancelB := context.WithTimeout(context.Background(), 75*time.Millisecond)
		defer cancelB()
		_, _, _, bErr := broadcastTxCommitWebContext(ctxB, rpc.URL, nil, signed)

		require.Error(t, aErr)
		require.Error(t, bErr)
		assert.Equal(t, "broadcast tx commit: timeout", aErr.Error(),
			"internal/tx's fence cause vocabulary moved; the fence records this category, not this text")
		assert.Equal(t, "broadcast tx commit: timed out waiting for commit", bErr.Error(),
			"web/'s operator-facing transport vocabulary moved")
		assert.NotEqual(t, aErr.Error(), bErr.Error(),
			"the two transport vocabularies are deliberately disjoint")
		assert.True(t, isIndeterminateCommitError(bErr),
			"a timed-out commit may already be in a block: indeterminate, so the fence holds")
	})

	t.Run("caller canceled", func(t *testing.T) {
		rpc := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		t.Cleanup(rpc.Close)

		// Canceled BEFORE the call, so Do fails immediately and both sides take
		// the context.Canceled leg that precedes their net.Error check.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, aErr := tx.BroadcastCometCommit(ctx, rpc.URL, nil, signed)
		_, _, _, bErr := broadcastTxCommitWebContext(ctx, rpc.URL, nil, signed)

		require.Error(t, aErr)
		require.Error(t, bErr)
		assert.Equal(t, "broadcast tx commit: canceled", aErr.Error())
		assert.Equal(t, "broadcast tx commit: the request was canceled", bErr.Error())
		assert.NotEqual(t, aErr.Error(), bErr.Error())
		assert.True(t, isIndeterminateCommitError(bErr),
			"a closed browser tab is not proof the node refused the transaction")
	})

	t.Run("connection reset before response headers", func(t *testing.T) {
		// Reuses web/comet_submit_delivery_test.go's raw HTTP/1.1 node, the one
		// fault httptest cannot express: the request is read IN FULL and then
		// the connection is reset before any status line. This is the most
		// dangerous transport shape — the bytes are already at the node — and
		// it is the bucket both decoders label most differently.
		node := newKillableWebCometNode(t)
		node.killTx.Store(hex.EncodeToString(signed))

		_, aErr := tx.BroadcastCometCommit(context.Background(), node.url(), nil, signed)
		_, _, _, bErr := broadcastTxCommitWebContext(context.Background(), node.url(), nil, signed)

		require.Error(t, aErr, "a submission whose response never arrived reported success")
		require.Error(t, bErr, "a submission whose response never arrived reported success")
		assert.Equal(t, "broadcast tx commit: transport", aErr.Error())
		assert.Equal(t, "broadcast tx commit: the connection to the node failed", bErr.Error())
		assert.NotEqual(t, aErr.Error(), bErr.Error())
		assert.True(t, isIndeterminateCommitError(bErr),
			"the bytes reached the kernel; a broken connection is the case the fence exists for")

		// Neither message may carry the request URL — which on this endpoint is
		// the entire signed transaction. Both sides refuse %w here for exactly
		// this reason, and this is the assertion that keeps it true when
		// somebody "improves" the error by wrapping the cause.
		for _, err := range []error{aErr, bErr} {
			assert.NotContains(t, err.Error(), hex.EncodeToString(signed),
				"the signed transaction leaked into a transport error")
			assert.NotContains(t, err.Error(), "tx=0x",
				"the broadcast URL leaked into a transport error")
		}
	})
}

// TestCometCommitDecoderDrift_SelfImposedDeadlineIsDecoderBOnly records that B
// bounds its own wait and A does not.
//
// B applies rbacCommitTimeout() (60s default, SAGE_TX_COMMIT_TIMEOUT_MS) on top
// of the caller's context, because a closed browser tab must not leave a server
// goroutine parked. A takes the caller's context unmodified and its client sets
// no Timeout at all, deliberately: broadcast_tx_commit legitimately blocks until
// the transaction is in a block, and a client-level deadline there would cap it
// silently for every adopter.
//
// The consequence, and the thing being pinned: B can MANUFACTURE the
// DeadlineExceeded transport shape — and therefore a fence — on a response A is
// still patiently waiting for. Giving A a default timeout, or removing B's,
// would change which of the two fences first on a slow single-validator commit,
// and neither change would be visible in any existing test.
func TestCometCommitDecoderDrift_SelfImposedDeadlineIsDecoderBOnly(t *testing.T) {
	t.Setenv("SAGE_TX_COMMIT_TIMEOUT_MS", "150")
	signed := []byte("a2a-prologue-self-deadline")

	rpc := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(rpc.Close)

	// A is given a context with NO deadline. It must still be blocked when B has
	// already given up.
	aCtx, cancelA := context.WithCancel(context.Background())
	aDone := make(chan error, 1)
	go func() {
		_, err := tx.BroadcastCometCommit(aCtx, rpc.URL, nil, signed)
		aDone <- err
	}()

	_, _, _, bErr := broadcastTxCommitWebContext(context.Background(), rpc.URL, nil, signed)
	require.Error(t, bErr, "web/'s self-imposed commit deadline no longer fires")
	assert.Equal(t, "broadcast tx commit: timed out waiting for commit", bErr.Error(),
		"web/ stopped bounding its own wait, or reworded the bucket it lands in")
	assert.True(t, isIndeterminateCommitError(bErr),
		"giving up waiting is not proof the node refused: indeterminate, so the fence holds")

	select {
	case err := <-aDone:
		t.Fatalf("internal/tx returned %v while its caller's context was still live: it has acquired "+
			"a deadline of its own, which silently caps broadcast_tx_commit for every adopter", err)
	case <-time.After(300 * time.Millisecond):
	}

	cancelA()
	select {
	case <-aDone:
	case <-time.After(10 * time.Second):
		t.Fatal("internal/tx did not unblock after its caller's context was canceled")
	}
}

// TestCometCommitDecoderDrift_VerdictContractsStayDeliberatelySplit is the
// guard against the wrong fix.
//
// Everything above pins the region where the two decoders are one contract. This
// pins the region where they are TWO, and where a well-meaning "let's share the
// decoder" refactor would do real damage in either direction:
//
//   - Make A return an error for a hash-bound rejection and every adopter that
//     reads a CheckTx code off the result loses it — A exists to DESCRIBE.
//   - Make B return a value for one and the five handlers that dispatch on
//     isIndeterminateCommitError silently start treating a consensus rejection
//     as a success — B exists to VERDICT.
//
// The single point where they MUST agree is asserted last: on a real success,
// both return the LOCALLY derived uppercase hash and the same height. Neither
// echoes result.hash, so a proxy's formatting never reaches a caller.
//
// Fixtures come from web/comet_commit_stub_test.go's commitEnvelope family
// rather than hand-rolled bodies: it derives the hash from the tx=0x bytes on
// the request, exactly as a real node computes it locally on EVERY return,
// including refusals. A placeholder hash here would fence instead of exercising
// the verdict.
func TestCometCommitDecoderDrift_VerdictContractsStayDeliberatelySplit(t *testing.T) {
	signed := []byte("a2a-verdict-contract")
	sum := tx.CometTxHash(signed)
	bound := strings.ToUpper(hex.EncodeToString(sum[:]))

	t.Run("hash-bound CheckTx rejection", func(t *testing.T) {
		out := driveBothCommitDecoders(t, signed, http.StatusOK, "application/json",
			func(r *http.Request) string { return commitEnvelope(r, 2, "unauthorized", 0, "", 0) })

		// A DESCRIBES: no error, the codes handed to the caller verbatim. Note
		// the height is 0 and A does not care — a CheckTx refusal never reached
		// a block, and A's no-height check is reached only when checkCode == 0.
		require.NoError(t, out.aErr,
			"internal/tx turned a hash-bound CheckTx rejection into an error. That is web/'s "+
				"contract, not A's: adopters read the code off the result")
		require.NotNil(t, out.aResult)
		assert.Equal(t, uint32(2), out.aResult.CheckTxCode)
		assert.Equal(t, "unauthorized", out.aResult.CheckTxLog)
		assert.Equal(t, bound, out.aResult.Hash)

		// B VERDICTS: a definitive error the handlers may act on, explicitly NOT
		// indeterminate — marking it so would fence the signing key on every
		// ordinary validation failure.
		require.Error(t, out.bErr,
			"web/ stopped reporting a hash-bound CheckTx rejection as a failure; five handlers "+
				"would now treat a refused transaction as applied")
		assert.Equal(t, "tx rejected in CheckTx (code 2): unauthorized", out.bErr.Error())
		assert.False(t, isIndeterminateCommitError(out.bErr),
			"a bound rejection IS proof of this transaction's fate; fencing on it would trap the key")
		assert.Empty(t, out.bHash)
		assert.Zero(t, out.bHeight)
	})

	t.Run("hash-bound FinalizeBlock rejection in a block", func(t *testing.T) {
		out := driveBothCommitDecoders(t, signed, http.StatusOK, "application/json",
			func(r *http.Request) string { return commitEnvelope(r, 0, "", 5, "refused", 12) })

		require.NoError(t, out.aErr,
			"internal/tx turned a hash-bound in-block rejection into an error")
		require.NotNil(t, out.aResult)
		assert.Equal(t, uint32(5), out.aResult.TxResultCode)
		assert.Equal(t, "refused", out.aResult.TxResultLog)
		assert.Equal(t, int64(12), out.aResult.Height)

		require.Error(t, out.bErr, "web/ stopped reporting an in-block rejection as a failure")
		assert.Equal(t, "tx rejected in FinalizeBlock (code 5): refused", out.bErr.Error())
		assert.False(t, isIndeterminateCommitError(out.bErr),
			"an in-block rejection is fully decided; nothing is in flight to fence")
	})

	t.Run("full success is the one answer both must agree on", func(t *testing.T) {
		out := driveBothCommitDecoders(t, signed, http.StatusOK, "application/json",
			func(r *http.Request) string { return commitEnvelopeOK(r, 12, "applied") })

		require.NoError(t, out.aErr)
		require.NotNil(t, out.aResult)
		require.NoError(t, out.bErr)

		assert.Equal(t, bound, out.aResult.Hash)
		assert.Equal(t, bound, out.bHash)
		assert.Equal(t, out.aResult.Hash, out.bHash,
			"the two decoders returned different hashes for the same committed transaction")
		assert.Equal(t, out.aResult.Height, out.bHeight,
			"the two decoders returned different heights for the same committed transaction")
		assert.Equal(t, out.aResult.TxResultLog, out.bLog,
			"both must hand back the SCRUBBED FinalizeBlock log; a committed transaction's log is "+
				"exactly as remote-controlled as a failed one's")
		assert.Equal(t, int64(12), out.bHeight)
		assert.Equal(t, "applied", out.bLog)
	})
}

// TestCometCommitDecoderDrift_RemoteLogsAreScrubbedByBoth pins the
// ScrubBroadcastText call sites that carry node-supplied logs back to callers.
// The other log fixtures in this file are scrub-invariant, so this witness
// deliberately embeds the signed transaction in the shape a reverse proxy can
// echo from a broadcast request line.
func TestCometCommitDecoderDrift_RemoteLogsAreScrubbedByBoth(t *testing.T) {
	signed := []byte("a2a-log-scrub-witness")
	leakedHex := hex.EncodeToString(signed)
	leak := "upstream refused: GET /broadcast_tx_commit?tx=0x" + leakedHex

	assertNoLeak := func(t *testing.T, where, got string) {
		t.Helper()
		assert.NotContains(t, got, leakedHex,
			where+" handed back a node-supplied log containing the signed transaction verbatim")
		assert.NotContains(t, strings.ToUpper(got), strings.ToUpper(leakedHex),
			where+" leaked the signed transaction in a different hex case")
	}

	t.Run("CheckTx refusal log", func(t *testing.T) {
		out := driveBothCommitDecoders(t, signed, http.StatusOK, "application/json",
			func(r *http.Request) string { return commitEnvelope(r, 2, leak, 0, "", 0) })

		require.NoError(t, out.aErr)
		require.NotNil(t, out.aResult)
		assertNoLeak(t, "internal/tx CheckTxLog", out.aResult.CheckTxLog)

		require.Error(t, out.bErr)
		assertNoLeak(t, "web CheckTx refusal error", out.bErr.Error())
	})

	t.Run("FinalizeBlock refusal log", func(t *testing.T) {
		out := driveBothCommitDecoders(t, signed, http.StatusOK, "application/json",
			func(r *http.Request) string { return commitEnvelope(r, 0, "", 5, leak, 12) })

		require.NoError(t, out.aErr)
		require.NotNil(t, out.aResult)
		assertNoLeak(t, "internal/tx TxResultLog", out.aResult.TxResultLog)

		require.Error(t, out.bErr)
		assertNoLeak(t, "web FinalizeBlock refusal error", out.bErr.Error())
	})

	t.Run("success log is exactly as remote-controlled as a failure log", func(t *testing.T) {
		out := driveBothCommitDecoders(t, signed, http.StatusOK, "application/json",
			func(r *http.Request) string { return commitEnvelopeOK(r, 12, leak) })

		require.NoError(t, out.aErr)
		require.NotNil(t, out.aResult)
		require.NoError(t, out.bErr)
		assertNoLeak(t, "internal/tx TxResultLog on success", out.aResult.TxResultLog)
		assertNoLeak(t, "web success log", out.bLog)
		assert.Equal(t, out.aResult.TxResultLog, out.bLog,
			"the two decoders scrubbed the same node-supplied log differently")
	})
}

// TestCometCommitDecoderDrift_AbsentContentTypeIsToleratedByA reaches the
// backward-compatibility leg that an empty Header value cannot exercise: Go
// otherwise sniffs the JSON body as text/plain. Decoder A deliberately accepts
// a genuinely absent Content-Type while decoder B does not inspect the header.
func TestCometCommitDecoderDrift_AbsentContentTypeIsToleratedByA(t *testing.T) {
	signed := []byte("a2a-absent-content-type")
	sum := tx.CometTxHash(signed)
	bound := strings.ToUpper(hex.EncodeToString(sum[:]))

	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Content-Type"] = nil
		_, _ = fmt.Fprint(w, commitEnvelopeOK(r, 9, "applied"))
	}))
	t.Cleanup(rpc.Close)

	resp, err := http.Get(rpc.URL) //nolint:noctx // probe: prove the header really is absent
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Empty(t, resp.Header.Get("Content-Type"),
		"the test requires a response with no Content-Type; Go sniffed one instead")

	aResult, aErr := tx.BroadcastCometCommit(context.Background(), rpc.URL, nil, signed)
	require.NoError(t, aErr,
		"internal/tx refused a response with no Content-Type despite its compatibility contract")
	require.NotNil(t, aResult)
	assert.Equal(t, bound, aResult.Hash)
	assert.Equal(t, int64(9), aResult.Height)
}
