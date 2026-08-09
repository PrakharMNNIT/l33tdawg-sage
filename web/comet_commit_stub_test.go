package web

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/l33tdawg/sage/internal/tx"
)

// commitEnvelope renders the /broadcast_tx_commit envelope a real CometBFT
// node returns for the exact bytes submitted in r: the hash is ALWAYS SHA-256
// of those bytes, uppercase — on rejections just as on successes, because a
// real node computes Hash locally from the submitted transaction on every
// return, including CheckTx refusals.
//
// Test stubs used to answer with placeholder hashes ("ABC123", "DENIED"), and
// the production path used to accept them. It no longer accepts them on ANY
// verdict: an envelope whose hash is not bound to the bytes that were sent is
// exactly the stale-proxy / wrong-transaction shape broadcastTxCommitWebContext
// now refuses as indeterminate — success and rejection alike — so a stub faking
// either MUST answer like a real node or the test fences its key instead of
// exercising the verdict it meant to.
func commitEnvelope(r *http.Request, checkCode int, checkLog string, txCode int, txLog string, height int64) string {
	hash := ""
	raw := strings.TrimPrefix(r.URL.Query().Get("tx"), "0x")
	if decoded, err := hex.DecodeString(raw); err == nil {
		sum := tx.CometTxHash(decoded)
		hash = strings.ToUpper(hex.EncodeToString(sum[:]))
	}
	encodedCheckLog, _ := json.Marshal(checkLog)
	encodedTxLog, _ := json.Marshal(txLog)
	return fmt.Sprintf(
		`{"result":{"check_tx":{"code":%d,"log":%s},"tx_result":{"code":%d,"log":%s},"hash":%q,"height":"%d"}}`,
		checkCode, encodedCheckLog, txCode, encodedTxLog, hash, height)
}

// commitEnvelopeOK renders the bound SUCCESS envelope: zero codes, bound hash,
// positive height.
func commitEnvelopeOK(r *http.Request, height int64, txLog string) string {
	return commitEnvelope(r, 0, "", 0, txLog, height)
}

// writeCommitOK answers a commit-broadcast stub request with a bound success
// envelope at an arbitrary fixed height.
func writeCommitOK(w http.ResponseWriter, r *http.Request) {
	writeCommitOKAt(w, r, 42, "")
}

// writeCommitOKAt is writeCommitOK with the height and FinalizeBlock log a
// fixture needs (e.g. reassign fixtures asserting on "purged N grants").
func writeCommitOKAt(w http.ResponseWriter, r *http.Request, height int64, txLog string) {
	_, _ = fmt.Fprint(w, commitEnvelopeOK(r, height, txLog))
}

// writeCommitCheckTxRejected answers with a bound CheckTx refusal: the mempool
// refused admission, so there is no block — height 0 is the shape a real node
// produces here, and the production path accepts it because a CheckTx verdict
// needs only the hash binding.
func writeCommitCheckTxRejected(w http.ResponseWriter, r *http.Request, code int, log string) {
	_, _ = fmt.Fprint(w, commitEnvelope(r, code, log, 0, "", 0))
}

// writeCommitTxRejected answers with a bound in-block (FinalizeBlock)
// rejection. height must be positive: a FinalizeBlock verdict IS inclusion in
// a block, and the production path treats a heightless one as silence.
func writeCommitTxRejected(w http.ResponseWriter, r *http.Request, code int, log string, height int64) {
	_, _ = fmt.Fprint(w, commitEnvelope(r, 0, "", code, log, height))
}
