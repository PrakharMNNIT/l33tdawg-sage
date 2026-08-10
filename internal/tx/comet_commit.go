package tx

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// CometCommitResult is a hash-bound, structurally complete CometBFT
// /broadcast_tx_commit result. It is returned only after the response proves it
// describes encoded and, for an in-block verdict, names a positive height.
type CometCommitResult struct {
	Hash         string
	Height       int64
	CheckTxCode  uint32
	CheckTxLog   string
	TxResultCode uint32
	TxResultLog  string
}

type CometSyncResult struct {
	Hash        string
	CheckTxCode uint32
	CheckTxLog  string
}

type strictCommitEnvelope struct {
	Result *struct {
		CheckTx *struct {
			Code *uint32 `json:"code"`
			Log  string  `json:"log"`
		} `json:"check_tx"`
		TxResult *struct {
			Code *uint32 `json:"code"`
			Log  string  `json:"log"`
		} `json:"tx_result"`
		Hash   string `json:"hash"`
		Height int64  `json:"height,string"`
	} `json:"result"`
	Error *struct {
		Message string `json:"message"`
		Data    string `json:"data"`
	} `json:"error"`
}

// indeterminateBroadcast returns the wrapper used for every outcome that
// cannot prove where the transaction ended up.
//
// WHY THIS EXISTS AS A TYPE RATHER THAN A SIDE EFFECT. Registration goes live
// one line before http.Do, so historically an unwrapped error still fenced:
// WithNonceLease's registration backstop (nonce.go:402-413) picks up any live
// registration when submit returns non-nil. That backstop is real and stays,
// but it is POSITIONAL — it holds only because of where RegisterSubmittedTx
// sits and because every caller propagates the error unchanged. Both are
// assumptions a future edit can break silently, and trusting callers to
// propagate is exactly what failed in the federation P0 this fence was built
// for. Typing the error makes the guarantee structural: errors.Is(err,
// ErrSubmitIndeterminate) is true at the point the ambiguity arises, whether or
// not a registration happens to be live.
//
// WHY IT REFUSES THE SAME INPUTS AS RegisterSubmittedTx, EXACTLY. The guard
// below mirrors nonce.go:480 in BOTH of its halves, and both halves are
// load-bearing:
//
//   - len(encoded) == 0: Indeterminate would happily wrap zero bytes, but
//     fenceSubmission then records no tx hash and no nonce, and reconciliation
//     dead-ends on errNoEncodedTx forever. That is a fence that can never be
//     proven and so is held for the life of the process. RegisterSubmittedTx
//     documents this refusal in as many words — "a permanent hold bought with
//     no evidence". Today an empty encode returns a bare error and nothing
//     fences; typing it unconditionally would convert a harmless no-op into a
//     permanent key outage.
//
//   - a key WithNonceLease would reject: such a key cannot hold a lease, so any
//     broadcast made with it necessarily runs under a lease held by a DIFFERENT
//     key. WithNonceLease's typed path fences the LEASE's key (nonce.go:401)
//     using THESE bytes, so typing here would fence signer B over a transaction
//     belonging to signer A. The registration backstop cannot do that, because
//     it is keyed by the broadcasting pubkey. Typing unconditionally would swap
//     a missing fence for a wrong-key fence, which is a new defect, not a fix.
//
// Keeping the two guards identical is what makes A1 purely additive: the set of
// outcomes that fence is unchanged, and only the MECHANISM by which they fence
// becomes typed rather than positional.
//
// The wrapped message is returned VERBATIM by indeterminateSubmit.Error(), so
// no operator-visible text changes and no caller's existing classification of
// that text breaks.
func indeterminateBroadcast(signingKey ed25519.PrivateKey, encoded []byte, endpoint string) func(error) error {
	// Mirror of RegisterSubmittedTx's guard (nonce.go:480). If these two ever
	// diverge, one of the fence mechanisms starts covering inputs the other
	// refuses — which is precisely the asymmetry A1 exists to remove.
	if len(signingKey) != ed25519.PrivateKeySize || len(encoded) == 0 {
		return func(err error) error { return err }
	}
	return func(err error) error {
		return Indeterminate(err, encoded, CometTxResolver(endpoint))
	}
}

// BroadcastCometCommit is the strict shared commit protocol for non-web
// adopters. It MUST be called inside WithNonceLease for signingKey.
//
// Every outcome that cannot prove the transaction's fate is returned wrapped as
// a typed indeterminate error (see indeterminateBroadcast), so WithNonceLease
// fences the exact bytes on the TYPE rather than on the caller having
// propagated it unchanged. Registration still goes live at the last boundary
// before http.Do and still acts as a second, independent backstop. A hash-bound
// rejection explicitly clears it.
//
// The two pre-send failures — a request that could not be built — stay bare on
// purpose: nothing reached a transport, so fencing there would take a signing
// key out of service over a malformed endpoint string.
func BroadcastCometCommit(ctx context.Context, cometRPC string, signingKey ed25519.PrivateKey, encoded []byte) (*CometCommitResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cometRPC), "/")
	url := fmt.Sprintf("%s/broadcast_tx_commit?tx=0x%s", endpoint, hex.EncodeToString(encoded))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) // #nosec G107 -- configured local CometBFT RPC
	if err != nil {
		// Deliberately NOT indeterminate, and deliberately above the fence
		// helper so it cannot become so by accident: this runs before
		// RegisterSubmittedTx and before any dial, so nothing was handed to a
		// transport. Typing it indeterminate would fence a signing key over a
		// malformed endpoint string that never put a byte on the wire.
		return nil, fmt.Errorf("broadcast tx commit: could not build request (%s)", classifyFenceCause(err))
	}

	// Everything below this line may have reached consensus. fence() marks that
	// explicitly instead of relying on the live registration alone — see the
	// function comment for why the positional guarantee was not enough.
	fence := indeterminateBroadcast(signingKey, encoded, endpoint)

	RegisterSubmittedTx(signingKey, encoded, CometTxResolver(endpoint))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fence(fmt.Errorf("broadcast tx commit: %s", classifyFenceCause(err)))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fence(fmt.Errorf("broadcast tx commit: unexpected status %s",
			ScrubBroadcastText(resp.Status, encoded)))
	}

	limited := &io.LimitedReader{R: resp.Body, N: CometRPCMaxResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	var envelope strictCommitEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fence(fmt.Errorf("decode broadcast commit response: %s",
			ScrubBroadcastText(err.Error(), encoded)))
	}
	if trailingErr := decoder.Decode(&struct{}{}); trailingErr == nil {
		return nil, fence(errors.New("decode broadcast commit response: multiple JSON values"))
	} else if !errors.Is(trailingErr, io.EOF) {
		return nil, fence(fmt.Errorf("decode broadcast commit response: trailing data: %s",
			ScrubBroadcastText(trailingErr.Error(), encoded)))
	}
	if limited.N <= 0 {
		return nil, fence(fmt.Errorf("broadcast commit response body exceeded %d bytes", CometRPCMaxResponseBytes))
	}
	if envelope.Error != nil {
		message := ScrubBroadcastText(envelope.Error.Message, encoded)
		data := ScrubBroadcastText(envelope.Error.Data, encoded)
		if data != "" {
			return nil, fence(fmt.Errorf("broadcast error: %s: %s", message, data))
		}
		return nil, fence(fmt.Errorf("broadcast error: %s", message))
	}
	if envelope.Result == nil || envelope.Result.CheckTx == nil || envelope.Result.TxResult == nil ||
		envelope.Result.CheckTx.Code == nil || envelope.Result.TxResult.Code == nil {
		return nil, fence(errors.New("broadcast commit response omitted result, check_tx, tx_result, or verdict code"))
	}

	want := CometTxHash(encoded)
	if !CometReportedHashMatches(envelope.Result.Hash, want) {
		return nil, fence(errors.New(cometHashMismatchDetail("broadcast commit", envelope.Result.Hash, want)))
	}
	checkCode := *envelope.Result.CheckTx.Code
	txCode := *envelope.Result.TxResult.Code
	checkLog := ScrubBroadcastText(envelope.Result.CheckTx.Log, encoded)
	txLog := ScrubBroadcastText(envelope.Result.TxResult.Log, encoded)
	wantHash := strings.ToUpper(hex.EncodeToString(want[:]))
	result := &CometCommitResult{
		Hash:         wantHash,
		Height:       envelope.Result.Height,
		CheckTxCode:  checkCode,
		CheckTxLog:   checkLog,
		TxResultCode: txCode,
		TxResultLog:  txLog,
	}
	if checkCode != 0 {
		ClearSubmittedTx(signingKey)
		return result, nil
	}
	if envelope.Result.Height <= 0 {
		// The strongest indeterminate in this file, and the easiest to misread
		// as a failure. Reaching here means CheckTx returned 0, which is
		// positive proof the node ADMITTED these bytes to its mempool and will
		// gossip them. The missing height says only that this response cannot
		// name the block — not that no block will ever contain it.
		return nil, fence(errors.New("broadcast commit response reported no committed height"))
	}
	if txCode != 0 {
		ClearSubmittedTx(signingKey)
		return result, nil
	}
	return result, nil
}

// BroadcastCometSync applies the same on-wire registration, bounded
// single-document decoding, hash binding, scrubbing, and typed indeterminate
// wrapping to /broadcast_tx_sync. A bound CheckTx refusal is definitive and
// retires the registration; every other failure is returned as a typed
// indeterminate error AND leaves the registration live for WithNonceLease.
//
// Note this returns admission, not commitment: a code-0 sync response proves
// only that CheckTx accepted the bytes into the mempool.
func BroadcastCometSync(ctx context.Context, cometRPC string, signingKey ed25519.PrivateKey, encoded []byte) (*CometSyncResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cometRPC), "/")
	url := fmt.Sprintf("%s/broadcast_tx_sync?tx=0x%s", endpoint, hex.EncodeToString(encoded))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) // #nosec G107 -- configured local CometBFT RPC
	if err != nil {
		// Pre-registration, pre-dial: definitively not sent. See the matching
		// comment in BroadcastCometCommit for why this one stays bare.
		return nil, fmt.Errorf("broadcast tx sync: could not build request (%s)", classifyFenceCause(err))
	}

	fence := indeterminateBroadcast(signingKey, encoded, endpoint)

	RegisterSubmittedTx(signingKey, encoded, CometTxResolver(endpoint))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fence(fmt.Errorf("broadcast tx sync: %s", classifyFenceCause(err)))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Load-bearing for sync in particular: CometBFT delivers mempool-level
		// refusals as HTTP 500 + a JSON-RPC error envelope, so genuine node
		// refusals leave through here rather than through a verdict code.
		return nil, fence(fmt.Errorf("broadcast tx sync: unexpected status %s", ScrubBroadcastText(resp.Status, encoded)))
	}

	limited := &io.LimitedReader{R: resp.Body, N: CometRPCMaxResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	var envelope struct {
		Result *struct {
			Code *uint32 `json:"code"`
			Hash string  `json:"hash"`
			Log  string  `json:"log"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
			Data    string `json:"data"`
		} `json:"error"`
	}
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fence(fmt.Errorf("decode broadcast sync response: %s", ScrubBroadcastText(err.Error(), encoded)))
	}
	if trailingErr := decoder.Decode(&struct{}{}); trailingErr == nil {
		return nil, fence(errors.New("decode broadcast sync response: multiple JSON values"))
	} else if !errors.Is(trailingErr, io.EOF) {
		return nil, fence(fmt.Errorf("decode broadcast sync response: trailing data: %s",
			ScrubBroadcastText(trailingErr.Error(), encoded)))
	}
	if limited.N <= 0 {
		return nil, fence(fmt.Errorf("broadcast sync response body exceeded %d bytes", CometRPCMaxResponseBytes))
	}
	if envelope.Error != nil {
		message := ScrubBroadcastText(envelope.Error.Message, encoded)
		data := ScrubBroadcastText(envelope.Error.Data, encoded)
		if data != "" {
			return nil, fence(fmt.Errorf("broadcast sync error: %s: %s", message, data))
		}
		return nil, fence(fmt.Errorf("broadcast sync error: %s", message))
	}
	if envelope.Result == nil || envelope.Result.Code == nil {
		return nil, fence(errors.New("broadcast sync response omitted result or CheckTx verdict code"))
	}
	want := CometTxHash(encoded)
	if !CometReportedHashMatches(envelope.Result.Hash, want) {
		return nil, fence(errors.New(cometHashMismatchDetail("broadcast sync", envelope.Result.Hash, want)))
	}
	code := *envelope.Result.Code
	log := ScrubBroadcastText(envelope.Result.Log, encoded)
	if code != 0 {
		ClearSubmittedTx(signingKey)
	}
	return &CometSyncResult{
		Hash:        strings.ToUpper(hex.EncodeToString(want[:])),
		CheckTxCode: code,
		CheckTxLog:  log,
	}, nil
}
