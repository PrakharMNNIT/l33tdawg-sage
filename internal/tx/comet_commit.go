package tx

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// CometRPCMaxRequestBytes mirrors CometBFT's production max_body_bytes. The
// JSON-RPC POST envelope base64-expands the signed transaction, so enforce the
// limit before handing any bytes to the transport. Oversized requests are a
// definitive pre-send refusal and must not fence the signing key.
const CometRPCMaxRequestBytes = 1_000_000

// CometMaxTxBytes mirrors CometBFT's default mempool max_tx_bytes. Operators
// may raise both limits in lockstep for an internal, authenticated RPC plane,
// but the client remains fail-closed unless its explicit environment matches
// the CometBFT configuration.
const CometMaxTxBytes = 1_048_576

const maxConfiguredCometBytes = 8_000_000

// cometRPCMaxSafeURIBytes leaves headroom below CometBFT's production
// max_header_bytes for the request line plus ordinary HTTP headers. Preserve
// the established GET wire shape for small transactions, but move a signed
// transaction to JSON-RPC POST before its hex query can approach that ceiling.
const cometRPCMaxSafeURIBytes = 900_000

// cometSubmitClient carries every SUBMISSION. It exists for exactly one reason:
// to make connection reuse impossible, because reuse is what lets one broadcast
// be delivered twice.
//
// Go's transport transparently re-sends a request when the response headers
// never arrive, and the conditions line up precisely against the wire shape
// built below. net/http/request.go isReplayable: a nil-body GET is replayable —
// and the small-transaction path here IS a nil-body GET. net/http/transport.go
// mapRoundTripError: a pre-header read failure is downgraded to "nothing
// written" ONLY when no bytes went out, so it stays retryable in exactly the
// case where the request DID reach the node and may already have been admitted.
// shouldRetryRequest then retries, gated on pc.isReused().
//
// A duplicate delivery to the SAME node is harmless — CometBFT's mempool cache
// rejects it before the application sees it, which surfaces as a JSON-RPC error
// and correctly leaves the registration live to be fenced. The danger is a
// multi-responder endpoint: the retry opens a NEW connection, which a load
// balancer may place on a different node, and that node can answer with a
// hash-bound nonzero CheckTx of its own (a node-local refusal such as a locked
// vault or unsealed boot state sync). BroadcastCometCommit would then treat that
// as a definitive refusal and clear the fence — on the evidence of a node that
// never accepted the bytes — while the first node's copy goes on to commit.
//
// Disabling keep-alives makes pc.isReused() false for every submission, which is
// the gate shouldRetryRequest checks before it ever consults replayability, so
// the retry cannot occur. HTTP/2 is disabled with it, because DisableKeepAlives
// governs the HTTP/1 connection pool only: an https endpoint that negotiated h2
// by ALPN would keep multiplexing over one connection and reintroduce the reuse
// this exists to remove. The cost is one handshake per broadcast against what is
// normally a loopback RPC.
//
// Nothing is lost by giving up the retry. The benign case it was written for —
// transport.go errServerClosedIdle, "an unfortunate keep-alive timeout just as
// the client was writing" — is a race BETWEEN a pooled idle connection and the
// server's idle timeout. With no pooled idle connection it cannot arise. The
// same change removes both the hazard and the reason the papering-over existed.
//
// NOT the fix: an Idempotency-Key header. It makes a request MORE replayable,
// not less — isReplayable returns true for it. It is a server-side contract that
// CometBFT does not implement.
var cometSubmitClient = newCometSubmitClient()

func newCometSubmitClient() *http.Client {
	transport := &http.Transport{}
	// Clone the process defaults where we can, so proxy configuration, dial and
	// TLS handshake timeouts keep matching every other client in the node. The
	// assertion is guarded rather than bare: this runs at package init, and a
	// panic here would kill the process before anything could report why.
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = base.Clone()
	}
	transport.DisableKeepAlives = true
	http1Only := new(http.Protocols)
	http1Only.SetHTTP1(true)
	transport.Protocols = http1Only
	// No Timeout, matching the http.DefaultClient this replaces: every caller
	// passes a context, and a client-level deadline here would silently cap
	// broadcast_tx_commit, which legitimately blocks until the tx is in a block.
	return &http.Client{Transport: transport}
}

// DoCometSubmission sends one already-built CometBFT submission through the
// process-wide non-reusing transport. It is exported for the legacy CEREBRUM
// commit path in web/, which owns additional request-aware error semantics but
// must share the same delivery guarantee as the strict broadcasters here.
// Read-only RPCs must keep using their ordinary client: this seam deliberately
// pays one connection (and, for HTTPS, one TLS handshake) per submission.
func DoCometSubmission(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("comet submission request is nil")
	}
	// #nosec G704 -- this sink intentionally targets the operator-configured
	// CometBFT RPC endpoint; callers supply signed transaction requests, never
	// an unauthenticated remote user's fetch URL.
	return cometSubmitClient.Do(req)
}

func cometBroadcastRequest(ctx context.Context, endpoint, method string, encoded []byte) (*http.Request, error) {
	maxTxBytes, limitErr := configuredCometByteLimit("SAGE_COMET_MAX_TX_BYTES", CometMaxTxBytes)
	if limitErr != nil {
		return nil, limitErr
	}
	if len(encoded) > maxTxBytes {
		return nil, fmt.Errorf("comet transaction is %d bytes, exceeds %d-byte limit", len(encoded), maxTxBytes)
	}

	legacyURL := fmt.Sprintf("%s/%s?tx=0x%s", endpoint, method, hex.EncodeToString(encoded))
	if len(legacyURL) < cometRPCMaxSafeURIBytes {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, legacyURL, nil) // #nosec G107 -- configured local CometBFT RPC
		if err != nil {
			return nil, fmt.Errorf("build Comet RPC request: %s", classifyFenceCause(err))
		}
		return req, nil
	}

	envelope := struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Method  string `json:"method"`
		Params  struct {
			Tx string `json:"tx"`
		} `json:"params"`
	}{
		JSONRPC: "2.0",
		ID:      1,
		Method:  method,
	}
	envelope.Params.Tx = base64.StdEncoding.EncodeToString(encoded)
	body, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode Comet JSON-RPC request: %w", err)
	}
	maxRequestBytes, err := configuredCometByteLimit("SAGE_COMET_RPC_MAX_BODY_BYTES", CometRPCMaxRequestBytes)
	if err != nil {
		return nil, err
	}
	if len(body) > maxRequestBytes {
		return nil, fmt.Errorf("comet JSON-RPC request body is %d bytes, exceeds %d-byte limit",
			len(body), maxRequestBytes)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body)) // #nosec G107 -- configured local CometBFT RPC
	if err != nil {
		return nil, fmt.Errorf("build Comet JSON-RPC request: %s", classifyFenceCause(err))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func configuredCometByteLimit(name string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < fallback || limit > maxConfiguredCometBytes {
		return 0, fmt.Errorf("invalid %s: require integer in [%d,%d]", name, fallback, maxConfiguredCometBytes)
	}
	return limit, nil
}

func validateCometJSONResponse(resp *http.Response) error {
	contentType := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if contentType == "" {
		return nil // Backward compatibility for older Comet/proxy deployments.
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	// Some older Comet/proxy deployments omit the header, and Go's minimal
	// httptest-style handlers default valid JSON bodies to text/plain. Preserve
	// those known-compatible forms while refusing HTML and every other media
	// type that commonly carries an intermediary error page.
	if err != nil || (mediaType != "application/json" && mediaType != "text/plain") {
		return fmt.Errorf("comet RPC returned non-JSON content type %q", contentType)
	}
	return nil
}

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
		Hash   string      `json:"hash"`
		Height CometHeight `json:"height"`
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
	req, err := cometBroadcastRequest(ctx, endpoint, "broadcast_tx_commit", encoded)
	if err != nil {
		// Deliberately NOT indeterminate, and deliberately above the fence
		// helper so it cannot become so by accident: this runs before
		// RegisterSubmittedTx and before any dial, so nothing was handed to a
		// transport. Typing it indeterminate would fence a signing key over a
		// malformed endpoint string that never put a byte on the wire.
		return nil, fmt.Errorf("broadcast tx commit: %w", err)
	}

	// Everything below this line may have reached consensus. fence() marks that
	// explicitly instead of relying on the live registration alone — see the
	// function comment for why the positional guarantee was not enough.
	fence := indeterminateBroadcast(signingKey, encoded, endpoint)

	RegisterSubmittedTx(signingKey, encoded, CometTxResolver(endpoint))
	resp, err := DoCometSubmission(req)
	if err != nil {
		return nil, fence(fmt.Errorf("broadcast tx commit: %s", classifyFenceCause(err)))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fence(fmt.Errorf("broadcast tx commit: unexpected status %s",
			ScrubBroadcastText(resp.Status, encoded)))
	}
	if err := validateCometJSONResponse(resp); err != nil {
		return nil, fence(fmt.Errorf("broadcast tx commit: %s", ScrubBroadcastText(err.Error(), encoded)))
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
		Height:       int64(envelope.Result.Height),
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
	req, err := cometBroadcastRequest(ctx, endpoint, "broadcast_tx_sync", encoded)
	if err != nil {
		// Pre-registration, pre-dial: definitively not sent. See the matching
		// comment in BroadcastCometCommit for why this one stays bare.
		return nil, fmt.Errorf("broadcast tx sync: %w", err)
	}

	fence := indeterminateBroadcast(signingKey, encoded, endpoint)

	RegisterSubmittedTx(signingKey, encoded, CometTxResolver(endpoint))
	resp, err := DoCometSubmission(req)
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
	if err := validateCometJSONResponse(resp); err != nil {
		return nil, fence(fmt.Errorf("broadcast tx sync: %s", ScrubBroadcastText(err.Error(), encoded)))
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
