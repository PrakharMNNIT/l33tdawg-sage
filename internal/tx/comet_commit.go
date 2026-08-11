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
	"strings"
)

// CometRPCMaxRequestBytes mirrors CometBFT's production max_body_bytes. The
// JSON-RPC POST envelope base64-expands the signed transaction, so enforce the
// limit before handing any bytes to the transport. Oversized requests are a
// definitive pre-send refusal and must not fence the signing key.
const CometRPCMaxRequestBytes = 1_000_000

// cometRPCMaxSafeURIBytes leaves headroom below CometBFT's production
// max_header_bytes for the request line plus ordinary HTTP headers. Preserve
// the established GET wire shape for small transactions, but move a signed
// transaction to JSON-RPC POST before its hex query can approach that ceiling.
const cometRPCMaxSafeURIBytes = 900_000

func cometBroadcastRequest(ctx context.Context, endpoint, method string, encoded []byte) (*http.Request, error) {
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
	if len(body) > CometRPCMaxRequestBytes {
		return nil, fmt.Errorf("comet JSON-RPC request body is %d bytes, exceeds %d-byte limit",
			len(body), CometRPCMaxRequestBytes)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body)) // #nosec G107 -- configured local CometBFT RPC
	if err != nil {
		return nil, fmt.Errorf("build Comet JSON-RPC request: %s", classifyFenceCause(err))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return req, nil
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

// BroadcastCometCommit is the strict shared commit protocol for non-web
// adopters. It MUST be called inside WithNonceLease for signingKey.
//
// Registration happens at the last boundary before http.Do. Any transport,
// status, RPC, decode, shape, hash, or height failure therefore leaves the
// registration live; WithNonceLease fences the exact bytes even if the caller
// forgets to wrap the error. A hash-bound rejection explicitly clears it.
func BroadcastCometCommit(ctx context.Context, cometRPC string, signingKey ed25519.PrivateKey, encoded []byte) (*CometCommitResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cometRPC), "/")
	req, err := cometBroadcastRequest(ctx, endpoint, "broadcast_tx_commit", encoded)
	if err != nil {
		return nil, fmt.Errorf("broadcast tx commit: %w", err)
	}

	RegisterSubmittedTx(signingKey, encoded, CometTxResolver(endpoint))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("broadcast tx commit: %s", classifyFenceCause(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("broadcast tx commit: unexpected status %s",
			ScrubBroadcastText(resp.Status, encoded))
	}
	if err := validateCometJSONResponse(resp); err != nil {
		return nil, fmt.Errorf("broadcast tx commit: %s", ScrubBroadcastText(err.Error(), encoded))
	}

	limited := &io.LimitedReader{R: resp.Body, N: CometRPCMaxResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	var envelope strictCommitEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode broadcast commit response: %s",
			ScrubBroadcastText(err.Error(), encoded))
	}
	if trailingErr := decoder.Decode(&struct{}{}); trailingErr == nil {
		return nil, errors.New("decode broadcast commit response: multiple JSON values")
	} else if !errors.Is(trailingErr, io.EOF) {
		return nil, fmt.Errorf("decode broadcast commit response: trailing data: %s",
			ScrubBroadcastText(trailingErr.Error(), encoded))
	}
	if limited.N <= 0 {
		return nil, fmt.Errorf("broadcast commit response body exceeded %d bytes", CometRPCMaxResponseBytes)
	}
	if envelope.Error != nil {
		message := ScrubBroadcastText(envelope.Error.Message, encoded)
		data := ScrubBroadcastText(envelope.Error.Data, encoded)
		if data != "" {
			return nil, fmt.Errorf("broadcast error: %s: %s", message, data)
		}
		return nil, fmt.Errorf("broadcast error: %s", message)
	}
	if envelope.Result == nil || envelope.Result.CheckTx == nil || envelope.Result.TxResult == nil ||
		envelope.Result.CheckTx.Code == nil || envelope.Result.TxResult.Code == nil {
		return nil, errors.New("broadcast commit response omitted result, check_tx, tx_result, or verdict code")
	}

	want := CometTxHash(encoded)
	if !CometReportedHashMatches(envelope.Result.Hash, want) {
		return nil, errors.New(cometHashMismatchDetail("broadcast commit", envelope.Result.Hash, want))
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
		return nil, errors.New("broadcast commit response reported no committed height")
	}
	if txCode != 0 {
		ClearSubmittedTx(signingKey)
		return result, nil
	}
	return result, nil
}

// BroadcastCometSync applies the same on-wire registration, bounded
// single-document decoding, hash binding, and scrubbing to
// /broadcast_tx_sync. A bound CheckTx refusal is definitive and retires the
// registration; every other failure remains live for WithNonceLease to fence.
func BroadcastCometSync(ctx context.Context, cometRPC string, signingKey ed25519.PrivateKey, encoded []byte) (*CometSyncResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cometRPC), "/")
	req, err := cometBroadcastRequest(ctx, endpoint, "broadcast_tx_sync", encoded)
	if err != nil {
		return nil, fmt.Errorf("broadcast tx sync: %w", err)
	}

	RegisterSubmittedTx(signingKey, encoded, CometTxResolver(endpoint))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("broadcast tx sync: %s", classifyFenceCause(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("broadcast tx sync: unexpected status %s", ScrubBroadcastText(resp.Status, encoded))
	}
	if err := validateCometJSONResponse(resp); err != nil {
		return nil, fmt.Errorf("broadcast tx sync: %s", ScrubBroadcastText(err.Error(), encoded))
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
		return nil, fmt.Errorf("decode broadcast sync response: %s", ScrubBroadcastText(err.Error(), encoded))
	}
	if trailingErr := decoder.Decode(&struct{}{}); trailingErr == nil {
		return nil, errors.New("decode broadcast sync response: multiple JSON values")
	} else if !errors.Is(trailingErr, io.EOF) {
		return nil, fmt.Errorf("decode broadcast sync response: trailing data: %s",
			ScrubBroadcastText(trailingErr.Error(), encoded))
	}
	if limited.N <= 0 {
		return nil, fmt.Errorf("broadcast sync response body exceeded %d bytes", CometRPCMaxResponseBytes)
	}
	if envelope.Error != nil {
		message := ScrubBroadcastText(envelope.Error.Message, encoded)
		data := ScrubBroadcastText(envelope.Error.Data, encoded)
		if data != "" {
			return nil, fmt.Errorf("broadcast sync error: %s: %s", message, data)
		}
		return nil, fmt.Errorf("broadcast sync error: %s", message)
	}
	if envelope.Result == nil || envelope.Result.Code == nil {
		return nil, errors.New("broadcast sync response omitted result or CheckTx verdict code")
	}
	want := CometTxHash(encoded)
	if !CometReportedHashMatches(envelope.Result.Hash, want) {
		return nil, errors.New(cometHashMismatchDetail("broadcast sync", envelope.Result.Hash, want))
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
