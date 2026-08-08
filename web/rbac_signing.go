package web

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/l33tdawg/sage/internal/tx"
)

type cometStatusTimeResult struct {
	Result struct {
		SyncInfo struct {
			LatestBlockTime time.Time `json:"latest_block_time"`
		} `json:"sync_info"`
	} `json:"result"`
}

// latestConsensusTimeWeb reads the chain's most recently committed time. The
// dashboard's app-v20 governance proof is checked against deterministic block
// time, not the host wall clock; on a recovering or CPU-starved personal node
// those clocks can differ by more than the strict five-minute proof window.
func latestConsensusTimeWeb(cometRPC string) (time.Time, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cometRPC, "/")+"/status", nil) // #nosec G107 -- internal CometBFT RPC
	if err != nil {
		return time.Time{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("comet status returned %s", resp.Status)
	}
	var result cometStatusTimeResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return time.Time{}, fmt.Errorf("decode comet status: %w", err)
	}
	if result.Result.SyncInfo.LatestBlockTime.IsZero() {
		return time.Time{}, fmt.Errorf("comet status omitted latest block time")
	}
	return result.Result.SyncInfo.LatestBlockTime, nil
}

const governanceProofClockSkew = 5 * time.Minute

// freshGovernanceProofTime chooses a timestamp that is fresh at the CheckTx
// boundary without moving behind the chain's last committed clock. An idle
// SAGE intentionally produces no heartbeat blocks, so latestBlockTime may be
// hours old even though the next block created by this transaction will use a
// current time. Reusing that old timestamp made a newly signed proof stale on
// arrival. A committed clock more than one proof window ahead of the host is a
// real clock-safety failure and remains fail-closed.
func freshGovernanceProofTime(now, latestBlockTime time.Time) (time.Time, error) {
	if latestBlockTime.After(now.Add(governanceProofClockSkew)) {
		return time.Time{}, fmt.Errorf(
			"committed consensus time is more than %s ahead of host time",
			governanceProofClockSkew,
		)
	}
	if latestBlockTime.After(now) {
		return latestBlockTime, nil
	}
	return now, nil
}

func (h *DashboardHandler) embedConsensusTimedGovernanceProof(ptx *tx.ParsedTx, operatorKey ed25519.PrivateKey, method, path string, body []byte) error {
	proofTime := time.Now()
	if h.ConsensusGovernanceClock {
		consensusTime, err := latestConsensusTimeWeb(h.CometBFTRPC)
		if err != nil {
			return fmt.Errorf("read committed consensus time: %w", err)
		}
		proofTime, err = freshGovernanceProofTime(proofTime, consensusTime)
		if err != nil {
			return fmt.Errorf("select governance proof time: %w", err)
		}
	}
	return embedDashboardGovernanceProofAt(ptx, operatorKey, method, path, body, proofTime)
}

const governanceProofAheadOfConsensus = "app-v20 governance proof timestamp is more than 5 minutes ahead of consensus time"

// retryGovernanceProofAtCommittedTime repairs the one honest race exposed by
// an idle single-validator chain. The rejected proposal mutates no consensus
// state, but its block gives us the clock the next proof must bind to.
func (h *DashboardHandler) retryGovernanceProofAtCommittedTime(
	ptx *tx.ParsedTx,
	operatorKey ed25519.PrivateKey,
	method string,
	path string,
	body []byte,
	broadcastErr error,
) (bool, error) {
	if broadcastErr == nil || !strings.Contains(broadcastErr.Error(), governanceProofAheadOfConsensus) {
		return false, nil
	}
	consensusTime, err := latestConsensusTimeWeb(h.CometBFTRPC)
	if err != nil {
		return true, fmt.Errorf("read committed consensus time after rejected proof: %w", err)
	}
	if err := embedDashboardGovernanceProofAt(
		ptx, operatorKey, method, path, body, consensusTime,
	); err != nil {
		return true, fmt.Errorf("re-sign governance proof at committed time: %w", err)
	}
	return true, nil
}

// This file is the commit-confirmed signing/broadcast plumbing for the v11.3
// RBAC reassign + access-control flow. The existing dashboard broadcast path
// (broadcastTxSync) is fire-and-forget: it cannot confirm a tx executed or
// enforce the strict propose -> executed -> reassign -> grant ordering the
// flow needs, so those handlers use the helpers here instead. Nothing here
// changes consensus; it only builds/signs/broadcasts existing tx types.

// cometCommitResult mirrors the /broadcast_tx_commit JSON envelope (a subset of
// the api/rest cometCommitResponse). It surfaces both the CheckTx and the
// FinalizeBlock (TxResult) codes so a consensus-side rejection becomes a real
// error rather than a silent success.
type cometCommitResult struct {
	Result struct {
		CheckTx struct {
			Code int    `json:"code"`
			Log  string `json:"log"`
		} `json:"check_tx"`
		TxResult struct {
			Code int    `json:"code"`
			Log  string `json:"log"`
		} `json:"tx_result"`
		Hash   string `json:"hash"`
		Height int64  `json:"height,string"`
	} `json:"result"`
	Error *struct {
		Message string `json:"message"`
		Data    string `json:"data"`
	} `json:"error"`
}

// rbacCommitTimeout bounds how long a commit-confirmed broadcast waits for
// /broadcast_tx_commit. Matches the api/rest client default (60s) so slow
// single-validator commits have headroom; overridable via SAGE_TX_COMMIT_TIMEOUT_MS.
func rbacCommitTimeout() time.Duration {
	if v := os.Getenv("SAGE_TX_COMMIT_TIMEOUT_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return 60 * time.Second
}

// broadcastTxCommitWeb sends a tx via /broadcast_tx_commit and waits for block
// finalization, returning (hash, committedHeight, finalizeLog). It returns an
// error if the RPC fails, or if the tx is rejected in CheckTx or FinalizeBlock,
// so callers can surface real consensus rejections.
func broadcastTxCommitWeb(cometRPC string, txBytes []byte) (hash string, height int64, txLog string, err error) {
	return broadcastTxCommitWebContext(context.Background(), cometRPC, txBytes)
}

// broadcastTxCommitWebContext is the request-aware variant used by CEREBRUM
// mutations. A closed browser tab or an explicit client deadline must cancel
// the in-flight Comet request instead of leaving the server goroutine detached
// for the full commit timeout. Callers must still treat cancellation as an
// indeterminate result: consensus may already have accepted the transaction.
func broadcastTxCommitWebContext(parent context.Context, cometRPC string, txBytes []byte) (hash string, height int64, txLog string, err error) {
	txHex := hex.EncodeToString(txBytes)
	url := fmt.Sprintf("%s/broadcast_tx_commit?tx=0x%s", cometRPC, txHex)

	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, rbacCommitTimeout())
	defer cancel()

	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) // #nosec G107 -- internal CometBFT RPC
	if reqErr != nil {
		return "", 0, "", fmt.Errorf("create broadcast request: %w", reqErr)
	}
	resp, doErr := http.DefaultClient.Do(req)
	if doErr != nil {
		return "", 0, "", fmt.Errorf("broadcast tx commit: %w", doErr)
	}
	defer resp.Body.Close()

	var result cometCommitResult
	if decErr := json.NewDecoder(resp.Body).Decode(&result); decErr != nil {
		return "", 0, "", fmt.Errorf("decode broadcast commit response: %w", decErr)
	}
	if result.Error != nil {
		if result.Error.Data != "" {
			return "", 0, "", fmt.Errorf("broadcast error: %s: %s", result.Error.Message, result.Error.Data)
		}
		return "", 0, "", fmt.Errorf("broadcast error: %s", result.Error.Message)
	}
	if result.Result.CheckTx.Code != 0 {
		return "", 0, "", fmt.Errorf("tx rejected in CheckTx (code %d): %s", result.Result.CheckTx.Code, result.Result.CheckTx.Log)
	}
	if result.Result.TxResult.Code != 0 {
		return "", 0, "", fmt.Errorf("tx rejected in FinalizeBlock (code %d): %s", result.Result.TxResult.Code, result.Result.TxResult.Log)
	}
	return result.Result.Hash, result.Result.Height, result.Result.TxResult.Log, nil
}

// signAndBroadcastCommit stamps the nonce, adds the legacy same-key proof for
// non-governance RBAC transactions, signs the envelope, encodes it, and waits
// for commit. Governance callers either supply a modern request-bound operator
// proof before calling this helper or intentionally use the proofless direct
// compatibility lane.
func (h *DashboardHandler) signAndBroadcastCommit(ptx *tx.ParsedTx, key ed25519.PrivateKey) (hash string, height int64, txLog string, err error) {
	return h.signAndBroadcastCommitContext(context.Background(), ptx, key)
}

// signAndBroadcastCommitContext runs the whole stamp -> sign -> encode ->
// broadcast sequence inside a per-signing-key nonce lease.
//
// The lease is load-bearing, not defensive. Every dashboard fan-out that
// mutates several records at once (clearing a Done/Dropped board column,
// bulk-forgetting selected memories) issues N concurrent HTTP requests that all
// land here with the SAME key. Allocating the nonce and then racing to CometBFT
// meant those txs could arrive in descending nonce order, and app-v9's replay
// gate rejects the late-arriving lower nonce with Code 4 "nonce too low" — so a
// random subset of the batch failed while the rest succeeded. Serializing
// allocation with submission is what makes the emitted order match the
// allocated order. Every signAndBroadcastCommit* caller in web/ inherits this.
//
// The lease's ordering guarantee holds only because this function does not
// return until the outcome is definitive: broadcastTxCommitWebContext waits for
// commit, and an indeterminate transport/RPC fault is classified by
// isIndeterminateCommitError rather than being reported as a clean failure. A
// submit that returned early on a timeout would release the lease while its
// lower nonce was still in flight, letting the next higher nonce overtake it.
func (h *DashboardHandler) signAndBroadcastCommitContext(ctx context.Context, ptx *tx.ParsedTx, key ed25519.PrivateKey) (string, int64, string, error) {
	var (
		hash   string
		height int64
		txLog  string
		txErr  error
	)
	leaseErr := tx.WithNonceLease(ctx, key, func(nonce uint64) error {
		ptx.Nonce = nonce
		if ptx.Timestamp.IsZero() {
			ptx.Timestamp = time.Now()
		}
		// Direct governance is authorized by the outer operator/validator signature
		// and deliberately carries no HTTP-agent proof. App-v20+ treats any proof
		// material on governance as a modern request-bound proof (8-byte request
		// nonce + canonical request body). The generic legacy dashboard proof lacks
		// those fields and is therefore correctly rejected. Keep the legacy same-key
		// proof for non-governance RBAC transactions, whose consensus path still
		// accepts it.
		switch ptx.Type {
		case tx.TxTypeGovPropose, tx.TxTypeGovVote, tx.TxTypeGovCancel:
		default:
			embedDashboardAgentProof(ptx, key)
		}
		if signErr := tx.SignTx(ptx, key); signErr != nil {
			txErr = fmt.Errorf("sign tx: %w", signErr)
			return txErr
		}
		encoded, encErr := tx.EncodeTx(ptx)
		if encErr != nil {
			txErr = fmt.Errorf("encode tx: %w", encErr)
			return txErr
		}
		hash, height, txLog, txErr = broadcastTxCommitWebContext(ctx, h.CometBFTRPC, encoded)
		return txErr
	})
	// txErr is still nil only when the closure never ran, i.e. the request was
	// cancelled while queued for the key. Nothing was signed or sent, so this is
	// a DEFINITIVE "no change" — deliberately not one of
	// isIndeterminateCommitError's shapes, and worded so it cannot be mistaken
	// for a consensus rejection.
	if txErr == nil && leaseErr != nil {
		return "", 0, "", fmt.Errorf("await signing slot for this key: %w", leaseErr)
	}
	return hash, height, txLog, txErr
}

// isIndeterminateCommitError reports whether a commit-confirmed request could
// have reached consensus but did not yield a trustworthy response to this
// process. CheckTx/FinalizeBlock failures are definitive rejections and must
// remain errors; transport and RPC response faults are not proof of no change.
func isIndeterminateCommitError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.HasPrefix(message, "broadcast tx commit:") ||
		strings.HasPrefix(message, "decode broadcast commit response:") ||
		strings.HasPrefix(message, "broadcast error:")
}

// agentIDForKey returns the on-chain agent id (hex(pubkey)) for an Ed25519 key,
// matching auth.PublicKeyToAgentID. Empty for a nil/invalid key.
func agentIDForKey(key ed25519.PrivateKey) string {
	if len(key) != ed25519.PrivateKeySize {
		return ""
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return ""
	}
	return hex.EncodeToString(pub)
}

// rbacPurgeRe extracts the purged-grant count from processDomainReassign's
// success log ("... purged N grants ...").
var rbacPurgeRe = regexp.MustCompile(`purged\s+(\d+)\s+grants`)

// parsePurgedGrantsWeb pulls the purged-grant count out of a DomainReassign
// FinalizeBlock log, or 0 if absent.
func parsePurgedGrantsWeb(log string) int {
	m := rbacPurgeRe.FindStringSubmatch(log)
	if len(m) < 2 {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0
	}
	return n
}
