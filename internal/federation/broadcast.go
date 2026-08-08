package federation

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/l33tdawg/sage/internal/tx"
)

// Local CometBFT broadcast for node-originated federation txs (CoCommitAttest).
// Mirrors api/rest's broadcastTxCommitWithHeight — duplicated here because
// internal/federation must not import api/rest (rest imports federation).

const defaultBroadcastTimeout = 60 * time.Second

// JoinConfirmationPeerTimeout covers the host's one consensus commit plus
// response headroom. JoinConfirmationOperationTimeout covers the guest and host
// commits sequentially for the browser-facing request. Both derive from the
// operator's broadcast override so raising it cannot silently recreate a
// shorter ceremony deadline on the same node.
func JoinConfirmationPeerTimeout() time.Duration {
	return broadcastTimeout() + 5*time.Second
}

func JoinConfirmationOperationTimeout() time.Duration {
	return 2*broadcastTimeout() + 10*time.Second
}

func broadcastTimeout() time.Duration {
	if v := os.Getenv("SAGE_TX_COMMIT_TIMEOUT_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return defaultBroadcastTimeout
}

// broadcastTxCommit submits tx bytes to the local CometBFT RPC and waits for
// block finalization, returning (txHash, height). CheckTx and FinalizeBlock
// rejections surface as errors.
func (m *Manager) broadcastTxCommit(signingKey ed25519.PrivateKey, txBytes []byte) (string, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), broadcastTimeout())
	defer cancel()
	return m.broadcastTxCommitContext(ctx, signingKey, txBytes)
}

// broadcastTxCommitContext is the context-aware form used by nonce-lease
// holders. Sharing one deadline across lease acquisition and Comet admission
// prevents a timed-out waiter from retaining the per-key lease for an
// additional detached broadcast timeout.
func (m *Manager) broadcastTxCommitContext(ctx context.Context, signingKey ed25519.PrivateKey, txBytes []byte) (string, int64, error) {
	result, err := tx.BroadcastCometCommit(ctx, m.cometRPC, signingKey, txBytes)
	if err != nil {
		return "", 0, err
	}
	if result.CheckTxCode != 0 {
		return "", 0, fmt.Errorf("tx rejected by CheckTx (code %d): %s", result.CheckTxCode, result.CheckTxLog)
	}
	if result.TxResultCode != 0 {
		return "", 0, fmt.Errorf("tx rejected in FinalizeBlock (code %d): %s", result.TxResultCode, result.TxResultLog)
	}
	return result.Hash, result.Height, nil
}
