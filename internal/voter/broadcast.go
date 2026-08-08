package voter

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/rs/zerolog"

	"github.com/l33tdawg/sage/internal/tx"
)

// broadcastTimeout bounds a single broadcast so a slow/hung CometBFT RPC can't
// wedge the voter's tick loop.
const broadcastTimeout = 10 * time.Second

type voteBroadcastResult struct {
	accepted    bool
	unavailable bool
}

// broadcastVoteTx sends an encoded vote transaction to CometBFT via
// broadcast_tx_sync and reports whether CheckTx accepted it into the mempool.
// This is not a commit receipt: callers must confirm the canonical vote before
// marking it completed. The request is derived from the voter ctx (so shutdown
// cancels in-flight broadcasts) and bounded by broadcastTimeout.
func broadcastVoteTx(ctx context.Context, cometRPC string, signingKey ed25519.PrivateKey, encoded []byte, logger zerolog.Logger) (voteBroadcastResult, error) {
	reqCtx, cancel := context.WithTimeout(ctx, broadcastTimeout)
	defer cancel()
	result, err := tx.BroadcastCometSync(reqCtx, cometRPC, signingKey, encoded)
	if err != nil {
		logger.Debug().Str("cause", tx.ScrubBroadcastText(err.Error(), encoded)).Msg("failed to broadcast vote tx")
		return voteBroadcastResult{unavailable: true}, err
	}
	if result.CheckTxCode != 0 {
		logger.Debug().
			Uint32("code", result.CheckTxCode).
			Str("log", result.CheckTxLog).
			Msg("vote rejected by CheckTx")
		return voteBroadcastResult{unavailable: result.CheckTxCode == 112}, nil
	}
	return voteBroadcastResult{accepted: true}, nil
}

// voteDecisionFromString maps a decision string to the on-chain enum.
func voteDecisionFromString(s string) tx.VoteDecision {
	switch s {
	case "accept":
		return tx.VoteDecisionAccept
	case "reject":
		return tx.VoteDecisionReject
	case "abstain":
		return tx.VoteDecisionAbstain
	default:
		return tx.VoteDecisionAccept
	}
}
