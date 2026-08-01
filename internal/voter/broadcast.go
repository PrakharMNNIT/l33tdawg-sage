package voter

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
func broadcastVoteTx(ctx context.Context, cometRPC string, encoded []byte, logger zerolog.Logger) voteBroadcastResult {
	txHex := hex.EncodeToString(encoded)
	url := fmt.Sprintf("%s/broadcast_tx_sync?tx=0x%s", cometRPC, txHex)
	reqCtx, cancel := context.WithTimeout(ctx, broadcastTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil) //nolint:gosec
	if err != nil {
		logger.Debug().Err(err).Msg("failed to create broadcast request")
		return voteBroadcastResult{unavailable: true}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cause := "transport error"
		switch {
		case errors.Is(err, context.Canceled):
			cause = "context canceled"
		case errors.Is(err, context.DeadlineExceeded):
			cause = "timeout"
		}
		// Do not attach err: net/http includes the full signed tx query in it,
		// which turns a single shutdown into megabytes of useless logs.
		logger.Debug().Str("cause", cause).Msg("failed to broadcast vote tx")
		return voteBroadcastResult{unavailable: true}
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		logger.Debug().Int("status", resp.StatusCode).Msg("vote broadcast HTTP request was rejected")
		return voteBroadcastResult{unavailable: true}
	}
	var envelope struct {
		Result struct {
			Code uint32 `json:"code"`
			Log  string `json:"log"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		logger.Debug().Err(err).Msg("failed to decode vote broadcast response")
		return voteBroadcastResult{unavailable: true}
	}
	if len(envelope.Error) > 0 && string(envelope.Error) != "null" {
		logger.Debug().RawJSON("rpc_error", envelope.Error).Msg("vote broadcast RPC returned an error")
		return voteBroadcastResult{unavailable: true}
	}
	if envelope.Result.Code != 0 {
		logger.Debug().
			Uint32("code", envelope.Result.Code).
			Str("log", envelope.Result.Log).
			Msg("vote rejected by CheckTx")
		return voteBroadcastResult{unavailable: envelope.Result.Code == 112}
	}
	return voteBroadcastResult{accepted: true}
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
