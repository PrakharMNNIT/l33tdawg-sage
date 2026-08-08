package web

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEmbeddingsProviderSwitch_ManualAdviceBranchesHoldWhileFenced covers the
// embeddings handler's OTHER manual-restart branches — no in-process restart
// support, or no restart hook wired. Unlike the error branch (where the veto
// fires and must not be swallowed; pinned in signer_fence_surface_test.go),
// these branches never consult the veto at all: they hand the operator a
// manual quit-and-reopen instruction directly, and the manual lane has no
// enforcement hook — the message IS the control. While a signing key is
// fenced, that message must be the hold notice, not the instruction.
func TestEmbeddingsProviderSwitch_ManualAdviceBranchesHoldWhileFenced(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	fenceOneSigningKey(t, key)

	// RequestRestart deliberately nil: on platforms with in-process restart
	// this exercises the no-hook branch; where restarts are unsupported it
	// exercises that branch instead. Both compose manual advice, and both must
	// refuse to advise the manual bypass while the fence stands.
	h := &DashboardHandler{
		SetEmbeddingProvider: func(string) error { return nil },
		RequestRestart:       nil,
	}
	rec := httptest.NewRecorder()
	h.persistEmbeddingProvider(rec,
		httptest.NewRequest(http.MethodPost, "/v1/dashboard/embeddings/provider", nil), "hash")

	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Message string `json:"message"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	lowered := strings.ToLower(body.Message)
	assert.Contains(t, lowered, "do not quit or restart",
		"with a fence held, the manual-restart branch must carry the hold notice")
	for _, forbidden := range []string{"fully quit", "relaunch", "reopen", "open it again"} {
		assert.NotContains(t, lowered, forbidden,
			"the response advises the manual restart that would discard the fence")
	}
}

// TestPendingUpdateConflict_HoldsRestartInstructionWhileFenced pins the
// handleApplyUpdate 409 for "an update is already installed and waiting for a
// restart". This branch escaped the first centralization sweep: it fires at the
// exact moment the operator is one restart away from activating an update, so
// composing "restart SAGE" inline here — with a signing key fenced — was
// handing them the manual bypass the veto refuses. The message must route
// through manualRestartAdvice like every other manual-restart surface.
func TestPendingUpdateConflict_HoldsRestartInstructionWhileFenced(t *testing.T) {
	// Unfenced: the instruction passes through verbatim, naming the pending
	// version so the operator knows which update the restart activates.
	unfenced := pendingUpdateConflictMessage("v11.19.0")
	assert.Contains(t, unfenced, "update v11.19.0 is already installed")
	assert.Contains(t, unfenced, "restart SAGE before installing another update")

	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	fenceOneSigningKey(t, key)

	fenced := strings.ToLower(pendingUpdateConflictMessage("v11.19.0"))
	assert.Contains(t, fenced, "do not quit or restart",
		"with a fence held, the pending-update conflict must carry the hold notice")
	assert.NotContains(t, fenced, "restart sage before installing",
		"the 409 advises the manual restart that would discard the fence and lose the protected transaction")
}

func TestCompletedUpdateStateRetainsFenceAwareAdvice(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	fenceOneSigningKey(t, key)

	h := &DashboardHandler{}
	h.sendInstalledUpdateComplete("Update installed")
	h.updateStateMu.RLock()
	state := make(map[string]string, len(h.updateState))
	for key, value := range h.updateState {
		state[key] = value
	}
	h.updateStateMu.RUnlock()

	assert.Equal(t, "complete", state["step"])
	assert.Equal(t, "done", state["status"])
	lowered := strings.ToLower(state["message"])
	assert.Contains(t, lowered, "do not quit or restart")
	assert.NotEqual(t, "ready_to_restart", state["message"],
		"the final retained state erased the signer-fence hold notice")
}
