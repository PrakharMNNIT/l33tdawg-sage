package web

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/l33tdawg/sage/internal/governance"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

// handleMemoryHashReanchorPlan builds, but never submits, the next canonical
// repair chunk. The exact payload is exposed only to the authenticated,
// same-machine current Root so the ordinary governance proposal route can bind
// and sign it without trusting browser-supplied SQL evidence.
func (h *DashboardHandler) handleMemoryHashReanchorPlan(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.requireAppV23ControlActor(w, r, false)
	if !ok {
		return
	}
	if !actor.IsRoot {
		writeAppV23AccessError(w, http.StatusForbidden, "current_root_required",
			"Only the current local CEREBRUM Root may plan memory commitment repair.")
		return
	}
	if h.AppV24ActiveFn == nil || !h.AppV24ActiveFn() {
		writeError(w, http.StatusConflict, "memory commitment repair requires app-v24 activation")
		return
	}
	entries, remaining, err := store.PlanMemoryHashReanchorEntries(
		r.Context(), h.store, h.BadgerStore, tx.MaxMemoryHashReanchorEntries,
	)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "memory commitment repair planning failed: "+err.Error())
		return
	}
	if len(entries) == 0 {
		writeJSONResp(w, http.StatusOK, map[string]any{
			"required":  false,
			"state":     "clear",
			"remaining": false,
		})
		return
	}
	payloadEntries := make([]tx.MemoryHashReanchorEntry, len(entries))
	for i, entry := range entries {
		payloadEntries[i] = tx.MemoryHashReanchorEntry{
			MemoryID:       entry.MemoryID,
			ExpectedStatus: entry.ExpectedStatus,
			ContentHash:    append([]byte(nil), entry.ContentHash...),
		}
	}
	payload, err := tx.EncodeMemoryHashReanchorPayload(tx.MemoryHashReanchorPayload{
		Version:          tx.MemoryHashReanchorPayloadVersion,
		RootCredentialID: actor.Root.CredentialID,
		RootGeneration:   actor.Root.Generation,
		Entries:          payloadEntries,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "memory commitment repair payload failed validation")
		return
	}
	targetID, err := tx.MemoryHashReanchorTargetID(payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "memory commitment repair target failed validation")
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{
		"required":      true,
		"state":         "ready_to_propose",
		"operation":     "memory_hash_reanchor",
		"target_id":     targetID,
		"payload":       base64.StdEncoding.EncodeToString(payload),
		"entries":       len(entries),
		"remaining":     remaining,
		"expiry_blocks": governance.DefaultExpiryBlocks,
	})
}

func (h *DashboardHandler) attestMemoryHashReanchorProposal(
	ctx context.Context,
	proposal *governance.ProposalState,
) error {
	if proposal == nil || proposal.Operation != governance.OpMemoryHashReanchor {
		return fmt.Errorf("proposal is not a memory_hash_reanchor operation")
	}
	targetID, err := tx.MemoryHashReanchorTargetID(proposal.Payload)
	if err != nil {
		return err
	}
	if proposal.TargetID != targetID {
		return fmt.Errorf("proposal target does not bind its exact repair payload")
	}
	payload, err := tx.DecodeMemoryHashReanchorPayload(proposal.Payload)
	if err != nil {
		return err
	}
	root, err := h.BadgerStore.GetAppV23Root()
	if err != nil || root == nil {
		return fmt.Errorf("current Root state is unavailable")
	}
	if payload.RootCredentialID != root.CredentialID ||
		payload.RootGeneration != root.Generation {
		return fmt.Errorf("proposal was authorized by a stale Root generation")
	}
	entries := make([]store.MemoryHashReanchorEntry, len(payload.Entries))
	for i, entry := range payload.Entries {
		entries[i] = store.MemoryHashReanchorEntry{
			MemoryID:       entry.MemoryID,
			ExpectedStatus: entry.ExpectedStatus,
			ContentHash:    append([]byte(nil), entry.ContentHash...),
		}
	}
	return store.AttestMemoryHashReanchorEntries(
		ctx, h.store, h.BadgerStore, entries,
	)
}
