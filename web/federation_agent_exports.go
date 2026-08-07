package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/l33tdawg/sage/internal/store"
)

type federatedAgentExportDriver interface {
	ListFederatedAgentExports(context.Context, string) ([]store.FederatedAgentExport, error)
	SetFederatedAgentExport(context.Context, string, string, string, uint8, []string, int64) (*store.FederatedAgentExport, error)
}

type fedAgentExportPutRequest struct {
	AgentID           string   `json:"agent_id"`
	State             string   `json:"state"`
	MaxClassification *uint8   `json:"max_classification,omitempty"`
	DomainExclusions  []string `json:"domain_exclusions,omitempty"`
	ExpectedRevision  int64    `json:"expected_revision"`
}

func (h *DashboardHandler) handleFedAgentExportsGet(w http.ResponseWriter, r *http.Request) {
	if !h.isFederationMutationOperatorRequest(r) {
		fedWriteErr(w, http.StatusForbidden, "Federated agent exports require the local node operator.")
		return
	}
	if !h.fedReady(w) {
		return
	}
	chain := chi.URLParam(r, "chain_id")
	if h.findAgreement(chain) == nil {
		fedWriteErr(w, http.StatusConflict, "No active agreement for this connection.")
		return
	}
	driver, ok := h.Federation.(federatedAgentExportDriver)
	if !ok {
		fedWriteErr(w, http.StatusNotImplemented, "Federated agent exports are unavailable on this node.")
		return
	}
	exports, err := driver.ListFederatedAgentExports(r.Context(), chain)
	if err != nil {
		fedWriteErr(w, http.StatusConflict, "Federated agent exports changed or are unavailable. Refresh the connection.")
		return
	}
	fedWriteJSON(w, http.StatusOK, map[string]any{
		"remote_chain_id": chain,
		"exports":         exports,
	})
}

func (h *DashboardHandler) handleFedAgentExportsPut(w http.ResponseWriter, r *http.Request) {
	if !h.isFederationMutationOperatorRequest(r) {
		fedWriteErr(w, http.StatusForbidden, "Federated agent exports require the local node operator.")
		return
	}
	if !h.fedReady(w) {
		return
	}
	chain := chi.URLParam(r, "chain_id")
	if h.findAgreement(chain) == nil {
		fedWriteErr(w, http.StatusConflict, "No active agreement for this connection.")
		return
	}
	var req fedAgentExportPutRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		fedWriteErr(w, http.StatusBadRequest, "Invalid federated agent export request.")
		return
	}
	req.AgentID = strings.ToLower(strings.TrimSpace(req.AgentID))
	if req.State != store.FederatedAgentExportStateActive && req.State != store.FederatedAgentExportStatePaused {
		fedWriteErr(w, http.StatusBadRequest, "Agent export state must be active or paused.")
		return
	}
	if req.ExpectedRevision < 0 {
		fedWriteErr(w, http.StatusBadRequest, "Expected revision must not be negative.")
		return
	}
	if req.State == store.FederatedAgentExportStateActive {
		owned, err := h.federatedAgentOwnedShareableDomains(r.Context(), req.AgentID)
		if err != nil || len(owned) == 0 {
			fedWriteErr(w, http.StatusConflict, "Only an active local agent that owns a shareable domain can be exported.")
			return
		}
	}
	maxClassification := uint8(store.ClearanceTopSecret)
	if req.MaxClassification != nil {
		maxClassification = *req.MaxClassification
	}
	driver, ok := h.Federation.(federatedAgentExportDriver)
	if !ok {
		fedWriteErr(w, http.StatusNotImplemented, "Federated agent exports are unavailable on this node.")
		return
	}
	export, err := driver.SetFederatedAgentExport(
		r.Context(), chain, req.AgentID, req.State, maxClassification,
		req.DomainExclusions, req.ExpectedRevision,
	)
	if err != nil {
		fedWriteErr(w, http.StatusConflict, "Federated agent export changed or is no longer authorized. Refresh and try again.")
		return
	}
	fedWriteJSON(w, http.StatusOK, map[string]any{
		"remote_chain_id": chain,
		"export":          export,
	})
}
