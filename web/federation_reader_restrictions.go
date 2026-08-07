package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/l33tdawg/sage/internal/store"
)

type federatedReaderRestrictionDriver interface {
	ListFederatedReaderRestrictions(context.Context, string) ([]store.FederatedReaderRestriction, error)
	SetFederatedReaderRestriction(context.Context, string, string, string, bool, []string, int64) (*store.FederatedReaderRestriction, error)
}

type fedReaderRestrictionPutRequest struct {
	AgentID          string   `json:"agent_id"`
	State            string   `json:"state"`
	DenyAll          bool     `json:"deny_all"`
	DeniedDomains    []string `json:"denied_domains,omitempty"`
	ExpectedRevision int64    `json:"expected_revision"`
}

func (h *DashboardHandler) handleFedReaderRestrictionsGet(w http.ResponseWriter, r *http.Request) {
	if !h.isFederationMutationOperatorRequest(r) {
		fedWriteErr(w, http.StatusForbidden, "Federation access controls require the local node operator.")
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
	driver, ok := h.Federation.(federatedReaderRestrictionDriver)
	if !ok {
		fedWriteErr(w, http.StatusNotImplemented, "Federation reader restrictions are unavailable on this node.")
		return
	}
	restrictions, err := driver.ListFederatedReaderRestrictions(r.Context(), chain)
	if err != nil {
		fedWriteErr(w, http.StatusConflict, "Federation reader restrictions changed or are unavailable. Refresh the connection.")
		return
	}
	fedWriteJSON(w, http.StatusOK, map[string]any{
		"remote_chain_id": chain,
		"restrictions":    restrictions,
	})
}

func (h *DashboardHandler) handleFedReaderRestrictionsPut(w http.ResponseWriter, r *http.Request) {
	if !h.isFederationMutationOperatorRequest(r) {
		fedWriteErr(w, http.StatusForbidden, "Federation access controls require the local node operator.")
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
	var req fedReaderRestrictionPutRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		fedWriteErr(w, http.StatusBadRequest, "Invalid federation reader restriction request.")
		return
	}
	req.AgentID = strings.ToLower(strings.TrimSpace(req.AgentID))
	if req.ExpectedRevision < 0 ||
		(req.State != store.FederatedReaderRestrictionStateActive &&
			req.State != store.FederatedReaderRestrictionStateRevoked) {
		fedWriteErr(w, http.StatusBadRequest, "Reader restriction state or revision is invalid.")
		return
	}
	driver, ok := h.Federation.(federatedReaderRestrictionDriver)
	if !ok {
		fedWriteErr(w, http.StatusNotImplemented, "Federation reader restrictions are unavailable on this node.")
		return
	}
	restriction, err := driver.SetFederatedReaderRestriction(
		r.Context(), chain, req.AgentID, req.State, req.DenyAll,
		req.DeniedDomains, req.ExpectedRevision,
	)
	if err != nil {
		fedWriteErr(w, http.StatusConflict, "Federation reader restriction changed or is no longer authorized. Refresh and try again.")
		return
	}
	fedWriteJSON(w, http.StatusOK, map[string]any{
		"remote_chain_id": chain,
		"restriction":     restriction,
	})
}
