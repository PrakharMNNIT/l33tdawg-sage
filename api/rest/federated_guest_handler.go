package rest

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/l33tdawg/sage/api/rest/middleware"
	"github.com/l33tdawg/sage/internal/federation"
	"github.com/l33tdawg/sage/internal/store"
)

type federatedGuestControl interface {
	PrepareFederatedGuestMutation(
		ctx context.Context,
		callerID string,
		input federation.FederatedGuestMutationInput,
	) (*federation.PreparedFederatedGuestMutation, error)
	MintFederatedGuestElevation(
		ctx context.Context,
		adminCallerID string,
		mutation federation.FederatedGuestMutation,
	) (*federation.FederatedGuestElevation, error)
	CommitFederatedGuestMutation(
		ctx context.Context,
		callerID string,
		mutation federation.FederatedGuestMutation,
	) (*store.FederatedGroupGuest, error)
	ListFederatedGuestLinks(
		ctx context.Context,
		callerID, remoteChainID, remoteAgentID string,
	) ([]federation.FederatedGuestLinkView, error)
}

func (s *Server) getFederatedGuestControl(w http.ResponseWriter) (federatedGuestControl, bool) {
	control, ok := s.federation.(federatedGuestControl)
	if !ok {
		writeProblem(w, http.StatusNotImplemented, "Linked readers unavailable",
			"App-v23 federated linked-reader control is not available on this node.")
	}
	return control, ok
}

func (s *Server) handleFederatedGuestPrepare(w http.ResponseWriter, r *http.Request) {
	control, ok := s.getFederatedGuestControl(w)
	if !ok {
		return
	}
	var input federation.FederatedGuestMutationInput
	if err := decodeJSON(r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	prepared, err := control.PrepareFederatedGuestMutation(
		r.Context(), middleware.ContextAgentID(r.Context()), input,
	)
	if err != nil {
		status := http.StatusForbidden
		if errors.Is(err, store.ErrAppV23RevisionConflict) {
			status = http.StatusConflict
		}
		writeProblem(w, status, "Linked-reader preparation denied", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, prepared)
}

func (s *Server) handleFederatedGuestElevation(w http.ResponseWriter, r *http.Request) {
	control, ok := s.getFederatedGuestControl(w)
	if !ok {
		return
	}
	if !federatedGuestBrokerLoopback(r.RemoteAddr) {
		writeProblem(w, http.StatusForbidden, "Local broker only",
			"Admin elevation can only be minted through this node's loopback control plane.")
		return
	}
	callerID := middleware.ContextAgentID(r.Context())
	var mutation federation.FederatedGuestMutation
	if err := decodeJSON(r, &mutation); err != nil {
		writeProblem(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	token, err := control.MintFederatedGuestElevation(
		r.Context(), callerID, mutation,
	)
	if err != nil {
		writeProblem(w, http.StatusForbidden, "Elevation denied", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, token)
}

func federatedGuestBrokerLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) handleFederatedGuestCommit(w http.ResponseWriter, r *http.Request) {
	control, ok := s.getFederatedGuestControl(w)
	if !ok {
		return
	}
	var mutation federation.FederatedGuestMutation
	if err := decodeJSON(r, &mutation); err != nil {
		writeProblem(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	guest, err := control.CommitFederatedGuestMutation(
		r.Context(), middleware.ContextAgentID(r.Context()), mutation,
	)
	if err != nil {
		status := http.StatusForbidden
		if errors.Is(err, store.ErrAppV23RevisionConflict) {
			status = http.StatusConflict
		}
		writeProblem(w, status, "Linked-reader mutation denied", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, guest)
}

func (s *Server) handleFederatedGuestList(w http.ResponseWriter, r *http.Request) {
	control, ok := s.getFederatedGuestControl(w)
	if !ok {
		return
	}
	links, err := control.ListFederatedGuestLinks(
		r.Context(), middleware.ContextAgentID(r.Context()),
		r.URL.Query().Get("remote_chain_id"), r.URL.Query().Get("remote_agent_id"),
	)
	if err != nil {
		writeProblem(w, http.StatusForbidden, "Linked-reader list denied", err.Error())
		return
	}
	if links == nil {
		links = []federation.FederatedGuestLinkView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": links, "total": len(links)})
}
