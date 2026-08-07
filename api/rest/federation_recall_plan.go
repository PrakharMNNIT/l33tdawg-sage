package rest

import (
	"context"
	"net/http"

	"github.com/l33tdawg/sage/api/rest/middleware"
	"github.com/l33tdawg/sage/internal/federation"
)

type federationRecallPlanner interface {
	PlanRecall(ctx context.Context, targets []string, agentID, domain string) (*federation.RecallPlan, error)
}

type federationRecallPlanRequest struct {
	DomainTag      string   `json:"domain_tag"`
	FederateChains []string `json:"federate_chains,omitempty"`
}

// handleFederationRecallPlan is the first half of the v23 two-request flow.
// It is authenticated as the original local agent, filters topology through
// that caller's local Read authority, and returns only exact destination state
// that must be included in the subsequently signed recall body.
func (s *Server) handleFederationRecallPlan(w http.ResponseWriter, r *http.Request) {
	callerID := middleware.ContextAgentID(r.Context())
	if !s.requireAppV23ActiveOrdinaryAgent(
		w, callerID, "federated recall planning",
	) {
		return
	}
	planner, ok := s.federation.(federationRecallPlanner)
	if !ok {
		writeProblem(w, http.StatusNotImplemented, "Federated recall unavailable",
			"Federation protocol v23 recall planning is not available on this node.")
		return
	}
	var req federationRecallPlanRequest
	if err := decodeJSON(r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	allowed, _ := s.federationCallerCanRead(r.Context(), callerID, req.DomainTag)
	if !allowed {
		writeProblem(w, http.StatusForbidden, "Access denied",
			"Caller is not authorized to read this federated domain.")
		return
	}
	targets := req.FederateChains
	if len(targets) == 0 {
		targets = []string{"*"}
	}
	privilegedTopology := s.nodeOperatorID != "" && callerID == s.nodeOperatorID
	if s.isPostV23ForNextTx() {
		privilegedTopology = s.callerIsOperatorOrAdmin(r.Context(), callerID)
	}
	if !privilegedTopology {
		targets = s.federationRecallTargets(r.Context(), targets, req.DomainTag)
		if len(targets) == 0 {
			writeJSON(w, http.StatusOK, &federation.RecallPlan{
				ProtocolVersion:           federation.FederationProtocolV23,
				SourceChainID:             s.federation.LocalChainID(),
				Destinations:              []string{},
				AgreementBindings:         map[string]string{},
				QueryChallenges:           map[string]string{},
				AuthorizationModels:       map[string]string{},
				AuthorizationAttestations: map[string]federation.SourceAuthorizationAttestation{},
				ExpiresAt:                 map[string]int64{},
			})
			return
		}
	}
	plan, err := planner.PlanRecall(r.Context(), targets, callerID, req.DomainTag)
	if err != nil {
		writeProblem(w, http.StatusBadGateway, "Federated recall plan failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, plan)
}
