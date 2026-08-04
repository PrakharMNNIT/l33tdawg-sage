package web

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"

	"github.com/l33tdawg/sage/internal/scope"
)

type dashboardScopeDomainResponse struct {
	Name    string `json:"name"`
	Subtree bool   `json:"subtree"`
}

type dashboardScopeMemberResponse struct {
	ValidatorID             string `json:"validator_id"`
	AssignedWeight          uint64 `json:"assigned_weight"`
	JoinedRevision          uint64 `json:"joined_revision"`
	Active                  bool   `json:"active"`
	PendingBallotCount      int    `json:"pending_ballot_count"`
	ValidatorRemovalBlocked bool   `json:"validator_removal_blocked"`
}

type dashboardScopeDrainResponse struct {
	PendingBallotCount   int      `json:"pending_ballot_count"`
	PendingMemoryIDs     []string `json:"pending_memory_ids"`
	BlockingValidatorIDs []string `json:"blocking_validator_ids"`
}

type dashboardScopeRecordResponse struct {
	ScopeID               string                         `json:"scope_id"`
	Revision              uint64                         `json:"revision"`
	RevisionHash          string                         `json:"revision_hash"`
	State                 string                         `json:"state"`
	ControllerValidatorID string                         `json:"controller_validator_id"`
	CreatedHeight         int64                          `json:"created_height"`
	UpdatedHeight         int64                          `json:"updated_height"`
	Domains               []dashboardScopeDomainResponse `json:"domains"`
	Members               []dashboardScopeMemberResponse `json:"members"`
	Drain                 dashboardScopeDrainResponse    `json:"drain"`
}

// handleChainScopes exposes canonical scope topology to the authenticated,
// same-machine CEREBRUM operator. The browser cannot sign the operator/admin
// REST contract at /v1/scopes, and that agent API must remain signed.
func (h *DashboardHandler) handleChainScopes(w http.ResponseWriter, _ *http.Request) {
	if h.BadgerStore == nil {
		writeError(w, http.StatusServiceUnavailable, "canonical scope storage is not configured")
		return
	}
	records, err := h.BadgerStore.ListScopeRecords()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	pending, err := h.BadgerStore.ListPendingScopeBallots()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]dashboardScopeRecordResponse, 0, len(records))
	for i := range records {
		view, viewErr := h.dashboardScopeRecordView(&records[i], pending)
		if viewErr != nil {
			writeError(w, http.StatusInternalServerError, viewErr.Error())
			return
		}
		views = append(views, view)
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"scopes": views, "count": len(views)})
}

func (h *DashboardHandler) dashboardScopeRecordView(
	record *scope.Record,
	pending []scope.Ballot,
) (dashboardScopeRecordResponse, error) {
	digest, err := h.BadgerStore.GetScopeRevisionHash(record.ScopeID, record.Revision)
	if err != nil {
		return dashboardScopeRecordResponse{}, err
	}
	if len(digest) != sha256.Size {
		return dashboardScopeRecordResponse{}, fmt.Errorf(
			"scope %q revision %d is missing its audit anchor", record.ScopeID, record.Revision,
		)
	}
	domains := make([]dashboardScopeDomainResponse, 0, len(record.Domains))
	for _, domain := range record.Domains {
		domains = append(domains, dashboardScopeDomainResponse{Name: domain.Name, Subtree: domain.Subtree})
	}
	pendingByValidator := make(map[string]int)
	pendingMemoryIDs := make([]string, 0)
	blockingValidators := make(map[string]struct{})
	for _, ballot := range pending {
		if ballot.ScopeID != record.ScopeID {
			continue
		}
		pendingMemoryIDs = append(pendingMemoryIDs, ballot.MemoryID)
		for _, member := range ballot.Members {
			pendingByValidator[member.ValidatorID]++
			blockingValidators[member.ValidatorID] = struct{}{}
		}
	}
	members := make([]dashboardScopeMemberResponse, 0, len(record.Members))
	for _, member := range record.Members {
		if record.State != scope.StateRetired && member.Active {
			blockingValidators[member.ValidatorID] = struct{}{}
		}
		members = append(members, dashboardScopeMemberResponse{
			ValidatorID: member.ValidatorID, AssignedWeight: member.AssignedWeight,
			JoinedRevision: member.JoinedRevision, Active: member.Active,
			PendingBallotCount: pendingByValidator[member.ValidatorID],
			ValidatorRemovalBlocked: (record.State != scope.StateRetired && member.Active) ||
				pendingByValidator[member.ValidatorID] > 0,
		})
	}
	blockingValidatorIDs := make([]string, 0, len(blockingValidators))
	for validatorID := range blockingValidators {
		blockingValidatorIDs = append(blockingValidatorIDs, validatorID)
	}
	sort.Strings(blockingValidatorIDs)
	return dashboardScopeRecordResponse{
		ScopeID: record.ScopeID, Revision: record.Revision,
		RevisionHash: hex.EncodeToString(digest), State: dashboardScopeStateString(record.State),
		ControllerValidatorID: record.ControllerValidatorID,
		CreatedHeight:         record.CreatedHeight, UpdatedHeight: record.UpdatedHeight,
		Domains: domains, Members: members,
		Drain: dashboardScopeDrainResponse{
			PendingBallotCount: len(pendingMemoryIDs), PendingMemoryIDs: pendingMemoryIDs,
			BlockingValidatorIDs: blockingValidatorIDs,
		},
	}, nil
}

func dashboardScopeStateString(state scope.State) string {
	switch state {
	case scope.StateActive:
		return "active"
	case scope.StatePaused:
		return "paused"
	case scope.StateRetired:
		return "retired"
	default:
		return "unknown"
	}
}
