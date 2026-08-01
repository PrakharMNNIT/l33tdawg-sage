package web

import (
	"context"

	"github.com/l33tdawg/sage/internal/governance"
	"github.com/l33tdawg/sage/internal/store"
)

// AppV25MaintenanceStatus is process-local proof that this running binary has
// inspected the app-v25 legacy projection. Persisted progress is intentionally
// not sufficient: after restart it describes an older process and must never
// release continuity work or readiness before this process verifies the same
// evidence.
type AppV25MaintenanceStatus struct {
	Required   bool
	Checked    bool
	OK         bool
	Recovery   bool
	State      string
	Revision   uint64
	Generation uint64
}

// ConfigureAppV25Maintenance publishes the startup state before listeners and
// workers race. Required maintenance begins fail-closed as checking; a
// pre-app-v25 node has no dependency.
func (h *DashboardHandler) ConfigureAppV25Maintenance(required bool) {
	if h == nil {
		return
	}
	h.appV25MaintenanceMu.Lock()
	defer h.appV25MaintenanceMu.Unlock()
	if !required {
		h.appV25Maintenance = AppV25MaintenanceStatus{
			Checked: true,
			OK:      true,
			State:   "not_required",
		}
		return
	}
	h.appV25Maintenance = AppV25MaintenanceStatus{
		Required:   true,
		State:      "checking",
		Generation: h.appV25Maintenance.Generation + 1,
	}
}

func (h *DashboardHandler) beginAppV25MaintenanceCheck() {
	if h == nil {
		return
	}
	h.appV25MaintenanceMu.Lock()
	defer h.appV25MaintenanceMu.Unlock()
	generation := h.appV25Maintenance.Generation
	if generation == 0 {
		generation = 1
	}
	h.appV25Maintenance = AppV25MaintenanceStatus{
		Required:   true,
		State:      "checking",
		Generation: generation,
	}
}

func (h *DashboardHandler) noteAppV25MaintenanceProgress(
	progress store.LegacyMemoryAdoptionProgress,
) {
	if h == nil {
		return
	}
	h.appV25MaintenanceMu.Lock()
	defer h.appV25MaintenanceMu.Unlock()
	generation := h.appV25Maintenance.Generation
	if generation == 0 {
		generation = 1
	}
	status := AppV25MaintenanceStatus{
		Required:   true,
		State:      progress.State,
		Revision:   progress.Revision,
		Generation: generation,
	}
	switch progress.State {
	case "complete", "migrating", "waiting", "attesting":
		// A stable current-process scan has already localized every row before
		// these states are published. Governance/signing can continue in the
		// background without making ordinary serving unavailable.
		status.Checked = true
		status.OK = true
	case "recovery":
		// Preserved, localized historical rows are not a serving failure.
		// They remain available for governed recovery or explicit deprecation.
		status.Checked = true
		status.OK = true
		status.Recovery = true
	}
	h.appV25Maintenance = status
}

// AppV25MaintenanceStatus returns an immutable process-local snapshot.
func (h *DashboardHandler) AppV25MaintenanceStatus() AppV25MaintenanceStatus {
	if h == nil {
		return AppV25MaintenanceStatus{}
	}
	h.appV25MaintenanceMu.RLock()
	defer h.appV25MaintenanceMu.RUnlock()
	return h.appV25Maintenance
}

func (h *DashboardHandler) appV25CurrentProcessAdoptionTerminal(
	persisted *store.LegacyMemoryAdoptionProgress,
) bool {
	if persisted == nil {
		return false
	}
	current := h.AppV25MaintenanceStatus()
	if !current.Required || !current.Checked || !current.OK {
		return false
	}
	if current.State != "complete" && current.State != "recovery" {
		return false
	}
	return current.State == persisted.State &&
		current.Revision == persisted.Revision &&
		persisted.Remaining == 0
}

// Only a provably single-validator personal node may automatically originate a
// maintenance proposal. Every validator may still attest an already-active
// proposal from its own exact evidence.
func (h *DashboardHandler) canAutomaticallyProposeAppV25Maintenance() bool {
	if h == nil || h.ValidatorCountFn == nil {
		return false
	}
	return h.ValidatorCountFn() == 1
}

// appV25MaintenanceTargetRejected uses the ordinary durable governance
// projection as the restart receipt for an exact evidence-bound target. A
// rejected target must not be proposed again after every process restart.
// Changed evidence produces a different target ID and remains recoverable.
func (h *DashboardHandler) appV25MaintenanceTargetRejected(
	ctx context.Context,
	operation governance.ProposalOp,
	targetID string,
) (bool, error) {
	if h.BadgerStore != nil {
		key := governance.MaintenanceRejectionReceiptKey(operation, targetID)
		if key != "" {
			receipt, err := h.BadgerStore.GetState(key)
			if err != nil {
				return false, err
			}
			if len(receipt) != 0 {
				return true, nil
			}
		}
	}
	governanceStore, ok := h.store.(store.GovernanceStore)
	if !ok {
		return false, nil
	}
	proposals, err := governanceStore.ListGovProposals(ctx, "rejected")
	if err != nil {
		return false, err
	}
	operationName := ""
	switch operation {
	case governance.OpMemoryLegacyAdopt:
		operationName = appV25LegacyAdoptionOperationName
	case governance.OpDomainContinuityAdopt:
		operationName = appV25DomainContinuityOperationName
	}
	for _, proposal := range proposals {
		if proposal != nil &&
			proposal.Operation == operationName &&
			proposal.TargetAgentID == targetID {
			return true, nil
		}
	}
	return false, nil
}
