package abci

import (
	"fmt"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

func (app *SageApp) postAppV22Fork(height int64) bool {
	return app.appV22AppliedHeight > 0 && height > app.appV22AppliedHeight
}

func (app *SageApp) postAppV22Rules(height int64) bool {
	return app.postAppV22Fork(height)
}

func (app *SageApp) IsAppV22ActiveForNextTx() bool {
	return app.state != nil && app.postAppV22Rules(app.state.Height+1)
}

func (app *SageApp) refreshAppV22Fork() error {
	app.appV22AppliedHeight = 0
	rec, err := app.badgerStore.GetAppliedUpgrade(appV22UpgradeName)
	if err != nil {
		return fmt.Errorf("read applied %s record: %w", appV22UpgradeName, err)
	}
	if rec == nil {
		return nil
	}
	if rec.Name != appV22UpgradeName {
		return fmt.Errorf("applied %s record has name %q", appV22UpgradeName, rec.Name)
	}
	if rec.TargetAppVersion != 22 {
		return fmt.Errorf("applied %s record has target app version %d, want 22", appV22UpgradeName, rec.TargetAppVersion)
	}
	if rec.AppliedHeight <= 0 {
		return fmt.Errorf("applied %s record has non-positive height %d", appV22UpgradeName, rec.AppliedHeight)
	}
	if app.state == nil {
		return fmt.Errorf("applied %s record cannot be checked without app state", appV22UpgradeName)
	}
	if app.state.Height < rec.AppliedHeight-1 {
		return fmt.Errorf("applied %s height %d is ahead of persisted app height %d", appV22UpgradeName, rec.AppliedHeight, app.state.Height)
	}
	app.appV22AppliedHeight = rec.AppliedHeight
	return nil
}

func (app *SageApp) validateAppV22Prerequisite() error {
	if app.appV22AppliedHeight <= 0 {
		return nil
	}
	lastPredecessorHeight, err := app.validatePersistedAppV22PredecessorLadder()
	if err != nil {
		return fmt.Errorf("applied %s has invalid predecessor ladder: %w", appV22UpgradeName, err)
	}
	if app.appV22AppliedHeight <= lastPredecessorHeight {
		return fmt.Errorf(
			"applied %s height %d must be after applied %s predecessor height %d",
			appV22UpgradeName, app.appV22AppliedHeight,
			appV21UpgradeName, lastPredecessorHeight,
		)
	}
	return nil
}

// validatePersistedAppV22PredecessorLadder requires canonical applied-upgrade
// evidence for app-v6 and every independent app version from 7 through 21, in
// strict activation-height order. The one compatibility exception is the
// canonical app-v6 record: the original upgrade protocol defined app-v6 as the
// cumulative PoE target and reconcilePoEForkMonotonicity makes that persisted
// activation consensus evidence that app-v2 through app-v5 rules activated
// together. No synthesized/subsumed evidence is accepted for app-v7 or later.
//
// The validator deliberately reads persisted audit records rather than cached
// fork heights. In-memory gate subsumption is an execution convenience, not
// proof that an independent app-v7+ state-machine version activated.
//
// This invariant is consulted only when proposing, executing, or restoring
// app-v22. Historical blocks below app-v22 retain their original replay rules.
func (app *SageApp) validatePersistedAppV22PredecessorLadder() (int64, error) {
	if app.badgerStore == nil {
		return 0, fmt.Errorf("app-v22 predecessor validation requires consensus state")
	}
	if app.state == nil {
		return 0, fmt.Errorf("app-v22 predecessor validation requires app state")
	}

	var previousHeight int64
	for version := uint64(6); version <= 21; version++ {
		name := tx.CanonicalUpgradeName(version)
		rec, err := app.badgerStore.GetAppliedUpgrade(name)
		if err != nil {
			return 0, fmt.Errorf("read applied %s record: %w", name, err)
		}
		if rec == nil {
			return 0, fmt.Errorf("missing canonical applied %s predecessor", name)
		}
		if rec.Name != name {
			return 0, fmt.Errorf("applied %s predecessor has name %q", name, rec.Name)
		}
		if rec.TargetAppVersion != version {
			return 0, fmt.Errorf(
				"applied %s predecessor has target app version %d, want %d",
				name, rec.TargetAppVersion, version,
			)
		}
		if rec.AppliedHeight <= 0 {
			return 0, fmt.Errorf(
				"applied %s predecessor has non-positive height %d",
				name, rec.AppliedHeight,
			)
		}
		if previousHeight > 0 && rec.AppliedHeight <= previousHeight {
			return 0, fmt.Errorf(
				"applied %s predecessor height %d must be after app-v%d height %d",
				name, rec.AppliedHeight, version-1, previousHeight,
			)
		}
		// MarkUpgradeApplied can be one height ahead of persisted AppState only
		// during the crash window between FinalizeBlock and Commit.
		if rec.AppliedHeight > app.state.Height+1 {
			return 0, fmt.Errorf(
				"applied %s predecessor height %d is ahead of persisted app height %d",
				name, rec.AppliedHeight, app.state.Height,
			)
		}
		previousHeight = rec.AppliedHeight
	}
	return previousHeight, nil
}

func (app *SageApp) agentCapabilitiesAt(agentID string, height int64) (store.AgentCapabilities, error) {
	if !app.postAppV22Rules(height) {
		return 0, nil
	}
	if agentID == "" {
		return 0, fmt.Errorf("app-v22 capability lookup requires an agent identity")
	}
	agent, err := app.badgerStore.GetRegisteredAgent(agentID)
	if err != nil {
		return 0, fmt.Errorf("app-v22 capability lookup for agent %s: %w", agentID, err)
	}
	if agent == nil {
		return 0, fmt.Errorf("app-v22 capability lookup for agent %s returned no record", agentID)
	}
	if !agent.Capabilities.Valid() {
		return 0, fmt.Errorf(
			"app-v22 capability lookup for agent %s contains unknown bits 0x%x",
			agentID,
			uint32(agent.Capabilities&^store.KnownAgentCapabilities),
		)
	}
	return agent.Capabilities, nil
}

func (app *SageApp) isGlobalAdminAgent(agentID string) bool {
	agent, err := app.badgerStore.GetRegisteredAgent(agentID)
	return err == nil && agent != nil && agent.Role == "admin"
}
