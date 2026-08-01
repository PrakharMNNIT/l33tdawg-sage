package web

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/governance"
	"github.com/l33tdawg/sage/internal/store"
)

func TestAppV25ContinuityRejectsPersistedTerminalProgressUntilCurrentProcessChecks(
	t *testing.T,
) {
	ctx := context.Background()
	sqlite, err := store.NewSQLiteStore(
		ctx, filepath.Join(t.TempDir(), "memories.db"),
	)
	require.NoError(t, err)
	defer func() { require.NoError(t, sqlite.Close()) }()
	badgerStore, err := store.NewBadgerStore(filepath.Join(t.TempDir(), "badger"))
	require.NoError(t, err)
	defer func() { require.NoError(t, badgerStore.CloseBadger()) }()

	persisted := store.LegacyMemoryAdoptionProgress{
		State:    "complete",
		Revision: 17,
		Message:  "old process said complete",
	}
	require.NoError(t, sqlite.PublishLegacyMemoryAdoptionProgress(ctx, persisted))

	handler := NewDashboardHandler(sqlite, "test")
	handler.BadgerStore = badgerStore
	handler.ConfigureAppV25Maintenance(true)
	run := &appV25DomainContinuityRun{}

	more, err := handler.runAppV25DomainContinuityPassWithRun(
		ctx, zerolog.Nop(), run,
	)
	require.NoError(t, err)
	require.False(t, more)
	require.Nil(t, run.plan,
		"persisted progress from an older process must not release continuity")

	handler.noteAppV25MaintenanceProgress(persisted)
	require.True(t, handler.appV25CurrentProcessAdoptionTerminal(&persisted))
	_, err = handler.runAppV25DomainContinuityPassWithRun(
		ctx, zerolog.Nop(), run,
	)
	require.ErrorContains(t, err, "live validator signing path is unavailable",
		"after current-process verification the worker must advance past the restart gate")
}

func TestAppV25CleanTerminalPlanIgnoresOrdinaryRevisionChanges(t *testing.T) {
	ctx := context.Background()
	sqlite, err := store.NewSQLiteStore(
		ctx, filepath.Join(t.TempDir(), "memories.db"),
	)
	require.NoError(t, err)
	defer func() { require.NoError(t, sqlite.Close()) }()
	badgerStore, err := store.NewBadgerStore(filepath.Join(t.TempDir(), "badger"))
	require.NoError(t, err)
	defer func() { require.NoError(t, badgerStore.CloseBadger()) }()

	handler := NewDashboardHandler(sqlite, "test")
	handler.BadgerStore = badgerStore
	plan := &appV25LegacyAdoptionPlan{
		SQLRevision:           999,
		VaultGeneration:       999,
		CanonicalRevision:     999,
		AuthorizationRevision: 999,
	}
	stale, err := handler.refreshAppV25LegacyAdoptionPlan(ctx, sqlite, plan)
	require.NoError(t, err)
	require.False(t, stale,
		"a verified zero-entry plan must not be invalidated by ordinary current writes")
	revision, err := sqlite.MemoryProjectionRevision(ctx)
	require.NoError(t, err)
	require.Equal(t, revision, plan.SQLRevision)
}

func TestAppV25AutomaticMaintenanceProposalRequiresKnownSingleValidator(t *testing.T) {
	handler := NewDashboardHandler(nil, "test")
	require.False(t, handler.canAutomaticallyProposeAppV25Maintenance())
	handler.ValidatorCountFn = func() int { return 2 }
	require.False(t, handler.canAutomaticallyProposeAppV25Maintenance())
	handler.ValidatorCountFn = func() int { return 1 }
	require.True(t, handler.canAutomaticallyProposeAppV25Maintenance())
}

func TestAppV25StableAdoptionStatesAreCheckedButNotContinuityTerminal(t *testing.T) {
	for _, state := range []string{"migrating", "waiting", "attesting"} {
		t.Run(state, func(t *testing.T) {
			handler := NewDashboardHandler(nil, "test")
			handler.ConfigureAppV25Maintenance(true)
			progress := store.LegacyMemoryAdoptionProgress{
				State:     state,
				Remaining: 1,
				Revision:  17,
			}
			handler.noteAppV25MaintenanceProgress(progress)

			status := handler.AppV25MaintenanceStatus()
			require.True(t, status.Required)
			require.True(t, status.Checked)
			require.True(t, status.OK)
			require.False(t, status.Recovery)
			require.Equal(t, state, status.State)
			require.False(t, handler.appV25CurrentProcessAdoptionTerminal(&progress),
				"background governance progress must not release continuity")
		})
	}

	handler := NewDashboardHandler(nil, "test")
	handler.ConfigureAppV25Maintenance(true)
	status := handler.AppV25MaintenanceStatus()
	require.Equal(t, "checking", status.State)
	require.False(t, status.Checked)
	require.False(t, status.OK)
}

func TestAppV25RejectedEvidenceTargetIsDurableAcrossWorkerRestart(t *testing.T) {
	ctx := context.Background()
	sqlite, err := store.NewSQLiteStore(
		ctx, filepath.Join(t.TempDir(), "memories.db"),
	)
	require.NoError(t, err)
	defer func() { require.NoError(t, sqlite.Close()) }()
	require.NoError(t, sqlite.InsertGovProposal(ctx, &store.GovProposal{
		ProposalID:    "rejected-maintenance-proposal",
		Operation:     appV25LegacyAdoptionOperationName,
		TargetAgentID: "evidence-bound-target",
		ProposerID:    "validator",
		Status:        "rejected",
		CreatedHeight: 10,
		ExpiryHeight:  20,
	}))

	restarted := NewDashboardHandler(sqlite, "test")
	rejected, err := restarted.appV25MaintenanceTargetRejected(
		ctx, governance.OpMemoryLegacyAdopt, "evidence-bound-target",
	)
	require.NoError(t, err)
	require.True(t, rejected)
	rejected, err = restarted.appV25MaintenanceTargetRejected(
		ctx, governance.OpMemoryLegacyAdopt, "changed-evidence-target",
	)
	require.NoError(t, err)
	require.False(t, rejected,
		"changed evidence has a new target and remains eligible for recovery")
}

func TestAppV25ContinuityCannotRaceCurrentProcessAdoptionScan(t *testing.T) {
	ctx := context.Background()
	fixture := newAppV23AccessFixture(t)
	sqlite, err := store.NewSQLiteStore(
		ctx, filepath.Join(t.TempDir(), "memories.db"),
	)
	require.NoError(t, err)
	defer func() { require.NoError(t, sqlite.Close()) }()
	old := store.LegacyMemoryAdoptionProgress{
		State:    "complete",
		Revision: 1,
		Message:  "persisted by the previous process",
	}
	require.NoError(t, sqlite.PublishLegacyMemoryAdoptionProgress(ctx, old))
	source := &blockingAppV25LegacyProjectionSource{
		SQLiteStore: sqlite,
		scanStarted: make(chan struct{}),
		releaseScan: make(chan struct{}),
	}
	handler := NewDashboardHandler(source, "test")
	handler.BadgerStore = fixture.badger
	handler.ConfigureAppV25Maintenance(true)

	adoptionDone := make(chan error, 1)
	go func() {
		_, runErr := handler.runAppV25LegacyAdoptionPassWithState(
			ctx, zerolog.Nop(), &appV25LegacyAdoptionRun{},
		)
		adoptionDone <- runErr
	}()
	select {
	case <-source.scanStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("current-process adoption scan did not start")
	}
	status := handler.AppV25MaintenanceStatus()
	require.True(t, status.Required)
	require.False(t, status.Checked)
	require.Equal(t, "checking", status.State)

	more, err := handler.runAppV25DomainContinuityPassWithRun(
		ctx, zerolog.Nop(), &appV25DomainContinuityRun{},
	)
	require.NoError(t, err)
	require.False(t, more,
		"continuity must not consume previous-process progress during the new scan")

	close(source.releaseScan)
	select {
	case <-adoptionDone:
	case <-time.After(2 * time.Second):
		t.Fatal("adoption scan did not finish after release")
	}
}

func TestAppV25RestartWithActiveContinuityDoesNotDeadlockAdoptionProof(
	t *testing.T,
) {
	ctx := context.Background()
	fixture := newAppV23AccessFixture(t)
	sqlite, err := store.NewSQLiteStore(
		ctx, filepath.Join(t.TempDir(), "memories.db"),
	)
	require.NoError(t, err)
	defer func() { require.NoError(t, sqlite.Close()) }()
	proposal := governance.ProposalState{
		ProposalID: "continuity-across-restart",
		Operation:  governance.OpDomainContinuityAdopt,
		Status:     governance.StatusVoting,
	}
	encoded, err := json.Marshal(proposal)
	require.NoError(t, err)
	require.NoError(t, fixture.badger.SetGovProposal(proposal.ProposalID, encoded))
	require.NoError(t, fixture.badger.SetActiveProposal(proposal.ProposalID))

	handler := NewDashboardHandler(sqlite, "test")
	handler.BadgerStore = fixture.badger
	handler.SigningKey = fixture.rootKey
	handler.CometBFTRPC = "http://unused.invalid"
	handler.ConfigureAppV25Maintenance(true)
	more, err := handler.runAppV25LegacyAdoptionPassWithState(
		ctx, zerolog.Nop(), &appV25LegacyAdoptionRun{},
	)
	require.NoError(t, err)
	require.False(t, more)
	status := handler.AppV25MaintenanceStatus()
	require.True(t, status.Checked)
	require.True(t, status.OK)
	require.Equal(t, "complete", status.State,
		"current-process zero-entry scan must release the restarted continuity proposal")
}
