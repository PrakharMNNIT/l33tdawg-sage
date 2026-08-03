package abci

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/poe"
	"github.com/l33tdawg/sage/internal/statesync"
	"github.com/l33tdawg/sage/internal/store"
)

func seedDirectAppV25HomeRepairFixture(
	t *testing.T, path string,
) (*store.BadgerStore, string) {
	t.Helper()
	bs, err := store.NewBadgerStore(path)
	require.NoError(t, err)
	root := deterministicScopedAgent(201)
	agent := deterministicScopedAgent(233)
	require.NoError(t, bs.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: root.id, Scope: strings.Repeat("4a", 32), AgentID: agent.id,
		Profile: store.AppV23ProfileCompanion, HomeDomain: "appv26-repair-home",
		Clearance: 1, Capabilities: 15, Height: 1,
		BootstrapDigest: strings.Repeat("5b", 32), ActivateAtGenesis: true,
		ValidatorID: root.id, ValidatorPower: 10,
	}))
	require.NoError(t, bs.MarkUpgradeApplied(appV24UpgradeName, 24, 2))
	require.NoError(t, bs.MarkUpgradeApplied(appV25UpgradeName, 25, 3))
	return bs, agent.id
}

func saveAppV26RepairTestState(
	t *testing.T, bs *store.BadgerStore, height int64,
) []byte {
	t.Helper()
	state := &AppState{Height: height, EpochNum: poe.EpochNumber(height)}
	hash, err := bs.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	state.AppHash = append([]byte(nil), hash...)
	require.NoError(t, SaveState(bs, state))
	hash, err = bs.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	state.AppHash = append([]byte(nil), hash...)
	require.NoError(t, SaveState(bs, state))
	return hash
}

func openAppV26RepairTestApp(
	t *testing.T, bs *store.BadgerStore, sqlitePath string,
) (*SageApp, error) {
	t.Helper()
	projection, err := store.NewSQLiteStore(context.Background(), sqlitePath)
	require.NoError(t, err)
	app, err := NewSageAppWithStores(bs, projection, zerolog.Nop())
	if err != nil {
		require.NoError(t, projection.Close())
	}
	return app, err
}

func TestAppV26ConstructorAllowsOnlyPreActivationCompatibilityThenBootsStrictRepair(t *testing.T) {
	rootDir := t.TempDir()
	badgerPath := filepath.Join(rootDir, "badger")
	bs, agentID := seedDirectAppV25HomeRepairFixture(t, badgerPath)
	enrollment, err := bs.GetAppV23Enrollment(agentID)
	require.NoError(t, err)
	require.NoError(t, bs.SetState("shared_domain:"+enrollment.HomeDomain, []byte{1}))
	require.Error(t, bs.ValidateAppV23State())
	require.NoError(t, bs.ValidateAppV23StateForPreV26Recovery())
	saveAppV26RepairTestState(t, bs, 3)

	preActivation, err := openAppV26RepairTestApp(
		t, bs, filepath.Join(rootDir, "pre-activation.db"),
	)
	require.NoError(t, err,
		"an app-v25 node must be able to boot far enough to execute app-v26 repair")
	require.Equal(t, uint64(25), preActivation.currentAppVersion())
	require.NoError(t, preActivation.badgerStore.MigrateAppV26AccessGroupAuthorities(4))
	require.NoError(t, preActivation.badgerStore.MarkUpgradeApplied(appV26UpgradeName, 26, 4))
	saveAppV26RepairTestState(t, preActivation.badgerStore, 4)
	require.NoError(t, preActivation.Close())

	reopened, err := store.NewBadgerStore(badgerPath)
	require.NoError(t, err)
	postActivation, err := openAppV26RepairTestApp(
		t, reopened, filepath.Join(rootDir, "post-activation.db"),
	)
	require.NoError(t, err)
	require.Equal(t, uint64(26), postActivation.currentAppVersion())
	require.NoError(t, postActivation.badgerStore.ValidateAppV23State())
	require.NoError(t, postActivation.Close())
}

func TestAppV26PreActivationServingProjectionDoesNotBlockDeterministicHomeRepair(t *testing.T) {
	rootDir := t.TempDir()
	badgerPath := filepath.Join(rootDir, "badger")
	bs, agentID := seedDirectAppV25HomeRepairFixture(t, badgerPath)
	enrollment, err := bs.GetAppV23Enrollment(agentID)
	require.NoError(t, err)
	require.NoError(t, bs.SetState("shared_domain:"+enrollment.HomeDomain, []byte{1}))
	require.ErrorContains(t, bs.ValidateAppV23State(), "shared_home")
	require.NoError(t, bs.ValidateAppV23StateForPreV26Recovery())
	saveAppV26RepairTestState(t, bs, 3)

	projection, err := store.NewSQLiteStore(
		context.Background(), filepath.Join(rootDir, "projection.db"),
	)
	require.NoError(t, err)
	app, err := NewSageAppWithStores(bs, projection, zerolog.Nop())
	require.NoError(t, err)
	require.Equal(t, uint64(25), app.currentAppVersion())
	require.NoError(t, MigrateAgentsOnChain(
		context.Background(), projection, bs, "", nil, true, zerolog.Nop(),
	), "startup serving projection must not preempt app-v26 consensus repair")
	projected, err := projection.GetAgent(context.Background(), agentID)
	require.NoError(t, err)
	require.NotNil(t, projected)
	require.Equal(t, "active", projected.Status)

	require.NoError(t, bs.MigrateAppV26AccessGroupAuthorities(4))
	require.NoError(t, bs.MarkUpgradeApplied(appV26UpgradeName, 26, 4))
	require.NoError(t, bs.ValidateAppV23State())
	require.NoError(t, app.Close())

	reopened, err := store.NewBadgerStore(badgerPath)
	require.NoError(t, err)
	strictProjection, err := store.NewSQLiteStore(
		context.Background(), filepath.Join(rootDir, "strict-projection.db"),
	)
	require.NoError(t, err)
	require.NoError(t, MigrateAgentsOnChain(
		context.Background(), strictProjection, reopened, "", nil, true, zerolog.Nop(),
	))
	require.NoError(t, reopened.ValidateAppV23State())
	require.NoError(t, strictProjection.Close())
	require.NoError(t, reopened.CloseBadger())
}

func TestAppV26AppliedConstructorRejectsAReintroducedHomeDefect(t *testing.T) {
	rootDir := t.TempDir()
	badgerPath := filepath.Join(rootDir, "badger")
	bs, agentID := seedDirectAppV25HomeRepairFixture(t, badgerPath)
	require.NoError(t, bs.MigrateAppV26AccessGroupAuthorities(4))
	require.NoError(t, bs.MarkUpgradeApplied(appV26UpgradeName, 26, 4))
	enrollment, err := bs.GetAppV23Enrollment(agentID)
	require.NoError(t, err)
	require.NoError(t, bs.SetState("shared_domain:"+enrollment.HomeDomain, []byte{1}))
	saveAppV26RepairTestState(t, bs, 4)
	require.NoError(t, bs.CloseBadger())

	reopened, err := store.NewBadgerStore(badgerPath)
	require.NoError(t, err)
	_, err = openAppV26RepairTestApp(
		t, reopened, filepath.Join(rootDir, "projection.db"),
	)
	require.ErrorContains(t, err, "shared_home")
	require.NoError(t, reopened.CloseBadger())
}

func TestAppV26AppliedServingProjectionRejectsAReintroducedHomeDefect(t *testing.T) {
	rootDir := t.TempDir()
	bs, agentID := seedDirectAppV25HomeRepairFixture(
		t, filepath.Join(rootDir, "badger"),
	)
	require.NoError(t, bs.MigrateAppV26AccessGroupAuthorities(4))
	require.NoError(t, bs.MarkUpgradeApplied(appV26UpgradeName, 26, 4))
	enrollment, err := bs.GetAppV23Enrollment(agentID)
	require.NoError(t, err)
	require.NoError(t, bs.SetState("shared_domain:"+enrollment.HomeDomain, []byte{1}))
	projection, err := store.NewSQLiteStore(
		context.Background(), filepath.Join(rootDir, "projection.db"),
	)
	require.NoError(t, err)

	_, err = store.ReconcileAppV23AgentProjectionsForPreV26Recovery(
		context.Background(), projection, bs,
	)
	require.ErrorContains(t, err, "forbidden after app-v26")
	require.ErrorContains(t, MigrateAgentsOnChain(
		context.Background(), projection, bs, "", nil, true, zerolog.Nop(),
	), "shared_home")
	require.NoError(t, projection.Close())
	require.NoError(t, bs.CloseBadger())
}

func TestAppV26MarkedActivationCrashWindowReopensAndReplaysIdempotently(t *testing.T) {
	rootDir := t.TempDir()
	badgerPath := filepath.Join(rootDir, "badger")
	bs, agentID := seedDirectAppV25HomeRepairFixture(t, badgerPath)
	enrollment, err := bs.GetAppV23Enrollment(agentID)
	require.NoError(t, err)
	require.NoError(t, bs.SetState("shared_domain:"+enrollment.HomeDomain, []byte{1}))
	require.NoError(t, bs.MigrateAppV26AccessGroupAuthorities(4))
	require.NoError(t, bs.MarkUpgradeApplied(appV26UpgradeName, 26, 4))
	// MarkUpgradeApplied(H) may be durable while Commit has not yet advanced
	// AppState beyond H-1. This is the supported activation crash window.
	saveAppV26RepairTestState(t, bs, 3)
	beforeReplay, err := bs.ComputeAppHash()
	require.NoError(t, err)
	require.NoError(t, bs.MigrateAppV26AccessGroupAuthorities(4))
	afterReplay, err := bs.ComputeAppHash()
	require.NoError(t, err)
	require.Equal(t, beforeReplay, afterReplay)
	require.NoError(t, bs.CloseBadger())

	reopened, err := store.NewBadgerStore(badgerPath)
	require.NoError(t, err)
	app, err := openAppV26RepairTestApp(
		t, reopened, filepath.Join(rootDir, "projection.db"),
	)
	require.NoError(t, err)
	require.Equal(t, uint64(26), app.currentAppVersion())
	require.Equal(t, int64(3), app.state.Height)
	require.NoError(t, app.badgerStore.ValidateAppV23State())
	require.NoError(t, app.Close())
}

func TestAppV26StateSyncRejectsACompletedImageWithInvalidHome(t *testing.T) {
	rootDir := t.TempDir()
	badgerPath := filepath.Join(rootDir, "source")
	bs, agentID := seedDirectAppV25HomeRepairFixture(t, badgerPath)
	require.NoError(t, bs.MigrateAppV26AccessGroupAuthorities(4))
	require.NoError(t, bs.MarkUpgradeApplied(appV26UpgradeName, 26, 4))
	enrollment, err := bs.GetAppV23Enrollment(agentID)
	require.NoError(t, err)
	require.NoError(t, bs.SetState("shared_domain:"+enrollment.HomeDomain, []byte{1}))
	hash := saveAppV26RepairTestState(t, bs, 4)

	backupPath := filepath.Join(rootDir, "invalid-app-v26.backup")
	backup, err := os.OpenFile(backupPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	require.NoError(t, statesync.WriteCanonicalState(context.Background(), bs.DB(), backup))
	require.NoError(t, backup.Close())
	require.NoError(t, bs.CloseBadger())

	err = PrepareAppV20StateSyncBackup(
		context.Background(), backupPath, filepath.Join(rootDir, "prepared"), 4, hash,
	)
	require.ErrorContains(t, err, "shared_home")
}
