package abci

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/poe"
	"github.com/l33tdawg/sage/internal/statesync"
	"github.com/l33tdawg/sage/internal/store"
)

func TestAppV23MigrationBaselineCanonicalStateSyncRoundTrip(t *testing.T) {
	rootDir := t.TempDir()
	source, err := store.NewBadgerStore(filepath.Join(rootDir, "source"))
	require.NoError(t, err)
	root := fmt.Sprintf("%064x", 7001)
	reader := fmt.Sprintf("%064x", 7002)
	require.NoError(t, source.RegisterAgentWithCapabilities(
		root, "root", store.AppV23RoleAdmin, "", "", "", 1, 0,
	))
	require.NoError(t, source.RegisterAgentWithCapabilities(
		reader, "reader", store.AppV23RoleMember, "", "", "", 2, 0,
	))
	require.NoError(t, source.SetAgentPermissionWithCapabilities(
		reader, 1, `[{"domain":"state-sync-domain","read":true}]`,
		`["peer"]`, "", "", 0,
	))
	require.NoError(t, source.RegisterDomain("state-sync-domain", root, "", 3))
	seedTestGovernanceDelegationDomain(t, source)
	require.NoError(t, source.MarkUpgradeApplied(appV20UpgradeName, 20, 1))
	require.NoError(t, source.MarkUpgradeApplied(appV21UpgradeName, 21, 2))
	require.NoError(t, source.MarkUpgradeApplied(appV22UpgradeName, 22, 3))
	require.NoError(t, source.EnsureAppV23Root("migration-state-sync", 100))
	require.NoError(t, source.MarkUpgradeApplied(appV23UpgradeName, 23, 100))
	require.NoError(t, source.ValidateAppV23State())

	state := &AppState{Height: 101, EpochNum: poe.EpochNumber(101)}
	hash, err := source.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	state.AppHash = append([]byte(nil), hash...)
	require.NoError(t, SaveState(source, state))
	hash, err = source.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	state.AppHash = append([]byte(nil), hash...)
	require.NoError(t, SaveState(source, state))

	backupPath := filepath.Join(rootDir, "migration-v23.backup")
	backup, err := os.OpenFile(backupPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	require.NoError(t, statesync.WriteCanonicalState(
		context.Background(), source.DB(), backup,
	))
	require.NoError(t, backup.Close())
	require.NoError(t, source.CloseBadger())

	target := filepath.Join(rootDir, "restored")
	require.NoError(t, PrepareAppV20StateSyncBackup(
		context.Background(), backupPath, target, 101, hash,
	))
	restored, err := store.NewBadgerStore(target)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restored.CloseBadger()) })
	require.NoError(t, restored.ValidateAppV23State())
	decision, err := restored.AppV23LegacyReadCompatibility(
		reader, "state-sync-domain", 1, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.True(t, decision.Eligible)
	require.True(t, decision.Allowed)
	visible, restricted, err := restored.AppV23LegacyVisibleAgents(reader)
	require.NoError(t, err)
	require.True(t, restricted)
	require.Equal(t, `["peer"]`, visible)
}
