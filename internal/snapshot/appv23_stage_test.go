package snapshot

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/l33tdawg/sage/internal/store"
)

func TestStandaloneSnapshotHashTracksPromotedAppV23Stage(t *testing.T) {
	path := t.TempDir()
	source, err := store.NewBadgerStore(path)
	require.NoError(t, err)
	for i := 0; i < 513; i++ {
		id := fmt.Sprintf("%064x", i+1)
		role := store.AppV23RoleMember
		if i == 0 {
			role = store.AppV23RoleAdmin
		}
		require.NoError(t, source.RegisterAgentWithCapabilities(
			id, fmt.Sprintf("legacy-%d", i), role, "", "", "",
			int64(i+1), 0,
		))
	}
	before, err := source.ComputeAppHash()
	require.NoError(t, err)
	require.NoError(t, source.PrepareAppV23Migration("snapshot-stage", 100))
	prepared, err := source.ComputeAppHash()
	require.NoError(t, err)
	require.Equal(t, before, prepared)
	require.NoError(t, source.CloseBadger())
	standalonePrepared, err := computeAppHashStandalone(path)
	require.NoError(t, err)
	require.Equal(t, before, standalonePrepared)

	source, err = store.NewBadgerStore(path)
	require.NoError(t, err)
	require.NoError(t, source.EnsureAppV23Root("snapshot-stage", 100))
	require.NoError(t, source.ValidateAppV23State())
	activated, err := source.ComputeAppHash()
	require.NoError(t, err)
	require.NotEqual(t, before, activated)
	require.NoError(t, source.CloseBadger())
	standaloneActivated, err := computeAppHashStandalone(path)
	require.NoError(t, err)
	require.Equal(t, activated, standaloneActivated)
}

func TestTakeVerifyRestorePromotedAppV23Stage(t *testing.T) {
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "source", "data")
	require.NoError(t, os.MkdirAll(dataDir, 0o700))
	source, err := store.NewBadgerStore(filepath.Join(dataDir, "badger"))
	require.NoError(t, err)
	var memberID string
	for i := 0; i < 513; i++ {
		id := fmt.Sprintf("%064x", i+1)
		role := store.AppV23RoleMember
		if i == 0 {
			role = store.AppV23RoleAdmin
		}
		if i == 1 {
			memberID = id
		}
		require.NoError(t, source.RegisterAgentWithCapabilities(
			id, fmt.Sprintf("legacy-%d", i), role, "", "", "",
			int64(i+1), 0,
		))
	}
	require.NoError(t, source.EnsureAppV23Root("private-snapshot-stage", 100))
	require.NoError(t, source.ValidateAppV23State())
	appHash, err := source.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)

	sqliteDB, err := sql.Open("sqlite", filepath.Join(dataDir, "sage.db"))
	require.NoError(t, err)
	_, err = sqliteDB.Exec(`CREATE TABLE snapshot_fixture (id INTEGER PRIMARY KEY)`)
	require.NoError(t, err)
	require.NoError(t, sqliteDB.Close())
	for _, relative := range []string{
		"cometbft/data/blockstore.db",
		"cometbft/data/state.db",
		"cometbft/data/tx_index.db",
		"cometbft/config",
	} {
		require.NoError(t, os.MkdirAll(filepath.Join(dataDir, relative), 0o700))
	}
	require.NoError(t, os.WriteFile(
		filepath.Join(dataDir, "cometbft", "data", "priv_validator_state.json"),
		[]byte(`{"height":"100","round":0,"step":0}`), 0o600,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(dataDir, "cometbft", "config", "genesis.json"),
		[]byte(`{"chain_id":"snapshot-appv23"}`), 0o600,
	))

	_, err = Take(
		context.Background(), dataDir, 100, appHash, "appv23-stage",
		Options{
			BinaryVersion: "v11.15.0-test",
			IncludeBinary: false,
			LiveBadger:    source.DB(),
		},
	)
	require.NoError(t, err)
	snapshotDir := filepath.Join(snapshotsRoot(dataDir), "100")
	require.NoError(t, Verify(snapshotDir))
	require.NoError(t, source.CloseBadger())

	restoreDir := filepath.Join(parent, "restored", "data")
	height, err := Restore(snapshotDir, restoreDir)
	require.NoError(t, err)
	require.Equal(t, int64(100), height)
	restored, err := store.NewBadgerStore(filepath.Join(restoreDir, "badger"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restored.CloseBadger()) })
	require.NoError(t, restored.ValidateAppV23State())
	restoredHash, err := restored.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	require.Equal(t, appHash, restoredHash)
	enrollment, err := restored.GetAppV23Enrollment(memberID)
	require.NoError(t, err)
	require.NotNil(t, enrollment)
	require.True(t, enrollment.Active)
}
