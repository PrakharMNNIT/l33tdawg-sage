package store

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppV23ElevationReplayRemainsConsumedAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "badger")
	s, err := NewBadgerStore(path)
	require.NoError(t, err)

	root := appV23Register(t, s, "restart-root", AppV23RoleAdmin, 1, 0)
	admin := appV23Register(t, s, "restart-admin", AppV23RoleAdmin, 2, 0)
	require.NoError(t, s.EnsureAppV23Root("restart-scope", 10))
	use := &AppV23ElevationUse{
		AdminID: admin, RootGeneration: 1,
		ValidFromHeight: 11, ValidUntilHeight: 12,
		Nonce: "restart_replay_nonce_01",
	}
	require.NoError(t, s.ConsumeAppV23Elevation(use, 11))
	require.NoError(t, s.CloseBadger())

	reopened, err := OpenBadgerStoreWithoutMigrations(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reopened.CloseBadger()) })
	require.Error(t, reopened.ConsumeAppV23Elevation(use, 11),
		"restart must not resurrect a consumed one-action elevation")

	state, err := reopened.GetAppV23Root()
	require.NoError(t, err)
	require.Equal(t, root, state.CredentialID)
}
