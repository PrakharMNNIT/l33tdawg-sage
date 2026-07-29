package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/vault"
)

func TestSQLiteVaultPublicationIsRaceSafe(t *testing.T) {
	sqliteStore, err := NewSQLiteStore(
		context.Background(),
		filepath.Join(t.TempDir(), "projection.db"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqliteStore.Close()) })
	sqliteStore.SetVaultExpected(true)

	keyPath := filepath.Join(t.TempDir(), "vault.key")
	require.NoError(t, vault.Init(keyPath, "race-safe-vault"))
	unlocked, err := vault.Open(keyPath, "race-safe-vault")
	require.NoError(t, err)

	var readers sync.WaitGroup
	for range 16 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 250 {
				_ = sqliteStore.VaultLocked()
				_ = sqliteStore.VaultActive()
				_, _ = sqliteStore.encryptContent("concurrent projection")
				_, _ = sqliteStore.encryptEmbedding([]byte("embedding"))
			}
		}()
	}
	sqliteStore.SetVault(unlocked)
	readers.Wait()

	require.True(t, sqliteStore.VaultActive())
	require.False(t, sqliteStore.VaultLocked())
	encrypted, err := sqliteStore.encryptContent("published")
	require.NoError(t, err)
	require.NotEqual(t, "published", encrypted)
}
