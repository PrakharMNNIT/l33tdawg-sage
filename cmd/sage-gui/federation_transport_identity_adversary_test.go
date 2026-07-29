package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover crash artifacts that prove a node reached durable CometBFT
// state even if the two primary DB directories or genesis were later damaged.
// Treating such a layout as a fresh node can silently mint a transport identity
// that no longer matches peer pins.
func TestAdversaryStableFederationTransportKeyRecognizesPartialCometState(t *testing.T) {
	tests := []struct {
		name string
		path func(federationTransportTestLayout) string
	}{
		{
			name: "validator signing state",
			path: func(layout federationTransportTestLayout) string {
				return filepath.Join(layout.cometHome, "data", "priv_validator_state.json")
			},
		},
		{
			name: "transaction index",
			path: func(layout federationTransportTestLayout) string {
				return filepath.Join(layout.cometHome, "data", "tx_index.db")
			},
		},
		{
			name: "evidence database",
			path: func(layout federationTransportTestLayout) string {
				return filepath.Join(layout.cometHome, "data", "evidence.db")
			},
		},
		{
			name: "genesis backup",
			path: func(layout federationTransportTestLayout) string {
				return filepath.Join(layout.cometHome, "config", "genesis.json.bak")
			},
		},
		{
			name: "SQLite write ahead log",
			path: func(layout federationTransportTestLayout) string {
				return filepath.Join(layout.dataDir, "sage.db-wal")
			},
		},
		{
			name: "SQLite shared memory state",
			path: func(layout federationTransportTestLayout) string {
				return filepath.Join(layout.dataDir, "sage.db-shm")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			layout := newFederationTransportTestLayout(t)
			evidencePath := tt.path(layout)
			require.NoError(t, os.MkdirAll(filepath.Dir(evidencePath), 0o700))
			require.NoError(t, os.WriteFile(evidencePath, []byte("persisted"), 0o600))

			key, err := loadTestFederationTransportKey(layout)
			require.Error(t, err)
			assert.Nil(t, key)
			assert.Contains(t, err.Error(), "stable node federation transport key is missing")
			assert.NoFileExists(t, layout.keyPath)
		})
	}
}

// A dangling durable-state path is corruption evidence, not proof that the
// node is fresh. os.Stat follows the link and reports ENOENT; this sentinel
// requires startup to notice the directory entry itself and fail closed.
func TestAdversaryStableFederationTransportKeyTreatsDanglingEvidenceSymlinkAsInitialized(t *testing.T) {
	layout := newFederationTransportTestLayout(t)
	genesisPath := filepath.Join(layout.cometHome, "config", "genesis.json")
	require.NoError(t, os.Symlink("missing-genesis-target", genesisPath))

	key, err := loadTestFederationTransportKey(layout)
	require.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "stable node federation transport key is missing")
	assert.NoFileExists(t, layout.keyPath)
}

// Peer pins bind the Ed25519 identity, not a local inode or config spelling.
// A pending-join config reload may therefore relocate the file without changing
// trust, provided the exact semantically-valid key bytes are re-read. This also
// prevents a false positive for normalized/symlinked configuration paths.
func TestAdversaryVerifyStableFederationTransportKeyAllowsExactIdentityRelocation(t *testing.T) {
	layout := newFederationTransportTestLayout(t)
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(layout.keyPath, key.Seed(), 0o600))

	relocatedPath := filepath.Join(layout.home, "relocated", "agent.key")
	require.NoError(t, os.MkdirAll(filepath.Dir(relocatedPath), 0o700))
	require.NoError(t, os.WriteFile(relocatedPath, key.Seed(), 0o600))

	err = verifyStableFederationTransportKey(relocatedPath, key)
	require.NoError(t, err)
}
