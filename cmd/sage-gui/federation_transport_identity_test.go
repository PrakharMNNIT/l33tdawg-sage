package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type federationTransportTestLayout struct {
	home      string
	dataDir   string
	cometHome string
	keyPath   string
}

func newFederationTransportTestLayout(t *testing.T) federationTransportTestLayout {
	t.Helper()
	home := t.TempDir()
	layout := federationTransportTestLayout{
		home:      home,
		dataDir:   filepath.Join(home, "data"),
		cometHome: filepath.Join(home, "data", "cometbft"),
		keyPath:   filepath.Join(home, "agent.key"),
	}
	require.NoError(t, os.MkdirAll(filepath.Join(layout.dataDir, "badger"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(layout.cometHome, "config"), 0o700))
	return layout
}

func loadTestFederationTransportKey(
	layout federationTransportTestLayout,
) (ed25519.PrivateKey, error) {
	return loadStableFederationTransportKey(
		layout.keyPath, layout.home, layout.dataDir, layout.cometHome,
	)
}

func TestStableFederationTransportKeyFreshNodeGeneratesOnce(t *testing.T) {
	layout := newFederationTransportTestLayout(t)

	key, err := loadTestFederationTransportKey(layout)
	require.NoError(t, err)
	require.Len(t, key, ed25519.PrivateKeySize)
	seed, err := os.ReadFile(layout.keyPath)
	require.NoError(t, err)
	require.Len(t, seed, ed25519.SeedSize)
	assert.Equal(t, key.Seed(), seed)

	reloaded, err := loadTestFederationTransportKey(layout)
	require.NoError(t, err)
	assert.Equal(t, key, reloaded)
}

func TestStableFederationTransportKeyInterruptedPreGenesisIdentityRequiresRecovery(t *testing.T) {
	layout := newFederationTransportTestLayout(t)
	// Validator and peer keys are durable identities even when a crash happens
	// before genesis/app_state is saved. Minting a new transport key around those
	// residues would create a mixed-origin node, so recovery must be explicit.
	require.NoError(t, os.WriteFile(
		filepath.Join(layout.cometHome, "config", "priv_validator_key.json"),
		[]byte(`{"partial":true}`),
		0o600,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(layout.cometHome, "config", "node_key.json"),
		[]byte(`{"partial":true}`),
		0o600,
	))

	key, err := loadTestFederationTransportKey(layout)
	require.Error(t, err)
	require.Nil(t, key)
	require.ErrorContains(t, err, "CometBFT validator identity")
	require.NoFileExists(t, layout.keyPath)
}

func TestStableFederationTransportKeyFreshCustomPathCreatesPrivateDirectory(t *testing.T) {
	layout := newFederationTransportTestLayout(t)
	layout.keyPath = filepath.Join(layout.home, "custom", "transport", "node.key")

	key, err := loadTestFederationTransportKey(layout)
	require.NoError(t, err)
	require.Len(t, key, ed25519.PrivateKeySize)
	info, err := os.Stat(filepath.Dir(layout.keyPath))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	require.FileExists(t, layout.keyPath)
}

func TestStableFederationTransportKeyLoadsBothSupportedFormats(t *testing.T) {
	for _, format := range []struct {
		name string
		full bool
	}{
		{name: "32-byte seed"},
		{name: "64-byte private key", full: true},
	} {
		t.Run(format.name, func(t *testing.T) {
			layout := newFederationTransportTestLayout(t)
			_, want, err := ed25519.GenerateKey(nil)
			require.NoError(t, err)
			data := want.Seed()
			if format.full {
				data = want
			}
			require.NoError(t, os.WriteFile(layout.keyPath, data, 0o600))
			require.NoError(t, os.WriteFile(
				filepath.Join(layout.cometHome, "config", "genesis.json"),
				[]byte(`{"chain_id":"established"}`),
				0o600,
			))

			got, err := loadTestFederationTransportKey(layout)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

func TestStableFederationTransportKeyRejectsInconsistent64ByteKey(t *testing.T) {
	layout := newFederationTransportTestLayout(t)
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	corrupt := append([]byte(nil), key...)
	corrupt[len(corrupt)-1] ^= 0xff
	require.NoError(t, os.WriteFile(layout.keyPath, corrupt, 0o600))
	require.NoError(t, os.WriteFile(
		filepath.Join(layout.cometHome, "config", "genesis.json"),
		[]byte(`{"chain_id":"established"}`),
		0o600,
	))

	got, err := loadTestFederationTransportKey(layout)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "public component does not match seed")
	after, readErr := os.ReadFile(layout.keyPath)
	require.NoError(t, readErr)
	assert.Equal(t, corrupt, after, "startup must preserve the damaged key for recovery")
}

func TestStableFederationTransportBootstrapIsVaultModeIndependent(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "unencrypted"
		if encrypted {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) {
			layout := newFederationTransportTestLayout(t)
			key, err := loadTestFederationTransportKey(layout)
			require.NoError(t, err)
			cfg := &Config{
				AgentKey: layout.keyPath,
				DataDir:  layout.dataDir,
				Encryption: EncryptionConfig{
					Enabled: encrypted,
				},
			}
			require.NoError(t, ensureGenesisSeedWithConfig(
				layout.cometHome, cfg, zerolog.Nop(),
			))
			require.NoError(t, verifyStableFederationTransportKey(layout.keyPath, key))

			genesis, err := os.ReadFile(filepath.Join(
				layout.cometHome, "config", "genesis.json",
			))
			require.NoError(t, err)
			rootID := hex.EncodeToString(key.Public().(ed25519.PublicKey))
			assert.Contains(t, string(genesis), rootID)
		})
	}
}

func TestStableFederationTransportKeyIgnoresRotatedRootBundle(t *testing.T) {
	layout := newFederationTransportTestLayout(t)
	_, transportKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(layout.keyPath, transportKey.Seed(), 0o600))
	require.NoError(t, os.WriteFile(
		filepath.Join(layout.cometHome, "config", "genesis.json"),
		[]byte(`{"chain_id":"established"}`),
		0o600,
	))

	_, rotatedRoot, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	rootBundle := filepath.Join(
		layout.home,
		"bundles",
		hex.EncodeToString(rotatedRoot.Public().(ed25519.PublicKey)),
	)
	require.NoError(t, os.MkdirAll(rootBundle, 0o700))
	require.NoError(t, os.WriteFile(
		filepath.Join(rootBundle, "agent.key"), rotatedRoot.Seed(), 0o600,
	))

	got, err := loadTestFederationTransportKey(layout)
	require.NoError(t, err)
	assert.Equal(t, transportKey, got)
	assert.NotEqual(t, rotatedRoot, got)
}

func TestStableFederationTransportKeyEstablishedStateNeverRegeneratesMissingKey(t *testing.T) {
	tests := []struct {
		name  string
		seed  func(t *testing.T, layout federationTransportTestLayout)
		label string
	}{
		{
			name: "existing node without agreements",
			seed: func(t *testing.T, layout federationTransportTestLayout) {
				require.NoError(t, os.WriteFile(
					filepath.Join(layout.cometHome, "config", "genesis.json"),
					[]byte(`{"chain_id":"established"}`),
					0o600,
				))
			},
			label: "CometBFT genesis",
		},
		{
			name: "damaged genesis path is a directory",
			seed: func(t *testing.T, layout federationTransportTestLayout) {
				require.NoError(t, os.Mkdir(
					filepath.Join(layout.cometHome, "config", "genesis.json"),
					0o700,
				))
			},
			label: "CometBFT genesis",
		},
		{
			name: "crash-surviving SQLite agreement state",
			seed: func(t *testing.T, layout federationTransportTestLayout) {
				require.NoError(t, os.WriteFile(
					filepath.Join(layout.dataDir, "sage.db"),
					[]byte("non-empty persisted agreement state"),
					0o600,
				))
			},
			label: "SQLite node state",
		},
		{
			name: "crash-surviving Badger agreement state",
			seed: func(t *testing.T, layout federationTransportTestLayout) {
				require.NoError(t, os.WriteFile(
					filepath.Join(layout.dataDir, "badger", "MANIFEST"),
					[]byte("persisted"),
					0o600,
				))
			},
			label: "Badger chain state",
		},
		{
			name: "federation trust material without stores",
			seed: func(t *testing.T, layout federationTransportTestLayout) {
				dir := filepath.Join(layout.home, "certs", "federation")
				require.NoError(t, os.MkdirAll(dir, 0o700))
				require.NoError(t, os.WriteFile(
					filepath.Join(dir, "peer-ca.pem"),
					[]byte("persisted"),
					0o600,
				))
			},
			label: "federation trust material",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			layout := newFederationTransportTestLayout(t)
			tt.seed(t, layout)

			key, err := loadTestFederationTransportKey(layout)
			require.Error(t, err)
			assert.Nil(t, key)
			assert.Contains(t, err.Error(), "stable node federation transport key is missing")
			assert.Contains(t, err.Error(), tt.label)
			assert.Contains(t, err.Error(), federationTransportKeyRecoveryGuidance)
			assert.NoFileExists(t, layout.keyPath)
		})
	}
}

func TestStableFederationTransportKeyEstablishedCorruptionIsPreservedForRecovery(t *testing.T) {
	layout := newFederationTransportTestLayout(t)
	require.NoError(t, os.WriteFile(
		filepath.Join(layout.cometHome, "config", "genesis.json"),
		[]byte(`{"chain_id":"established"}`),
		0o600,
	))
	corrupt := []byte("not-an-ed25519-key")
	require.NoError(t, os.WriteFile(layout.keyPath, corrupt, 0o600))

	key, err := loadTestFederationTransportKey(layout)
	require.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "stable node federation transport key is unreadable")
	assert.Contains(t, err.Error(), "invalid key file size")
	assert.Contains(t, err.Error(), federationTransportKeyRecoveryGuidance)
	after, readErr := os.ReadFile(layout.keyPath)
	require.NoError(t, readErr)
	assert.Equal(t, corrupt, after, "startup must not rewrite recovery evidence")
}

func TestStableFederationTransportKeyFreshFirstLaunchRaceUsesOneIdentity(t *testing.T) {
	layout := newFederationTransportTestLayout(t)
	const callers = 24
	ids := make(chan string, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, err := loadTestFederationTransportKey(layout)
			if err == nil {
				ids <- hex.EncodeToString(key.Public().(ed25519.PublicKey))
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
	unique := make(map[string]struct{})
	for id := range ids {
		unique[id] = struct{}{}
	}
	require.Len(t, unique, 1)
}

func TestStableFederationTransportKeyEstablishedMissingRaceNeverCreates(t *testing.T) {
	layout := newFederationTransportTestLayout(t)
	require.NoError(t, os.WriteFile(
		filepath.Join(layout.cometHome, "config", "genesis.json"),
		[]byte(`{"chain_id":"established"}`),
		0o600,
	))

	const callers = 24
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := loadTestFederationTransportKey(layout)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		require.Error(t, err)
		assert.Contains(t, err.Error(), "will not generate a replacement")
	}
	assert.NoFileExists(t, layout.keyPath)
}

func TestVerifyStableFederationTransportKeyRejectsStartupReplacement(t *testing.T) {
	layout := newFederationTransportTestLayout(t)
	_, original, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(layout.keyPath, original.Seed(), 0o600))
	require.NoError(t, verifyStableFederationTransportKey(layout.keyPath, original))

	_, replacement, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(layout.keyPath, replacement.Seed(), 0o600))
	err = verifyStableFederationTransportKey(layout.keyPath, original)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "changed during startup")
	assert.Contains(t, err.Error(), federationTransportKeyRecoveryGuidance)
	assert.False(t, bytes.Equal(original, replacement))
}
