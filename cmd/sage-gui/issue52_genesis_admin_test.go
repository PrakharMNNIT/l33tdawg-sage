package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cmtcryptoed "github.com/cometbft/cometbft/crypto/ed25519"
	cmttypes "github.com/cometbft/cometbft/types"
	cmttime "github.com/cometbft/cometbft/types/time"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// Test 4: ensureOperatorAdminID derives the canonical lowercase-hex PUBLIC key from
// both on-disk agent.key formats (32-byte seed and 64-byte private key), generates
// one if absent, and the result equals readNodeOperatorKey() and decodes to 32 bytes.
func TestIssue52_EnsureOperatorAdminID(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	want := hex.EncodeToString(pub)

	for name, keyBytes := range map[string][]byte{
		"32-byte-seed":       priv.Seed(),
		"64-byte-privatekey": priv,
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("SAGE_HOME", home)
			require.NoError(t, os.WriteFile(filepath.Join(home, "agent.key"), keyBytes, 0600))

			got := ensureOperatorAdminID()
			require.Equal(t, want, got, "derived admin id must be hex(pub)")
			require.Len(t, got, 64)
			raw, err := hex.DecodeString(got)
			require.NoError(t, err)
			require.Len(t, raw, ed25519.PublicKeySize)

			rk, err := readNodeOperatorKey(filepath.Join(home, "agent.key"))
			require.NoError(t, err)
			require.Equal(t, rk, got, "must match readNodeOperatorKey")
		})
	}

	t.Run("generate-if-absent", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("SAGE_HOME", home)
		got := ensureOperatorAdminID()
		require.Len(t, got, 64, "must generate a key and return its pubkey hex")
		_, statErr := os.Stat(filepath.Join(home, "agent.key"))
		require.NoError(t, statErr, "agent.key must now exist")
		// second call is stable (reads the generated key)
		require.Equal(t, got, ensureOperatorAdminID())
	})
}

func TestIssue52_GenesisAppStateHasInitialAdmin(t *testing.T) {
	id := hex.EncodeToString(make([]byte, 32))
	require.False(t, genesisAppStateHasInitialAdmin(nil))
	require.False(t, genesisAppStateHasInitialAdmin(json.RawMessage(`{}`)))
	require.False(t, genesisAppStateHasInitialAdmin(json.RawMessage(`{"sage":{}}`)))
	require.False(t, genesisAppStateHasInitialAdmin(json.RawMessage(`{"sage":{"initial_admin":""}}`)))
	require.False(t, genesisAppStateHasInitialAdmin(json.RawMessage(`not json`)))
	require.True(t, genesisAppStateHasInitialAdmin(json.RawMessage(`{"sage":{"initial_admin":"`+id+`"}}`)))
}

// i52WriteGenesis writes a genesis.json under home/config with nVals validators and
// the given app_state (nil for none), returning the operator's admin id.
func i52WriteGenesis(t *testing.T, home string, nVals int, appState json.RawMessage) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(home, "config"), 0700))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "data"), 0700))
	vals := make([]cmttypes.GenesisValidator, 0, nVals)
	for i := 0; i < nVals; i++ {
		pk := cmtcryptoed.GenPrivKey().PubKey()
		vals = append(vals, cmttypes.GenesisValidator{Address: pk.Address(), PubKey: pk, Power: 10, Name: "v"})
	}
	gd := cmttypes.GenesisDoc{
		ChainID: "sage-personal", GenesisTime: cmttime.Now(),
		ConsensusParams: cmttypes.DefaultConsensusParams(), Validators: vals, AppState: appState,
	}
	require.NoError(t, gd.ValidateAndComplete())
	require.NoError(t, gd.SaveAs(filepath.Join(home, "config", "genesis.json")))
}

func i52ReadGenesisAppState(t *testing.T, home string) json.RawMessage {
	t.Helper()
	gd, err := cmttypes.GenesisDocFromFile(filepath.Join(home, "config", "genesis.json"))
	require.NoError(t, err)
	return gd.AppState
}

// Test M6: healGenesisAdminIfReset injects the admin ONLY when the chain is at
// height-0 (no block store) and the genesis is a single-validator chain without an
// existing admin. It must NEVER touch a live chain's genesis.
func TestIssue52_HealGenesisAdminIfReset(t *testing.T) {
	// In production the CometBFT home (config/genesis.json + data/) and the SAGE home
	// (agent.key, via SageHome()) are DISTINCT directories. setup wires up that real
	// two-dir layout: agent.key under sageHome, genesis under cometHome, and returns
	// the cometHome to pass to healGenesisAdminIfReset plus the operator's admin id.
	setup := func(t *testing.T) (cometHome, admin string) {
		cometHome = t.TempDir()
		sageHome := t.TempDir()
		t.Setenv("SAGE_HOME", sageHome)
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(sageHome, "agent.key"), priv.Seed(), 0600))
		return cometHome, hex.EncodeToString(pub)
	}

	t.Run("reset-single-validator-no-admin -> injects", func(t *testing.T) {
		cometHome, admin := setup(t)
		i52WriteGenesis(t, cometHome, 1, nil) // no app_state, no blockstore/state (height 0)
		healGenesisAdminIfReset(cometHome, zerolog.Nop())
		require.True(t, genesisAppStateHasInitialAdmin(i52ReadGenesisAppState(t, cometHome)))
		require.Contains(t, string(i52ReadGenesisAppState(t, cometHome)), admin)
	})

	t.Run("LIVE chain (blockstore.db present) -> genesis untouched", func(t *testing.T) {
		cometHome, _ := setup(t)
		i52WriteGenesis(t, cometHome, 1, nil)
		require.NoError(t, os.MkdirAll(filepath.Join(cometHome, "data", "blockstore.db"), 0700)) // live
		healGenesisAdminIfReset(cometHome, zerolog.Nop())
		require.False(t, genesisAppStateHasInitialAdmin(i52ReadGenesisAppState(t, cometHome)),
			"a live chain's genesis must NOT be rewritten")
	})

	t.Run("partial reset (state.db survives) -> genesis untouched", func(t *testing.T) {
		cometHome, _ := setup(t)
		i52WriteGenesis(t, cometHome, 1, nil)
		// blockstore.db wiped but state.db survived: CometBFT loads the cached
		// (admin-less) genesis doc from state.db FIRST, so a rewrite would be silently
		// ignored and the chain would re-deadlock. heal MUST treat this as live.
		require.NoError(t, os.MkdirAll(filepath.Join(cometHome, "data", "state.db"), 0700))
		healGenesisAdminIfReset(cometHome, zerolog.Nop())
		require.False(t, genesisAppStateHasInitialAdmin(i52ReadGenesisAppState(t, cometHome)),
			"a surviving state.db must block the rewrite (cached genesis doc would win)")
	})

	t.Run("already-seeded -> no-op", func(t *testing.T) {
		cometHome, _ := setup(t)
		existing := hex.EncodeToString(make([]byte, 32))
		i52WriteGenesis(t, cometHome, 1, json.RawMessage(`{"sage":{"initial_admin":"`+existing+`"}}`))
		healGenesisAdminIfReset(cometHome, zerolog.Nop())
		require.Contains(t, string(i52ReadGenesisAppState(t, cometHome)), existing,
			"existing admin must be preserved")
	})

	t.Run("multi-validator -> not touched", func(t *testing.T) {
		cometHome, _ := setup(t)
		i52WriteGenesis(t, cometHome, 2, nil)
		healGenesisAdminIfReset(cometHome, zerolog.Nop())
		require.False(t, genesisAppStateHasInitialAdmin(i52ReadGenesisAppState(t, cometHome)))
	})

	t.Run("no genesis -> no panic", func(t *testing.T) {
		cometHome, _ := setup(t)
		require.NotPanics(t, func() { healGenesisAdminIfReset(cometHome, zerolog.Nop()) })
	})
}

func TestIssue52_ExistingAdminlessGenesisIsNotHealedAtStartup(t *testing.T) {
	cometHome := t.TempDir()
	sageHome := t.TempDir()
	t.Setenv("SAGE_HOME", sageHome)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(sageHome, "agent.key"), priv.Seed(), 0o600))

	i52WriteGenesis(t, cometHome, 1, nil)
	genesisPath := filepath.Join(cometHome, "config", "genesis.json")
	before, err := os.ReadFile(genesisPath)
	require.NoError(t, err)

	require.NoError(t, ensureGenesisSeed(cometHome, zerolog.Nop()))
	after, err := os.ReadFile(genesisPath)
	require.NoError(t, err)
	require.Equal(t, before, after, "startup must not rewrite existing genesis authority")
	require.False(t, genesisAppStateHasInitialAdmin(i52ReadGenesisAppState(t, cometHome)))
	require.NoFileExists(t, genesisPath+".bak")
}

func TestInitializedOriginMissingGenesisRefusesWithoutMutation(t *testing.T) {
	cometHome := t.TempDir()
	statePath := filepath.Join(cometHome, "data", "state.db", "sentinel")
	require.NoError(t, os.MkdirAll(filepath.Dir(statePath), 0o700))
	require.NoError(t, os.WriteFile(statePath, []byte("preserve"), 0o600))

	err := preflightGenesisOrigin(cometHome, false)
	require.Error(t, err)
	data, readErr := os.ReadFile(statePath)
	require.NoError(t, readErr)
	require.Equal(t, "preserve", string(data))
	require.NoFileExists(t, filepath.Join(cometHome, "config", "genesis.json"))
}

func TestIssue52_RepairChainStateIsDisabledAndPreservesHistory(t *testing.T) {
	dataDir := t.TempDir()
	sageHome := t.TempDir()
	t.Setenv("SAGE_HOME", sageHome)

	cometHome := filepath.Join(dataDir, "cometbft")
	i52WriteGenesis(t, cometHome, 1, nil)
	cometData := filepath.Join(cometHome, "data")
	require.NoError(t, os.MkdirAll(filepath.Join(cometData, "blockstore.db"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(cometData, "state.db"), 0o700))
	badgerPath := filepath.Join(dataDir, "badger")
	require.NoError(t, os.MkdirAll(badgerPath, 0o700))
	sentinel := filepath.Join(badgerPath, "canonical.sentinel")
	require.NoError(t, os.WriteFile(sentinel, []byte("preserve"), 0o600))

	err := repairChainState(dataDir, zerolog.Nop())
	require.ErrorIs(t, err, errDestructiveChainRepairDisabled)
	require.DirExists(t, filepath.Join(cometData, "blockstore.db"))
	require.DirExists(t, filepath.Join(cometData, "state.db"))
	require.FileExists(t, sentinel)
	require.False(t, genesisAppStateHasInitialAdmin(i52ReadGenesisAppState(t, cometHome)))
}

// TestIssue52_InitCometBFTConfigSeedsNewChain covers the PREVENTION path: when
// initCometBFTConfig CREATES a brand-new chain's genesis (none exists yet), it must
// seed the operator key as app_state.sage.initial_admin so a freshly-born personal
// chain is admin-protected from the start and never strands climbing the fork ladder.
func TestIssue52_InitCometBFTConfigSeedsNewChain(t *testing.T) {
	cometHome := t.TempDir()
	sageHome := t.TempDir()
	t.Setenv("SAGE_HOME", sageHome)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(sageHome, "agent.key"), priv.Seed(), 0600))
	adminID := hex.EncodeToString(pub)

	require.NoError(t, initCometBFTConfig(cometHome)) // no genesis yet -> creates one

	as := i52ReadGenesisAppState(t, cometHome)
	require.True(t, genesisAppStateHasInitialAdmin(as), "a newly created genesis must carry the admin seed")
	require.Contains(t, string(as), adminID, "the seed must be the operator's agent.key pubkey")
}
