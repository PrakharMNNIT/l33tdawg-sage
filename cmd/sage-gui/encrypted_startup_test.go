package main

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"sync"
	"testing"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	rpctypes "github.com/cometbft/cometbft/rpc/jsonrpc/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	sageabci "github.com/l33tdawg/sage/internal/abci"
	"github.com/l33tdawg/sage/internal/vault"
)

func TestValidateLockedVaultConsensusShape(t *testing.T) {
	personal := &Config{}
	quorum := &Config{Quorum: QuorumConfig{Enabled: true}}
	stateSync := &Config{Quorum: QuorumConfig{
		StateSync: QuorumStateSyncConfig{Serving: true},
	}}
	tests := []struct {
		name             string
		cfg              *Config
		genesisCount     int
		height           int64
		applicationCount int
		wantError        string
	}{
		{name: "fresh direct genesis", cfg: personal, genesisCount: 1},
		{name: "committed personal chain", cfg: personal, genesisCount: 1, height: 7, applicationCount: 1},
		{name: "quorum config", cfg: quorum, genesisCount: 1, wantError: "quorum and state-sync nodes"},
		{name: "state sync config", cfg: stateSync, genesisCount: 1, wantError: "quorum and state-sync nodes"},
		{name: "multi-validator genesis", cfg: personal, genesisCount: 2, wantError: "genesis has 2 validators"},
		{name: "multi-validator pre-init state", cfg: personal, genesisCount: 1, applicationCount: 2, wantError: "pre-Init application has 2 validators"},
		{name: "missing committed validator", cfg: personal, genesisCount: 1, height: 7, wantError: "committed application state has 0 validators"},
		{name: "multi-validator committed state", cfg: personal, genesisCount: 1, height: 7, applicationCount: 2, wantError: "committed application state has 2 validators"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateLockedVaultConsensusShape(
				test.cfg,
				test.genesisCount,
				test.height,
				test.applicationCount,
			)
			if test.wantError == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.wantError)
			require.ErrorContains(t, err, lockedVaultStartupRemedy)
		})
	}
}

func TestValidateLockedVaultConsensusStartupFailsClosedOnMissingOrMalformedGenesis(t *testing.T) {
	app, badgerStore, projection := openVendoredTestApp(
		t,
		filepath.Join(t.TempDir(), "badger"),
		filepath.Join(t.TempDir(), "projection.db"),
	)
	t.Cleanup(func() {
		require.NoError(t, projection.Close())
		require.NoError(t, badgerStore.CloseBadger())
	})

	genesisPath := filepath.Join(t.TempDir(), "genesis.json")
	err := validateLockedVaultConsensusStartup(
		context.Background(),
		&Config{},
		genesisPath,
		app,
	)
	require.ErrorContains(t, err, "validate locked-vault startup genesis")

	require.NoError(t, os.WriteFile(genesisPath, []byte(`{"chain_id":`), 0o600))
	err = validateLockedVaultConsensusStartup(
		context.Background(),
		&Config{},
		genesisPath,
		app,
	)
	require.ErrorContains(t, err, "validate locked-vault startup genesis")
}

func TestIsolateLockedPersonalP2PRejectsEveryPeerPath(t *testing.T) {
	t.Setenv("SAGE_CMT_P2P_ADDR", "tcp://0.0.0.0:0")
	cfg := vendoredCometConfig(t.TempDir()).P2P
	cfg.ExternalAddress = "tcp://public.example:26656"
	cfg.Seeds = "seed@127.0.0.1:26656"
	cfg.PersistentPeers = "peer@127.0.0.1:26657"
	cfg.UnconditionalPeerIDs = "peer"
	cfg.PrivatePeerIDs = "peer"
	cfg.PexReactor = true
	cfg.SeedMode = true
	cfg.MaxNumInboundPeers = 40
	cfg.MaxNumOutboundPeers = 10

	isolateLockedPersonalP2P(cfg)

	require.Equal(t, "tcp://127.0.0.1:0", cfg.ListenAddress)
	require.Empty(t, cfg.ExternalAddress)
	require.Empty(t, cfg.Seeds)
	require.Empty(t, cfg.PersistentPeers)
	require.Empty(t, cfg.UnconditionalPeerIDs)
	require.Empty(t, cfg.PrivatePeerIDs)
	require.False(t, cfg.PexReactor)
	require.False(t, cfg.SeedMode)
	require.Zero(t, cfg.MaxNumInboundPeers)
	require.Zero(t, cfg.MaxNumOutboundPeers)
}

func TestValidateLockedVaultReplayShape(t *testing.T) {
	hash := sha256.Sum256([]byte("synchronized locked-vault state"))
	otherHash := sha256.Sum256([]byte("different state"))
	tests := []struct {
		name             string
		appHeight        int64
		appHash          []byte
		cometStateEmpty  bool
		cometStateHeight int64
		cometStateHash   []byte
		blockHeight      int64
		wantError        bool
	}{
		{name: "fresh genesis", cometStateEmpty: true},
		{name: "cached genesis without blocks", cometStateHeight: 0},
		{name: "exact positive height", appHeight: 7, appHash: hash[:], cometStateHeight: 7, cometStateHash: hash[:], blockHeight: 7},
		{name: "missing Comet state", appHeight: 7, appHash: hash[:], cometStateEmpty: true, blockHeight: 7, wantError: true},
		{name: "application replay pending", appHeight: 6, appHash: otherHash[:], cometStateHeight: 7, cometStateHash: hash[:], blockHeight: 7, wantError: true},
		{name: "WAL replay pending", appHeight: 7, appHash: hash[:], cometStateHeight: 7, cometStateHash: hash[:], blockHeight: 8, wantError: true},
		{name: "hash disagreement", appHeight: 7, appHash: otherHash[:], cometStateHeight: 7, cometStateHash: hash[:], blockHeight: 7, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateLockedVaultReplayShape(
				test.appHeight,
				test.appHash,
				test.cometStateEmpty,
				test.cometStateHeight,
				test.cometStateHash,
				test.blockHeight,
			)
			if !test.wantError {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, "unlock before CometBFT starts")
			require.ErrorContains(t, err, lockedVaultStartupRemedy)
		})
	}
}

func TestLockedPersonalRawLocalRPCRejectsUntilVaultPublication(t *testing.T) {
	t.Setenv("SAGE_CMT_P2P_ADDR", "tcp://127.0.0.1:0")
	cometHome := t.TempDir()
	sageHome := t.TempDir()
	t.Setenv("SAGE_HOME", sageHome)
	rootKeyPath := filepath.Join(sageHome, "agent.key")
	bootstrap := &VendoredAgentBootstrapConfig{
		AgentKeyFile: filepath.Join(sageHome, "agents", "mynah", "agent.key"),
		HomeDomain:   "voice-interface",
		Clearance:    1,
	}
	require.NoError(t, initCometBFTConfigWithBootstrap(cometHome, rootKeyPath, bootstrap))
	genesis, err := cmttypes.GenesisDocFromFile(filepath.Join(cometHome, "config", "genesis.json"))
	require.NoError(t, err)

	app, badgerStore, projection := openVendoredTestApp(
		t,
		filepath.Join(t.TempDir(), "badger"),
		filepath.Join(t.TempDir(), "projection.db"),
	)
	t.Cleanup(func() {
		require.NoError(t, projection.Close())
		require.NoError(t, badgerStore.CloseBadger())
	})
	projection.SetVaultExpected(true)
	require.NoError(t, app.SetExpectedGovernanceDelegationDomain(genesis.ChainID))

	bundle, err := sageabci.NewConsensusBundleWithCleanup(
		context.Background(),
		app,
		app.CloseConsensusState,
	)
	require.NoError(t, err)
	runtime, err := sageabci.NewBootStateSyncRuntime(bundle)
	require.NoError(t, err)
	runtime.SetLocalTxAdmissionBlocked(true)

	cometCfg := vendoredCometConfig(cometHome)
	isolateLockedPersonalP2P(cometCfg.P2P)
	pv := privval.LoadFilePV(cometCfg.PrivValidatorKeyFile(), cometCfg.PrivValidatorStateFile())
	nodeKey, err := p2p.LoadNodeKey(cometCfg.NodeKeyFile())
	require.NoError(t, err)
	controller := NewSageNodeController(
		cometCfg,
		runtime,
		pv,
		nodeKey,
		cmtlog.NewNopLogger(),
		zerolog.Nop(),
		t.TempDir(),
	)
	require.NoError(t, controller.StartChain())
	t.Cleanup(func() { require.NoError(t, controller.StopChain()) })

	rpcEnvironment, err := controller.GetCometNode().ConfigureRPC()
	require.NoError(t, err)
	raw := vendoredFirstMemoryRaw(t, bootstrap)
	denied, err := rpcEnvironment.BroadcastTxSync(&rpctypes.Context{}, cmttypes.Tx(raw))
	require.NoError(t, err)
	require.Equal(t, uint32(112), denied.Code)
	require.Equal(t, "sage-local-admission", denied.Codespace)

	vaultKeyPath := filepath.Join(t.TempDir(), "vault.key")
	require.NoError(t, vault.Init(vaultKeyPath, "locked-personal-test"))
	unlocked, err := vault.Open(vaultKeyPath, "locked-personal-test")
	require.NoError(t, err)

	// Exercise publication against concurrent local CheckTx calls. Every call
	// before the latch opens is denied; after it opens the already-published
	// vault makes the real memory transaction safe to commit.
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = runtime.CheckTx(
				context.Background(),
				&abcitypes.RequestCheckTx{Tx: []byte("concurrent local probe")},
			)
		}()
	}
	projection.SetVault(unlocked)
	runtime.SetLocalTxAdmissionBlocked(false)
	wg.Wait()

	accepted, err := rpcEnvironment.BroadcastTxCommit(
		&rpctypes.Context{},
		cmttypes.Tx(raw),
	)
	require.NoError(t, err)
	require.Zero(t, accepted.CheckTx.Code, accepted.CheckTx.Log)
	require.Zero(t, accepted.TxResult.Code, accepted.TxResult.Log)
	require.NotEmpty(t, accepted.TxResult.Data)
}
