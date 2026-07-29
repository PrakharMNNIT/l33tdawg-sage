package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	cmtconfig "github.com/cometbft/cometbft/config"
	cmtstate "github.com/cometbft/cometbft/state"
	cmtstore "github.com/cometbft/cometbft/store"
	cmttypes "github.com/cometbft/cometbft/types"

	sageabci "github.com/l33tdawg/sage/internal/abci"
)

const lockedVaultStartupRemedy = "set SAGE_PASSPHRASE or launch from an interactive terminal to unlock before consensus starts"

// validateLockedVaultConsensusStartup allows a locked projection to coexist
// with CometBFT only for a provably single-validator personal node. In that
// mode CheckTx is held behind a process-local latch and P2P is disabled below.
// A quorum/state-sync/multi-validator node can receive a proposal without
// passing local CheckTx, so it must unlock before node.NewNode is constructed.
func validateLockedVaultConsensusStartup(
	ctx context.Context,
	cfg *Config,
	genesisPath string,
	app *sageabci.SageApp,
) error {
	if cfg == nil || app == nil {
		return errors.New("validate locked-vault startup: config and application are required")
	}
	genesis, err := cmttypes.GenesisDocFromFile(genesisPath)
	if err != nil {
		return fmt.Errorf("validate locked-vault startup genesis: %w", err)
	}
	info, err := app.Info(ctx, &abcitypes.RequestInfo{})
	if err != nil {
		return fmt.Errorf("validate locked-vault startup application state: %w", err)
	}
	if info == nil {
		return errors.New("validate locked-vault startup application state: nil Info response")
	}
	return validateLockedVaultConsensusShape(
		cfg,
		len(genesis.Validators),
		info.LastBlockHeight,
		app.ValidatorCount(),
	)
}

func validateLockedVaultConsensusShape(
	cfg *Config,
	genesisValidatorCount int,
	appHeight int64,
	appValidatorCount int,
) error {
	if cfg == nil {
		return errors.New("locked-vault startup config is required")
	}
	if cfg.Quorum.Enabled || cfg.Quorum.StateSync.armed() {
		return fmt.Errorf(
			"encrypted vault is locked; quorum and state-sync nodes must unlock before CometBFT starts — %s",
			lockedVaultStartupRemedy,
		)
	}
	if genesisValidatorCount != 1 {
		return fmt.Errorf(
			"encrypted vault is locked; genesis has %d validators, not a provably isolated personal node — %s",
			genesisValidatorCount,
			lockedVaultStartupRemedy,
		)
	}
	if appHeight < 0 {
		return errors.New("encrypted vault is locked; application reported a negative height")
	}
	if appHeight == 0 {
		// Before InitChain the application validator set is normally empty and
		// the validated one-validator genesis is authoritative. A pre-seeded
		// set is acceptable only when it independently says the same thing.
		if appValidatorCount > 1 {
			return fmt.Errorf(
				"encrypted vault is locked; pre-Init application has %d validators — %s",
				appValidatorCount,
				lockedVaultStartupRemedy,
			)
		}
		return nil
	}
	if appValidatorCount != 1 {
		return fmt.Errorf(
			"encrypted vault is locked; committed application state has %d validators — %s",
			appValidatorCount,
			lockedVaultStartupRemedy,
		)
	}
	return nil
}

// validateLockedVaultCometReplaySafety refuses locked startup when CometBFT
// would replay a committed block through FinalizeBlock/Commit before the local
// browser unlock flow exists. CheckTx isolation cannot protect that crash
// recovery path. A fresh height-zero node and an exactly synchronized positive
// height are the only safe shapes.
func validateLockedVaultCometReplaySafety(
	ctx context.Context,
	cfg *cmtconfig.Config,
	app *sageabci.SageApp,
) error {
	if cfg == nil || app == nil {
		return errors.New("validate locked-vault replay safety: CometBFT config and application are required")
	}
	info, err := app.Info(ctx, &abcitypes.RequestInfo{})
	if err != nil {
		return fmt.Errorf("validate locked-vault replay application state: %w", err)
	}
	if info == nil {
		return errors.New("validate locked-vault replay application state: nil Info response")
	}
	stateDB, err := cmtconfig.DefaultDBProvider(&cmtconfig.DBContext{ID: "state", Config: cfg})
	if err != nil {
		return fmt.Errorf("open CometBFT state DB for locked-vault replay check: %w", err)
	}
	state, loadErr := cmtstate.NewStore(stateDB, cmtstate.StoreOptions{}).Load()
	stateCloseErr := stateDB.Close()
	if loadErr != nil {
		return fmt.Errorf("load CometBFT state for locked-vault replay check: %w", loadErr)
	}
	if stateCloseErr != nil {
		return fmt.Errorf("close CometBFT state DB after locked-vault replay check: %w", stateCloseErr)
	}
	blockDB, err := cmtconfig.DefaultDBProvider(&cmtconfig.DBContext{ID: "blockstore", Config: cfg})
	if err != nil {
		return fmt.Errorf("open CometBFT block store for locked-vault replay check: %w", err)
	}
	blockStore := cmtstore.NewBlockStore(blockDB)
	blockHeight := blockStore.Height()
	blockCloseErr := blockStore.Close()
	if blockCloseErr != nil {
		return fmt.Errorf("close CometBFT block store after locked-vault replay check: %w", blockCloseErr)
	}
	return validateLockedVaultReplayShape(
		info.LastBlockHeight,
		info.LastBlockAppHash,
		state.IsEmpty(),
		state.LastBlockHeight,
		state.AppHash,
		blockHeight,
	)
}

func validateLockedVaultReplayShape(
	appHeight int64,
	appHash []byte,
	cometStateEmpty bool,
	cometStateHeight int64,
	cometStateHash []byte,
	blockStoreHeight int64,
) error {
	if appHeight < 0 || cometStateHeight < 0 || blockStoreHeight < 0 {
		return errors.New("encrypted vault is locked; application or CometBFT reported a negative replay height")
	}
	if appHeight == 0 && blockStoreHeight == 0 &&
		(cometStateEmpty || cometStateHeight == 0) {
		return nil
	}
	if cometStateEmpty ||
		appHeight == 0 ||
		appHeight != cometStateHeight ||
		appHeight != blockStoreHeight ||
		!bytes.Equal(appHash, cometStateHash) {
		return fmt.Errorf(
			"encrypted vault is locked and CometBFT may need application replay "+
				"(app=%d state=%d blocks=%d); unlock before CometBFT starts — %s",
			appHeight,
			cometStateHeight,
			blockStoreHeight,
			lockedVaultStartupRemedy,
		)
	}
	return nil
}

// isolateLockedPersonalP2P removes every peer path while a personal node waits
// for its local vault. The loopback listener remains because CometBFT requires a
// concrete node address, but it accepts no inbound peers, dials no outbound
// peers, and runs no peer exchange.
func isolateLockedPersonalP2P(cfg *cmtconfig.P2PConfig) {
	if cfg == nil {
		return
	}
	port := "26656"
	if _, configuredPort, err := net.SplitHostPort(
		strings.TrimPrefix(cmtP2PAddr("tcp://127.0.0.1:26656"), "tcp://"),
	); err == nil && configuredPort != "" {
		port = configuredPort
	}
	cfg.ListenAddress = "tcp://" + net.JoinHostPort("127.0.0.1", port)
	cfg.ExternalAddress = ""
	cfg.Seeds = ""
	cfg.PersistentPeers = ""
	cfg.UnconditionalPeerIDs = ""
	cfg.PrivatePeerIDs = ""
	cfg.PexReactor = false
	cfg.SeedMode = false
	cfg.MaxNumInboundPeers = 0
	cfg.MaxNumOutboundPeers = 0
}
