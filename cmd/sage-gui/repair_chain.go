package main

import (
	"errors"
	"fmt"

	"github.com/rs/zerolog"
)

var errDestructiveChainRepairDisabled = errors.New(
	"repair-chain is disabled because SQLite cannot reconstruct canonical chain history",
)

// repairChainState is retained as a compatibility seam for callers and tests,
// but v11.16.1 deliberately performs no repair. The retired implementation
// deleted canonical Badger state and CometBFT history, then attempted to rebuild
// authority from SQLite. That serving projection does not contain complete
// memory envelopes, RBAC, governance, validator, or authorship history.
func repairChainState(dataDir string, logger zerolog.Logger) error {
	_ = dataDir
	_ = logger
	return errDestructiveChainRepairDisabled
}

// runRepairChain refuses before loading config, reading stdin, creating
// backups, or touching any node path. Recovery now requires restoring a full
// stopped-node backup or a future governed, history-preserving migration.
func runRepairChain(args []string) error {
	_ = args
	return fmt.Errorf(
		"%w; no files were changed — restore a complete stopped-node backup "+
			"or use a governed history-preserving recovery",
		errDestructiveChainRepairDisabled,
	)
}
