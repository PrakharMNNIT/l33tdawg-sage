// Package main — legacy explicit/offline adapter wiring
// internal/snapshot.Restore behind the Restorer interface.
//
// The v11.16.1+ supervisor never instantiates this adapter automatically.
// It remains for compatibility tests and a future separately authorized
// recovery ceremony.
package main

import (
	"fmt"

	"github.com/l33tdawg/sage/internal/snapshot"
)

// snapshotRestorer satisfies the Restorer interface in rollback.go by
// delegating to snapshot.Restore. We keep it in its own file (rather
// than next to Restorer) so the tests in launcher_test.go can keep
// using a stub Restorer without picking up the snapshot package
// (and all its BadgerDB / SQLite / zstd deps) by import.
type snapshotRestorer struct {
	logf func(format string, args ...interface{})
}

// Restore wraps snapshot.Restore. The launcher does not pass a
// VaultPassphrase — if the snapshot is encrypted the restore will
// fail with a clear error during the embedded Verify pass. Encrypted
// snapshots in a non-interactive rollback are out of scope for v7.5
// task #0; passphrase pickup will be a follow-up once the chain
// binary surfaces it via the HALT sentinel.
func (r *snapshotRestorer) Restore(snapshotDir, dataDir string) error {
	if r.logf != nil {
		r.logf("snapshotRestorer: restoring %s -> %s", snapshotDir, dataDir)
	}
	height, err := snapshot.Restore(snapshotDir, dataDir)
	if err != nil {
		return fmt.Errorf("snapshot.Restore: %w", err)
	}
	if r.logf != nil {
		r.logf("snapshotRestorer: restored to height %d", height)
	}
	return nil
}
