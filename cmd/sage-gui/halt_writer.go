// Package main — legacy HALT sentinel wire format.
//
// v11.16.1 retires automatic rollback authorization from sage-gui:
// a prior executable may contain startup migrations that are unsafe
// for the current on-disk lineage. Panics therefore propagate without
// writing HALT and the supervisor applies its bounded crash-loop
// circuit breaker instead of restoring or executing an older version.
//
// The legacy writer and wire-format types remain so launchers and
// offline recovery tooling can still parse explicitly supplied
// sentinels. They are not called by the live startup path.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// haltSignal mirrors cmd/sage-launcher/halt_sentinel.go HaltSignal.
// We do not import the launcher package here (sage-gui must not
// depend on the launcher; the launcher already depends on sage-gui
// state). Keeping a structurally identical local copy is the
// intended boundary.
type haltSignal struct {
	FailedVersion  string `json:"failed_version"`
	RollbackTo     string `json:"rollback_to"`
	FailureMessage string `json:"failure_message"`
	Timestamp      int64  `json:"timestamp"`
}

// writeHaltSentinel persists a HALT sentinel atomically into
// <dataDir>/HALT. rollbackTo MAY be empty — the launcher's
// findLatestRollbackAnchor handles that case by picking "any
// anchor whose BinaryVersion isn't the failed version". This lets
// the chain binary signal "halt me" without having to enumerate
// available anchors at panic time.
//
// Atomicity: write to <dataDir>/.HALT.tmp first, fsync, then
// os.Rename to <dataDir>/HALT. A crash between write and rename
// leaves no sentinel; the supervisor will treat the crash as a
// regular non-zero exit and apply the crash-loop circuit-breaker
// rather than triggering rollback. Acceptable failure mode —
// rollback without a sentinel could be wrong.
func writeHaltSentinel(dataDir, failedVersion, rollbackTo, failureMsg string) error {
	if dataDir == "" {
		return fmt.Errorf("writeHaltSentinel: empty dataDir")
	}
	if failedVersion == "" {
		return fmt.Errorf("writeHaltSentinel: empty failedVersion")
	}

	sig := haltSignal{
		FailedVersion:  failedVersion,
		RollbackTo:     rollbackTo,
		FailureMessage: failureMsg,
		Timestamp:      time.Now().Unix(),
	}
	payload, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal HALT sentinel: %w", err)
	}

	if mkErr := os.MkdirAll(dataDir, 0o700); mkErr != nil {
		return fmt.Errorf("mkdir %s: %w", dataDir, mkErr)
	}

	tmp := filepath.Join(dataDir, ".HALT.tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	if _, err := f.Write(payload); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("fsync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, err)
	}

	final := filepath.Join(dataDir, "HALT")
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, final, err)
	}
	return nil
}

// haltOnPanic recovers a panic at the top of runServe and immediately
// re-panics so the original stack still reaches stderr. It deliberately
// does not write HALT: doing so would authorize the supervisor to restore
// state and execute an older binary whose startup path may destructively
// rewrite current data.
func haltOnPanic(_ string) {
	r := recover()
	if r == nil {
		return
	}
	panic(r)
}
