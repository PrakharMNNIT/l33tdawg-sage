package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/l33tdawg/sage/internal/store"

	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

const versionFile = "version.txt"

var errAutomaticChainResetRefused = errors.New(
	"automatic chain reset refused to preserve canonical history",
)

// migrateOnUpgrade reconciles persisted chain state with the running binary.
// Same-fork upgrades are stamped in place. A legacy or mismatched fork is
// refused without changing any state: rebuilding from SQLite cannot reconstruct
// canonical memory envelopes, RBAC, governance, or historical blocks, and is
// therefore not an upgrade migration.
//
// Pre-v7.5.5 behaviour was to reset on ANY version-string change, which
// silently destroyed operator state — domain registry, access grants, org
// memberships, validator set — on every patch and minor bump. See the
// ConsensusForkVersion docstring for why this gate exists.
//
// migrated is retained for call-site compatibility and is always false: safe
// same-fork reconciliation stamps diagnostics, while incompatible state returns
// errAutomaticChainResetRefused without changing anything.
func migrateOnUpgrade(dataDir string) (migrated bool, err error) {
	_ = dataDir
	versionPath := filepath.Join(SageHome(), versionFile)
	forkPath := filepath.Join(SageHome(), forkVersionFile)

	// Dev builds: never touch state.
	if version == "dev" {
		return false, nil
	}

	lastVersion := ""
	if data, readErr := os.ReadFile(versionPath); readErr == nil {
		lastVersion = strings.TrimSpace(string(data))
	}
	onDiskFork, forkMarkerPresent, forkReadErr := inspectForkVersion(forkPath)
	if forkReadErr != nil {
		return false, fmt.Errorf(
			"%w: cannot verify persisted fork marker: %v; no files were changed",
			errAutomaticChainResetRefused,
			forkReadErr,
		)
	}

	// Fresh install — no prior state. Stamp both files and return.
	if lastVersion == "" && !forkMarkerPresent {
		cometHome := filepath.Join(dataDir, "cometbft")
		if evidence, evidenceErr := persistedNodeIdentityEvidence(
			SageHome(),
			dataDir,
			cometHome,
		); evidenceErr != nil {
			return false, fmt.Errorf(
				"%w: cannot verify whether this marker-less data directory is fresh: %v; no files were changed",
				errAutomaticChainResetRefused,
				evidenceErr,
			)
		} else if evidence != "" {
			return false, fmt.Errorf(
				"%w: version/fork markers are missing but persisted chain evidence exists (%s); "+
					"no files were changed",
				errAutomaticChainResetRefused,
				evidence,
			)
		}
		if _, statErr := os.Lstat(filepath.Join(dataDir, "badger")); statErr == nil {
			return false, fmt.Errorf(
				"%w: version/fork markers are missing but a Badger path already exists; "+
					"no files were changed",
				errAutomaticChainResetRefused,
			)
		} else if !os.IsNotExist(statErr) {
			return false, fmt.Errorf(
				"%w: cannot inspect marker-less Badger path: %v; no files were changed",
				errAutomaticChainResetRefused,
				statErr,
			)
		}
		if stampErr := stampForkVersion(forkPath, ConsensusForkVersion); stampErr != nil {
			return false, stampErr
		}
		return false, stampVersion(versionPath)
	}

	// Legacy install (version.txt exists but no fork-version.txt) — predates
	// the gate. Two sub-paths:
	//
	//   (a) lastVersion is a pre-gate v7.5.x release (v7.5.0..v7.5.4). Same
	//       fork lineage as the current binary — adopt fork=1 without
	//       resetting. The upgrade that introduces the gate itself must
	//       not produce a spurious reset.
	//
	//   (b) lastVersion is older (v6.x, v7.0..v7.4). Different fork lineage —
	//       refuse without stamping or modifying state. A history-preserving
	//       migration is required.
	if !forkMarkerPresent {
		if isLegacyForkOneVersion(lastVersion) {
			if stampErr := stampForkVersion(forkPath, ConsensusForkVersion); stampErr != nil {
				return false, stampErr
			}
			if lastVersion != version {
				fmt.Fprintf(os.Stderr, "\n  SAGE %s → %s · your memories are preserved (no chain rebuild needed)\n\n", lastVersion, version)
			}
			return false, stampVersion(versionPath)
		}

		return false, fmt.Errorf(
			"%w: SAGE %s cannot be upgraded automatically to %s because its persisted "+
				"fork marker predates safe in-place migration; no files were changed",
			errAutomaticChainResetRefused, lastVersion, version,
		)
	}

	// Same fork — patch/minor upgrade that doesn't touch consensus state.
	if onDiskFork == ConsensusForkVersion {
		if lastVersion != version {
			fmt.Fprintf(os.Stderr, "\n  SAGE %s → %s · your memories are preserved (no chain rebuild needed)\n\n", lastVersion, version)
		}
		return false, stampVersion(versionPath)
	}

	// A fork transition must be implemented as an in-place deterministic
	// migration or governed application upgrade. Never erase the old canonical
	// state and synthesize a new chain from the SQLite serving projection.
	return false, fmt.Errorf(
		"%w: SAGE %s uses persisted fork %d but %s expects fork %d; "+
			"no files were changed",
		errAutomaticChainResetRefused,
		lastVersion, onDiskFork, version, ConsensusForkVersion,
	)
}

// genuinelyFreshNodeOrigin is evaluated before startup creates directories,
// keys, sockets, or migration stamps. Marker presence or any durable node
// identity evidence makes the origin initialized/ambiguous, never fresh.
func genuinelyFreshNodeOrigin(dataDir string) (bool, error) {
	for _, marker := range []string{versionFile, forkVersionFile} {
		path := filepath.Join(SageHome(), marker)
		if _, err := os.Lstat(path); err == nil {
			return false, nil
		} else if !os.IsNotExist(err) {
			return false, fmt.Errorf("inspect %s: %w", marker, err)
		}
	}
	cometHome := filepath.Join(dataDir, "cometbft")
	evidence, err := persistedNodeIdentityEvidence(SageHome(), dataDir, cometHome)
	if err != nil {
		return false, err
	}
	if evidence != "" {
		return false, nil
	}
	// An empty Badger path can be the remnant of an interrupted first launch.
	// At this pre-mutation point it is ambiguous, so fail closed.
	if _, err := os.Lstat(filepath.Join(dataDir, "badger")); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("inspect Badger path: %w", err)
	}
	return true, nil
}

// resetChainState performs an explicit destructive chain reset:
// back up the vault key + SQLite, wipe BadgerDB, wipe CometBFT block/state DBs,
// and retain config/genesis. SQLite cannot reconstruct the deleted canonical
// history; automatic migration and chain-id re-mint paths must never call this.
func resetChainState(dataDir, badgerPath, cometHome, sqlitePath, lastVersion string) error {
	// Step -1: Refuse to run while another SAGE instance is live on this home.
	// A serving node holds BadgerDB's directory lock; if we proceeded we would delete
	// the SQLite -wal/-shm sidecars and wipe chain state out from under the running
	// process — silently losing memories it is still committing and risking a
	// two-writer corruption of sage.db. The lock is the AUTHORITATIVE signal (it holds
	// regardless of the RPC address, which an env-var mismatch could hide from the
	// serveIsRunning probe), so every caller — migrateOnUpgrade, remintLegacyChainID,
	// repairChainState — is protected here rather than at one call site. Mirrors the
	// live-instance guard in repairChainState.
	if bs, openErr := store.NewBadgerStore(badgerPath); openErr != nil {
		// BadgerDB has no typed open error. A SERVING node fails the open with the
		// directory-lock message — the only case that means "stop, the node is running".
		// Any OTHER failure (corrupt/unreadable index, or a fresh/empty dir) is not a
		// liveness signal for this explicitly destructive command, so fall through.
		if strings.Contains(openErr.Error(), "Another process is using this Badger database") {
			return fmt.Errorf("your memories are intact — another SAGE instance is running on this home; stop it and retry before any chain rebuild: %w", openErr)
		}
	} else {
		_ = bs.CloseBadger()
	}

	// Step 0: Protect the vault key — back it up before touching anything.
	// The vault key is irreplaceable: if lost, all encrypted memories become
	// permanently unrecoverable.
	vaultKeyPath := filepath.Join(SageHome(), "vault.key")
	if _, vkErr := os.Stat(vaultKeyPath); vkErr == nil {
		backupDir := filepath.Join(SageHome(), "backups")
		_ = os.MkdirAll(backupDir, 0700)
		ts := time.Now().Format("2006-01-02T15-04-05")
		vaultBackup := filepath.Join(backupDir, fmt.Sprintf("vault-pre-upgrade-%s-%s.key", lastVersion, ts))
		if src, readErr := os.ReadFile(vaultKeyPath); readErr == nil {
			if writeErr := os.WriteFile(vaultBackup, src, 0600); writeErr == nil { //nolint:gosec // trusted local vault backup
				fmt.Fprintf(os.Stderr, "  Vault key saved to %s\n", vaultBackup)
			}
		}
	}

	// Step 1: Backup SQLite (the precious data) using VACUUM INTO for atomic consistency
	if _, statErr := os.Stat(sqlitePath); statErr == nil {
		// Fold any write-ahead log back into the main DB so the backup is complete.
		// If the checkpoint can't run (e.g. the DB is briefly busy), ABORT rather than
		// deleting an un-checkpointed WAL — deleting it would discard committed memories
		// not yet folded into the main file. The live DB + WAL stay intact, so the node
		// keeps every memory and simply retries next boot. checkpointWAL uses TRUNCATE,
		// which empties the WAL on success, so the sidecars are safe to remove after.
		if _, walErr := os.Stat(sqlitePath + "-wal"); walErr == nil {
			if cpErr := checkpointWAL(sqlitePath); cpErr != nil {
				return fmt.Errorf("your memories are intact — could not checkpoint the write-ahead log before backup (is the database busy?); aborting before any chain rebuild: %w", cpErr)
			}
		}
		for _, suffix := range []string{"-wal", "-shm"} {
			_ = os.Remove(sqlitePath + suffix)
		}

		backupDir := filepath.Join(SageHome(), "backups")
		if mkErr := os.MkdirAll(backupDir, 0700); mkErr != nil {
			return fmt.Errorf("create backup dir: %w", mkErr)
		}
		ts := time.Now().Format("2006-01-02T15-04-05")
		backupPath := filepath.Join(backupDir, fmt.Sprintf("sage-pre-upgrade-%s-%s.db", lastVersion, ts))

		vacuumErr := vacuumBackup(sqlitePath, backupPath)
		if vacuumErr != nil {
			fmt.Fprintf(os.Stderr, "  VACUUM INTO failed (%v), falling back to file copy\n", vacuumErr)
			src, readErr := os.ReadFile(sqlitePath)
			if readErr != nil {
				return fmt.Errorf("read sqlite for backup: %w", readErr)
			}
			if writeErr := os.WriteFile(backupPath, src, 0600); writeErr != nil { //nolint:gosec // backupPath is server-controlled
				return fmt.Errorf("write backup: %w", writeErr)
			}
		}
		// Verify the backup actually landed before proceeding to wipe derived chain
		// state. Verify by CONTENT, not size: VACUUM INTO compacts (drops free pages),
		// so a valid backup of a fragmented DB is legitimately smaller than the source
		// — a size heuristic falsely rejects it. Instead run a structural check and
		// confirm no memory row was lost. The live sage.db is still intact here, so
		// refusing means the user keeps every memory. A rejected backup is deleted so
		// it can't accumulate across repeated boots.
		if verifyErr := verifyBackup(sqlitePath, backupPath); verifyErr != nil {
			_ = os.Remove(backupPath) //nolint:gosec // backupPath is server-controlled
			return verifyErr
		}
		if backupInfo, statErr := os.Stat(backupPath); statErr == nil { //nolint:gosec // backupPath is server-controlled
			fmt.Fprintf(os.Stderr, "  Memories saved to %s (%d bytes, verified)\n", backupPath, backupInfo.Size())
		}
	}

	// Step 2: Delete canonical Badger state. SQLite cannot reconstruct it.
	if _, statErr := os.Stat(badgerPath); statErr == nil {
		if removeErr := os.RemoveAll(badgerPath); removeErr != nil {
			return fmt.Errorf("remove badger: %w", removeErr)
		}
		if mkErr := os.MkdirAll(badgerPath, 0700); mkErr != nil {
			return fmt.Errorf("recreate badger dir: %w", mkErr)
		}
		fmt.Fprintf(os.Stderr, "  Deleted canonical chain index\n")
	}

	// Step 3: Delete CometBFT blocks, votes, state, and WAL. Keep
	// config/genesis, but do not claim this can be rebuilt from SQLite.
	cometDataDir := filepath.Join(cometHome, "data")
	if _, statErr := os.Stat(cometDataDir); statErr == nil {
		for _, dbName := range []string{"blockstore.db", "state.db", "tx_index.db", "evidence.db", "cs.wal"} {
			dbPath := filepath.Join(cometDataDir, dbName)
			if removeErr := os.RemoveAll(dbPath); removeErr != nil {
				fmt.Fprintf(os.Stderr, "  Note: could not clear %s: %v\n", dbName, removeErr)
			}
		}
		pvStatePath := filepath.Join(cometDataDir, "priv_validator_state.json")
		pvState := []byte(`{"height":"0","round":0,"step":0}`)
		if writeErr := os.WriteFile(pvStatePath, pvState, 0600); writeErr != nil {
			fmt.Fprintf(os.Stderr, "  Note: could not reset validator state: %v\n", writeErr)
		}
		fmt.Fprintf(os.Stderr, "  Deleted consensus log\n")
	}

	return nil
}

// checkpointWAL forces a WAL checkpoint on the database, merging any
// pending WAL writes into the main DB file. This prevents stale WAL files
// from causing hangs on upgrade.
func checkpointWAL(dbPath string) error {
	// modernc.org/sqlite honors busy_timeout only via a _pragma param (mattn-style
	// _busy_timeout is silently ignored), so a briefly-locked DB waits 5s here rather
	// than failing the checkpoint instantly.
	dsn := dbPath + "?_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// wal_checkpoint(TRUNCATE) reports its outcome in a result ROW (busy, log,
	// checkpointed), not as an exec error: a concurrent reader can leave busy=1 with
	// WAL frames un-backfilled while Exec sees no error. Read the row and treat busy!=0
	// as failure so the caller never deletes an un-truncated WAL.
	var busy, logFrames, checkpointed int
	if scanErr := db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed); scanErr != nil {
		return scanErr
	}
	if busy != 0 {
		return fmt.Errorf("WAL checkpoint blocked (database busy) — refusing to treat the WAL as flushed")
	}
	return nil
}

// vacuumBackup creates an atomic backup using VACUUM INTO with a timeout.
func vacuumBackup(srcPath, dstPath string) error {
	// _pragma=busy_timeout is the modernc-honored form (mattn-style _busy_timeout is a
	// no-op) so a transient lock waits rather than dropping straight to raw-copy.
	dsn := srcPath + "?_pragma=busy_timeout(15000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = db.ExecContext(ctx, fmt.Sprintf(`VACUUM INTO '%s'`, dstPath))
	return err
}

func stampVersion(path string) error {
	return os.WriteFile(path, []byte(version+"\n"), 0600)
}

// verifyBackup gates the destructive chain rebuild on the SQLite backup being a
// STRUCTURALLY SOUND copy that lost no memory — verifying by content, not size.
// VACUUM INTO compacts (drops free pages), so a valid backup of a fragmented DB is
// legitimately smaller than the source; a size heuristic falsely rejects it and, on
// the re-mint path, silently denies the fix to exactly the fragmented-DB nodes that
// need it. Instead: the backup must exist, be non-empty, pass a structural
// quick_check, and carry at least as many `memories` rows as the live DB (VACUUM
// preserves rows; a row shortfall is the real truncation signal). If the source has
// no `memories` table (fresh/foreign DB) the row check is skipped — quick_check
// still guards structure.
//
// The abort happens BEFORE any destructive operation, so the live sage.db is intact;
// error messages lead with that reassurance for an operator reading the logs.
func verifyBackup(srcPath, backupPath string) error {
	bi, statErr := os.Stat(backupPath) //nolint:gosec // backupPath is server-controlled
	if statErr != nil {
		return fmt.Errorf("your memories are intact — the pre-upgrade backup at %s could not be found; aborting before any chain rebuild: %w", backupPath, statErr)
	}
	if bi.Size() == 0 {
		return fmt.Errorf("your memories are intact — the pre-upgrade backup at %s is empty; aborting before any chain rebuild so nothing destructive runs", backupPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	bdb, openErr := sql.Open("sqlite", roDSN(backupPath))
	if openErr != nil {
		return fmt.Errorf("your memories are intact — could not open the pre-upgrade backup %s to verify it; aborting: %w", backupPath, openErr)
	}
	defer func() { _ = bdb.Close() }()

	var check string
	if qErr := bdb.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&check); qErr != nil {
		return fmt.Errorf("your memories are intact — could not run an integrity check on the pre-upgrade backup %s; aborting: %w", backupPath, qErr)
	}
	if check != "ok" {
		return fmt.Errorf("your memories are intact — the pre-upgrade backup %s failed its integrity check (%s); aborting before any chain rebuild", backupPath, check)
	}

	// Row-count parity on the precious table. Distinguish "no memories table" (a
	// fresh/foreign DB — legitimately skip parity) from "couldn't read the DB" (a
	// lock/corruption — must NOT silently skip the truncation check; refuse instead).
	srcCount, srcPresent, srcErr := memoriesRowCount(ctx, srcPath)
	if srcErr != nil {
		return fmt.Errorf("your memories are intact — could not read the live database %s to verify the backup (is it locked?); aborting before any chain rebuild: %w", srcPath, srcErr)
	}
	if srcPresent {
		backupCount, backupPresent, backupErr := memoriesRowCount(ctx, backupPath)
		if backupErr != nil || !backupPresent {
			return fmt.Errorf("your memories are intact — the pre-upgrade backup %s is missing its memories table or could not be read; aborting", backupPath)
		}
		if backupCount < srcCount {
			return fmt.Errorf("your memories are intact — the pre-upgrade backup %s has %d memories vs. %d live (possible truncation); aborting before any chain rebuild", backupPath, backupCount, srcCount)
		}
	}
	return nil
}

// roDSN builds a genuinely read-only modernc.org/sqlite DSN with a real busy timeout.
// Both busy_timeout and query_only must go through _pragma — the mattn-style
// _busy_timeout / mode=ro query params are silently ignored by this driver.
func roDSN(path string) string {
	return path + "?_pragma=busy_timeout(15000)&_pragma=query_only(true)"
}

// memoriesRowCount returns the memories-table row count. present=false means the
// table is ABSENT (a fresh/foreign DB — the caller skips parity). A non-nil err means
// the DB could not be opened or read (lock/corruption); the caller must treat that as
// a verification failure, never a silent skip.
func memoriesRowCount(ctx context.Context, dbPath string) (count int64, present bool, err error) {
	db, err := sql.Open("sqlite", roDSN(dbPath))
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = db.Close() }()
	var name string
	switch scanErr := db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name='memories'`).Scan(&name); {
	case scanErr == sql.ErrNoRows:
		return 0, false, nil // no memories table — legitimate skip
	case scanErr != nil:
		return 0, false, scanErr // couldn't read schema — real error (lock/corruption)
	}
	if scanErr := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM memories`).Scan(&count); scanErr != nil {
		return 0, true, scanErr // table present but unreadable — real error
	}
	return count, true, nil
}
