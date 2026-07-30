package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/l33tdawg/sage/internal/store"

	_ "modernc.org/sqlite"
)

// TestResetChainState_RefusesWhileInstanceLive locks the #1 data-safety fix: with
// another instance holding the BadgerDB directory lock (as a serving node does),
// resetChainState must refuse rather than delete the SQLite -wal/-shm sidecars and
// wipe chain state out from under the live process.
func TestResetChainState_RefusesWhileInstanceLive(t *testing.T) {
	dataDir := t.TempDir()
	badgerPath := filepath.Join(dataDir, "badger")
	bs, err := store.NewBadgerStore(badgerPath)
	if err != nil {
		t.Fatalf("open badger (simulating a live node): %v", err)
	}
	defer func() { _ = bs.CloseBadger() }()

	err = resetChainState(dataDir, badgerPath,
		filepath.Join(dataDir, "cometbft"), filepath.Join(dataDir, "sage.db"), "v11.0.2")
	if err == nil {
		t.Fatal("resetChainState must refuse while another instance holds the Badger lock")
	}
	if !strings.Contains(err.Error(), "another SAGE instance is running") {
		t.Fatalf("expected live-instance refusal, got: %v", err)
	}
}

func TestMigrateOnUpgrade_FirstRun(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SAGE_HOME", tmpDir)

	dataDir := filepath.Join(tmpDir, "data")
	os.MkdirAll(dataDir, 0700)

	oldVersion := version
	version = "v2.5.0"
	defer func() { version = oldVersion }()

	migrated, err := migrateOnUpgrade(dataDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if migrated {
		t.Error("expected no migration on first run")
	}

	vPath := filepath.Join(tmpDir, versionFile)
	data, err := os.ReadFile(vPath)
	if err != nil {
		t.Fatalf("version file not written: %v", err)
	}
	if got := string(data); got != "v2.5.0\n" {
		t.Errorf("version file content = %q, want %q", got, "v2.5.0\n")
	}

	if got := readForkVersion(filepath.Join(tmpDir, forkVersionFile)); got != ConsensusForkVersion {
		t.Errorf("fork-version file = %d, want %d (first run must stamp current fork)", got, ConsensusForkVersion)
	}
}

func TestMigrateOnUpgrade_SameVersion(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SAGE_HOME", tmpDir)

	dataDir := filepath.Join(tmpDir, "data")
	os.MkdirAll(dataDir, 0700)

	oldVersion := version
	version = "v2.5.0"
	defer func() { version = oldVersion }()

	os.WriteFile(filepath.Join(tmpDir, versionFile), []byte("v2.5.0\n"), 0600)
	stampForkVersion(filepath.Join(tmpDir, forkVersionFile), ConsensusForkVersion)

	migrated, err := migrateOnUpgrade(dataDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if migrated {
		t.Error("should not migrate when version unchanged")
	}
}

// TestMigrateOnUpgrade_VersionChangedSameFork_PreservesState is the v7.5.5
// contract: patch/minor bumps that don't touch consensus must NOT reset
// BadgerDB or CometBFT state. Pre-v7.5.5 wiped both on any version-string
// change, silently destroying every operator's domain registry, access
// grants, org memberships, and validator set. This test guards against
// that regression.
func TestMigrateOnUpgrade_VersionChangedSameFork_PreservesState(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SAGE_HOME", tmpDir)

	dataDir := filepath.Join(tmpDir, "data")
	badgerDir := filepath.Join(dataDir, "badger")
	cometDir := filepath.Join(dataDir, "cometbft", "data")
	sqlitePath := filepath.Join(dataDir, "sage.db")

	os.MkdirAll(badgerDir, 0700)
	os.MkdirAll(cometDir, 0700)
	makeMemoriesDB(t, sqlitePath, 10)
	os.WriteFile(filepath.Join(badgerDir, "000001.vlog"), []byte("badger"), 0600)
	os.MkdirAll(filepath.Join(cometDir, "blockstore.db"), 0700)
	os.MkdirAll(filepath.Join(cometDir, "state.db"), 0700)
	os.WriteFile(filepath.Join(cometDir, "priv_validator_state.json"), []byte(`{"height":"100"}`), 0600)

	os.WriteFile(filepath.Join(tmpDir, versionFile), []byte("v7.5.4\n"), 0600)
	stampForkVersion(filepath.Join(tmpDir, forkVersionFile), ConsensusForkVersion)

	oldVersion := version
	version = "v7.5.5"
	defer func() { version = oldVersion }()

	migrated, err := migrateOnUpgrade(dataDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if migrated {
		t.Fatal("same-fork version bump must NOT report migration — pre-v7.5.5 regression")
	}

	if data, _ := os.ReadFile(filepath.Join(badgerDir, "000001.vlog")); string(data) != "badger" {
		t.Error("badger value log must be preserved on same-fork upgrade")
	}
	if _, err := os.Stat(filepath.Join(cometDir, "blockstore.db")); os.IsNotExist(err) {
		t.Error("CometBFT blockstore.db must be preserved on same-fork upgrade")
	}
	if _, err := os.Stat(filepath.Join(cometDir, "state.db")); os.IsNotExist(err) {
		t.Error("CometBFT state.db must be preserved on same-fork upgrade")
	}
	if data, _ := os.ReadFile(filepath.Join(cometDir, "priv_validator_state.json")); string(data) != `{"height":"100"}` {
		t.Errorf("priv_validator_state.json must be preserved, got %q", data)
	}

	vData, _ := os.ReadFile(filepath.Join(tmpDir, versionFile))
	if string(vData) != "v7.5.5\n" {
		t.Errorf("version file = %q, want v7.5.5\\n (diagnostics stamp must still happen)", vData)
	}
}

func TestMigrateOnUpgrade_11_16_0To11_16_1_IsStampOnly(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SAGE_HOME", tmpDir)

	dataDir := filepath.Join(tmpDir, "data")
	badgerDir := filepath.Join(dataDir, "badger")
	cometDir := filepath.Join(dataDir, "cometbft", "data")
	sqlitePath := filepath.Join(dataDir, "sage.db")
	requireNoErr := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	requireNoErr(os.MkdirAll(badgerDir, 0o700))
	requireNoErr(os.MkdirAll(cometDir, 0o700))
	makeMemoriesDB(t, sqlitePath, 10)
	requireNoErr(os.WriteFile(filepath.Join(badgerDir, "canonical.sentinel"), []byte("badger"), 0o600))
	requireNoErr(os.MkdirAll(filepath.Join(cometDir, "blockstore.db"), 0o700))
	requireNoErr(os.MkdirAll(filepath.Join(cometDir, "state.db"), 0o700))
	requireNoErr(os.WriteFile(filepath.Join(cometDir, "priv_validator_state.json"), []byte(`{"height":"22271"}`), 0o600))
	requireNoErr(os.WriteFile(filepath.Join(tmpDir, versionFile), []byte("11.16.0\n"), 0o600))
	requireNoErr(stampForkVersion(filepath.Join(tmpDir, forkVersionFile), 1))

	oldVersion, oldFork := version, ConsensusForkVersion
	version, ConsensusForkVersion = "11.16.1", 1
	defer func() {
		version, ConsensusForkVersion = oldVersion, oldFork
	}()

	migrated, err := migrateOnUpgrade(dataDir)
	if err != nil {
		t.Fatalf("live same-fork patch upgrade must succeed: %v", err)
	}
	if migrated {
		t.Fatal("same-fork patch upgrade must not report a migration")
	}
	if data, _ := os.ReadFile(filepath.Join(badgerDir, "canonical.sentinel")); string(data) != "badger" {
		t.Fatal("Badger canonical state changed")
	}
	if _, err := os.Stat(filepath.Join(cometDir, "blockstore.db")); err != nil {
		t.Fatalf("CometBFT blockstore changed: %v", err)
	}
	if state, _ := os.ReadFile(filepath.Join(cometDir, "priv_validator_state.json")); string(state) != `{"height":"22271"}` {
		t.Fatalf("validator state changed: %s", state)
	}
	if n, present, err := memoriesRowCount(context.Background(), sqlitePath); err != nil || !present || n != 10 {
		t.Fatalf("SQLite changed: rows=%d present=%v err=%v", n, present, err)
	}
	if stamp, _ := os.ReadFile(filepath.Join(tmpDir, versionFile)); string(stamp) != "11.16.1\n" {
		t.Fatalf("version diagnostic stamp = %q, want 11.16.1", stamp)
	}
}

func TestMigrateOnUpgrade_MarkerlessPersistedNodeRefusesWithoutMutation(t *testing.T) {
	cases := map[string]func(home, dataDir, cometHome string) string{
		"genesis": func(_, _, cometHome string) string {
			path := filepath.Join(cometHome, "config", "genesis.json")
			_ = os.MkdirAll(filepath.Dir(path), 0o700)
			_ = os.WriteFile(path, []byte(`{"chain_id":"survived"}`), 0o600)
			return path
		},
		"badger": func(_, dataDir, _ string) string {
			path := filepath.Join(dataDir, "badger", "MANIFEST")
			_ = os.MkdirAll(filepath.Dir(path), 0o700)
			_ = os.WriteFile(path, []byte("survived"), 0o600)
			return path
		},
		"sqlite-wal": func(_, dataDir, _ string) string {
			path := filepath.Join(dataDir, "sage.db-wal")
			_ = os.MkdirAll(filepath.Dir(path), 0o700)
			_ = os.WriteFile(path, []byte("survived"), 0o600)
			return path
		},
		"backup": func(home, _, _ string) string {
			path := filepath.Join(home, "backups", "node.backup")
			_ = os.MkdirAll(filepath.Dir(path), 0o700)
			_ = os.WriteFile(path, []byte("survived"), 0o600)
			return path
		},
	}
	for name, seed := range cases {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("SAGE_HOME", home)
			dataDir := filepath.Join(home, "data")
			cometHome := filepath.Join(dataDir, "cometbft")
			sentinel := seed(home, dataDir, cometHome)
			before, readErr := os.ReadFile(sentinel)
			if readErr != nil {
				t.Fatal(readErr)
			}

			oldVersion := version
			version = "11.16.1"
			defer func() { version = oldVersion }()

			migrated, err := migrateOnUpgrade(dataDir)
			if !errors.Is(err, errAutomaticChainResetRefused) || migrated {
				t.Fatalf("markerless persisted node must refuse, migrated=%v err=%v", migrated, err)
			}
			if data, readErr := os.ReadFile(sentinel); readErr != nil || string(data) != string(before) {
				t.Fatalf("persisted evidence changed: before=%q after=%q err=%v", before, data, readErr)
			}
			if _, statErr := os.Stat(filepath.Join(home, versionFile)); !os.IsNotExist(statErr) {
				t.Fatalf("version marker must not be created, stat err=%v", statErr)
			}
			if _, statErr := os.Stat(filepath.Join(home, forkVersionFile)); !os.IsNotExist(statErr) {
				t.Fatalf("fork marker must not be created, stat err=%v", statErr)
			}
		})
	}

	t.Run("empty-badger-path", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("SAGE_HOME", home)
		dataDir := filepath.Join(home, "data")
		badgerPath := filepath.Join(dataDir, "badger")
		if err := os.MkdirAll(badgerPath, 0o700); err != nil {
			t.Fatal(err)
		}
		oldVersion := version
		version = "11.16.1"
		defer func() { version = oldVersion }()

		migrated, err := migrateOnUpgrade(dataDir)
		if !errors.Is(err, errAutomaticChainResetRefused) || migrated {
			t.Fatalf("empty pre-existing Badger path must refuse, migrated=%v err=%v", migrated, err)
		}
		if _, statErr := os.Stat(filepath.Join(home, versionFile)); !os.IsNotExist(statErr) {
			t.Fatalf("version marker must not be created, stat err=%v", statErr)
		}
		if _, statErr := os.Stat(filepath.Join(home, forkVersionFile)); !os.IsNotExist(statErr) {
			t.Fatalf("fork marker must not be created, stat err=%v", statErr)
		}
	})
}

func TestMigrateOnUpgrade_InvalidForkMarkerRefusesWithoutMutation(t *testing.T) {
	for _, raw := range []string{"garbage", "0", "-1", ""} {
		t.Run(fmt.Sprintf("marker_%q", raw), func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("SAGE_HOME", home)
			dataDir := filepath.Join(home, "data")
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(home, versionFile), []byte("11.16.0\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			forkPath := filepath.Join(home, forkVersionFile)
			if err := os.WriteFile(forkPath, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}

			oldVersion := version
			version = "11.16.1"
			defer func() { version = oldVersion }()

			migrated, err := migrateOnUpgrade(dataDir)
			if !errors.Is(err, errAutomaticChainResetRefused) || migrated {
				t.Fatalf("invalid fork marker must refuse, migrated=%v err=%v", migrated, err)
			}
			if data, _ := os.ReadFile(forkPath); string(data) != raw {
				t.Fatalf("invalid fork marker changed: %q", data)
			}
			if data, _ := os.ReadFile(filepath.Join(home, versionFile)); string(data) != "11.16.0\n" {
				t.Fatalf("version marker changed: %q", data)
			}
		})
	}

	t.Run("unreadable-kind", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("SAGE_HOME", home)
		if err := os.WriteFile(filepath.Join(home, versionFile), []byte("11.16.0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(home, forkVersionFile), 0o700); err != nil {
			t.Fatal(err)
		}
		oldVersion := version
		version = "11.16.1"
		defer func() { version = oldVersion }()
		if _, err := migrateOnUpgrade(filepath.Join(home, "data")); !errors.Is(err, errAutomaticChainResetRefused) {
			t.Fatalf("wrong-kind marker must refuse, got %v", err)
		}
	})
}

// TestMigrateOnUpgrade_PreV75_LegacyInstall_RefusesWithoutMutation locks the
// v11.16.1 safety contract: SQLite is a serving projection, not a replacement
// for canonical Badger/CometBFT history. An incompatible automatic upgrade must
// stop with every byte and diagnostic stamp unchanged.
func TestMigrateOnUpgrade_PreV75_LegacyInstall_RefusesWithoutMutation(t *testing.T) {
	for _, fromVersion := range []string{"v6.8.0", "v7.1.2", "v7.4.5", "7.3.0"} {
		fromVersion := fromVersion
		t.Run(fromVersion, func(t *testing.T) {
			tmpDir := t.TempDir()
			t.Setenv("SAGE_HOME", tmpDir)

			dataDir := filepath.Join(tmpDir, "data")
			badgerDir := filepath.Join(dataDir, "badger")
			cometDir := filepath.Join(dataDir, "cometbft", "data")
			sqlitePath := filepath.Join(dataDir, "sage.db")

			os.MkdirAll(badgerDir, 0700)
			os.MkdirAll(cometDir, 0700)
			makeMemoriesDB(t, sqlitePath, 10)
			os.WriteFile(filepath.Join(badgerDir, "000001.vlog"), []byte("badger"), 0600)
			os.MkdirAll(filepath.Join(cometDir, "blockstore.db"), 0700)
			os.MkdirAll(filepath.Join(cometDir, "state.db"), 0700)
			os.WriteFile(filepath.Join(cometDir, "priv_validator_state.json"), []byte(`{"height":"100"}`), 0600)

			os.WriteFile(filepath.Join(tmpDir, versionFile), []byte(fromVersion+"\n"), 0600)

			oldVersion := version
			version = "v7.5.6"
			defer func() { version = oldVersion }()

			migrated, err := migrateOnUpgrade(dataDir)
			if !errors.Is(err, errAutomaticChainResetRefused) {
				t.Fatalf("pre-v7.5 install (%s) must refuse automatic reset, got: %v", fromVersion, err)
			}
			if migrated {
				t.Fatalf("pre-v7.5 install (%s) must not report a migration", fromVersion)
			}

			if data, _ := os.ReadFile(filepath.Join(badgerDir, "000001.vlog")); string(data) != "badger" {
				t.Error("Badger canonical state must be preserved after refusal")
			}
			if _, statErr := os.Stat(filepath.Join(cometDir, "blockstore.db")); statErr != nil {
				t.Errorf("CometBFT blockstore must be preserved after refusal: %v", statErr)
			}
			if _, statErr := os.Stat(filepath.Join(cometDir, "state.db")); statErr != nil {
				t.Errorf("CometBFT state store must be preserved after refusal: %v", statErr)
			}
			if pvState, _ := os.ReadFile(filepath.Join(cometDir, "priv_validator_state.json")); string(pvState) != `{"height":"100"}` {
				t.Errorf("validator state must be preserved after refusal: %s", pvState)
			}

			if n, present, err := memoriesRowCount(context.Background(), sqlitePath); err != nil || !present || n != 10 {
				t.Errorf("SQLite must remain unchanged after refusal; got %d present=%v err=%v", n, present, err)
			}

			if got := readForkVersion(filepath.Join(tmpDir, forkVersionFile)); got != 0 {
				t.Errorf("fork-version = %d, want no new stamp after refusal", got)
			}
			if vData, _ := os.ReadFile(filepath.Join(tmpDir, versionFile)); strings.TrimSpace(string(vData)) != fromVersion {
				t.Errorf("version stamp changed after refusal: %q", vData)
			}
			if _, statErr := os.Stat(filepath.Join(tmpDir, "backups")); !os.IsNotExist(statErr) {
				t.Errorf("automatic refusal must not create reset backups, stat err=%v", statErr)
			}
		})
	}
}

// TestIsLegacyForkOneVersion checks the version classifier directly.
func TestIsLegacyForkOneVersion(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"v7.5.0", true},
		{"v7.5.4", true},
		{"v7.5.4-1-gabc123", true},
		{"7.5.0", true},
		{"7.5.2", true},
		{"v7.4.9", false},
		{"v7.0.0", false},
		{"v6.8.0", false},
		{"v8.0.0", false},
		{"v7.50.0", false},
		{"v75.0.0", false},
		{"", false},
		{"dev", false},
	}
	for _, c := range cases {
		if got := isLegacyForkOneVersion(c.in); got != c.want {
			t.Errorf("isLegacyForkOneVersion(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestMigrateOnUpgrade_LegacyInstall_AdoptsCurrentFork: an install that
// predates the gate (has version.txt but no fork-version.txt) must adopt
// the current ConsensusForkVersion on first boot WITHOUT resetting state.
// This is the in-place upgrade path from v7.5.4 → v7.5.5.
func TestMigrateOnUpgrade_LegacyInstall_AdoptsCurrentFork(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SAGE_HOME", tmpDir)

	dataDir := filepath.Join(tmpDir, "data")
	badgerDir := filepath.Join(dataDir, "badger")
	os.MkdirAll(badgerDir, 0700)
	os.WriteFile(filepath.Join(badgerDir, "000001.vlog"), []byte("badger"), 0600)

	os.WriteFile(filepath.Join(tmpDir, versionFile), []byte("v7.5.4\n"), 0600)

	oldVersion := version
	version = "v7.5.5"
	defer func() { version = oldVersion }()

	migrated, err := migrateOnUpgrade(dataDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if migrated {
		t.Fatal("legacy install must adopt current fork without reset")
	}

	if data, _ := os.ReadFile(filepath.Join(badgerDir, "000001.vlog")); string(data) != "badger" {
		t.Error("badger value log must be preserved on legacy-install adoption")
	}

	if got := readForkVersion(filepath.Join(tmpDir, forkVersionFile)); got != ConsensusForkVersion {
		t.Errorf("fork-version file = %d, want %d (legacy install must adopt current fork)", got, ConsensusForkVersion)
	}
}

// TestMigrateOnUpgrade_ForkBump_RefusesWithoutMutation ensures a future fork
// cannot silently destroy canonical state. A real fork transition must ship a
// deterministic in-place/governed migration.
func TestMigrateOnUpgrade_ForkBump_RefusesWithoutMutation(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SAGE_HOME", tmpDir)

	dataDir := filepath.Join(tmpDir, "data")
	badgerDir := filepath.Join(dataDir, "badger")
	cometDir := filepath.Join(dataDir, "cometbft", "data")
	sqlitePath := filepath.Join(dataDir, "sage.db")

	os.MkdirAll(badgerDir, 0700)
	os.MkdirAll(cometDir, 0700)
	makeMemoriesDB(t, sqlitePath, 10)
	os.WriteFile(filepath.Join(badgerDir, "000001.vlog"), []byte("badger"), 0600)
	os.MkdirAll(filepath.Join(cometDir, "blockstore.db"), 0700)
	os.MkdirAll(filepath.Join(cometDir, "state.db"), 0700)
	os.WriteFile(filepath.Join(cometDir, "priv_validator_state.json"), []byte(`{"height":"100"}`), 0600)

	os.WriteFile(filepath.Join(tmpDir, versionFile), []byte("v7.5.5\n"), 0600)
	stampForkVersion(filepath.Join(tmpDir, forkVersionFile), 1)

	oldVersion := version
	version = "v8.0.0"
	defer func() { version = oldVersion }()

	oldFork := ConsensusForkVersion
	ConsensusForkVersion = 2
	defer func() { ConsensusForkVersion = oldFork }()

	migrated, err := migrateOnUpgrade(dataDir)
	if !errors.Is(err, errAutomaticChainResetRefused) {
		t.Fatalf("fork bump must refuse automatic reset, got: %v", err)
	}
	if migrated {
		t.Fatal("fork bump refusal must not report migration")
	}

	if data, _ := os.ReadFile(filepath.Join(badgerDir, "000001.vlog")); string(data) != "badger" {
		t.Error("Badger canonical state must be preserved after fork refusal")
	}
	if _, statErr := os.Stat(filepath.Join(cometDir, "blockstore.db")); statErr != nil {
		t.Errorf("blockstore.db must be preserved after fork refusal: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(cometDir, "state.db")); statErr != nil {
		t.Errorf("state.db must be preserved after fork refusal: %v", statErr)
	}
	if pvState, _ := os.ReadFile(filepath.Join(cometDir, "priv_validator_state.json")); string(pvState) != `{"height":"100"}` {
		t.Errorf("validator state changed after fork refusal: %s", pvState)
	}

	if n, present, err := memoriesRowCount(context.Background(), sqlitePath); err != nil || !present || n != 10 {
		t.Errorf("SQLite must remain unchanged after fork refusal; got %d present=%v err=%v", n, present, err)
	}

	if _, statErr := os.Stat(filepath.Join(tmpDir, "backups")); !os.IsNotExist(statErr) {
		t.Errorf("automatic refusal must not create reset backups, stat err=%v", statErr)
	}

	if got := readForkVersion(filepath.Join(tmpDir, forkVersionFile)); got != 1 {
		t.Errorf("fork-version file = %d, want old stamp 1 after refusal", got)
	}
	vData, _ := os.ReadFile(filepath.Join(tmpDir, versionFile))
	if strings.TrimSpace(string(vData)) != "v7.5.5" {
		t.Errorf("version file changed after refusal: %q", vData)
	}
}

func TestMigrateOnUpgrade_ForkBump_RefusalLeavesOldForkStamp(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SAGE_HOME", tmpDir)

	dataDir := filepath.Join(tmpDir, "data")
	os.MkdirAll(dataDir, 0700)

	os.WriteFile(filepath.Join(tmpDir, versionFile), []byte("v7.5.5\n"), 0600)
	stampForkVersion(filepath.Join(tmpDir, forkVersionFile), 1)

	oldVersion := version
	version = "v8.0.0"
	defer func() { version = oldVersion }()
	oldFork := ConsensusForkVersion
	ConsensusForkVersion = 2
	defer func() { ConsensusForkVersion = oldFork }()

	_, err := migrateOnUpgrade(dataDir)
	if !errors.Is(err, errAutomaticChainResetRefused) {
		t.Fatalf("fork mismatch must return typed refusal, got: %v", err)
	}

	got := readForkVersion(filepath.Join(tmpDir, forkVersionFile))
	if got != 1 {
		t.Errorf("fork stamp after refusal = %d, want original 1", got)
	}
}

func TestMigrateOnUpgrade_DevVersion(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SAGE_HOME", tmpDir)

	dataDir := filepath.Join(tmpDir, "data")
	os.MkdirAll(dataDir, 0700)

	oldVersion := version
	version = "dev"
	defer func() { version = oldVersion }()

	os.WriteFile(filepath.Join(tmpDir, versionFile), []byte("v2.4.0\n"), 0600)

	migrated, err := migrateOnUpgrade(dataDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if migrated {
		t.Error("dev builds should skip migration")
	}
}

// makeMemoriesDB writes a sqlite DB at path with a memories table holding n rows,
// optionally padded with a wide free-able column so a later VACUUM can shrink it a
// lot (to model a fragmented DB).
func makeMemoriesDB(t *testing.T, path string, n int) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE TABLE memories (memory_id TEXT PRIMARY KEY, status TEXT, content TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	for i := 0; i < n; i++ {
		if _, err := db.Exec(`INSERT INTO memories VALUES (?, 'committed', ?)`, i, strings.Repeat("x", 4096)); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
}

// TestVerifyBackup_FragmentedVacuumAccepted is the F1 regression: a VACUUM INTO
// backup of a heavily-fragmented DB is >5% smaller than the source yet perfectly
// valid — the old size gate falsely rejected it. It must now pass.
func TestVerifyBackup_FragmentedVacuumAccepted(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "sage.db")
	makeMemoriesDB(t, src, 200)
	// Fragment: delete 80% of rows, leaving lots of free pages.
	db, _ := sql.Open("sqlite", src)
	if _, err := db.Exec(`DELETE FROM memories WHERE CAST(memory_id AS INTEGER) >= 40`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_ = db.Close()

	backup := filepath.Join(dir, "backup.db")
	if err := vacuumBackup(src, backup); err != nil {
		t.Fatalf("vacuum backup: %v", err)
	}
	si, _ := os.Stat(src)
	bi, _ := os.Stat(backup)
	if bi.Size() >= (si.Size()*19)/20 {
		t.Skip("backup did not shrink >5%; fragmentation model insufficient on this platform")
	}
	if err := verifyBackup(src, backup); err != nil {
		t.Errorf("a valid VACUUM backup of a fragmented DB must pass, got: %v", err)
	}
}

// TestVerifyBackup_RawCopyAccepted: when VACUUM INTO fails, resetChainState falls
// back to a byte-for-byte file copy. Verify such a copy (identical bytes, full row
// count, larger-or-equal size) passes the content check.
func TestVerifyBackup_RawCopyAccepted(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "sage.db")
	makeMemoriesDB(t, src, 50)
	backup := filepath.Join(dir, "backup.db")
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyBackup(src, backup); err != nil {
		t.Errorf("a raw byte-for-byte copy must pass verify, got: %v", err)
	}
}

// TestVerifyBackup_MissingOrEmptyRejected covers the trivial failure modes.
func TestVerifyBackup_MissingOrEmptyRejected(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "sage.db")
	makeMemoriesDB(t, src, 5)

	if err := verifyBackup(src, filepath.Join(dir, "nope.db")); err == nil {
		t.Error("missing backup must be rejected")
	}
	empty := filepath.Join(dir, "empty.db")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyBackup(src, empty); err == nil {
		t.Error("empty backup must be rejected")
	}
}

// TestVerifyBackup_TruncatedRowsRejected: a backup with FEWER memories than the live
// DB is the real truncation signal and must be refused, with the intact reassurance.
func TestVerifyBackup_TruncatedRowsRejected(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "sage.db")
	backup := filepath.Join(dir, "backup.db")
	makeMemoriesDB(t, src, 100)
	makeMemoriesDB(t, backup, 40) // fewer rows -> truncation
	err := verifyBackup(src, backup)
	if err == nil {
		t.Fatal("a backup missing memories must be rejected")
	}
	if !strings.Contains(err.Error(), "intact") {
		t.Errorf("error must reassure with 'intact', got: %v", err)
	}
}

// TestVerifyBackup_CorruptRejected: a non-sqlite / garbage backup fails quick_check.
func TestVerifyBackup_CorruptRejected(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "sage.db")
	makeMemoriesDB(t, src, 5)
	corrupt := filepath.Join(dir, "corrupt.db")
	if err := os.WriteFile(corrupt, []byte("this is not a sqlite database, at all, nope"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyBackup(src, corrupt); err == nil {
		t.Error("a corrupt backup must be rejected")
	}
}

// TestVerifyBackup_FreshSourceNoMemoriesTable: a source without a memories table
// (fresh/foreign DB) skips the row check but still requires a structurally sound
// backup.
func TestVerifyBackup_FreshSourceNoMemoriesTable(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "sage.db")
	db, _ := sql.Open("sqlite", src)
	if _, err := db.Exec(`CREATE TABLE other (x INTEGER)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	backup := filepath.Join(dir, "backup.db")
	if err := vacuumBackup(src, backup); err != nil {
		t.Fatalf("vacuum: %v", err)
	}
	if err := verifyBackup(src, backup); err != nil {
		t.Errorf("a valid backup of a memories-less DB must pass, got: %v", err)
	}
}

func TestReadForkVersion_AbsentFileReturnsZero(t *testing.T) {
	tmpDir := t.TempDir()
	if got := readForkVersion(filepath.Join(tmpDir, "nope.txt")); got != 0 {
		t.Errorf("missing file should return 0, got %d", got)
	}
}

func TestStampForkVersion_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "fork.txt")
	if err := stampForkVersion(path, 42); err != nil {
		t.Fatal(err)
	}
	if got := readForkVersion(path); got != 42 {
		t.Errorf("round trip = %d, want 42", got)
	}
	// File should be parseable plain integer with trailing newline.
	data, _ := os.ReadFile(path)
	if strings.TrimSpace(string(data)) != strconv.Itoa(42) {
		t.Errorf("file content = %q", data)
	}
}
