package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/rs/zerolog"
)

// testGenesisJSON builds a valid genesis document (single validator) with the
// given chain_id and returns its canonical JSON bytes.
func testGenesisJSON(t *testing.T, chainID string) []byte {
	t.Helper()
	pk := ed25519.GenPrivKey().PubKey()
	gen := cmttypes.GenesisDoc{
		ChainID:         chainID,
		GenesisTime:     time.Unix(1700000000, 0).UTC(),
		ConsensusParams: cmttypes.DefaultConsensusParams(),
		Validators: []cmttypes.GenesisValidator{{
			Address: pk.Address(),
			PubKey:  pk,
			Power:   10,
			Name:    "host",
		}},
	}
	if err := gen.ValidateAndComplete(); err != nil {
		t.Fatalf("build genesis: %v", err)
	}
	dir := t.TempDir()
	path := dir + "/genesis.json"
	if err := gen.SaveAs(path); err != nil {
		t.Fatalf("save genesis: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read genesis: %v", err)
	}
	return data
}

const goodHostPeer = "0123456789abcdef0123456789abcdef01234567@192.168.1.5:26656"

func writeVendoredNetworkTransitionConfig(t *testing.T, home string) *Config {
	t.Helper()
	t.Setenv("SAGE_HOME", home)
	cfg := DefaultConfig(home)
	cfg.VendoredAgentBootstrap = &VendoredAgentBootstrapConfig{
		AgentKeyFile: filepath.Join(home, "app-owned", "agent.key"),
		HomeDomain:   "voice-interface",
		Clearance:    1,
	}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("save vendored config: %v", err)
	}
	return cfg
}

func snapshotTestTree(t *testing.T, root string) map[string]string {
	t.Helper()
	snapshot := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			snapshot[relative] = "<dir>"
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		snapshot[relative] = string(data)
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", root, err)
	}
	return snapshot
}

func seedVendoredJoinSentinels(t *testing.T, home string) {
	t.Helper()
	files := map[string]string{
		filepath.Join(home, "data", "cometbft", "config", "genesis.json"):            "original vendored genesis",
		filepath.Join(home, "data", "cometbft", "data", "blockstore.db", "MANIFEST"): "original block state",
		filepath.Join(home, "data", "badger", "MANIFEST"):                            "original app state",
		filepath.Join(home, "data", "sage.db"):                                       "original projection",
	}
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
	}
}

func TestVendoredNodeJoinRejectsBeforeAnyMutation(t *testing.T) {
	home := t.TempDir()
	writeVendoredNetworkTransitionConfig(t, home)
	seedVendoredJoinSentinels(t, home)
	before := snapshotTestTree(t, home)

	err := doWipeAndAdopt(NodeJoinBundle{
		ChainID:  "sage-quorum-replacement",
		HostPeer: goodHostPeer,
	}, []byte("replacement genesis"))
	if err == nil || !strings.Contains(err.Error(), "use federation") {
		t.Fatalf("vendored network join error = %v, want use-federation refusal", err)
	}
	after := snapshotTestTree(t, home)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("vendored network join mutated files before refusal\nbefore=%v\nafter=%v", before, after)
	}
}

func TestGenericNodeJoinStillAdoptsAndPersistsQuorum(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SAGE_HOME", home)
	cfg := DefaultConfig(home)
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("save generic config: %v", err)
	}
	const chainID = "sage-quorum-generic"
	genesis := testGenesisJSON(t, chainID)
	if err := doWipeAndAdopt(NodeJoinBundle{
		ChainID:  chainID,
		HostPeer: goodHostPeer,
	}, genesis); err != nil {
		t.Fatalf("generic network join: %v", err)
	}

	reloaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("reload adopted config: %v", err)
	}
	if !reloaded.Quorum.Enabled {
		t.Fatal("generic network join did not persist quorum mode")
	}
	if reloaded.ChainID != chainID {
		t.Fatalf("adopted chain_id = %q, want %q", reloaded.ChainID, chainID)
	}
	if len(reloaded.Quorum.Peers) != 1 || reloaded.Quorum.Peers[0] != goodHostPeer {
		t.Fatalf("adopted peers = %v, want [%s]", reloaded.Quorum.Peers, goodHostPeer)
	}
	writtenGenesis, err := os.ReadFile(filepath.Join(home, "data", "cometbft", "config", "genesis.json"))
	if err != nil {
		t.Fatalf("read adopted genesis: %v", err)
	}
	if !reflect.DeepEqual(writtenGenesis, genesis) {
		t.Fatal("generic network join did not preserve the host genesis bytes")
	}
}

func TestVendoredQuorumJoinRejectsBeforeAnyMutation(t *testing.T) {
	home := t.TempDir()
	writeVendoredNetworkTransitionConfig(t, home)
	seedVendoredJoinSentinels(t, home)
	before := snapshotTestTree(t, home)
	originalArgs := os.Args
	os.Args = []string{"sage-gui", "quorum-join"}
	t.Cleanup(func() { os.Args = originalArgs })

	err := runQuorumJoin()
	if err == nil || !strings.Contains(err.Error(), "use federation") {
		t.Fatalf("vendored quorum join error = %v, want use-federation refusal", err)
	}
	after := snapshotTestTree(t, home)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("vendored quorum join mutated files before refusal\nbefore=%v\nafter=%v", before, after)
	}
}

func TestVendoredQuorumInitRejectsBeforeAnyMutation(t *testing.T) {
	home := t.TempDir()
	writeVendoredNetworkTransitionConfig(t, home)
	seedVendoredJoinSentinels(t, home)
	before := snapshotTestTree(t, home)
	originalArgs := os.Args
	os.Args = []string{"sage-gui", "quorum-init", "--address", "127.0.0.1:26656"}
	t.Cleanup(func() { os.Args = originalArgs })

	err := runQuorumInit()
	if err == nil || !strings.Contains(err.Error(), "use federation") {
		t.Fatalf("vendored quorum init error = %v, want use-federation refusal", err)
	}
	after := snapshotTestTree(t, home)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("vendored quorum init mutated files before refusal\nbefore=%v\nafter=%v", before, after)
	}
}

func TestVendoredPendingJoinRejectsStagingAndDiscardsLegacyStage(t *testing.T) {
	home := t.TempDir()
	writeVendoredNetworkTransitionConfig(t, home)
	seedVendoredJoinSentinels(t, home)
	before := snapshotTestTree(t, home)

	if err := WritePendingJoin([]byte(`{"chain_id":"never-stage"}`)); err == nil ||
		!strings.Contains(err.Error(), "use federation") {
		t.Fatalf("vendored pending join staging error = %v, want use-federation refusal", err)
	}
	if _, err := os.Stat(pendingJoinPath()); !os.IsNotExist(err) {
		t.Fatalf("vendored pending join was staged: stat error=%v", err)
	}

	const chainID = "sage-quorum-legacy-stage"
	runningSHA, err := runningBinarySHA256()
	if err != nil {
		t.Fatalf("fingerprint running test binary: %v", err)
	}
	legacyBundle, err := json.Marshal(NodeJoinBundle{
		AppVersion:   version,
		BinarySHA256: runningSHA,
		ChainID:      chainID,
		GenesisB64:   base64.StdEncoding.EncodeToString(testGenesisJSON(t, chainID)),
		HostPeer:     goodHostPeer,
	})
	if err != nil {
		t.Fatalf("marshal legacy staged join: %v", err)
	}
	if err := os.WriteFile(pendingJoinPath(), legacyBundle, 0o600); err != nil {
		t.Fatalf("seed legacy pending join: %v", err)
	}
	applied, err := applyPendingJoinAtStartup(zerolog.Nop())
	if err != nil {
		t.Fatalf("discard legacy staged join: %v", err)
	}
	if applied {
		t.Fatal("vendored legacy staged join was unexpectedly applied")
	}
	if _, err := os.Stat(pendingJoinPath()); !os.IsNotExist(err) {
		t.Fatalf("legacy pending join still causes a restart loop: stat error=%v", err)
	}
	after := snapshotTestTree(t, home)
	delete(after, "pending-join.json")
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("legacy pending join mutated the vendored node\nbefore=%v\nafter=%v", before, after)
	}
}

func TestVendoredSettingsNetworkModeDoesNotMutateOrPersist(t *testing.T) {
	home := t.TempDir()
	cfg := writeVendoredNetworkTransitionConfig(t, home)
	configPath := filepath.Join(home, "config.yaml")
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config before toggle: %v", err)
	}

	err = setNetworkMode(cfg, true)
	if err == nil || !strings.Contains(err.Error(), "use federation") {
		t.Fatalf("vendored Settings toggle error = %v, want use-federation refusal", err)
	}
	if cfg.Quorum.Enabled {
		t.Fatal("vendored Settings toggle mutated the live config before refusal")
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config after toggle: %v", err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatal("vendored Settings toggle persisted an invalid quorum config")
	}
}

func TestGenericSettingsNetworkModeStillPersists(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SAGE_HOME", home)
	cfg := DefaultConfig(home)
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("save generic config: %v", err)
	}
	if err := setNetworkMode(cfg, true); err != nil {
		t.Fatalf("enable generic quorum mode: %v", err)
	}
	if !cfg.Quorum.Enabled {
		t.Fatal("generic Settings toggle did not update the live config")
	}
	reloaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("reload generic config: %v", err)
	}
	if !reloaded.Quorum.Enabled {
		t.Fatal("generic Settings toggle did not persist quorum mode")
	}
}

func TestValidateNodeJoinBundle_Valid(t *testing.T) {
	gen := testGenesisJSON(t, "sage-quorum-abc123")
	b := NodeJoinBundle{
		ChainID:    "sage-quorum-abc123",
		GenesisB64: base64.StdEncoding.EncodeToString(gen),
		HostPeer:   goodHostPeer,
	}
	out, err := validateNodeJoinBundle(b)
	if err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
	if len(out) != len(gen) {
		t.Fatalf("returned genesis bytes mismatch")
	}
}

func TestValidateNodeJoinBundle_Rejects(t *testing.T) {
	gen := testGenesisJSON(t, "sage-quorum-abc123")
	genB64 := base64.StdEncoding.EncodeToString(gen)

	cases := []struct {
		name string
		b    NodeJoinBundle
	}{
		{"empty chain_id", NodeJoinBundle{ChainID: "", GenesisB64: genB64, HostPeer: goodHostPeer}},
		{"host_peer no @", NodeJoinBundle{ChainID: "x", GenesisB64: genB64, HostPeer: "0123456789abcdef0123456789abcdef01234567_192.168.1.5:26656"}},
		{"host_peer bad node id", NodeJoinBundle{ChainID: "x", GenesisB64: genB64, HostPeer: "shortid@192.168.1.5:26656"}},
		{"host_peer non-ip host", NodeJoinBundle{ChainID: "x", GenesisB64: genB64, HostPeer: "0123456789abcdef0123456789abcdef01234567@example.com:26656"}},
		{"host_peer no port", NodeJoinBundle{ChainID: "x", GenesisB64: genB64, HostPeer: "0123456789abcdef0123456789abcdef01234567@192.168.1.5"}},
		{"bad base64", NodeJoinBundle{ChainID: "x", GenesisB64: "!!!not base64!!!", HostPeer: goodHostPeer}},
		{"unparseable genesis", NodeJoinBundle{ChainID: "x", GenesisB64: base64.StdEncoding.EncodeToString([]byte("{not genesis")), HostPeer: goodHostPeer}},
		{"chain_id mismatch", NodeJoinBundle{ChainID: "sage-quorum-DIFFERENT", GenesisB64: genB64, HostPeer: goodHostPeer}},
	}
	for _, c := range cases {
		if _, err := validateNodeJoinBundle(c.b); err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}

func TestResetProjectionReceiptsForJoinPreservesUserData(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "sage.db")
	db, openErr := sql.Open("sqlite", dbPath)
	if openErr != nil {
		t.Fatalf("open SQLite: %v", openErr)
	}
	if _, err := db.Exec(`
		CREATE TABLE memories (memory_id TEXT PRIMARY KEY, content TEXT NOT NULL);
		CREATE TABLE abci_projection_batches (
			block_height INTEGER PRIMARY KEY,
			app_hash BLOB NOT NULL
		);
		INSERT INTO memories(memory_id, content) VALUES ('keep-me', 'local memory');
		INSERT INTO abci_projection_batches(block_height, app_hash) VALUES (15, zeroblob(32));
	`); err != nil {
		_ = db.Close()
		t.Fatalf("seed SQLite: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close SQLite: %v", err)
	}

	if err := resetProjectionReceiptsForJoin(dbPath); err != nil {
		t.Fatalf("reset receipts: %v", err)
	}

	db, openErr = sql.Open("sqlite", dbPath)
	if openErr != nil {
		t.Fatalf("reopen SQLite: %v", openErr)
	}
	defer func() { _ = db.Close() }()
	var memories, receipts int
	if err := db.QueryRow(`SELECT COUNT(*) FROM memories`).Scan(&memories); err != nil {
		t.Fatalf("count memories: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM abci_projection_batches`).Scan(&receipts); err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if memories != 1 {
		t.Fatalf("memories = %d, want 1", memories)
	}
	if receipts != 0 {
		t.Fatalf("projection receipts = %d, want 0", receipts)
	}
}

func TestResetProjectionReceiptsForJoinAcceptsFreshNode(t *testing.T) {
	if err := resetProjectionReceiptsForJoin(filepath.Join(t.TempDir(), "missing.db")); err != nil {
		t.Fatalf("fresh node reset: %v", err)
	}
}

func TestValidateNodeJoinCompatibilityRejectsDifferentDevBuild(t *testing.T) {
	b := NodeJoinBundle{
		AppVersion:   version,
		BinarySHA256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
	if err := validateNodeJoinCompatibility(b); err == nil {
		t.Fatal("expected a different executable fingerprint to be rejected")
	}
}

func TestValidateNodeJoinCompatibilityAcceptsRunningBuild(t *testing.T) {
	sha, err := runningBinarySHA256()
	if err != nil {
		t.Fatalf("fingerprint running test binary: %v", err)
	}
	if err := validateNodeJoinCompatibility(NodeJoinBundle{AppVersion: version, BinarySHA256: sha}); err != nil {
		t.Fatalf("running build rejected: %v", err)
	}
}
