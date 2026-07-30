package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const federationTransportKeyRecoveryGuidance = "Restore the original key from backup. SAGE will not generate a replacement for an initialized node because peers pin this exact identity. If the original key is unrecoverable, create a new node identity and re-pair every federation peer; do not copy another node's key."

// persistedNodeIdentityEvidence reports state that makes cfg.AgentKey an
// existing identity rather than a first-launch input. Genesis is the ordinary
// signal; the other paths fail closed for partial/crash-recovered layouts where
// agreement or chain state survived without genesis.json.
func persistedNodeIdentityEvidence(sageHome, dataDir, cometHome string) (string, error) {
	files := []struct {
		label string
		path  string
	}{
		{"CometBFT genesis", filepath.Join(cometHome, "config", "genesis.json")},
		{"CometBFT genesis backup", filepath.Join(cometHome, "config", "genesis.json.bak")},
		{"CometBFT pre-remint genesis backup", filepath.Join(cometHome, "config", "genesis.json.pre-remint.bak")},
		{"CometBFT interrupted genesis rewrite", filepath.Join(cometHome, "config", "genesis.json.tmp")},
		{"CometBFT validator identity", filepath.Join(cometHome, "config", "priv_validator_key.json")},
		{"CometBFT peer identity", filepath.Join(cometHome, "config", "node_key.json")},
		{"CometBFT node configuration", filepath.Join(cometHome, "config", "config.toml")},
		{"CometBFT block store", filepath.Join(cometHome, "data", "blockstore.db")},
		{"CometBFT state store", filepath.Join(cometHome, "data", "state.db")},
		{"CometBFT validator signing state", filepath.Join(cometHome, "data", "priv_validator_state.json")},
		{"CometBFT transaction index", filepath.Join(cometHome, "data", "tx_index.db")},
		{"CometBFT evidence store", filepath.Join(cometHome, "data", "evidence.db")},
		{"CometBFT consensus WAL", filepath.Join(cometHome, "data", "cs.wal")},
		{"SQLite node state", filepath.Join(dataDir, "sage.db")},
		{"SQLite write-ahead log", filepath.Join(dataDir, "sage.db-wal")},
		{"SQLite shared-memory state", filepath.Join(dataDir, "sage.db-shm")},
		{"SQLite rollback journal", filepath.Join(dataDir, "sage.db-journal")},
		{"state-sync activation journal", filepath.Join(dataDir, stateSyncActivationJournalName)},
		{"state-sync projection baseline", stateSyncProjectionBaselinePath(dataDir)},
		{"pending state-sync projection baseline", stateSyncProjectionBaselinePendingPath(dataDir)},
		{"post-crash HALT sentinel", filepath.Join(dataDir, "HALT")},
		{"interrupted post-crash HALT sentinel", filepath.Join(dataDir, ".HALT.tmp")},
	}
	for _, candidate := range files {
		// Lstat deliberately treats dangling symlinks and wrong-kind directory
		// entries as durable/corrupt evidence. Following a dangling link would
		// report ENOENT and could incorrectly authorize a fresh key mint.
		_, err := os.Lstat(candidate.path)
		switch {
		case err == nil:
			// A zero-byte file or wrong-kind directory is still evidence of an
			// interrupted/corrupted initialized node. Never turn damaged state into
			// permission to mint a different transport identity.
			return candidate.label, nil
		case os.IsNotExist(err):
			continue
		default:
			return "", fmt.Errorf("inspect %s at %s: %w", candidate.label, candidate.path, err)
		}
	}

	dirs := []struct {
		label string
		path  string
	}{
		{"Badger chain state", filepath.Join(dataDir, "badger")},
		{"state-sync working state", filepath.Join(dataDir, "state-sync")},
		{"canonical node snapshots", filepath.Join(dataDir, "snapshots")},
		{"node recovery backups", filepath.Join(sageHome, "backups")},
		// The redeploy orchestrator intentionally roots backups beside DataDir.
		// With a custom DataDir this is distinct from SAGE_HOME/backups, and either
		// location proves that this is not a genuinely fresh chain origin.
		{"data-directory recovery backups", filepath.Clean(filepath.Join(dataDir, "..", "backups"))},
		{"federation trust material", filepath.Join(sageHome, "certs", "federation")},
	}
	for _, candidate := range dirs {
		entries, err := os.ReadDir(candidate.path)
		switch {
		case err == nil && len(entries) > 0:
			return candidate.label, nil
		case err == nil:
			continue
		case os.IsNotExist(err):
			continue
		default:
			return "", fmt.Errorf("inspect %s at %s: %w", candidate.label, candidate.path, err)
		}
	}

	// Activation directory names are minted dynamically, so they cannot be
	// enumerated as fixed paths above. Their mere presence—even empty after a
	// crash—is evidence that startup must recover rather than mint a new chain.
	entries, err := os.ReadDir(dataDir)
	switch {
	case err == nil:
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "badger.state-sync-prepared-") ||
				strings.HasPrefix(entry.Name(), "badger.state-sync-quarantine-") {
				return "state-sync activation directory", nil
			}
		}
	case os.IsNotExist(err):
		// A missing data root is the ordinary first-launch case.
	default:
		return "", fmt.Errorf("inspect state-sync activation directories at %s: %w", dataDir, err)
	}
	return "", nil
}

func readFederationTransportKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // configured local identity path
	if err != nil {
		return nil, err
	}
	return decodeEd25519PrivateKey(data)
}

// loadStableFederationTransportKey generates cfg.AgentKey only for a genuinely
// fresh node. Once any chain/agreement identity exists, missing or malformed key
// material is a recovery event: silently replacing it would make every peer's
// JOIN-frozen operator pin reject this node.
func loadStableFederationTransportKey(
	keyPath, sageHome, dataDir, cometHome string,
) (ed25519.PrivateKey, error) {
	keyPath = filepath.Clean(keyPath)
	evidence, err := persistedNodeIdentityEvidence(sageHome, dataDir, cometHome)
	if err != nil {
		return nil, fmt.Errorf("determine whether the node transport identity is initialized: %w", err)
	}
	if evidence == "" {
		if mkdirErr := os.MkdirAll(filepath.Dir(keyPath), 0o700); mkdirErr != nil {
			return nil, fmt.Errorf(
				"create fresh node federation transport key directory for %s: %w",
				keyPath, mkdirErr,
			)
		}
		key, loadErr := loadOrGenerateKey(keyPath)
		if loadErr != nil {
			return nil, fmt.Errorf(
				"initialize fresh node federation transport key at %s: %w; "+
					"if this is a disposable first launch, repair or remove only this invalid key file and restart",
				keyPath, loadErr,
			)
		}
		return key, nil
	}

	key, loadErr := readFederationTransportKey(keyPath)
	if loadErr != nil {
		state := "unreadable"
		if errors.Is(loadErr, os.ErrNotExist) {
			state = "missing"
		}
		return nil, fmt.Errorf(
			"stable node federation transport key is %s at %s (initialized state: %s): %w. %s",
			state, keyPath, evidence, loadErr, federationTransportKeyRecoveryGuidance,
		)
	}
	return key, nil
}

// verifyStableFederationTransportKey closes the startup window between the
// first-launch/bootstrap work and federation Manager construction. It never
// generates: deletion, corruption, or a key-path target content change stops
// networking before a different identity can be advertised. Relocating the
// exact semantically valid key preserves the peer-pinned cryptographic
// identity and is safe.
func verifyStableFederationTransportKey(path string, expected ed25519.PrivateKey) error {
	current, err := readFederationTransportKey(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf(
			"stable node federation transport key changed during startup at %s: %w. %s",
			path, err, federationTransportKeyRecoveryGuidance,
		)
	}
	if !bytes.Equal(current, expected) {
		return fmt.Errorf(
			"stable node federation transport key changed during startup at %s. %s",
			path, federationTransportKeyRecoveryGuidance,
		)
	}
	return nil
}

func federationTransportKeyLabel(key ed25519.PrivateKey) string {
	if len(key) != ed25519.PrivateKeySize {
		return ""
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return ""
	}
	return strings.ToLower(fmt.Sprintf("%x", pub))
}
