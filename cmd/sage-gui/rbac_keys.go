package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/l33tdawg/sage/internal/store"
)

// This file wires the two signing identities the v11.3 RBAC reassign +
// access-control surface needs, WITHOUT changing consensus:
//
//   - adminSigningKey = the stable node operator/transport key at
//     cfg.agent_key_file. Before app-v23 it is normally the on-chain genesis
//     admin (Role=="admin"). App-v23 Root handover may retire that governance
//     authority without rotating the JOIN-frozen transport identity; current
//     Root signing is therefore resolved separately at action time.
//
//   - localAgentKeyResolver maps an on-chain agent id (hex(pubkey)) to the
//     local Ed25519 key that produces it, over the keys this node already
//     holds. AccessGrant/AccessRevoke are authorized by DOMAIN OWNERSHIP (not
//     admin), so a grant must be signed AS the domain owner; the resolver
//     finds that owner's key when it lives on this box and reports absence for
//     remote agents (so the caller can defer instead of failing).

// parseKeyFile reads an Ed25519 key file (32-byte seed or 64-byte full key)
// WITHOUT the generate-on-missing side effect of loadOrGenerateKey. Returns
// (nil, false) for a missing/unreadable/malformed file so a scan never mints a
// new key.
func parseKeyFile(path string) (ed25519.PrivateKey, bool) {
	data, err := os.ReadFile(path) //nolint:gosec // path is an internal ~/.sage agent key file
	if err != nil {
		return nil, false
	}
	key, err := decodeEd25519PrivateKey(data)
	return key, err == nil
}

// decodeEd25519PrivateKey accepts both SAGE's canonical 32-byte seed encoding
// and the standard 64-byte seed||public encoding. The latter is redundant, so
// accepting length alone would let damaged bytes advertise one Agent ID while
// ed25519.Sign derives a signature from another. Always copy caller-owned bytes
// so a later buffer mutation cannot change the resolved identity.
func decodeEd25519PrivateKey(data []byte) (ed25519.PrivateKey, error) {
	switch len(data) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(append([]byte(nil), data...)), nil
	case ed25519.PrivateKeySize:
		key := ed25519.PrivateKey(append([]byte(nil), data...))
		derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
		if !bytes.Equal(derived, key) {
			return nil, fmt.Errorf("invalid 64-byte Ed25519 private key: public component does not match seed")
		}
		return key, nil
	default:
		return nil, fmt.Errorf(
			"invalid key file size: %d bytes (expected %d-byte Ed25519 seed or %d-byte private key)",
			len(data), ed25519.SeedSize, ed25519.PrivateKeySize,
		)
	}
}

// adminSigningKeyAt loads the stable operator/transport key (normally
// ~/.sage/agent.key, but the configured cfg.AgentKey path wins). It is the
// legacy/pre-v23 genesis admin signer; app-v23 callers must resolve the current
// Root credential instead of assuming this transport key still has authority.
// Returns nil if the key is absent.
func adminSigningKeyAt(path string) ed25519.PrivateKey {
	k, ok := parseKeyFile(path)
	if !ok {
		return nil
	}
	return k
}

// localAgentKeyResolverWithOperator builds a resolver mapping agentID
// (hex(pubkey)) -> the local private key that produces it, scanning the
// operator key path plus ~/.sage/agent.key, installed-agent keys, and
// CEREBRUM-created bundle keys.
// The resolver only ever returns keys already held locally and never derives or
// exposes key material; it reports (nil, false) for any agent whose key is not
// on this node (e.g. a remote federated agent).
func localAgentKeyResolverWithOperator(operatorKeyPath string) func(agentID string) (ed25519.PrivateKey, bool) {
	return localAgentKeyResolverWithOperatorCache(operatorKeyPath, time.Second, time.Now)
}

type localAgentKeyCacheEntry struct {
	key       ed25519.PrivateKey
	found     bool
	expiresAt time.Time
}

// localAgentKeyResolverWithOperatorCache is split out so the bounded freshness
// and negative-cache behavior can be tested without sleeping. Cache expiry is
// per requested agent: one recently missed identity must not suppress a scan
// for a different identity, while both positive and negative answers avoid
// repeated directory walks for cacheTTL.
func localAgentKeyResolverWithOperatorCache(
	operatorKeyPath string,
	cacheTTL time.Duration,
	now func() time.Time,
) func(agentID string) (ed25519.PrivateKey, bool) {
	var (
		mu    sync.Mutex
		cache = make(map[string]localAgentKeyCacheEntry)
	)
	scan := func() map[string]ed25519.PrivateKey {
		byID := make(map[string]ed25519.PrivateKey)
		add := func(path string) {
			k, ok := parseKeyFile(path)
			if !ok {
				return
			}
			pub, ok := k.Public().(ed25519.PublicKey)
			if !ok {
				return
			}
			byID[hex.EncodeToString(pub)] = k
		}
		home := SageHome()
		add(operatorKeyPath)
		// Also recognize the conventional path when a custom configured key is
		// used; it may belong to another explicitly local agent/legacy install.
		if operatorKeyPath != filepath.Join(home, "agent.key") {
			add(filepath.Join(home, "agent.key"))
		}
		agentsDir := filepath.Join(home, "agents")
		if entries, err := os.ReadDir(agentsDir); err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				add(filepath.Join(agentsDir, e.Name(), "agent.key"))
			}
		}
		bundlesDir := filepath.Join(home, "bundles")
		if entries, err := os.ReadDir(bundlesDir); err == nil {
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				add(filepath.Join(bundlesDir, e.Name(), "agent.key"))
			}
		}
		return byID
	}
	return func(agentID string) (ed25519.PrivateKey, bool) {
		mu.Lock()
		defer mu.Unlock()
		nowAt := now()
		if entry, ok := cache[agentID]; ok && nowAt.Before(entry.expiresAt) {
			return entry.key, entry.found
		}
		byID := scan()
		next := make(map[string]localAgentKeyCacheEntry, len(byID)+1)
		for id, key := range byID {
			expiresAt := nowAt.Add(cacheTTL)
			if previous, exists := cache[id]; exists && previous.found && nowAt.Before(previous.expiresAt) {
				// A scan for another identity may refresh the key bytes, but it must
				// not indefinitely extend this identity's own rotation deadline.
				expiresAt = previous.expiresAt
			}
			next[id] = localAgentKeyCacheEntry{key: key, found: true, expiresAt: expiresAt}
		}
		for id, previous := range cache {
			if !previous.found && nowAt.Before(previous.expiresAt) {
				next[id] = previous
			}
		}
		k, ok := byID[agentID]
		if !ok {
			next[agentID] = localAgentKeyCacheEntry{expiresAt: nowAt.Add(cacheTTL)}
		}
		cache = next
		return k, ok
	}
}

type appV23RootStateReader interface {
	GetAppV23Root() (*store.AppV23RootState, error)
}

// currentUpgradeSigningKey resolves the identity allowed to drive unattended
// governance. Before app-v23 exists, the configured operator key retains the
// historical behavior needed to climb the fork ladder. Once app-v23 is active,
// only the exact current consensus Root credential is accepted; a missing
// recovery-bundle key is an explicit failure, never a fallback to stale
// ~/.sage/agent.key.
func currentUpgradeSigningKey(
	rootState appV23RootStateReader,
	postV23 func() bool,
	resolveLocalKey func(string) (ed25519.PrivateKey, bool),
	legacyKeyPath string,
	logger zerolog.Logger,
) (ed25519.PrivateKey, error) {
	if rootState == nil {
		return nil, fmt.Errorf("consensus Root state reader unavailable")
	}
	root, err := rootState.GetAppV23Root()
	if err != nil {
		return nil, fmt.Errorf("read current CEREBRUM Root: %w", err)
	}
	if root == nil {
		if postV23 != nil && postV23() {
			return nil, fmt.Errorf("app-v23 is active but no committed CEREBRUM Root exists")
		}
		key := loadOperatorAgentKeyAt(legacyKeyPath, logger)
		if key == nil {
			return nil, fmt.Errorf("legacy operator agent key unavailable")
		}
		return key, nil
	}
	credentialID := strings.TrimSpace(root.CredentialID)
	if credentialID == "" {
		return nil, fmt.Errorf("committed CEREBRUM Root credential is empty")
	}
	if resolveLocalKey == nil {
		return nil, fmt.Errorf("local CEREBRUM key resolver unavailable")
	}
	key, ok := resolveLocalKey(credentialID)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("current CEREBRUM Root key %s is not held on this machine", credentialID)
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok || hex.EncodeToString(pub) != credentialID {
		return nil, fmt.Errorf("local key does not match current CEREBRUM Root credential %s", credentialID)
	}
	return key, nil
}
