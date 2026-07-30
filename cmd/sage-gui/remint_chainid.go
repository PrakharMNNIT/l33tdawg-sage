package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/rs/zerolog"

	"github.com/l33tdawg/sage/internal/tlsca"
)

// legacySharedChainID is the literal chain_id every pre-v11 personal node was
// born with. Globally-unique per-node minting only landed in v11.0.0 (see
// mintChainID) and only applies to genesis CREATED on v11+, so every node
// upgraded from an older release still carries this shared id (the chain_id
// reconcile deliberately grandfathers it — no destructive re-genesis on upgrade).
//
// Because the id is IDENTICAL across independently-created nodes, federation's
// self-federation guard — which refuses when a scanned peer's chain_id equals our
// own (internal/federation/join_routes.go, manager.go, and the ABCI guard) — treats
// any two such nodes as the same network and blocks the connection. Two
// "sage-personal" nodes are also genuinely indistinguishable at the protocol level
// (cross_fed records + co-commit anchors + chain-qualified signatures are all keyed
// by chain_id), so the guard is correct: the id must be made unique to fix federation.
const legacySharedChainID = "sage-personal"

// instanceIsServing reports whether another SAGE node is already live on this home
// (Guard 4). Indirected through a var so tests can exercise the guard without a real
// listener and so the destructive path is decoupled from whatever is on the RPC port
// in the test environment.
var instanceIsServing = serveIsRunning

// remintLegacyChainID detects a personal node still using the shared legacy
// "sage-personal" chain_id. It is intentionally detection-only and always
// returns migrated=false.
//
// v11.16.1 SAFETY FENCE: a chain_id cannot be changed without replacing the
// canonical CometBFT/Badger history. Rebuilding from SQLite loses canonical
// memory envelopes and RBAC/governance state, so this automatic migration is now
// detection-only. A matching legacy node keeps running unchanged and federation
// remains unavailable until a governed, history-preserving migration exists.
//
// The legacy eligibility guards remain so warnings are limited to the exact
// standalone-node case. Quorum/LAN-networked nodes and guests are left alone.
func remintLegacyChainID(dataDir string, cfg *Config, logger zerolog.Logger) (migrated bool, err error) {
	// Dev builds never touch persisted state (mirrors migrateOnUpgrade).
	if version == "dev" {
		return false, nil
	}

	cometHome := filepath.Join(dataDir, "cometbft")

	// Guard 1: quorum / LAN-networked nodes share a chain_id across validators by
	// design. Both the mode flag and any configured peers count — a node that ever
	// joined a shared network must never be re-minted.
	if cfg.Quorum.Enabled || len(cfg.Quorum.Peers) > 0 {
		return false, nil
	}

	// Guard 1b (defense-in-depth): the CometBFT address book records every peer this
	// node has DIALED. A standalone personal node dials nobody (0 addrs), so any
	// recorded peer means the node joined/participated in a P2P network — skip it,
	// even if its current config flags have been cleared.
	//
	// Detection remains conservative even though it performs no mutation.
	if hasNetworkedPeers(cometHome) {
		logger.Warn().Msg("legacy chain_id re-mint skipped — address book shows dialed peers (this node participated in a P2P network)")
		return false, nil
	}

	// Read the authoritative chain_id from genesis. No genesis => brand-new install
	// (initCometBFTConfig mints a unique id downstream) — nothing to migrate.
	curID, readErr := readChainIDFromGenesis(cometHome)
	if readErr != nil || curID == "" {
		return false, nil
	}

	// Guard 2: only the exact legacy literal. Freshly-minted unique ids and legacy
	// "sage-quorum" are left untouched.
	if curID != legacySharedChainID {
		return false, nil
	}

	// Guard 3: single-validator (personal) genesis only. A multi-validator
	// "sage-personal" genesis would be an old shared network; re-minting would fork
	// it away from its peers.
	genesisPath := filepath.Join(cometHome, "config", "genesis.json")
	genDoc, gErr := cmttypes.GenesisDocFromFile(genesisPath)
	if gErr != nil {
		logger.Warn().Err(gErr).Msg("legacy chain_id re-mint skipped — genesis.json unreadable")
		return false, nil
	}
	if len(genDoc.Validators) != 1 {
		logger.Warn().Int("validators", len(genDoc.Validators)).
			Msg("legacy chain_id re-mint skipped — multi-validator genesis looks like a shared network")
		return false, nil
	}
	validator := genDoc.Validators[0]

	// Guard 3b: the sole genesis validator must be OUR OWN signing key. A Flow-3
	// guest adopts the host's genesis verbatim, so its single validator is the HOST's
	// pubkey — re-minting would fork the guest onto a chain it can never sign
	// (priv_validator_key.json wouldn't match) and sever it from its network. The
	// quorum guard normally catches guests, but a MISSING config.yaml makes
	// LoadConfig silently return Quorum.Enabled=false, so verify key ownership
	// directly rather than trust the flag.
	localPub, lpErr := localValidatorPubKey(cometHome)
	if lpErr != nil {
		logger.Warn().Err(lpErr).Msg("legacy chain_id re-mint skipped — cannot read local validator key to confirm ownership")
		return false, nil
	}
	if !bytes.Equal(localPub, validator.PubKey.Bytes()) {
		logger.Warn().Msg("legacy chain_id re-mint skipped — genesis validator is not this node's key (adopted/guest genesis); re-minting would fork it off its network")
		return false, nil
	}

	// Avoid emitting a startup migration warning from a second process pointed at
	// an already-serving home. The normal database lock still owns enforcement.
	if instanceIsServing() {
		logger.Warn().Msg("legacy chain_id re-mint skipped — another SAGE instance appears to be running on this home")
		return false, nil
	}

	logger.Warn().Str("chain_id", curID).
		Msg("legacy shared chain_id detected — automatic re-mint is disabled because it would discard canonical history")
	fmt.Fprintf(
		os.Stderr,
		"\n  SAGE: this node still uses the legacy shared network id %q.\n"+
			"  Federation remains unavailable, but the node will keep running unchanged.\n"+
			"  SAGE will not reset canonical history to change this id.\n\n",
		curID,
	)
	return false, nil
}

// localValidatorPubKey returns the raw ed25519 public key bytes from this node's
// priv_validator_key.json — the identity CometBFT actually signs blocks with. Used
// to distinguish a standalone legacy node from an adopted/guest genesis before
// reporting the migration warning. Parses the JSON directly (rather than
// privval.LoadFilePV, which exits the
// process on a malformed file) so an unreadable key is a safe skip, not a crash.
func localValidatorPubKey(cometHome string) ([]byte, error) {
	path := filepath.Join(cometHome, "config", "priv_validator_key.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pv struct {
		PubKey struct {
			Value string `json:"value"`
		} `json:"pub_key"`
	}
	if uErr := json.Unmarshal(data, &pv); uErr != nil {
		return nil, uErr
	}
	if pv.PubKey.Value == "" {
		return nil, fmt.Errorf("priv_validator_key.json has no pub_key value")
	}
	raw, decErr := base64.StdEncoding.DecodeString(pv.PubKey.Value)
	if decErr != nil {
		return nil, fmt.Errorf("decode validator pubkey: %w", decErr)
	}
	return raw, nil
}

// reconcileCACommonName self-heals a stale TLS CA CommonName on a personal node.
// The CA CN is "sage-ca-<chain_id>" and the federation handshake enforces it
// (requireChainCN); if the chain_id changed — e.g. a legacy "sage-personal" node was
// re-minted — this reconcile is the ONE mechanism that keeps the CA CommonName in
// step with the chain_id. Because it runs on every boot (not gated on the re-mint,
// which is idempotent-by-chain-id), a stale CN can never silently block federation
// forever, even across crashes or partial cert writes. Called BEFORE the cert
// auto-gen: when the CN no longer matches, it removes all four cert files so they
// regenerate with the correct CN. A CN mismatch implies no live agreement (a
// matching CA is a precondition for ever having federated, and re-mint wipes
// agreements anyway), so this strands no peer. Quorum CAs come from the shared
// genesis flow and are left alone. Returns true if certs were removed.
func reconcileCACommonName(certsDir, chainID string, quorum bool, logger zerolog.Logger) bool {
	if quorum || chainID == "" {
		return false
	}
	// Check the CA CommonName whenever the CA is readable — do NOT gate on
	// tlsca.CertsExist, which only inspects the NODE cert/key. A stale legacy-CN CA can
	// linger with the node cert absent (e.g. a partial cert write after re-mint); if we
	// skipped that case, the auto-gen would reuse the legacy-CN CA (LoadOrGenerateCA
	// does no CN check) and sign a node cert under the wrong CN, so peers' requireChainCN
	// rejects every join for the whole re-mint boot. Reading the CA directly catches it.
	caCert, err := tlsca.ReadCert(filepath.Join(certsDir, tlsca.CACertFile))
	if err != nil {
		// CA missing or unreadable. If node cert/key exist without a readable CA (a
		// partial rotation), clear all four so the auto-gen makes a consistent set. If
		// nothing exists (a fresh certs dir), there is nothing to reconcile.
		if !tlsca.CertsExist(certsDir) {
			return false
		}
		logger.Warn().Err(err).Msg("TLS node cert present but CA missing/unreadable — clearing certs to regenerate a consistent set")
		removeOwnCerts(certsDir)
		return true
	}
	want := "sage-ca-" + chainID
	if caCert.Subject.CommonName == want {
		return false
	}
	logger.Warn().Str("have", caCert.Subject.CommonName).Str("want", want).
		Msg("TLS CA CommonName does not match chain_id — regenerating certs so federation presents the correct identity")
	removeOwnCerts(certsDir)
	return true
}

// removeOwnCerts deletes this node's own CA + node TLS material (best-effort).
func removeOwnCerts(certsDir string) {
	for _, f := range []string{tlsca.CACertFile, tlsca.CAKeyFile, tlsca.NodeCertFile, tlsca.NodeKeyFile} {
		_ = os.Remove(filepath.Join(certsDir, f))
	}
}

// hasNetworkedPeers reports whether the CometBFT address book records any DIALED
// peer — a durable signal that this node joined/participated in a P2P network. A
// standalone personal node dials nobody, so its address book stays empty (0 addrs).
// NOTE: this only sees dialed peers; a Flow-3 host (which only accepts inbound dials,
// PEX disabled) leaves an empty book — see the Guard 1b residual note. Absent or
// unreadable address book => treat as not networked (fresh / never-networked node).
func hasNetworkedPeers(cometHome string) bool {
	data, err := os.ReadFile(filepath.Join(cometHome, "config", "addrbook.json"))
	if err != nil {
		return false
	}
	var ab struct {
		Addrs []json.RawMessage `json:"addrs"`
	}
	if json.Unmarshal(data, &ab) != nil {
		return false
	}
	return len(ab.Addrs) > 0
}
