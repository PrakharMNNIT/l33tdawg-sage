package abci

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/l33tdawg/sage/internal/consensuskeys"
	"github.com/l33tdawg/sage/internal/store"
)

const (
	AppV23GenesisManifestVersion uint8  = 2
	AppV23GenesisAppVersion      uint64 = consensuskeys.AppV23GenesisVersion
)

// AppV23GenesisManifest is the first-party, zero-touch bootstrap contract
// embedded under app_state.sage.app_v23_bootstrap. It intentionally contains
// no display name: identity is the canonical Ed25519 key, while presentation
// metadata remains independently mutable.
type AppV23GenesisManifest struct {
	Version        uint8  `json:"version"`
	RootID         string `json:"root_id"`
	AgentID        string `json:"agent_id"`
	Profile        string `json:"profile"`
	Clearance      uint8  `json:"clearance"`
	Capabilities   uint32 `json:"capabilities"`
	HomeDomain     string `json:"home_domain"`
	ValidatorID    string `json:"validator_id"`
	ValidatorPower int64  `json:"validator_power"`
	RootSignature  string `json:"root_signature"`
	AgentSignature string `json:"agent_signature"`
}

func appendAppV23ManifestPart(dst []byte, value string) []byte {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value))) // #nosec G115 -- genesis manifest is bounded during verification
	dst = append(dst, size[:]...)
	return append(dst, value...)
}

// AppV23GenesisManifestSignBytes returns the canonical, domain-separated bytes
// signed by both the root/operator key and the vendored agent key. chainID is
// the authoritative RequestInitChain chain ID, preventing cross-chain replay.
func AppV23GenesisManifestSignBytes(chainID string, manifest AppV23GenesisManifest) []byte {
	out := appendAppV23ManifestPart(nil, "sage/app-v23/genesis-bootstrap/v2")
	out = appendAppV23ManifestPart(out, chainID)
	out = append(out, manifest.Version)
	out = appendAppV23ManifestPart(out, manifest.RootID)
	out = appendAppV23ManifestPart(out, manifest.AgentID)
	out = appendAppV23ManifestPart(out, manifest.Profile)
	out = append(out, manifest.Clearance)
	var capabilities [4]byte
	binary.BigEndian.PutUint32(capabilities[:], manifest.Capabilities)
	out = append(out, capabilities[:]...)
	out = appendAppV23ManifestPart(out, manifest.HomeDomain)
	out = appendAppV23ManifestPart(out, manifest.ValidatorID)
	var validatorPower [8]byte
	binary.BigEndian.PutUint64(validatorPower[:], uint64(manifest.ValidatorPower)) // #nosec G115 -- verified positive
	return append(out, validatorPower[:]...)
}

func decodeManifestIdentity(field, value string) (string, ed25519.PublicKey, error) {
	if value != strings.ToLower(value) || len(value) != ed25519.PublicKeySize*2 {
		return "", nil, fmt.Errorf("%s must be canonical lowercase 64-hex", field)
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return "", nil, fmt.Errorf("%s must encode an Ed25519 public key", field)
	}
	return hex.EncodeToString(raw), ed25519.PublicKey(raw), nil
}

// VerifyAppV23GenesisManifest validates the complete root-bound manifest and
// returns its deterministic digest for the persisted audit record.
func VerifyAppV23GenesisManifest(chainID string, manifest AppV23GenesisManifest) (string, error) {
	if chainID == "" {
		return "", errors.New("app-v23 genesis manifest requires chain_id")
	}
	if manifest.Version != AppV23GenesisManifestVersion {
		return "", fmt.Errorf("app-v23 genesis manifest version %d, want %d", manifest.Version, AppV23GenesisManifestVersion)
	}
	rootID, rootKey, rootErr := decodeManifestIdentity("root_id", manifest.RootID)
	if rootErr != nil {
		return "", rootErr
	}
	agentID, agentKey, agentErr := decodeManifestIdentity("agent_id", manifest.AgentID)
	if agentErr != nil {
		return "", agentErr
	}
	if rootID == agentID {
		return "", errors.New("app-v23 genesis root and agent must be distinct")
	}
	capabilities := store.AgentCapabilities(manifest.Capabilities)
	if !capabilities.Valid() {
		return "", fmt.Errorf("app-v23 genesis manifest has unknown capability bits 0x%x", uint32(capabilities&^store.KnownAgentCapabilities))
	}
	if manifest.Clearance > 4 {
		return "", errors.New("app-v23 genesis manifest clearance must be 0..4")
	}
	if manifest.Profile != store.AppV23ProfileCompanion {
		return "", fmt.Errorf("vendored app-v23 genesis profile must be %q", store.AppV23ProfileCompanion)
	}
	if manifest.Capabilities != 15 {
		return "", errors.New("vendored app-v23 Companion profile must use capability mask 15")
	}
	if manifest.HomeDomain == "" || store.IsSharedDomainName(manifest.HomeDomain) {
		return "", errors.New("app-v23 genesis manifest requires a non-shared home domain")
	}
	if _, _, validatorErr := decodeManifestIdentity("validator_id", manifest.ValidatorID); validatorErr != nil {
		return "", validatorErr
	}
	if manifest.ValidatorPower <= 0 {
		return "", errors.New("app-v23 genesis manifest validator power must be positive")
	}
	rootSignature, err := hex.DecodeString(manifest.RootSignature)
	if err != nil || len(rootSignature) != ed25519.SignatureSize {
		return "", errors.New("app-v23 genesis root_signature must be canonical Ed25519 hex")
	}
	agentSignature, err := hex.DecodeString(manifest.AgentSignature)
	if err != nil || len(agentSignature) != ed25519.SignatureSize {
		return "", errors.New("app-v23 genesis agent_signature must be canonical Ed25519 hex")
	}
	signBytes := AppV23GenesisManifestSignBytes(chainID, manifest)
	if !ed25519.Verify(rootKey, signBytes, rootSignature) {
		return "", errors.New("app-v23 genesis root signature is invalid")
	}
	if !ed25519.Verify(agentKey, signBytes, agentSignature) {
		return "", errors.New("app-v23 genesis agent signature is invalid")
	}
	digest := sha256.New()
	_, _ = digest.Write(signBytes)
	_, _ = digest.Write(rootSignature)
	_, _ = digest.Write(agentSignature)
	return hex.EncodeToString(digest.Sum(nil)), nil
}
