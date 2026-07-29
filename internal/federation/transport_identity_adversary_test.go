package federation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

// Transport authentication and consensus control are separate after app-v23
// Root handover. Existing peers must keep seeing the JOIN-frozen transport key,
// while a new/repaired/revoked agreement must be authorized on-chain by the
// current Root credential rather than the retired transport credential.
func TestAdversaryRootHandoverKeepsTransportIdentityButRotatesFederationControlSigner(t *testing.T) {
	node := newTestChain(t, "transport-root-separation")
	node.mgr.postV23ForNextTx = func() bool { return true }
	transportID := hex.EncodeToString(node.agentPub)
	companionPub, _, companionKeyErr := ed25519.GenerateKey(rand.Reader)
	if companionKeyErr != nil {
		t.Fatal(companionKeyErr)
	}
	if err := node.badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: transportID, Scope: node.chainID,
		AgentID: hex.EncodeToString(companionPub),
		Profile: store.AppV23ProfileStandard, HomeDomain: "companion.home",
		Clearance: 2, Capabilities: 0, Height: 1, BootstrapDigest: "adversary",
	}); err != nil {
		t.Fatal(err)
	}
	newRootPub, newRootKey, rootKeyErr := ed25519.GenerateKey(rand.Reader)
	if rootKeyErr != nil {
		t.Fatal(rootKeyErr)
	}
	newRootID := hex.EncodeToString(newRootPub)
	if err := node.badger.RotateAppV23RootCredential(1, newRootID, 2); err != nil {
		t.Fatal(err)
	}
	node.mgr.SetRootKeyResolver(func(credentialID string) (ed25519.PrivateKey, bool) {
		if credentialID == newRootID {
			return newRootKey, true
		}
		return nil, false
	})

	var captured *tx.ParsedTx
	node.mgr.broadcastFn = func(encoded []byte) (string, int64, error) {
		var decodeErr error
		captured, decodeErr = tx.DecodeTx(encoded)
		return "captured", 3, decodeErr
	}
	_, broadcastErr := node.mgr.broadcastCrossFedSet(&tx.CrossFedTerms{
		RemoteChainID: "peer-after-handover",
		Endpoint:      "https://peer.invalid",
		PeerPubKey:    bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize),
		MaxClearance:  tx.ClearanceTopSecret,
		AllowedDomains: []string{
			"*",
		},
		Status: "active",
	})
	if broadcastErr != nil {
		t.Fatal(broadcastErr)
	}
	if captured == nil {
		t.Fatal("federation mutation did not broadcast")
	}
	if got := hex.EncodeToString(captured.PublicKey); got != newRootID {
		t.Fatalf("outer federation control signer = %s, want current Root %s", got, newRootID)
	}
	if got := hex.EncodeToString(captured.AgentPubKey); got != newRootID {
		t.Fatalf("embedded federation control signer = %s, want current Root %s", got, newRootID)
	}
	if got := hex.EncodeToString(node.mgr.agentPub); got != transportID {
		t.Fatalf("transport identity rotated during Root handover: got %s want %s", got, transportID)
	}
}

// A synchronized Copy is a new local MemorySubmit, not a transport request.
// Letting the retired transport key keep signing those writes either strands
// Copy after handover (the current v23 behavior) or would require granting the
// retired Root a dangerous generic write capability. The local transaction
// must instead use current Root while retaining remote provenance in the item.
func TestAdversaryRootHandoverRotatesFederatedCopySubmitSigner(t *testing.T) {
	node := newTestChain(t, "copy-root-separation")
	node.mgr.postV23ForNextTx = func() bool { return true }
	transportID := hex.EncodeToString(node.agentPub)
	companionPub, _, companionKeyErr := ed25519.GenerateKey(rand.Reader)
	if companionKeyErr != nil {
		t.Fatal(companionKeyErr)
	}
	if err := node.badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: transportID, Scope: node.chainID,
		AgentID: hex.EncodeToString(companionPub),
		Profile: store.AppV23ProfileStandard, HomeDomain: "companion.home",
		Clearance: 2, Capabilities: 0, Height: 1, BootstrapDigest: "copy-adversary",
	}); err != nil {
		t.Fatal(err)
	}
	newRootPub, newRootKey, rootKeyErr := ed25519.GenerateKey(rand.Reader)
	if rootKeyErr != nil {
		t.Fatal(rootKeyErr)
	}
	newRootID := hex.EncodeToString(newRootPub)
	if err := node.badger.RotateAppV23RootCredential(1, newRootID, 2); err != nil {
		t.Fatal(err)
	}
	node.mgr.SetRootKeyResolver(func(credentialID string) (ed25519.PrivateKey, bool) {
		if credentialID == newRootID {
			return newRootKey, true
		}
		return nil, false
	})

	contentHash := sha256.Sum256([]byte("federated copy after root handover"))
	encoded, err := node.mgr.buildSyncSubmitTx("copy-after-handover", &SyncItem{
		ContentHash:     hex.EncodeToString(contentHash[:]),
		MemoryType:      "fact",
		Domain:          "shared.copy",
		Content:         "federated copy after root handover",
		Classification:  0,
		ConfidenceScore: 0.9,
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := tx.DecodeTx(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(parsed.PublicKey); got != newRootID {
		t.Fatalf("outer Copy submit signer = %s, want current Root %s", got, newRootID)
	}
	if got := hex.EncodeToString(parsed.AgentPubKey); got != newRootID {
		t.Fatalf("embedded Copy submit signer = %s, want current Root %s", got, newRootID)
	}
	if got := hex.EncodeToString(node.mgr.agentPub); got != transportID {
		t.Fatalf("transport identity rotated while fixing Copy signer: got %s want %s", got, transportID)
	}
}
