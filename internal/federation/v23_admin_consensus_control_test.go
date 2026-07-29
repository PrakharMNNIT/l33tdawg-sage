package federation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

func promoteV23FederationAdmin(
	t *testing.T,
	badger *store.BadgerStore,
	rootID, adminID string,
	height int64,
) {
	t.Helper()
	enrollment, err := badger.GetAppV23Enrollment(adminID)
	if err != nil {
		t.Fatal(err)
	}
	role, err := badger.GetAppV23Role(adminID)
	if err != nil {
		t.Fatal(err)
	}
	if err := badger.SetAppV23Policy(
		rootID, adminID, store.AppV23RoleAdmin,
		enrollment.Profile, store.AppV23ProfileStandard,
		4, store.AgentCapabilityReadAllDomains,
		role.Revision, enrollment.Revision, height,
	); err != nil {
		t.Fatal(err)
	}
}

func TestAppV23FederationConsensusControlPreservesPromotedAdminEnvelope(t *testing.T) {
	node := newTestChain(t, "v23-promoted-admin-control")
	node.mgr.postV23ForNextTx = func() bool { return true }
	transportID := hex.EncodeToString(node.agentPub)

	adminPub, adminKey, adminKeyErr := ed25519.GenerateKey(rand.Reader)
	if adminKeyErr != nil {
		t.Fatal(adminKeyErr)
	}
	adminID := hex.EncodeToString(adminPub)
	if err := node.badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: transportID, Scope: node.chainID,
		AgentID: adminID, Profile: store.AppV23ProfileStandard,
		HomeDomain: "admin.home", Clearance: 1, Height: 1,
		BootstrapDigest: strings.Repeat("c7", 32),
	}); err != nil {
		t.Fatal(err)
	}
	promoteV23FederationAdmin(t, node.badger, transportID, adminID, 2)

	currentRootPub, currentRootKey, rootKeyErr := ed25519.GenerateKey(rand.Reader)
	if rootKeyErr != nil {
		t.Fatal(rootKeyErr)
	}
	currentRootID := hex.EncodeToString(currentRootPub)
	if err := node.badger.RotateAppV23RootCredential(1, currentRootID, 3); err != nil {
		t.Fatal(err)
	}
	var height [8]byte
	binary.BigEndian.PutUint64(height[:], 10)
	if err := node.badger.SetState("height", height[:]); err != nil {
		t.Fatal(err)
	}

	keys := map[string]ed25519.PrivateKey{
		transportID:   node.agentKey,
		adminID:       adminKey,
		currentRootID: currentRootKey,
	}
	node.mgr.SetRootKeyResolver(func(credentialID string) (ed25519.PrivateKey, bool) {
		key, ok := keys[credentialID]
		return key, ok
	})

	broadcasts := 0
	var captured []*tx.ParsedTx
	node.mgr.broadcastFn = func(encoded []byte) (string, int64, error) {
		parsed, decodeErr := tx.DecodeTx(encoded)
		if decodeErr == nil {
			broadcasts++
			captured = append(captured, parsed)
		}
		return "captured", 11, decodeErr
	}

	if _, err := node.mgr.broadcastCrossFedSetAs(
		adminID, testCrossFedTerms("peer-stale-admin"),
	); err == nil || !strings.Contains(err.Error(), "current-generation") {
		t.Fatalf("stale-generation Admin error = %v, want fail-closed refusal", err)
	}
	if broadcasts != 0 {
		t.Fatalf("stale-generation Admin broadcast %d transactions", broadcasts)
	}

	promoteV23FederationAdmin(t, node.badger, currentRootID, adminID, 4)
	if _, err := node.mgr.broadcastCrossFedSetAs(
		adminID, testCrossFedTerms("peer-admin-set"),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := node.mgr.broadcastRevokeAgreementLockedReasonAs(
		adminID, "peer-admin-revoke", "promoted Admin test",
	); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 2 {
		t.Fatalf("Admin broadcasts = %d, want 2", len(captured))
	}
	for _, parsed := range captured {
		assertFederationConsensusSigner(t, parsed, adminID)
		if parsed.LocalElevation == nil {
			t.Fatalf("tx-%d omitted current-Root elevation", parsed.Type)
		}
		if parsed.LocalElevation.RootGeneration != 2 {
			t.Fatalf("tx-%d root generation = %d, want 2",
				parsed.Type, parsed.LocalElevation.RootGeneration)
		}
		action, payloadErr := tx.PayloadBytes(parsed)
		if payloadErr != nil {
			t.Fatal(payloadErr)
		}
		if !ed25519.Verify(
			currentRootPub,
			tx.AppV23ElevationSignBytes(
				node.chainID, adminID, parsed.Type, action, parsed.LocalElevation,
			),
			parsed.LocalElevation.Signature,
		) {
			t.Fatalf("tx-%d Admin envelope is not countersigned by current Root", parsed.Type)
		}
		if hex.EncodeToString(parsed.PublicKey) == transportID {
			t.Fatalf("stable transport credential signed tx-%d after Root handover", parsed.Type)
		}
	}

	if _, err := node.mgr.broadcastCrossFedSet(
		testCrossFedTerms("peer-current-root"),
	); err != nil {
		t.Fatal(err)
	}
	rootTx := captured[len(captured)-1]
	assertFederationConsensusSigner(t, rootTx, currentRootID)
	if rootTx.LocalElevation != nil {
		t.Fatal("current Root path unexpectedly carried a delegated-Admin elevation")
	}
	if got := hex.EncodeToString(node.mgr.agentPub); got != transportID {
		t.Fatalf("consensus control mutated stable transport identity: got %s want %s",
			got, transportID)
	}

	projectedAdmin, err := node.badger.GetRegisteredAgent(adminID)
	if err != nil {
		t.Fatal(err)
	}
	projectedAdmin.Clearance = 3
	rawProjection, err := json.Marshal(projectedAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := node.badger.SetRawForTest(
		[]byte("appv23:agent:"+adminID), rawProjection,
	); err != nil {
		t.Fatal(err)
	}
	beforeDriftAttempt := len(captured)
	if _, err := node.mgr.broadcastCrossFedSetAs(
		adminID, testCrossFedTerms("peer-projection-drift"),
	); err == nil || !strings.Contains(err.Error(), "current-generation") {
		t.Fatalf("projection-drift Admin error = %v, want fail-closed refusal", err)
	}
	if len(captured) != beforeDriftAttempt {
		t.Fatal("projection-drift Admin reached the consensus broadcaster")
	}
}

func TestAppV23HostApprovalFreezesControlActorThroughPeerConfirmation(t *testing.T) {
	joins, sessionID, certSPKI, attestation, guestKey, _ := approvedSession(t)
	snapshot, ok := joins.Get(sessionID, time.Now())
	if !ok {
		t.Fatal("approved session disappeared")
	}
	codeG, _ := snapshot.confirmCodes()
	grant := trustOnlyJoinScope
	const adminID = "current-local-admin"
	locked, err := joins.ApproveWithCode(sessionID, codeG, HostGrant{
		Clearance: uint8(grant.MaxClearance),
		Mode:      grant.Mode, Direction: grant.Direction, Scope: grant.digest(),
		ControlActorID: adminID,
	})
	if err != nil || locked {
		t.Fatalf("re-approve with exact Admin: locked=%v err=%v", locked, err)
	}
	confirm, err := joins.CheckConfirm(
		sessionID, certSPKI,
		SignEnroll(guestKey, attestation, false),
		SignEnroll(guestKey, attestation, true),
		time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if confirm.HostGrant.ControlActorID != adminID {
		t.Fatalf("confirmed control actor = %q, want %q",
			confirm.HostGrant.ControlActorID, adminID)
	}
}
