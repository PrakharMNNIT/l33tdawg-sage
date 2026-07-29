package federation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/l33tdawg/sage/internal/store"
)

type v23GuestControlFixture struct {
	manager       *Manager
	badger        *store.BadgerStore
	sqlite        *store.SQLiteStore
	rootKey       ed25519.PrivateKey
	rootID        string
	adminKey      ed25519.PrivateKey
	adminID       string
	peerAgentID   string
	remoteAgentID string
}

func newV23GuestControlFixture(t *testing.T) *v23GuestControlFixture {
	t.Helper()
	ctx := context.Background()
	rootPub, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	adminPub, adminKey, _ := ed25519.GenerateKey(rand.Reader)
	peerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	remotePub, _, _ := ed25519.GenerateKey(rand.Reader)
	rootID, adminID := hex.EncodeToString(rootPub), hex.EncodeToString(adminPub)

	badger, badgerErr := store.NewBadgerStore(filepath.Join(t.TempDir(), "badger"))
	if badgerErr != nil {
		t.Fatal(badgerErr)
	}
	t.Cleanup(func() { _ = badger.CloseBadger() })
	if err := badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: rootID, Scope: "fixture", AgentID: adminID,
		Profile: store.AppV23ProfileStandard, HomeDomain: "admin-home",
		Clearance: 1, Capabilities: 0, Height: 1,
		BootstrapDigest: strings.Repeat("77", 32),
	}); err != nil {
		t.Fatal(err)
	}
	enrollment, _ := badger.GetAppV23Enrollment(adminID)
	role, _ := badger.GetAppV23Role(adminID)
	if err := badger.SetAppV23Policy(
		rootID, adminID, store.AppV23RoleAdmin,
		store.AppV23ProfileStandard, store.AppV23ProfileStandard,
		4, store.AgentCapabilityReadAllDomains,
		role.Revision, enrollment.Revision, 2,
	); err != nil {
		t.Fatal(err)
	}
	if err := badger.MutateAppV23AccessGroup(
		rootID, "local-research", "Research", []string{adminID}, 0, false, 3,
	); err != nil {
		t.Fatal(err)
	}
	pin := append([]byte(nil), peerPub...)
	if err := badger.SetCrossFed(
		"chain-a", "https://peer.example:8444", pin, 4, 0,
		[]string{"*"}, nil, "active",
	); err != nil {
		t.Fatal(err)
	}
	sqlite, sqliteErr := store.NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "federation.db"))
	if sqliteErr != nil {
		t.Fatal(sqliteErr)
	}
	t.Cleanup(func() { _ = sqlite.Close() })
	peerID := hex.EncodeToString(peerPub)
	if err := sqlite.PrepareSyncControl(ctx, store.SyncControl{
		RemoteChainID: "chain-a", Role: "host", ControllerChainID: "chain-b",
		ControllerAgentID: rootID, PeerAgentID: peerID,
		PolicyEpoch: "epoch-v23", RemoteCAPin: hex.EncodeToString(pin),
		PolicyVersion: SyncPolicyVersionPeerRBAC,
	}); err != nil {
		t.Fatal(err)
	}
	if err := sqlite.ActivateSyncControl(ctx, "chain-a", "epoch-v23"); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlite.ReplaceBoundPeerRBACPolicy(ctx, store.PeerRBACPolicy{
		RemoteChainID: "chain-a", PeerAgentID: peerID,
		PolicyEpoch: "epoch-v23", RemoteCAPin: hex.EncodeToString(pin),
		PolicyVersion: store.CurrentPeerRBACPolicyVersion,
		Domains:       []store.PeerRBACDomainPermission{{Domain: "admin-home", Read: true}},
	}); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(Config{
		LocalChainID: "chain-b", CertsDir: t.TempDir(), AgentKey: rootKey,
		Badger: badger, MemStore: sqlite, FederatedGuestStore: sqlite,
		LocalGroupResolver: badger, QueryChallengeStore: sqlite,
		PostV23ForNextTx: func() bool { return true }, Logger: zerolog.Nop(),
	})
	// Unit control tests isolate local CAS/elevation semantics. Dedicated
	// two-node tests exercise the real signed mTLS exact-agent oracle.
	manager.federatedGuestEligibilityFn = func(
		context.Context, string, string,
	) error {
		return nil
	}
	commitSeed, rollbackSeed, stageErr := manager.stageSeed(
		"chain-a", []byte("0123456789abcdef0123456789abcdef"),
		[]byte("0123456789abcdef0123456789abcdef"), time.Now().Unix(),
	)
	if stageErr != nil {
		t.Fatal(stageErr)
	}
	t.Cleanup(rollbackSeed)
	if err := commitSeed(); err != nil {
		t.Fatal(err)
	}
	return &v23GuestControlFixture{
		manager: manager, badger: badger, sqlite: sqlite,
		rootKey: rootKey, rootID: rootID, adminKey: adminKey, adminID: adminID,
		peerAgentID: peerID, remoteAgentID: hex.EncodeToString(remotePub),
	}
}

func (f *v23GuestControlFixture) preparedAttach(t *testing.T) FederatedGuestMutation {
	t.Helper()
	prepared, prepareErr := f.manager.PrepareFederatedGuestMutation(
		context.Background(), f.adminID, FederatedGuestMutationInput{
			Operation: FederatedGuestOperationAttach, GroupID: "local-research",
			RemoteChainID: "chain-a", RemoteAgentID: f.remoteAgentID,
			MaxClassification: 2, ExpectedRevision: 0,
		},
	)
	if prepareErr != nil {
		t.Fatal(prepareErr)
	}
	guest := prepared.Guest
	if err := store.SignFederatedGroupGuest(&guest, f.adminKey); err != nil {
		t.Fatal(err)
	}
	mutation := FederatedGuestMutation{
		Operation: prepared.Operation, ExpectedRevision: prepared.ExpectedRevision, Guest: guest,
	}
	token, mintErr := f.manager.MintFederatedGuestElevation(
		context.Background(), f.adminID, mutation,
	)
	if mintErr != nil {
		t.Fatal(mintErr)
	}
	mutation.Elevation = token
	return mutation
}

func TestFederatedGuestRootRotationAndAdminDemotionInvalidatePreparedAction(t *testing.T) {
	t.Run("caller mismatch", func(t *testing.T) {
		fixture := newV23GuestControlFixture(t)
		mutation := fixture.preparedAttach(t)
		if _, err := fixture.manager.MintFederatedGuestElevation(
			context.Background(), fixture.rootID, mutation,
		); err == nil {
			t.Fatal("root/other caller minted a promoted Admin's broker token")
		}
	})
	t.Run("root rotation", func(t *testing.T) {
		fixture := newV23GuestControlFixture(t)
		mutation := fixture.preparedAttach(t)
		newRootPub, newRootKey, _ := ed25519.GenerateKey(rand.Reader)
		newRootID := hex.EncodeToString(newRootPub)
		if err := fixture.badger.RotateAppV23RootCredential(
			1, newRootID, 10,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.manager.CommitFederatedGuestMutation(
			context.Background(), fixture.adminID, mutation,
		); err == nil {
			t.Fatal("pre-rotation local elevation survived root rotation")
		}
		fixture.manager.SetRootKeyResolver(func(credentialID string) (ed25519.PrivateKey, bool) {
			return newRootKey, credentialID == newRootID
		})
		if _, err := fixture.manager.MintFederatedGuestElevation(
			context.Background(), fixture.adminID, mutation,
		); err == nil {
			t.Fatal("stale-generation Admin minted an elevation before root rebind")
		}
		enrollment, enrollmentErr := fixture.badger.GetAppV23Enrollment(fixture.adminID)
		if enrollmentErr != nil {
			t.Fatal(enrollmentErr)
		}
		role, roleErr := fixture.badger.GetAppV23Role(fixture.adminID)
		if roleErr != nil {
			t.Fatal(roleErr)
		}
		if err := fixture.badger.SetAppV23Policy(
			newRootID, fixture.adminID, store.AppV23RoleAdmin,
			store.AppV23ProfileStandard, store.AppV23ProfileStandard,
			4, store.AgentCapabilityReadAllDomains,
			role.Revision, enrollment.Revision, 11,
		); err != nil {
			t.Fatalf("root rebind of promoted Admin: %v", err)
		}
		// Root rotation and the Admin's re-approval both change bytes frozen
		// into the prepared guest row. Re-prepare and re-sign; a fresh Root
		// elevation must never bless the stale pre-rotation Admin signature.
		mutation = fixture.preparedAttach(t)
		token, mintErr := fixture.manager.MintFederatedGuestElevation(
			context.Background(), fixture.adminID, mutation,
		)
		if mintErr != nil {
			t.Fatalf("rebound Admin could not mint current-root elevation: %v", mintErr)
		}
		mutation.Elevation = token
		if _, err := fixture.manager.CommitFederatedGuestMutation(
			context.Background(), fixture.adminID, mutation,
		); err != nil {
			t.Fatalf("rebound Admin's fresh rotated-root elevation was denied: %v", err)
		}
	})
	t.Run("admin demotion", func(t *testing.T) {
		fixture := newV23GuestControlFixture(t)
		mutation := fixture.preparedAttach(t)
		enrollment, _ := fixture.badger.GetAppV23Enrollment(fixture.adminID)
		role, _ := fixture.badger.GetAppV23Role(fixture.adminID)
		if err := fixture.badger.SetAppV23Policy(
			fixture.rootID, fixture.adminID, store.AppV23RoleMember,
			store.AppV23ProfileStandard, store.AppV23ProfileStandard,
			1, 0, role.Revision, enrollment.Revision, 10,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.manager.CommitFederatedGuestMutation(
			context.Background(), fixture.adminID, mutation,
		); err == nil {
			t.Fatal("demoted Admin committed a prepared guest action")
		}
	})
}

func TestFederatedGuestPromotedAdminLinkRequiresExplicitRebindAfterRootRotation(t *testing.T) {
	fixture := newV23GuestControlFixture(t)
	mutation := fixture.preparedAttach(t)
	if _, err := fixture.manager.CommitFederatedGuestMutation(
		context.Background(), fixture.adminID, mutation,
	); err != nil {
		t.Fatal(err)
	}
	agreement, agreementErr := fixture.manager.ActiveAgreement("chain-a")
	if agreementErr != nil {
		t.Fatal(agreementErr)
	}
	peer := &peerIdentity{
		ChainID: "chain-a", AgentID: fixture.peerAgentID, Agreement: agreement,
	}
	if ceiling, err := fixture.manager.authorizeFederatedGuestRead(
		context.Background(), peer, agreement, fixture.remoteAgentID, "admin-home",
	); err != nil || ceiling != 2 {
		t.Fatalf("current-generation Admin link denied: ceiling=%d err=%v", ceiling, err)
	}

	newRootPub, newRootKey, _ := ed25519.GenerateKey(rand.Reader)
	newRootID := hex.EncodeToString(newRootPub)
	if err := fixture.badger.RotateAppV23RootCredential(1, newRootID, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.manager.authorizeFederatedGuestRead(
		context.Background(), peer, agreement, fixture.remoteAgentID, "admin-home",
	); err == nil {
		t.Fatal("stale-generation promoted Admin link disclosed after root rotation")
	}

	enrollment, _ := fixture.badger.GetAppV23Enrollment(fixture.adminID)
	role, _ := fixture.badger.GetAppV23Role(fixture.adminID)
	if err := fixture.badger.SetAppV23Policy(
		newRootID, fixture.adminID, store.AppV23RoleAdmin,
		store.AppV23ProfileStandard, store.AppV23ProfileStandard,
		4, store.AgentCapabilityReadAllDomains,
		role.Revision, enrollment.Revision, 11,
	); err != nil {
		t.Fatalf("root rebind of promoted Admin: %v", err)
	}
	if _, err := fixture.manager.authorizeFederatedGuestRead(
		context.Background(), peer, agreement, fixture.remoteAgentID, "admin-home",
	); err == nil {
		t.Fatal("Admin reapproval silently revived an old delegated capability")
	}
	fixture.manager.SetRootKeyResolver(func(credentialID string) (ed25519.PrivateKey, bool) {
		return newRootKey, credentialID == newRootID
	})
	prepared, prepareErr := fixture.manager.PrepareFederatedGuestMutation(
		context.Background(), fixture.adminID, FederatedGuestMutationInput{
			Operation: FederatedGuestOperationRebind, GroupID: "local-research",
			RemoteChainID: "chain-a", RemoteAgentID: fixture.remoteAgentID,
			MaxClassification: 2, ExpectedRevision: 1,
		},
	)
	if prepareErr != nil {
		t.Fatalf("prepare explicit Admin rebind: %v", prepareErr)
	}
	rebound := prepared.Guest
	if err := store.SignFederatedGroupGuest(&rebound, fixture.adminKey); err != nil {
		t.Fatal(err)
	}
	rebindMutation := FederatedGuestMutation{
		Operation: prepared.Operation, ExpectedRevision: prepared.ExpectedRevision,
		Guest: rebound,
	}
	elevation, mintErr := fixture.manager.MintFederatedGuestElevation(
		context.Background(), fixture.adminID, rebindMutation,
	)
	if mintErr != nil {
		t.Fatalf("mint explicit Admin rebind elevation: %v", mintErr)
	}
	rebindMutation.Elevation = elevation
	if _, err := fixture.manager.CommitFederatedGuestMutation(
		context.Background(), fixture.adminID, rebindMutation,
	); err != nil {
		t.Fatalf("commit explicit Admin rebind: %v", err)
	}
	if ceiling, err := fixture.manager.authorizeFederatedGuestRead(
		context.Background(), peer, agreement, fixture.remoteAgentID, "admin-home",
	); err != nil || ceiling != 2 {
		t.Fatalf("explicitly rebound Admin link did not resume: ceiling=%d err=%v", ceiling, err)
	}
}

func TestFederatedGuestPromotedAdminLinkStopsAfterDemotion(t *testing.T) {
	fixture := newV23GuestControlFixture(t)
	mutation := fixture.preparedAttach(t)
	if _, err := fixture.manager.CommitFederatedGuestMutation(
		context.Background(), fixture.adminID, mutation,
	); err != nil {
		t.Fatal(err)
	}
	agreement, err := fixture.manager.ActiveAgreement("chain-a")
	if err != nil {
		t.Fatal(err)
	}
	peer := &peerIdentity{
		ChainID: "chain-a", AgentID: fixture.peerAgentID, Agreement: agreement,
	}
	if _, err := fixture.manager.authorizeFederatedGuestRead(
		context.Background(), peer, agreement, fixture.remoteAgentID, "admin-home",
	); err != nil {
		t.Fatalf("current promoted-Admin row denied: %v", err)
	}
	enrollment, _ := fixture.badger.GetAppV23Enrollment(fixture.adminID)
	role, _ := fixture.badger.GetAppV23Role(fixture.adminID)
	if err := fixture.badger.SetAppV23Policy(
		fixture.rootID, fixture.adminID, store.AppV23RoleMember,
		store.AppV23ProfileStandard, store.AppV23ProfileStandard,
		1, 0, role.Revision, enrollment.Revision, 10,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.manager.authorizeFederatedGuestRead(
		context.Background(), peer, agreement, fixture.remoteAgentID, "admin-home",
	); err == nil {
		t.Fatal("row signed by a demoted promoted Admin remained authoritative")
	}
	enrollment, _ = fixture.badger.GetAppV23Enrollment(fixture.adminID)
	role, _ = fixture.badger.GetAppV23Role(fixture.adminID)
	if err := fixture.badger.SetAppV23Policy(
		fixture.rootID, fixture.adminID, store.AppV23RoleAdmin,
		store.AppV23ProfileStandard, store.AppV23ProfileStandard,
		4, store.AgentCapabilityReadAllDomains,
		role.Revision, enrollment.Revision, 11,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.manager.authorizeFederatedGuestRead(
		context.Background(), peer, agreement, fixture.remoteAgentID, "admin-home",
	); err == nil {
		t.Fatal("demote then repromote silently revived an old delegated capability")
	}
}

func TestFederatedGuestEligibilityNetworkCallHoldsNoLocalAgreementLease(t *testing.T) {
	fixture := newV23GuestControlFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	fixture.manager.federatedGuestEligibilityFn = func(
		context.Context, string, string,
	) error {
		close(entered)
		<-release
		return nil
	}
	result := make(chan error, 1)
	go func() {
		_, err := fixture.manager.PrepareFederatedGuestMutation(
			context.Background(), fixture.adminID, FederatedGuestMutationInput{
				Operation: FederatedGuestOperationAttach, GroupID: "local-research",
				RemoteChainID: "chain-a", RemoteAgentID: fixture.remoteAgentID,
				MaxClassification: 2, ExpectedRevision: 0,
			},
		)
		result <- err
	}()
	<-entered
	leaseAcquired := make(chan struct{})
	go func() {
		unlock := fixture.manager.LockAgreementMutation()
		unlock()
		close(leaseAcquired)
	}()
	select {
	case <-leaseAcquired:
	case <-time.After(time.Second):
		t.Fatal("remote eligibility call retained the local agreement mutation lease")
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatalf("preparation after eligibility release: %v", err)
	}
}

func TestFederatedGuestEligibilitySnapshotRejectsLocalAgreementTOCTOU(t *testing.T) {
	fixture := newV23GuestControlFixture(t)
	fixture.manager.federatedGuestEligibilityFn = func(
		context.Context, string, string,
	) error {
		agreement, err := fixture.manager.ActiveAgreement("chain-a")
		if err != nil {
			return err
		}
		return fixture.badger.SetCrossFed(
			agreement.RemoteChainID,
			"https://replacement.example:8444",
			agreement.PeerPubKey,
			agreement.MaxClearance,
			agreement.ExpiresAt,
			agreement.AllowedDomains,
			agreement.AllowedDepts,
			agreement.Status,
		)
	}
	if _, err := fixture.manager.PrepareFederatedGuestMutation(
		context.Background(), fixture.adminID, FederatedGuestMutationInput{
			Operation: FederatedGuestOperationAttach, GroupID: "local-research",
			RemoteChainID: "chain-a", RemoteAgentID: fixture.remoteAgentID,
			MaxClassification: 2, ExpectedRevision: 0,
		},
	); err == nil || !strings.Contains(err.Error(), "agreement changed") {
		t.Fatalf("agreement generation changed during oracle but prepare error=%v", err)
	}
}

func TestFederatedGuestAdminSignerFailsClosedOnPolicyProjectionDrift(t *testing.T) {
	fixture := newV23GuestControlFixture(t)
	if !fixture.manager.localAdminSignerActive(fixture.adminID) {
		t.Fatal("coherent promoted Admin was not active")
	}
	projected, err := fixture.badger.GetRegisteredAgent(fixture.adminID)
	if err != nil {
		t.Fatal(err)
	}
	projected.Clearance = 3
	rawProjection, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.badger.SetRawForTest(
		[]byte("appv23:agent:"+fixture.adminID), rawProjection,
	); err != nil {
		t.Fatal(err)
	}
	if fixture.manager.localAdminSignerActive(fixture.adminID) {
		t.Fatal("Admin signer remained active after its on-chain clearance projection drifted")
	}
}

func TestFederatedGuestPrepareCommitTOCTOUAndRebindProjection(t *testing.T) {
	fixture := newV23GuestControlFixture(t)
	mutation := fixture.preparedAttach(t)
	policy, policyErr := fixture.sqlite.GetPeerRBACPolicy(context.Background(), "chain-a")
	if policyErr != nil {
		t.Fatal(policyErr)
	}
	policy.Domains = append(policy.Domains,
		store.PeerRBACDomainPermission{Domain: "another-domain", Read: true})
	if _, err := fixture.sqlite.ReplaceBoundPeerRBACPolicy(context.Background(), *policy); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.manager.CommitFederatedGuestMutation(
		context.Background(), fixture.adminID, mutation,
	); err == nil {
		t.Fatal("policy-generation TOCTOU committed stale prepared bytes")
	}

	// Prepare and commit against the new generation, then rotate once more.
	mutation = fixture.preparedAttach(t)
	if _, err := fixture.manager.CommitFederatedGuestMutation(
		context.Background(), fixture.adminID, mutation,
	); err != nil {
		t.Fatal(err)
	}
	policy, _ = fixture.sqlite.GetPeerRBACPolicy(context.Background(), "chain-a")
	policy.Domains = append(policy.Domains,
		store.PeerRBACDomainPermission{Domain: "third-domain", Read: true})
	if _, err := fixture.sqlite.ReplaceBoundPeerRBACPolicy(context.Background(), *policy); err != nil {
		t.Fatal(err)
	}
	links, linksErr := fixture.manager.ListFederatedGuestLinks(
		context.Background(), fixture.adminID, "chain-a", fixture.remoteAgentID,
	)
	if linksErr != nil || len(links) != 1 {
		t.Fatalf("list stale guest: len=%d err=%v", len(links), linksErr)
	}
	if links[0].BindingCurrent ||
		links[0].EffectiveState != store.FederatedGuestStateRebindRequired {
		t.Fatalf("stale link projection=%+v, want rebind_required", links[0])
	}
}

func TestFederatedGuestCurrentRootCommitsWithoutElevation(t *testing.T) {
	fixture := newV23GuestControlFixture(t)
	prepared, prepareErr := fixture.manager.PrepareFederatedGuestMutation(
		context.Background(), fixture.rootID, FederatedGuestMutationInput{
			Operation: FederatedGuestOperationAttach, GroupID: "local-research",
			RemoteChainID: "chain-a", RemoteAgentID: fixture.remoteAgentID,
			MaxClassification: 2, ExpectedRevision: 0,
		},
	)
	if prepareErr != nil {
		t.Fatal(prepareErr)
	}
	guest := prepared.Guest
	if err := store.SignFederatedGroupGuest(&guest, fixture.rootKey); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.manager.CommitFederatedGuestMutation(
		context.Background(), fixture.rootID, FederatedGuestMutation{
			Operation: prepared.Operation, ExpectedRevision: prepared.ExpectedRevision,
			Guest: guest,
		},
	); err != nil {
		t.Fatalf("current root direct commit required elevation: %v", err)
	}
}

func TestLegacySyncPolicyAdminChecksHonorV23RootGeneration(t *testing.T) {
	fixture := newV23GuestControlFixture(t)
	fixture.manager.agentKey = fixture.adminKey
	fixture.manager.agentPub = fixture.adminKey.Public().(ed25519.PublicKey)
	if err := fixture.manager.authorizeSyncPolicyDomains([]string{"not-owned"}); err != nil {
		t.Fatalf("current-generation promoted Admin was denied before rotation: %v", err)
	}
	if err := fixture.manager.authorizeOwnerUnilateralDomain("not-owned", false, nil); err != nil {
		t.Fatalf("current-generation promoted Admin owner action was denied before rotation: %v", err)
	}

	newRootPub, _, _ := ed25519.GenerateKey(rand.Reader)
	newRootID := hex.EncodeToString(newRootPub)
	if err := fixture.badger.RotateAppV23RootCredential(1, newRootID, 10); err != nil {
		t.Fatal(err)
	}
	if err := fixture.manager.authorizeSyncPolicyDomains([]string{"not-owned"}); err == nil {
		t.Fatal("stale-generation promoted Admin retained legacy sync-policy authority")
	}
	if err := fixture.manager.authorizeOwnerUnilateralDomain("not-owned", false, nil); err == nil {
		t.Fatal("stale-generation promoted Admin retained legacy owner-unilateral authority")
	}

	enrollment, _ := fixture.badger.GetAppV23Enrollment(fixture.adminID)
	role, _ := fixture.badger.GetAppV23Role(fixture.adminID)
	if err := fixture.badger.SetAppV23Policy(
		newRootID, fixture.adminID, store.AppV23RoleAdmin,
		store.AppV23ProfileStandard, store.AppV23ProfileStandard,
		4, store.AgentCapabilityReadAllDomains,
		role.Revision, enrollment.Revision, 11,
	); err != nil {
		t.Fatalf("root rebind of promoted Admin: %v", err)
	}
	if err := fixture.manager.authorizeSyncPolicyDomains([]string{"not-owned"}); err != nil {
		t.Fatalf("rebound promoted Admin did not regain sync-policy authority: %v", err)
	}
	if err := fixture.manager.authorizeOwnerUnilateralDomain("not-owned", false, nil); err != nil {
		t.Fatalf("rebound promoted Admin did not regain owner-unilateral authority: %v", err)
	}
}
