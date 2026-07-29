package federation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/store"
)

func enrollV23OrdinaryAgent(
	t *testing.T,
	node *testChain,
	name string,
	key ed25519.PrivateKey,
	height int64,
) string {
	t.Helper()
	pub := key.Public().(ed25519.PublicKey)
	agentID := hex.EncodeToString(pub)
	if err := node.badger.RegisterAgentWithCapabilities(
		agentID, name, store.AppV23RoleMember, "", "oracle-test", "", height, 0,
	); err != nil {
		t.Fatal(err)
	}
	root, err := node.badger.GetAppV23Root()
	if err != nil || root == nil {
		t.Fatalf("read Root: state=%+v err=%v", root, err)
	}
	if err := node.badger.ApproveAppV23LocalAgent(store.AppV23LocalEnrollment{
		AgentID: agentID, ApprovedBy: root.CredentialID,
		RootGeneration: root.Generation,
		Profile:        store.AppV23ProfileStandard,
		HomeDomain:     "oracle-" + agentID[:16],
		Clearance:      1,
		Capabilities:   0,
		Active:         true,
		UpdatedHeight:  height + 1,
	}, store.AppV23RoleMember, 0, 0); err != nil {
		t.Fatal(err)
	}
	return agentID
}

func deactivateV23OrdinaryAgent(
	t *testing.T,
	node *testChain,
	agentID string,
	height int64,
) {
	t.Helper()
	enrollment, err := node.badger.GetAppV23Enrollment(agentID)
	if err != nil || enrollment == nil {
		t.Fatalf("read enrollment: state=%+v err=%v", enrollment, err)
	}
	role, err := node.badger.GetAppV23Role(agentID)
	if err != nil || role == nil {
		t.Fatalf("read role: state=%+v err=%v", role, err)
	}
	root, err := node.badger.GetAppV23Root()
	if err != nil || root == nil {
		t.Fatalf("read Root: state=%+v err=%v", root, err)
	}
	enrollment.Active = false
	enrollment.ApprovedBy = root.CredentialID
	enrollment.RootGeneration = root.Generation
	enrollment.UpdatedHeight = height
	if err := node.badger.ApproveAppV23LocalAgent(
		*enrollment,
		store.AppV23RoleMember,
		enrollment.Revision,
		role.Revision,
	); err != nil {
		t.Fatal(err)
	}
}

type v23GuestEligibilityPair struct {
	local, remote *testChain
	remoteAgentID string
}

func newV23GuestEligibilityPair(t *testing.T) *v23GuestEligibilityPair {
	t.Helper()
	local := newTestChain(t, "guest-eligibility-local")
	remote := newTestChain(t, "guest-eligibility-remote")
	remoteListener := startListener(t, remote)
	federate(t, local, remote, remoteListener.URL, []string{"*"}, 4, 0)
	federate(t, remote, local, "https://unused.invalid", []string{"*"}, 4, 0)
	enableV23Pair(t, local, remote, []string{"shared"})
	localRootID := hex.EncodeToString(local.agentPub)
	if err := local.badger.MutateAppV23AccessGroup(
		localRootID, "linked-readers", "Linked readers", nil, 0, false, 3,
	); err != nil {
		t.Fatal(err)
	}
	_, remoteAgentKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	remoteAgentID := enrollV23OrdinaryAgent(
		t, remote, "exact-only-agent", remoteAgentKey, 4,
	)
	return &v23GuestEligibilityPair{
		local: local, remote: remote, remoteAgentID: remoteAgentID,
	}
}

func (p *v23GuestEligibilityPair) prepare(
	t *testing.T,
	operation string,
	expectedRevision int64,
) *PreparedFederatedGuestMutation {
	t.Helper()
	prepared, err := p.local.mgr.PrepareFederatedGuestMutation(
		context.Background(),
		hex.EncodeToString(p.local.agentPub),
		FederatedGuestMutationInput{
			Operation: operation, GroupID: "linked-readers",
			RemoteChainID: p.remote.chainID, RemoteAgentID: p.remoteAgentID,
			MaxClassification: 2, ExpectedRevision: expectedRevision,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func (p *v23GuestEligibilityPair) rootMutation(
	t *testing.T,
	prepared *PreparedFederatedGuestMutation,
) FederatedGuestMutation {
	t.Helper()
	guest := prepared.Guest
	if err := store.SignFederatedGroupGuest(&guest, p.local.agentKey); err != nil {
		t.Fatal(err)
	}
	return FederatedGuestMutation{
		Operation: prepared.Operation, ExpectedRevision: prepared.ExpectedRevision,
		Guest: guest,
	}
}

func TestFederatedGuestExactAgentOracleIsConsensusBasedAndExcludesRootHistory(t *testing.T) {
	pair := newV23GuestEligibilityPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// No SQLite AgentEntry/contact/directory row was created for this identity.
	// Exact consensus enrollment is authoritative despite that directory miss.
	sqlite := pair.remote.mem.(*store.SQLiteStore)
	candidates, candidatesErr := sqlite.GetPipeContactAgents(ctx, []string{pair.remoteAgentID})
	if candidatesErr != nil {
		t.Fatal(candidatesErr)
	}
	if len(candidates) != 0 {
		t.Fatalf("test identity unexpectedly appeared in SQLite directory: %+v", candidates)
	}
	if err := pair.local.mgr.CheckRemoteFederatedGuestAgentEligibility(
		ctx, pair.remote.chainID, pair.remoteAgentID,
	); err != nil {
		t.Fatalf("exact active enrolled agent was denied after directory miss: %v", err)
	}

	remoteRoot, rootErr := pair.remote.badger.GetAppV23Root()
	if rootErr != nil || remoteRoot == nil {
		t.Fatalf("remote Root: state=%+v err=%v", remoteRoot, rootErr)
	}
	retiredRootID := remoteRoot.CredentialID
	nextRootPub, _, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	nextRootID := hex.EncodeToString(nextRootPub)
	if err := pair.remote.badger.RotateAppV23RootCredential(
		remoteRoot.Generation, nextRootID, 8,
	); err != nil {
		t.Fatal(err)
	}
	for label, agentID := range map[string]string{
		"retired Root": retiredRootID,
		"current Root": nextRootID,
		"absent agent": strings.Repeat("ab", ed25519.PublicKeySize),
	} {
		err := pair.local.mgr.CheckRemoteFederatedGuestAgentEligibility(
			ctx, pair.remote.chainID, agentID,
		)
		if !errors.Is(err, ErrRemoteFederatedGuestAgentIneligible) {
			t.Fatalf("%s exact-ID oracle error=%v, want generic ineligible", label, err)
		}
	}
}

func TestFederatedGuestAttachCommitRechecksRemoteEligibilityTOCTOU(t *testing.T) {
	pair := newV23GuestEligibilityPair(t)
	prepared := pair.prepare(t, FederatedGuestOperationAttach, 0)
	mutation := pair.rootMutation(t, prepared)

	deactivateV23OrdinaryAgent(t, pair.remote, pair.remoteAgentID, 9)
	if _, err := pair.local.mgr.CommitFederatedGuestMutation(
		context.Background(),
		hex.EncodeToString(pair.local.agentPub),
		mutation,
	); !errors.Is(err, ErrRemoteFederatedGuestAgentIneligible) {
		t.Fatalf("commit did not recheck remote deactivation: %v", err)
	}
	guest, err := pair.local.mem.(*store.SQLiteStore).GetFederatedGroupGuest(
		context.Background(), "linked-readers",
		pair.remote.chainID, pair.remoteAgentID,
	)
	if err != nil || guest != nil {
		t.Fatalf("TOCTOU denial persisted a row: guest=%+v err=%v", guest, err)
	}
}

func TestFederatedGuestPauseRemainsLocalWhenPeerIsOffline(t *testing.T) {
	pair := newV23GuestEligibilityPair(t)
	attach := pair.rootMutation(
		t, pair.prepare(t, FederatedGuestOperationAttach, 0),
	)
	rootID := hex.EncodeToString(pair.local.agentPub)
	if _, err := pair.local.mgr.CommitFederatedGuestMutation(
		context.Background(), rootID, attach,
	); err != nil {
		t.Fatal(err)
	}

	agreement, agreementErr := pair.local.mgr.ActiveAgreement(pair.remote.chainID)
	if agreementErr != nil {
		t.Fatal(agreementErr)
	}
	if err := pair.local.badger.SetCrossFed(
		agreement.RemoteChainID,
		"https://127.0.0.1:1",
		agreement.PeerPubKey,
		agreement.MaxClearance,
		agreement.ExpiresAt,
		agreement.AllowedDomains,
		agreement.AllowedDepts,
		agreement.Status,
	); err != nil {
		t.Fatal(err)
	}
	pause := pair.rootMutation(
		t, pair.prepare(t, FederatedGuestOperationPause, 1),
	)
	guest, err := pair.local.mgr.CommitFederatedGuestMutation(
		context.Background(), rootID, pause,
	)
	if err != nil {
		t.Fatalf("local pause depended on peer reachability: %v", err)
	}
	if guest.State != store.FederatedGuestStatePaused {
		t.Fatalf("paused guest state=%q", guest.State)
	}
}
