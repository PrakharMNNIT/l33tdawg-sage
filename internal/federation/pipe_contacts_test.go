package federation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/store"
)

type blockingStatusWriter struct {
	header  http.Header
	started chan struct{}
	release chan struct{}
}

func ensurePipeContactAppV23(t *testing.T, m *Manager, bs *store.BadgerStore) {
	t.Helper()
	root, err := bs.GetAppV23Root()
	require.NoError(t, err)
	if root == nil {
		companion := newPeerOperatorID(t)
		require.NoError(t, bs.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
			RootID: hex.EncodeToString(m.agentPub), Scope: "pipe-contact-explicit-exports",
			AgentID: companion, Profile: store.AppV23ProfileStandard,
			HomeDomain: "pipe-contact-bootstrap", Clearance: 1, Height: 1,
			BootstrapDigest: strings.Repeat("91", 32),
		}))
	}
	m.postV23ForNextTx = func() bool { return true }
	m.postV22ForNextTx = func() bool { return true }
	m.postV8ForAccess = func() bool { return true }
}

func seedPipeContactOrdinaryAgent(
	t *testing.T, m *Manager, ss *store.SQLiteStore, bs *store.BadgerStore,
	agentID, name, status string, capabilities store.AgentCapabilities, height int64,
) {
	t.Helper()
	ensurePipeContactAppV23(t, m, bs)
	role := store.AppV23RoleMember
	clearance := uint8(1)
	if capabilities.Has(store.AgentCapabilityReadAllDomains) {
		role = store.AppV23RoleAdmin
		clearance = 4
	}
	require.NoError(t, bs.RegisterAgentWithCapabilities(
		agentID, name, role, "", "pipe-contact-test", "", height, capabilities,
	))
	root, err := bs.GetAppV23Root()
	require.NoError(t, err)
	require.NotNil(t, root)
	require.NoError(t, bs.ApproveAppV23LocalAgent(store.AppV23LocalEnrollment{
		AgentID: agentID, ApprovedBy: root.CredentialID, RootGeneration: root.Generation,
		Profile: store.AppV23ProfileStandard, HomeDomain: "local-" + agentID,
		Clearance: clearance, Capabilities: capabilities, Active: status == "active",
		UpdatedHeight: height + 1,
	}, role, 0, 0))
	require.NoError(t, ss.CreateAgent(context.Background(), &store.AgentEntry{
		AgentID: agentID, Name: name, RegisteredName: name, Status: status,
	}))
}

func exportPipeContactAgent(
	t *testing.T, m *Manager, remoteChainID, agentID string,
) *store.FederatedAgentExport {
	t.Helper()
	exported, err := m.SetFederatedAgentExport(
		context.Background(), remoteChainID, agentID,
		store.FederatedAgentExportStateActive, 4, nil, 0,
	)
	require.NoError(t, err)
	require.NotNil(t, exported)
	return exported
}

func (w *blockingStatusWriter) Header() http.Header { return w.header }
func (w *blockingStatusWriter) WriteHeader(int)     {}
func (w *blockingStatusWriter) Write(p []byte) (int, error) {
	close(w.started)
	<-w.release
	return len(p), nil
}

func TestStatusPipeContactsExposeOnlyExplicitActiveOrdinaryOwners(t *testing.T) {
	ctx := context.Background()
	m, ss, bs := newDrainTestManager(t)
	m.SetNetworkName("Amy's SAGE")
	ensurePipeContactAppV23(t, m, bs)
	peerID := newPeerOperatorID(t)
	agreement := configurePeerRBACConnection(t, m, ss, bs, "chain-peer", peerID, "host", nil, 4)

	activeOwner := newPeerOperatorID(t)
	inactiveOwner := newPeerOperatorID(t)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, activeOwner, "tii-sentinel", "active", 0, 10)
	require.NoError(t, ss.CreateAgent(ctx, &store.AgentEntry{
		AgentID: inactiveOwner, Name: "ops-agent", RegisteredName: "ops-agent", Status: "inactive",
	}))
	require.NoError(t, bs.RegisterDomain("tii", activeOwner, "", 1))
	require.NoError(t, bs.RegisterDomain("ops", inactiveOwner, "", 2))
	require.NoError(t, bs.RegisterDomain("open.shared", activeOwner, "", 3))
	require.NoError(t, bs.SetSharedDomain("open.shared"))

	_, err := m.ReplacePeerRBACPolicy(ctx, "chain-peer", []store.PeerRBACDomainPermission{
		{Domain: "general", Read: true},
		{Domain: "open.shared", Read: true},
		{Domain: "ops.alerts", Read: true},
		{Domain: "tii.findings", Copy: true},
		{Domain: "tii.security", Read: true},
	})
	require.NoError(t, err)
	exportPipeContactAgent(t, m, "chain-peer", activeOwner)

	status := statusForPeer(t, m, "chain-peer", peerID, agreement)
	require.NotNil(t, status.PipeContacts)
	require.Equal(t, PipeContactVersion, status.PipeContacts.Version)
	require.NotEmpty(t, status.PipeContacts.AgreementID)
	require.NotEmpty(t, status.PipeContacts.Revision)
	require.False(t, status.PipeContacts.Paused)
	require.Len(t, status.PipeContacts.Contacts, 1,
		"manual Read domains and unexported owners must not synthesize contacts")

	contacts := make(map[string]PipeContact, len(status.PipeContacts.Contacts))
	for _, contact := range status.PipeContacts.Contacts {
		contacts[contact.AgentID] = contact
	}
	active := contacts[activeOwner]
	require.Equal(t, "tii-sentinel", active.DisplayName)
	require.True(t, active.Available)
	require.True(t, active.Accepting, "explicit federation membership defaults messaging on")
	require.NotEmpty(t, active.ContactID)
	require.Equal(t, activeOwner+"@chain-local", active.Address)
	require.True(t, strings.HasPrefix(active.Handle, "#amy-s-sage-"), active.Handle)
	require.True(t, strings.HasSuffix(active.Handle, "/"+activeOwner[:pipeContactMinAgentPrefix]), active.Handle)
	require.Equal(t, []PipeContactDomain{
		{Domain: "local-" + activeOwner, OwningDomain: "local-" + activeOwner, OwnerHeight: 11},
		{Domain: "tii", OwningDomain: "tii", OwnerHeight: 1},
	}, active.Domains)
	require.NotContains(t, contacts, inactiveOwner)
	require.Contains(t, status.Capabilities, CapabilityFederatedPipeline)
}

func TestAppV23PipeContactsExplicitExportPauseRemovesContact(t *testing.T) {
	ctx := context.Background()
	m, ss, bs := newDrainTestManager(t)
	rootID := hex.EncodeToString(m.agentPub)
	companionPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	companionID := hex.EncodeToString(companionPub)
	require.NoError(t, bs.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: rootID, Scope: "pipe-shared-barrier",
		AgentID: companionID, Profile: store.AppV23ProfileStandard,
		HomeDomain: "team", Clearance: 1, Height: 1,
		BootstrapDigest: strings.Repeat("24", 32),
	}))
	require.NoError(t, bs.SetSharedDomain("team.shared"))
	require.NoError(t, ss.CreateAgent(ctx, &store.AgentEntry{
		AgentID: companionID, Name: "team-owner", Status: "active",
	}))
	peerID := newPeerOperatorID(t)
	agreement := configurePeerRBACConnection(
		t, m, ss, bs, "chain-peer", peerID, "host", nil, 4,
	)
	_, err = m.ReplacePeerRBACPolicy(
		ctx, "chain-peer",
		[]store.PeerRBACDomainPermission{{
			Domain: "team.shared.secret", Read: true,
		}},
	)
	require.NoError(t, err)
	m.postV23ForNextTx = func() bool { return true }
	exported := exportPipeContactAgent(t, m, "chain-peer", companionID)
	current := statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.Len(t, current.Contacts, 1)
	require.Equal(t, companionID, current.Contacts[0].AgentID)
	require.Equal(t, []PipeContactDomain{{Domain: "team", OwningDomain: "team", OwnerHeight: 1}}, current.Contacts[0].Domains)
	_, err = m.SetFederatedAgentExport(ctx, "chain-peer", companionID,
		store.FederatedAgentExportStatePaused, 4, nil, exported.Revision)
	require.NoError(t, err)
	require.Empty(t, statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts.Contacts)
}

func TestPipeContactsRequireExplicitOwnerExportNotNonOwnerGrants(t *testing.T) {
	ctx := context.Background()
	m, ss, bs := newDrainTestManager(t)
	ensurePipeContactAppV23(t, m, bs)
	peerID := newPeerOperatorID(t)
	agreement := configurePeerRBACConnection(t, m, ss, bs, "chain-peer", peerID, "host", nil, 4)

	owner := newPeerOperatorID(t)
	reader := newPeerOperatorID(t)
	writer := newPeerOperatorID(t)
	unrelated := newPeerOperatorID(t)
	inactive := newPeerOperatorID(t)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, owner, "domain-owner", "active", 0, 10)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, reader, "Research worker", "active", 0, 20)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, writer, "domain-writer", "active", 0, 30)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, unrelated, "unrelated", "active", 0, 40)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, inactive, "inactive-reader", "inactive", 0, 50)
	require.NoError(t, bs.RegisterDomain("research", owner, "", 10))
	require.NoError(t, bs.SetAccessGrant("research", reader, 1, 0, owner))
	require.NoError(t, bs.SetAccessGrant("research", writer, 2, 0, owner))
	require.NoError(t, bs.SetAccessGrant("research", inactive, 1, 0, owner))
	_, err := m.ReplacePeerRBACPolicy(ctx, "chain-peer", []store.PeerRBACDomainPermission{{Domain: "research.findings", Read: true}})
	require.NoError(t, err)
	exported := exportPipeContactAgent(t, m, "chain-peer", owner)

	grant := statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.NotNil(t, grant)
	contacts := make(map[string]PipeContact, len(grant.Contacts))
	for _, contact := range grant.Contacts {
		contacts[contact.AgentID] = contact
	}
	require.Contains(t, contacts, owner, "the explicitly exported owner is visible")
	require.NotContains(t, contacts, reader, "a non-owner read grant must not synthesize identity")
	require.NotContains(t, contacts, writer, "a non-owner write grant must not synthesize identity")
	require.NotContains(t, contacts, unrelated)
	require.NotContains(t, contacts, inactive)
	accepted := contacts[owner]
	require.True(t, accepted.Accepting)
	require.Equal(t, []PipeContactDomain{
		{Domain: "local-" + owner, OwningDomain: "local-" + owner, OwnerHeight: 11},
		{Domain: "research", OwningDomain: "research", OwnerHeight: 10},
	}, accepted.Domains)
	policy, err := m.GetPeerRBACPolicy(ctx, "chain-peer")
	require.NoError(t, err)
	require.NotNil(t, policy)
	event := &PipeEvent{
		PolicyEpoch:     policy.PolicyEpoch,
		AgreementID:     grant.AgreementID,
		ContactID:       accepted.ContactID,
		ContactRevision: pipeContactAuthorizationRevision(grant, &accepted),
		TargetAgentID:   owner,
	}
	peer := &peerIdentity{ChainID: "chain-peer", AgentID: peerID, Agreement: agreement}
	resolved, err := m.authorizeInboundPipeContact(ctx, peer, event)
	require.NoError(t, err)
	require.Equal(t, owner, resolved.AgentID)

	// Pausing the explicit export removes the recipient from the live projection, so an
	// already queued event cannot be accepted with a stale contact revision.
	_, err = m.SetFederatedAgentExport(ctx, "chain-peer", owner,
		store.FederatedAgentExportStatePaused, 4, nil, exported.Revision)
	require.NoError(t, err)
	_, err = m.authorizeInboundPipeContact(ctx, peer, event)
	require.ErrorIs(t, err, ErrFederatedPipeInvalid)
}

func TestAppV23PipeContactsNeverExposeRootOrGrantedNonOwner(t *testing.T) {
	ctx := context.Background()
	m, ss, bs := newDrainTestManager(t)
	rootID := hex.EncodeToString(m.agentPub)
	companionPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	currentRootPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	currentRootID := hex.EncodeToString(currentRootPub)
	finalRootPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	finalRootID := hex.EncodeToString(finalRootPub)
	require.NoError(t, bs.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: rootID, Scope: "pipe-contact-test",
		AgentID: hex.EncodeToString(companionPub), Profile: store.AppV23ProfileStandard,
		HomeDomain: "pipe-contact-companion", Clearance: 1, Height: 1,
		BootstrapDigest: strings.Repeat("23", 32),
	}))
	require.NoError(t, bs.RotateAppV23RootCredential(1, currentRootID, 2))
	require.NoError(t, bs.RotateAppV23RootCredential(2, finalRootID, 3))
	m.postV23ForNextTx = func() bool { return true }
	m.postV8ForAccess = func() bool { return true }

	peerID := newPeerOperatorID(t)
	agreement := configurePeerRBACConnection(t, m, ss, bs, "chain-peer", peerID, "host", nil, 4)
	reader := newPeerOperatorID(t)
	for _, agent := range []*store.AgentEntry{
		{AgentID: rootID, Name: "root-principal", Status: "active"},
		{AgentID: currentRootID, Name: "root-retired-generation", Status: "active"},
		{AgentID: finalRootID, Name: "root-current", Status: "active"},
		{AgentID: reader, Name: "ordinary-reader", Status: "active"},
	} {
		require.NoError(t, ss.CreateAgent(ctx, agent))
	}
	require.NoError(t, bs.RegisterAgentWithCapabilities(
		reader, "ordinary-reader", store.AppV23RoleMember, "", "test", "", 4, 0,
	))
	root, err := bs.GetAppV23Root()
	require.NoError(t, err)
	require.NotNil(t, root)
	require.NoError(t, bs.ApproveAppV23LocalAgent(store.AppV23LocalEnrollment{
		AgentID: reader, ApprovedBy: root.CredentialID,
		RootGeneration: root.Generation,
		Profile:        store.AppV23ProfileStandard,
		HomeDomain:     "ordinary-reader-home",
		Clearance:      1,
		Active:         true,
		UpdatedHeight:  5,
	}, store.AppV23RoleMember, 0, 0))
	require.NoError(t, bs.RegisterDomain("root-owned", rootID, "", 10))
	require.NoError(t, bs.SetAccessGrant("root-owned", currentRootID, 1, 0, rootID))
	require.NoError(t, bs.SetAccessGrant("root-owned", finalRootID, 1, 0, rootID))
	require.NoError(t, bs.SetAccessGrant("root-owned", reader, 1, 0, rootID))
	_, err = m.ReplacePeerRBACPolicy(ctx, "chain-peer", []store.PeerRBACDomainPermission{
		{Domain: "root-owned.work", Read: true},
	})
	require.NoError(t, err)
	_, err = m.SetFederatedAgentExport(ctx, "chain-peer", rootID,
		store.FederatedAgentExportStateActive, 4, nil, 0)
	require.Error(t, err, "Root authority must never be exportable as an ordinary identity")

	grant := statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.NotNil(t, grant)
	contacts := make(map[string]PipeContact, len(grant.Contacts))
	for _, contact := range grant.Contacts {
		contacts[contact.AgentID] = contact
	}
	require.NotContains(t, contacts, rootID, "the immutable Root principal is authority, never an agent contact")
	require.NotContains(t, contacts, currentRootID, "a retired Root generation is never an agent contact")
	require.NotContains(t, contacts, finalRootID, "the live Root credential is never an agent contact")
	require.NotContains(t, contacts, reader,
		"a non-owner grant on a Root-owned domain must not synthesize federation identity")
}

func TestAppV23PipeContactsExcludeConsensusInactiveAgentWithStaleSQLiteStatus(t *testing.T) {
	ctx := context.Background()
	m, ss, bs := newDrainTestManager(t)
	rootID := hex.EncodeToString(m.agentPub)
	agentPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	agentID := hex.EncodeToString(agentPub)
	require.NoError(t, bs.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: rootID, Scope: "pipe-stale-active",
		AgentID: agentID, Profile: store.AppV23ProfileStandard,
		HomeDomain: "stale-home", Clearance: 1, Height: 1,
		BootstrapDigest: strings.Repeat("25", 32),
	}))
	m.postV23ForNextTx = func() bool { return true }
	m.postV8ForAccess = func() bool { return true }
	require.NoError(t, ss.CreateAgent(ctx, &store.AgentEntry{
		AgentID: agentID, Name: "stale-active", RegisteredName: "stale-active",
		Provider: "local", Status: "active",
	}))
	peerID := newPeerOperatorID(t)
	agreement := configurePeerRBACConnection(t, m, ss, bs, "chain-peer", peerID, "host", nil, 4)
	_, err = m.ReplacePeerRBACPolicy(ctx, "chain-peer", []store.PeerRBACDomainPermission{{
		Domain: "stale-home", Read: true,
	}})
	require.NoError(t, err)
	exportPipeContactAgent(t, m, "chain-peer", agentID)

	before := statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.Len(t, before.Contacts, 1)
	require.Equal(t, agentID, before.Contacts[0].AgentID)

	enrollment, err := bs.GetAppV23Enrollment(agentID)
	require.NoError(t, err)
	require.NotNil(t, enrollment)
	role, err := bs.GetAppV23Role(agentID)
	require.NoError(t, err)
	require.NotNil(t, role)
	inactive := *enrollment
	inactive.Active = false
	inactive.ApprovedBy = rootID
	inactive.UpdatedHeight = 2
	require.NoError(t, bs.ApproveAppV23LocalAgent(
		inactive, store.AppV23RoleMember, enrollment.Revision, role.Revision,
	))

	// The operational SQLite directory deliberately remains stale-active. The
	// consensus enrollment is authoritative for a newly advertised federated
	// contact, so deactivation must remove it immediately.
	stale, err := ss.GetAgent(ctx, agentID)
	require.NoError(t, err)
	require.Equal(t, "active", stale.Status)
	after := statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.Empty(t, after.Contacts)
}

func TestPipeContactExportDefaultsMessagingOnReadAllDoesNotSynthesizeAndDenySuspends(t *testing.T) {
	ctx := context.Background()
	m, ss, bs := newDrainTestManager(t)
	ensurePipeContactAppV23(t, m, bs)
	peerID := newPeerOperatorID(t)
	agreement := configurePeerRBACConnection(t, m, ss, bs, "chain-peer", peerID, "host", nil, 4)

	owner := newPeerOperatorID(t)
	readAllNonOwner := newPeerOperatorID(t)
	deniedOwner := newPeerOperatorID(t)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, owner, "research-owner", "active", 0, 10)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, readAllNonOwner, "MYNAH companion", "active",
		store.AgentCapabilityReadAllDomains, 20)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, deniedOwner, "denied-owner", "active",
		store.AgentCapabilityDenyFederatedPipe, 30)
	require.NoError(t, bs.RegisterDomain("research", owner, "", 10))
	require.NoError(t, bs.RegisterDomain("operations", deniedOwner, "", 11))
	_, err := m.ReplacePeerRBACPolicy(ctx, "chain-peer", []store.PeerRBACDomainPermission{
		{Domain: "research", Read: true},
		{Domain: "operations", Read: true},
	})
	require.NoError(t, err)
	exportPipeContactAgent(t, m, "chain-peer", owner)
	exportPipeContactAgent(t, m, "chain-peer", deniedOwner)

	grant := statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.NotNil(t, grant)
	contacts := make(map[string]PipeContact, len(grant.Contacts))
	for _, contact := range grant.Contacts {
		contacts[contact.AgentID] = contact
	}
	require.Contains(t, contacts, owner)
	require.NotContains(t, contacts, readAllNonOwner,
		"ReadAllDomains is local read authority, not explicit federation membership")
	targetContact := contacts[owner]
	require.True(t, targetContact.Accepting, "an explicit export defaults messaging on")
	deniedContact, ok := contacts[deniedOwner]
	require.True(t, ok, "DenyFederatedPipe is messaging-only and does not unexport readable domains")
	require.False(t, deniedContact.Accepting)
	require.Equal(t, []PipeContactDomain{
		{Domain: "local-" + deniedOwner, OwningDomain: "local-" + deniedOwner, OwnerHeight: 31},
		{Domain: "operations", OwningDomain: "operations", OwnerHeight: 11},
	}, deniedContact.Domains)
	require.Equal(t, []PipeContactDomain{
		{Domain: "local-" + owner, OwningDomain: "local-" + owner, OwnerHeight: 11},
		{Domain: "research", OwningDomain: "research", OwnerHeight: 10},
	}, targetContact.Domains)

	policy, err := m.GetPeerRBACPolicy(ctx, "chain-peer")
	require.NoError(t, err)
	require.NotNil(t, policy)
	event := &PipeEvent{
		PolicyEpoch: policy.PolicyEpoch, AgreementID: grant.AgreementID,
		ContactID:       targetContact.ContactID,
		ContactRevision: pipeContactAuthorizationRevision(grant, &targetContact),
		TargetAgentID:   owner,
	}
	peer := &peerIdentity{ChainID: "chain-peer", AgentID: peerID, Agreement: agreement}
	resolved, err := m.authorizeInboundPipeContact(ctx, peer, event)
	require.NoError(t, err)
	require.Equal(t, owner, resolved.AgentID)
	deniedEvent := &PipeEvent{
		PolicyEpoch: policy.PolicyEpoch, AgreementID: grant.AgreementID,
		ContactID:       deniedContact.ContactID,
		ContactRevision: pipeContactAuthorizationRevision(grant, &deniedContact),
		TargetAgentID:   deniedOwner,
	}
	_, err = m.authorizeInboundPipeContact(ctx, peer, deniedEvent)
	require.ErrorIs(t, err, ErrFederatedPipeSuspended)
}

func TestPipeContactExplicitExportTargetedLookupFiltersSimilarlyNamedNonOwner(t *testing.T) {
	ctx := context.Background()
	m, ss, bs := newDrainTestManager(t)
	ensurePipeContactAppV23(t, m, bs)
	peerID := newPeerOperatorID(t)
	agreement := configurePeerRBACConnection(t, m, ss, bs, "chain-peer", peerID, "host", nil, 4)
	target := newPeerOperatorID(t)
	nonOwner := newPeerOperatorID(t)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, target, "Innovium", "active", 0, 10)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, nonOwner, "Innovium helper", "active", 0, 20)
	require.NoError(t, bs.RegisterDomain("research", target, "", 10))
	require.NoError(t, bs.SetAccessGrant("research", nonOwner, 1, 0, target))
	_, err := m.ReplacePeerRBACPolicy(ctx, "chain-peer", []store.PeerRBACDomainPermission{{Domain: "research", Read: true}})
	require.NoError(t, err)
	_, err = m.SetFederatedAgentExport(ctx, "chain-peer", target,
		store.FederatedAgentExportStateActive, 4, []string{"local-" + target}, 0)
	require.NoError(t, err)
	admin, err := m.LocalPipeContacts(ctx, "chain-peer")
	require.NoError(t, err)
	require.LessOrEqual(t, len(admin.Contacts), maxPipeContactStatusCandidates+1,
		"the CEREBRUM contact endpoint must not construct a full recipient roster")
	// Targeted lookup discovers the explicitly exported owner. The similarly
	// named non-owner grant recipient remains invisible.
	grant, err := m.localPipeContacts(ctx, "chain-peer", target)
	require.NoError(t, err)
	var targetContact PipeContact
	for _, contact := range grant.Contacts {
		if contact.AgentID == target {
			targetContact = contact
			break
		}
	}
	require.NotEmpty(t, targetContact.ContactID)
	require.True(t, targetContact.Accepting)

	status := statusForPeer(t, m, "chain-peer", peerID, agreement)
	require.NotNil(t, status.PipeContacts, "legacy peers retain a valid bounded status snapshot")
	require.LessOrEqual(t, len(status.PipeContacts.Contacts), maxPipeContactStatusContacts)
	require.LessOrEqual(t, len(status.PipeContacts.Contacts), maxPipeContactStatusCandidates+1,
		"legacy status construction must not scan the entire recipient roster")
	require.True(t, fitsPipeContactStatusSnapshot(status.PipeContacts))
	require.NoError(t, ValidateRemotePipeContactGrant("chain-local", status.PipeContacts))
	require.Contains(t, status.Capabilities, CapabilityFederatedPipelineContactLookup)
	compactReq := httptest.NewRequest(http.MethodGet, "/fed/v1/status", nil)
	compactReq.Header.Set(HeaderClientCapabilities, CapabilityFederatedPipelineContactLookup)
	compactReq = compactReq.WithContext(context.WithValue(compactReq.Context(), peerCtxKey{}, &peerIdentity{
		ChainID: "chain-peer", AgentID: peerID, Agreement: agreement,
	}))
	compactRec := httptest.NewRecorder()
	m.handleStatus(compactRec, compactReq)
	require.Equal(t, http.StatusOK, compactRec.Code, compactRec.Body.String())
	var compact StatusResponse
	require.NoError(t, json.NewDecoder(compactRec.Body).Decode(&compact))
	require.Nil(t, compact.PipeContacts, "lookup-capable clients must not force the legacy roster projection")

	body, err := json.Marshal(PipeContactLookupRequest{Name: "nov", Limit: 20})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/fed/v1/pipe/contacts/lookup", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), peerCtxKey{}, &peerIdentity{
		ChainID: "chain-peer", AgentID: peerID, Agreement: agreement,
	}))
	rec := httptest.NewRecorder()
	m.handlePipeContactLookup(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var response PipeContactLookupResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&response))
	require.Equal(t, 1, response.Total)
	require.False(t, response.Truncated)
	require.Len(t, response.Grant.Contacts, 1)
	require.Equal(t, target, response.Grant.Contacts[0].AgentID)
	require.True(t, response.Grant.Contacts[0].Accepting)

	tooShortBody, err := json.Marshal(PipeContactLookupRequest{Name: "i", Limit: 20})
	require.NoError(t, err)
	tooShortReq := httptest.NewRequest(http.MethodPost, "/fed/v1/pipe/contacts/lookup", bytes.NewReader(tooShortBody))
	tooShortReq = tooShortReq.WithContext(context.WithValue(tooShortReq.Context(), peerCtxKey{}, &peerIdentity{
		ChainID: "chain-peer", AgentID: peerID, Agreement: agreement,
	}))
	tooShortRec := httptest.NewRecorder()
	m.handlePipeContactLookup(tooShortRec, tooShortReq)
	require.Equal(t, http.StatusBadRequest, tooShortRec.Code, tooShortRec.Body.String())

	// Human-name discovery accepts substrings, but a friendly Target remains an
	// exact display-name selector so /pipe/resolve cannot silently widen routing.
	exactTargetBody, err := json.Marshal(PipeContactLookupRequest{Target: "nov", Limit: 20})
	require.NoError(t, err)
	exactTargetReq := httptest.NewRequest(http.MethodPost, "/fed/v1/pipe/contacts/lookup", bytes.NewReader(exactTargetBody))
	exactTargetReq = exactTargetReq.WithContext(context.WithValue(exactTargetReq.Context(), peerCtxKey{}, &peerIdentity{
		ChainID: "chain-peer", AgentID: peerID, Agreement: agreement,
	}))
	exactTargetRec := httptest.NewRecorder()
	m.handlePipeContactLookup(exactTargetRec, exactTargetReq)
	require.Equal(t, http.StatusOK, exactTargetRec.Code, exactTargetRec.Body.String())
	var exactTargetResponse PipeContactLookupResponse
	require.NoError(t, json.NewDecoder(exactTargetRec.Body).Decode(&exactTargetResponse))
	require.Zero(t, exactTargetResponse.Total)
	require.Empty(t, exactTargetResponse.Grant.Contacts)

	oversizedBody, err := json.Marshal(PipeContactLookupRequest{Name: "innovium", Limit: maxPipeContactLookupResults + 1})
	require.NoError(t, err)
	oversizedReq := httptest.NewRequest(http.MethodPost, "/fed/v1/pipe/contacts/lookup", bytes.NewReader(oversizedBody))
	oversizedReq = oversizedReq.WithContext(context.WithValue(oversizedReq.Context(), peerCtxKey{}, &peerIdentity{
		ChainID: "chain-peer", AgentID: peerID, Agreement: agreement,
	}))
	oversizedRec := httptest.NewRecorder()
	m.handlePipeContactLookup(oversizedRec, oversizedReq)
	require.Equal(t, http.StatusBadRequest, oversizedRec.Code, oversizedRec.Body.String())
}

func TestLegacyStatusLoadsAnOwnerOutsideItsCandidateSample(t *testing.T) {
	ctx := context.Background()
	m, ss, bs := newDrainTestManager(t)
	ensurePipeContactAppV23(t, m, bs)
	peerID := newPeerOperatorID(t)
	agreement := configurePeerRBACConnection(t, m, ss, bs, "chain-peer", peerID, "host", nil, 4)

	// Status samples the lowest agent IDs first. Put the owner above every
	// sampled ID to prove that the owner-specific metadata load, rather than
	// incidental candidate ordering, makes legacy routing viable.
	owner := strings.Repeat("f", 64)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, owner, "out-of-sample-owner", "active", 0, 10)
	for i := 1; i <= maxPipeContactStatusCandidates; i++ {
		agentID := fmt.Sprintf("%064x", i)
		require.NoError(t, ss.CreateAgent(ctx, &store.AgentEntry{AgentID: agentID, Name: fmt.Sprintf("sample-%03d", i), Status: "active"}))
	}
	require.NoError(t, bs.RegisterDomain("research", owner, "", 10))
	_, err := m.ReplacePeerRBACPolicy(ctx, "chain-peer", []store.PeerRBACDomainPermission{{Domain: "research", Read: true}})
	require.NoError(t, err)
	_, err = m.SetFederatedAgentExport(ctx, "chain-peer", owner,
		store.FederatedAgentExportStateActive, 4, []string{"local-" + owner}, 0)
	require.NoError(t, err)

	status := statusForPeer(t, m, "chain-peer", peerID, agreement)
	require.NotNil(t, status.PipeContacts)
	var contact *PipeContact
	for i := range status.PipeContacts.Contacts {
		if status.PipeContacts.Contacts[i].AgentID == owner {
			contact = &status.PipeContacts.Contacts[i]
			break
		}
	}
	require.NotNil(t, contact, "effective owners remain visible beyond the status candidate sample")
	require.Equal(t, "out-of-sample-owner", contact.DisplayName)
	require.True(t, contact.Available)
	require.NotEmpty(t, contact.Address)
}

func TestPipeContactStatusSnapshotHasByteLimit(t *testing.T) {
	wide := strings.Repeat("domain-", 36) // 252 bytes, representative max-width names
	grant := &PipeContactGrant{Contacts: []PipeContact{{}, {}}}
	for i := range grant.Contacts {
		grant.Contacts[i].Domains = make([]PipeContactDomain, maxPipeContactStatusContacts)
		for j := range grant.Contacts[i].Domains {
			grant.Contacts[i].Domains[j] = PipeContactDomain{Domain: wide, OwningDomain: wide}
		}
	}
	require.False(t, fitsPipeContactStatusSnapshot(grant), "a status contact envelope must leave room below the federated response limit")
	bounded := boundedPipeContactStatusSnapshot(grant)
	require.NotNil(t, bounded)
	require.NotEmpty(t, bounded.Contacts)
	require.Less(t, len(bounded.Contacts), len(grant.Contacts))
	require.True(t, fitsPipeContactStatusSnapshot(bounded))
}

func TestPipeContactLookupCapsTargetMatchesAndResponseBytes(t *testing.T) {
	grant := &PipeContactGrant{Contacts: make([]PipeContact, 0, maxPipeContactLookupResults+1)}
	for i := 0; i < maxPipeContactLookupResults+1; i++ {
		grant.Contacts = append(grant.Contacts, PipeContact{
			AgentID: fmt.Sprintf("agent-%02d", i), DisplayName: "worker",
		})
	}
	filtered, total := filterPipeContactLookup(grant, PipeContactLookupRequest{Target: "worker", Limit: maxPipeContactLookupResults})
	require.Equal(t, maxPipeContactLookupResults+1, total)
	require.Len(t, filtered.Contacts, maxPipeContactLookupResults)
	for _, invalidLimit := range []int{0, -1, maxPipeContactLookupResults + 1} {
		filtered, total = filterPipeContactLookup(grant, PipeContactLookupRequest{Target: "worker", Limit: invalidLimit})
		require.Equal(t, maxPipeContactLookupResults+1, total)
		require.Len(t, filtered.Contacts, maxPipeContactLookupResults)
	}

	// Twenty matching contacts can still be too wide if each one has a large
	// but valid shared-domain basis. The handler must return a byte-bounded
	// subset and preserve that the result was truncated.
	wide := strings.Repeat("x", 512)
	wideGrant := &PipeContactGrant{Contacts: make([]PipeContact, 0, maxPipeContactLookupResults)}
	for i := 0; i < maxPipeContactLookupResults; i++ {
		contact := PipeContact{AgentID: fmt.Sprintf("wide-%02d", i), DisplayName: "wide-worker"}
		for j := 0; j < maxPipeContactStatusContacts; j++ {
			contact.Domains = append(contact.Domains, PipeContactDomain{Domain: wide, OwningDomain: wide})
		}
		wideGrant.Contacts = append(wideGrant.Contacts, contact)
	}
	response, err := boundedPipeContactLookupResponse(wideGrant, len(wideGrant.Contacts))
	require.NoError(t, err)
	require.NotEmpty(t, response.Grant.Contacts)
	require.Less(t, len(response.Grant.Contacts), len(wideGrant.Contacts))
	require.True(t, response.Truncated)
	encoded, err := json.Marshal(response)
	require.NoError(t, err)
	require.LessOrEqual(t, len(encoded), maxPipeContactLookupBytes)
}

func TestPipeContactExplicitExportDefaultsOnPauseUnexportAndOwnershipChange(t *testing.T) {
	ctx := context.Background()
	m, ss, bs := newDrainTestManager(t)
	ensurePipeContactAppV23(t, m, bs)
	peerID := newPeerOperatorID(t)
	agreement := configurePeerRBACConnection(t, m, ss, bs, "chain-peer", peerID, "host", nil, 4)
	owner := newPeerOperatorID(t)
	replacement := newPeerOperatorID(t)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, owner, "owner", "active", 0, 10)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, replacement, "replacement", "active", 0, 20)
	require.NoError(t, bs.RegisterDomain("research", owner, "", 10))
	_, err := m.ReplacePeerRBACPolicy(ctx, "chain-peer", []store.PeerRBACDomainPermission{{Domain: "research.work", Read: true}})
	require.NoError(t, err)
	exported, err := m.SetFederatedAgentExport(ctx, "chain-peer", owner,
		store.FederatedAgentExportStateActive, 4, []string{"local-" + owner}, 0)
	require.NoError(t, err)

	initial := statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.Len(t, initial.Contacts, 1)
	contact := initial.Contacts[0]
	require.True(t, contact.Accepting, "explicit export defaults inbound messaging on")

	_, err = m.SetPeerRBACPaused(ctx, "chain-peer", true)
	require.NoError(t, err)
	paused := statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.True(t, paused.Paused)
	require.True(t, paused.Contacts[0].Accepting, "peer pause suspends the lane without changing membership")
	require.Equal(t, contact.ContactID, paused.Contacts[0].ContactID)
	_, err = m.SetPeerRBACPaused(ctx, "chain-peer", false)
	require.NoError(t, err)
	resumed := statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.False(t, resumed.Paused)
	require.True(t, resumed.Contacts[0].Accepting)

	pausedExport, err := m.SetFederatedAgentExport(ctx, "chain-peer", owner,
		store.FederatedAgentExportStatePaused, 4, []string{"local-" + owner}, exported.Revision)
	require.NoError(t, err)
	require.Empty(t, statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts.Contacts)
	activeExport, err := m.SetFederatedAgentExport(ctx, "chain-peer", owner,
		store.FederatedAgentExportStateActive, 4, []string{"local-" + owner}, pausedExport.Revision)
	require.NoError(t, err)
	require.NoError(t, bs.TransferDomain("research", replacement, "", 11))
	transferred := statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.Empty(t, transferred.Contacts, "ownership transfer must not follow the old owner's export")
	replacementExport, err := m.SetFederatedAgentExport(ctx, "chain-peer", replacement,
		store.FederatedAgentExportStateActive, 4, []string{"local-" + replacement}, 0)
	require.NoError(t, err)
	transferred = statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.Len(t, transferred.Contacts, 1)
	require.Equal(t, replacement, transferred.Contacts[0].AgentID)
	require.True(t, transferred.Contacts[0].Accepting)
	_, err = m.SetFederatedAgentExport(ctx, "chain-peer", replacement,
		store.FederatedAgentExportStateRevoked, 4, []string{"local-" + replacement}, replacementExport.Revision)
	require.NoError(t, err)
	require.Empty(t, statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts.Contacts)
	require.Equal(t, int64(3), activeExport.Revision)
}

func TestPipeContactRevisionTracksOwnerAvailabilityAndPause(t *testing.T) {
	ctx := context.Background()
	m, ss, bs := newDrainTestManager(t)
	m.SetNetworkName("Owner Lab")
	ensurePipeContactAppV23(t, m, bs)
	peerID := newPeerOperatorID(t)
	agreement := configurePeerRBACConnection(t, m, ss, bs, "chain-peer", peerID, "host", nil, 4)

	ownerA := newPeerOperatorID(t)
	ownerB := newPeerOperatorID(t)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, ownerA, "owner-a", "active", 0, 10)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, ownerB, "owner-b", "active", 0, 20)
	require.NoError(t, bs.RegisterDomain("research", ownerA, "", 10))
	_, err := m.ReplacePeerRBACPolicy(ctx, "chain-peer", []store.PeerRBACDomainPermission{{Domain: "research.child", Read: true}})
	require.NoError(t, err)
	_, err = m.SetFederatedAgentExport(ctx, "chain-peer", ownerA,
		store.FederatedAgentExportStateActive, 4, []string{"local-" + ownerA}, 0)
	require.NoError(t, err)

	first := statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.Len(t, first.Contacts, 1)
	require.Equal(t, ownerA, first.Contacts[0].AgentID)

	m.SetNetworkName("Renamed Owner Lab")
	networkRenamed := statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.NotEqual(t, first.Contacts[0].Handle, networkRenamed.Contacts[0].Handle)
	require.Equal(t, first.Revision, networkRenamed.Revision, "a cosmetic network rename is not an authorization change")
	agent, err := ss.GetAgent(ctx, ownerA)
	require.NoError(t, err)
	agent.Name = "renamed-owner-a"
	require.NoError(t, ss.UpdateAgent(ctx, agent))
	agentRenamed := statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.Equal(t, "renamed-owner-a", agentRenamed.Contacts[0].DisplayName)
	require.Equal(t, first.Revision, agentRenamed.Revision, "a cosmetic agent rename is not an authorization change")

	require.NoError(t, bs.TransferDomain("research", ownerB, "", 11))
	transferred := statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.Empty(t, transferred.Contacts, "ownership transfer does not implicitly export the replacement")
	_, err = m.SetFederatedAgentExport(ctx, "chain-peer", ownerB,
		store.FederatedAgentExportStateActive, 4, []string{"local-" + ownerB}, 0)
	require.NoError(t, err)
	transferred = statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.Len(t, transferred.Contacts, 1)
	require.Equal(t, ownerB, transferred.Contacts[0].AgentID)
	require.NotEqual(t, first.Revision, transferred.Revision)
	require.True(t, transferred.Contacts[0].Accepting,
		"the new owner is visible only after its own explicit export, which defaults messaging on")

	require.NoError(t, ss.UpdateAgentStatus(ctx, ownerB, "inactive"))
	inactive := statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.False(t, inactive.Contacts[0].Available)
	require.NotEqual(t, transferred.Revision, inactive.Revision)

	_, err = m.SetPeerRBACPaused(ctx, "chain-peer", true)
	require.NoError(t, err)
	paused := statusForPeer(t, m, "chain-peer", peerID, agreement).PipeContacts
	require.True(t, paused.Paused)
	require.NotEqual(t, inactive.Revision, paused.Revision)
}

func TestPipeContactAuthorizationRevisionIgnoresUnrelatedReversibleState(t *testing.T) {
	ctx := context.Background()
	m, ss, bs := newDrainTestManager(t)
	peerID := newPeerOperatorID(t)
	configurePeerRBACConnection(t, m, ss, bs, "chain-peer", peerID, "host", nil, 4)
	ownerX, ownerY := newPeerOperatorID(t), newPeerOperatorID(t)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, ownerX, ownerX[:8], "active", 0, 10)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, ownerY, ownerY[:8], "active", 0, 20)
	require.NoError(t, bs.RegisterDomain("exact-x", ownerX, "", 10))
	require.NoError(t, bs.RegisterDomain("unrelated-y", ownerY, "", 11))
	_, err := m.ReplacePeerRBACPolicy(ctx, "chain-peer", []store.PeerRBACDomainPermission{
		{Domain: "exact-x.work", Read: true},
		{Domain: "unrelated-y.work", Read: true},
	})
	require.NoError(t, err)
	_, err = m.SetFederatedAgentExport(ctx, "chain-peer", ownerX,
		store.FederatedAgentExportStateActive, 4, []string{"local-" + ownerX}, 0)
	require.NoError(t, err)
	_, err = m.SetFederatedAgentExport(ctx, "chain-peer", ownerY,
		store.FederatedAgentExportStateActive, 4, []string{"local-" + ownerY}, 0)
	require.NoError(t, err)

	find := func(t *testing.T, grant *PipeContactGrant, agentID string) PipeContact {
		t.Helper()
		for _, contact := range grant.Contacts {
			if contact.AgentID == agentID {
				return contact
			}
		}
		t.Fatalf("contact %s not found", agentID)
		return PipeContact{}
	}
	grant, err := m.LocalPipeContacts(ctx, "chain-peer")
	require.NoError(t, err)
	baseline := grant
	xBaseline, yBaseline := find(t, baseline, ownerX), find(t, baseline, ownerY)
	xRevision := pipeContactAuthorizationRevision(baseline, &xBaseline)
	yRevision := pipeContactAuthorizationRevision(baseline, &yBaseline)

	require.NoError(t, ss.UpdateAgentStatus(ctx, ownerY, "inactive"))
	yOff, err := m.LocalPipeContacts(ctx, "chain-peer")
	require.NoError(t, err)
	xAfterYOff, yAfterOff := find(t, yOff, ownerX), find(t, yOff, ownerY)
	require.NotEqual(t, baseline.Revision, yOff.Revision, "aggregate cache revision must see Y's state")
	require.Equal(t, xRevision, pipeContactAuthorizationRevision(yOff, &xAfterYOff), "Y must not invalidate exact X work")
	require.NotEqual(t, yRevision, pipeContactAuthorizationRevision(yOff, &yAfterOff))

	require.NoError(t, ss.UpdateAgentStatus(ctx, ownerY, "active"))
	restored, err := m.LocalPipeContacts(ctx, "chain-peer")
	require.NoError(t, err)
	xRestored, yRestored := find(t, restored, ownerX), find(t, restored, ownerY)
	require.Equal(t, xRevision, pipeContactAuthorizationRevision(restored, &xRestored))
	require.Equal(t, yRevision, pipeContactAuthorizationRevision(restored, &yRestored))

	require.NoError(t, ss.UpdateAgentStatus(ctx, ownerY, "inactive"))
	yInactive, err := m.LocalPipeContacts(ctx, "chain-peer")
	require.NoError(t, err)
	xWhileYInactive, yWhileInactive := find(t, yInactive, ownerX), find(t, yInactive, ownerY)
	require.Equal(t, xRevision, pipeContactAuthorizationRevision(yInactive, &xWhileYInactive), "Y availability must not invalidate X")
	require.NotEqual(t, yRevision, pipeContactAuthorizationRevision(yInactive, &yWhileInactive))

	_, err = m.SetPeerRBACPaused(ctx, "chain-peer", true)
	require.NoError(t, err)
	paused, err := m.LocalPipeContacts(ctx, "chain-peer")
	require.NoError(t, err)
	xPaused := find(t, paused, ownerX)
	require.NotEqual(t, xRevision, pipeContactAuthorizationRevision(paused, &xPaused))
	_, err = m.SetPeerRBACPaused(ctx, "chain-peer", false)
	require.NoError(t, err)
	require.NoError(t, ss.UpdateAgentStatus(ctx, ownerY, "active"))
	resumed, err := m.LocalPipeContacts(ctx, "chain-peer")
	require.NoError(t, err)
	xResumed := find(t, resumed, ownerX)
	require.Equal(t, xRevision, pipeContactAuthorizationRevision(resumed, &xResumed), "Resume must restore unchanged X work")
}

func TestStatusReleasesContactSnapshotBeforePeerSocketWrite(t *testing.T) {
	ctx := context.Background()
	m, ss, bs := newDrainTestManager(t)
	ensurePipeContactAppV23(t, m, bs)
	peerID := newPeerOperatorID(t)
	agreement := configurePeerRBACConnection(t, m, ss, bs, "chain-peer", peerID, "host", nil, 4)
	owner := newPeerOperatorID(t)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, owner, "owner", "active", 0, 10)
	require.NoError(t, bs.RegisterDomain("research", owner, "", 10))
	_, err := m.ReplacePeerRBACPolicy(ctx, "chain-peer", []store.PeerRBACDomainPermission{{Domain: "research.work", Read: true}})
	require.NoError(t, err)
	_, err = m.SetFederatedAgentExport(ctx, "chain-peer", owner,
		store.FederatedAgentExportStateActive, 4, []string{"local-" + owner}, 0)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/fed/v1/status", nil)
	req = req.WithContext(context.WithValue(req.Context(), peerCtxKey{}, &peerIdentity{
		ChainID: "chain-peer", AgentID: peerID, Agreement: agreement,
	}))
	w := &blockingStatusWriter{header: make(http.Header), started: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		m.handleStatus(w, req)
		close(done)
	}()
	<-w.started

	updated := make(chan error, 1)
	go func() { updated <- ss.UpdateAgentStatus(ctx, owner, "inactive") }()
	select {
	case err := <-updated:
		require.NoError(t, err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("a slow status response retained the contact snapshot lease")
	}
	close(w.release)
	<-done
}

func TestPipeContactLookupReleasesSnapshotBeforePeerSocketWrite(t *testing.T) {
	ctx := context.Background()
	m, ss, bs := newDrainTestManager(t)
	ensurePipeContactAppV23(t, m, bs)
	peerID := newPeerOperatorID(t)
	agreement := configurePeerRBACConnection(t, m, ss, bs, "chain-peer", peerID, "host", nil, 4)
	owner := newPeerOperatorID(t)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, owner, "owner", "active", 0, 10)
	require.NoError(t, bs.RegisterDomain("research", owner, "", 10))
	_, err := m.ReplacePeerRBACPolicy(ctx, "chain-peer", []store.PeerRBACDomainPermission{{Domain: "research.work", Read: true}})
	require.NoError(t, err)
	_, err = m.SetFederatedAgentExport(ctx, "chain-peer", owner,
		store.FederatedAgentExportStateActive, 4, []string{"local-" + owner}, 0)
	require.NoError(t, err)

	body, err := json.Marshal(PipeContactLookupRequest{Name: "owner", Limit: 1})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/fed/v1/pipe/contacts/lookup", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), peerCtxKey{}, &peerIdentity{
		ChainID: "chain-peer", AgentID: peerID, Agreement: agreement,
	}))
	w := &blockingStatusWriter{header: make(http.Header), started: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		m.handlePipeContactLookup(w, req)
		close(done)
	}()
	<-w.started

	updated := make(chan error, 1)
	go func() { updated <- ss.UpdateAgentStatus(ctx, owner, "inactive") }()
	select {
	case err := <-updated:
		require.NoError(t, err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("a slow lookup response retained the contact snapshot lease")
	}
	close(w.release)
	<-done
}

func TestUniqueAgentPrefixesLengthenCollisions(t *testing.T) {
	a := "aaaaaaaa0" + strings.Repeat("0", 55)
	b := "aaaaaaaa1" + strings.Repeat("0", 55)
	require.Len(t, a, 64)
	require.Len(t, b, 64)
	prefixes := uniqueAgentPrefixes([]string{a, b})
	require.Equal(t, 12, len(prefixes[a]))
	require.Equal(t, 12, len(prefixes[b]))
	require.NotEqual(t, prefixes[a], prefixes[b])
	require.Empty(t, uniqueAgentPrefixes([]string{"legacy-agent"})["legacy-agent"])
}

func statusForPeer(t *testing.T, m *Manager, chainID, peerAgentID string, agreement *store.CrossFedRecord) StatusResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/fed/v1/status", nil)
	req = req.WithContext(context.WithValue(req.Context(), peerCtxKey{}, &peerIdentity{
		ChainID: chainID, AgentID: peerAgentID, Agreement: agreement,
	}))
	rec := httptest.NewRecorder()
	m.handleStatus(rec, req)
	require.Equal(t, 200, rec.Code, rec.Body.String())
	var status StatusResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&status))
	return status
}
