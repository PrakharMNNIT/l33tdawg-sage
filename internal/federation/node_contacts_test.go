package federation

import (
	"context"
	"testing"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/stretchr/testify/require"
)

func TestNodeContactsRequireNoMemoryExportAndPreserveRestrictions(t *testing.T) {
	ctx := context.Background()
	m, ss, bs := newDrainTestManager(t)
	ensurePipeContactAppV23(t, m, bs)
	peerID := newPeerOperatorID(t)
	agreement := configurePeerRBACConnection(t, m, ss, bs, "chain-peer", peerID, "host", nil, 4)
	active, denied, inactive := newPeerOperatorID(t), newPeerOperatorID(t), newPeerOperatorID(t)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, active, "codex/visible", "active", 0, 10)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, denied, "codex/blocked", "active", store.AgentCapabilityDenyFederatedPipe, 20)
	seedPipeContactOrdinaryAgent(t, m, ss, bs, inactive, "codex/retired", "inactive", 0, 30)
	policy, err := m.getPeerRBACPolicyForAgreement(ctx, agreement)
	require.NoError(t, err)
	peer := &peerIdentity{ChainID: "chain-peer", AgentID: peerID, Agreement: agreement}
	grant, err := m.buildNodeContactPage(ctx, peer, policy, "", 128)
	require.NoError(t, err)
	require.Len(t, grant.Contacts, 2)
	byID := map[string]PipeContact{}
	for _, contact := range grant.Contacts {
		byID[contact.AgentID] = contact
		require.Empty(t, contact.Domains)
		require.Equal(t, NodeMessageAuthorizationMode, contact.AuthorizationMode)
	}
	require.True(t, byID[active].Accepting)
	require.False(t, byID[denied].Accepting)
	require.NotContains(t, byID, inactive)
	root, err := bs.GetAppV23Root()
	require.NoError(t, err)
	require.NotContains(t, byID, root.CredentialID)
	legacy := statusForPeer(t, m, "chain-peer", peerID, agreement)
	require.Empty(t, legacy.PipeContacts.Contacts, "unnegotiated legacy clients retain explicit-export behavior")
	require.Empty(t, legacy.PeerRBACGrant.Domains, "connecting and discovering agents cannot grant memory access")
	before := byID[active].ContactID
	policy.Revision++
	policy.Domains = []store.PeerRBACDomainPermission{{Domain: "unrelated", Read: true}}
	updated, err := m.buildNodeContactPage(ctx, peer, policy, "", 128)
	require.NoError(t, err)
	for _, contact := range updated.Contacts {
		if contact.AgentID == active {
			require.Equal(t, before, contact.ContactID, "memory permissions must not invalidate messages")
		}
	}
	forged := *grant
	forged.Contacts = append([]PipeContact(nil), grant.Contacts...)
	forged.Contacts[0].Domains = []PipeContactDomain{{Domain: "private"}}
	require.Error(t, ValidateRemotePipeContactGrant(m.localChainID, &forged))
}

func TestNodeContactPagesEnumerateEveryEligibleAgent(t *testing.T) {
	ctx := context.Background()
	m, ss, bs := newDrainTestManager(t)
	ensurePipeContactAppV23(t, m, bs)
	peerID := newPeerOperatorID(t)
	agreement := configurePeerRBACConnection(t, m, ss, bs, "chain-peer", peerID, "host", nil, 4)
	for i := range 7 {
		seedPipeContactOrdinaryAgent(t, m, ss, bs, newPeerOperatorID(t), "agent", "active", 0, int64(10+i*2))
	}
	policy, err := m.getPeerRBACPolicyForAgreement(ctx, agreement)
	require.NoError(t, err)
	peer := &peerIdentity{ChainID: "chain-peer", AgentID: peerID, Agreement: agreement}
	seen, after := map[string]bool{}, ""
	for page := 0; ; page++ {
		require.Less(t, page, 5, "cursor must progress")
		grant, err := m.buildNodeContactPage(ctx, peer, policy, after, 2)
		require.NoError(t, err)
		require.LessOrEqual(t, len(grant.Contacts), 2)
		for _, contact := range grant.Contacts {
			require.False(t, seen[contact.AgentID])
			seen[contact.AgentID] = true
		}
		if grant.NextCursor == "" {
			break
		}
		require.NotEqual(t, grant.NextCursor, after)
		position, err := m.openNodeCursor(peer, policy, grant.NextCursor)
		require.NoError(t, err)
		require.True(t, isCanonicalAgentID(position))
		wrongPeer := *peer
		wrongPeer.AgentID = newPeerOperatorID(t)
		_, err = m.openNodeCursor(&wrongPeer, policy, grant.NextCursor)
		require.ErrorIs(t, err, errNodeContactCursor)
		after = grant.NextCursor
	}
	require.Len(t, seen, 7)
}

func TestNodeMessagingPreservesAlreadyQueuedLegacyAuthorization(t *testing.T) {
	ctx := context.Background()
	source, destination := newTestChain(t, "upgrade-source"), newTestChain(t, "upgrade-destination")
	sourceServer, destinationServer := startRestartablePipeServer(t, source, ""), startRestartablePipeServer(t, destination, "")
	defer func() { sourceServer.stop(t); destinationServer.stop(t) }()
	federate(t, source, destination, "https://"+destinationServer.address, nil, 4, 0)
	federate(t, destination, source, "https://"+sourceServer.address, nil, 4, 0)
	activatePipePeer(t, source, destination, "host")
	activatePipePeer(t, destination, source, "guest")
	fixture := configurePipeFaultFixture(t, source, destination)
	exportPipeContactAgent(t, destination.mgr, source.chainID, fixture.targetAgent)
	legacy, err := source.mgr.resolveRemotePipeTarget(ctx, fixture.target.Address, false, "")
	require.NoError(t, err)
	require.Empty(t, legacy.AuthorizationMode)
	require.NotEmpty(t, legacy.Domains)
	fixture.target = legacy
	_, outbox := enqueueFaultGateSend(t, source, destination, fixture)
	event, terminal, err := source.mgr.buildPipelineEvent(ctx, pipeSQLite(t, source), outbox)
	require.NoError(t, err)
	require.False(t, terminal)
	require.Empty(t, event.AuthorizationMode, "an upgrade must not reinterpret the authority of a queued message")
	accepted, err := source.mgr.PushPipeEvent(ctx, destination.chainID, event)
	require.NoError(t, err)
	require.Equal(t, "accepted", accepted.Status)
}
