package federation

import (
	"context"
	"errors"
	"strings"

	"github.com/l33tdawg/sage/internal/store"
)

func readerBindingFromPolicy(policy *store.PeerRBACPolicy) store.FederatedReaderBinding {
	if policy == nil {
		return store.FederatedReaderBinding{}
	}
	return store.FederatedReaderBinding{
		RemoteChainID: policy.RemoteChainID,
		PeerAgentID:   policy.PeerAgentID,
		PolicyEpoch:   policy.PolicyEpoch,
		RemoteCAPin:   policy.RemoteCAPin,
	}
}

func (m *Manager) ListFederatedReaderRestrictions(
	ctx context.Context, remoteChainID string,
) ([]store.FederatedReaderRestriction, error) {
	if _, err := m.GetPeerRBACPolicy(ctx, remoteChainID); err != nil {
		return nil, err
	}
	ss := m.syncStore()
	if ss == nil {
		return nil, errors.New("federated reader restrictions require SQLite")
	}
	return ss.ListFederatedReaderRestrictions(ctx, remoteChainID)
}

func (m *Manager) SetFederatedReaderRestriction(
	ctx context.Context,
	remoteChainID, localAgentID, state string,
	denyAll bool,
	deniedDomains []string,
	expectedRevision int64,
) (*store.FederatedReaderRestriction, error) {
	if !isCanonicalAgentID(localAgentID) {
		return nil, errors.New("a canonical local agent id is required")
	}
	localAgentID = strings.ToLower(localAgentID)
	eligible, err := m.localFederatedGuestAgentEligible(localAgentID)
	if err != nil || !eligible {
		return nil, errors.New("reader restrictions require an active ordinary local agent")
	}
	policy, err := m.GetPeerRBACPolicy(ctx, remoteChainID)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, errors.New("reader restrictions require an active peer binding")
	}
	ss := m.syncStore()
	if ss == nil {
		return nil, errors.New("federated reader restrictions require SQLite")
	}
	releaseDelivery := m.beginPeerLinkedAuthorizationMutation(remoteChainID)
	defer releaseDelivery()
	restriction, err := ss.PutBoundFederatedReaderRestrictionCAS(ctx, store.FederatedReaderRestriction{
		RemoteChainID: remoteChainID,
		LocalAgentID:  localAgentID,
		PeerAgentID:   policy.PeerAgentID,
		PolicyEpoch:   policy.PolicyEpoch,
		RemoteCAPin:   policy.RemoteCAPin,
		DenyAll:       denyAll,
		DeniedDomains: deniedDomains,
		Revision:      expectedRevision + 1,
		State:         state,
	}, expectedRevision)
	if err != nil {
		return nil, err
	}
	m.federatedReaderPolicyRevision.Add(1)
	return restriction, nil
}

// FederatedReaderPolicyRevision is a process-local cache coherency epoch. It
// changes only after a reader restriction mutation commits successfully.
func (m *Manager) FederatedReaderPolicyRevision() uint64 {
	return m.federatedReaderPolicyRevision.Load()
}

func (m *Manager) federatedReaderAllowsLocked(
	ctx context.Context,
	agreement *store.CrossFedRecord,
	localAgentID, domain string,
) (bool, error) {
	ss := m.syncStore()
	if ss == nil {
		return false, errors.New("federated reader restrictions require SQLite")
	}
	policy, err := m.getPeerRBACPolicyForAgreement(ctx, agreement)
	if err != nil || policy == nil {
		return false, err
	}
	return ss.FederatedReaderAllowsLocked(
		ctx, readerBindingFromPolicy(policy), strings.ToLower(localAgentID), domain,
	)
}

func (m *Manager) FederatedReaderAllows(
	ctx context.Context, remoteChainID, localAgentID, domain string,
) (bool, error) {
	agreement, err := m.ActiveAgreement(remoteChainID)
	if err != nil {
		return false, err
	}
	ss := m.syncStore()
	if ss == nil {
		return false, errors.New("federated reader restrictions require SQLite")
	}
	unlock := ss.LockSyncPolicyRead()
	defer unlock()
	return m.federatedReaderAllowsLocked(ctx, agreement, localAgentID, domain)
}
