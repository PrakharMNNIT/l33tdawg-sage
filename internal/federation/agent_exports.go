package federation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/l33tdawg/sage/internal/store"
)

func (m *Manager) effectiveAgentExportDomainPermissions(
	ctx context.Context, peer *peerIdentity, policy *store.PeerRBACPolicy,
) ([]store.PeerRBACDomainPermission, error) {
	if peer == nil || policy == nil || m.badger == nil {
		return nil, nil
	}
	ss := m.syncStore()
	if ss == nil {
		return nil, errors.New("agent exports require the SQLite store backend")
	}
	exports, err := ss.ListActiveFederatedAgentExports(ctx, peer.ChainID)
	if err != nil {
		return nil, err
	}
	byOwner := make(map[string]store.FederatedAgentExport, len(exports))
	for _, export := range exports {
		if export.PeerAgentID != policy.PeerAgentID || export.PolicyEpoch != policy.PolicyEpoch ||
			export.RemoteCAPin != policy.RemoteCAPin {
			continue
		}
		eligible, eligibilityErr := m.localFederatedGuestAgentEligible(export.LocalAgentID)
		if eligibilityErr != nil {
			return nil, eligibilityErr
		}
		if eligible {
			byOwner[strings.ToLower(export.LocalAgentID)] = export
		}
	}
	domains, err := m.badger.ListRegisteredDomains()
	if err != nil {
		return nil, err
	}
	out := make([]store.PeerRBACDomainPermission, 0)
	seen := make(map[string]struct{})
	for _, domain := range domains {
		export, ok := byOwner[strings.ToLower(domain.OwnerAgentID)]
		if !ok || domain.DomainName == "" {
			continue
		}
		shared, sharedErr := m.badger.IsAppV23SharedDomain(domain.DomainName)
		if sharedErr != nil {
			return nil, sharedErr
		}
		if shared {
			continue
		}
		excluded := false
		for _, denied := range export.DomainExclusions {
			if DomainAllowed([]string{denied}, domain.DomainName) ||
				DomainAllowed([]string{domain.DomainName}, denied) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		if _, duplicate := seen[domain.DomainName]; duplicate {
			continue
		}
		seen[domain.DomainName] = struct{}{}
		out = append(out, store.PeerRBACDomainPermission{Domain: domain.DomainName, Read: true})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, nil
}

func mergePeerRBACReadDomains(
	base, derived []store.PeerRBACDomainPermission,
) []store.PeerRBACDomainPermission {
	byDomain := make(map[string]store.PeerRBACDomainPermission, len(base)+len(derived))
	for _, permission := range append(append([]store.PeerRBACDomainPermission(nil), base...), derived...) {
		current := byDomain[permission.Domain]
		current.Domain = permission.Domain
		current.Read = current.Read || permission.Read || permission.Copy
		current.Copy = current.Copy || permission.Copy
		current.Write = false
		byDomain[current.Domain] = current
	}
	out := make([]store.PeerRBACDomainPermission, 0, len(byDomain))
	for _, permission := range byDomain {
		out = append(out, permission)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// ListFederatedAgentExports returns the current connection generation's
// explicit local-agent exports. Historical rows from a retired generation are
// intentionally not projected into the live operator surface.
func (m *Manager) ListFederatedAgentExports(ctx context.Context, remoteChainID string) ([]store.FederatedAgentExport, error) {
	policy, err := m.GetPeerRBACPolicy(ctx, remoteChainID)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, errors.New("agent exports require an active peer policy binding")
	}
	ss := m.syncStore()
	if ss == nil {
		return nil, errors.New("agent exports require the SQLite store backend")
	}
	exports, err := ss.ListFederatedAgentExports(ctx, remoteChainID)
	if err != nil {
		return nil, err
	}
	live := make([]store.FederatedAgentExport, 0, len(exports))
	for _, export := range exports {
		if export.PeerAgentID == policy.PeerAgentID && export.PolicyEpoch == policy.PolicyEpoch &&
			export.RemoteCAPin == policy.RemoteCAPin {
			live = append(live, export)
		}
	}
	return live, nil
}

// SetFederatedAgentExport creates, pauses, or resumes one explicit local-agent
// export. The caller supplies only mutable intent; the current JOIN generation
// is always derived from the live peer policy and frozen by the store CAS.
func (m *Manager) SetFederatedAgentExport(
	ctx context.Context,
	remoteChainID, localAgentID, state string,
	maxClassification uint8,
	domainExclusions []string,
	expectedRevision int64,
) (*store.FederatedAgentExport, error) {
	if !isCanonicalAgentID(localAgentID) {
		return nil, errors.New("a canonical local agent id is required")
	}
	localAgentID = strings.ToLower(localAgentID)
	if state == store.FederatedAgentExportStateActive {
		eligible, err := m.localFederatedGuestAgentEligible(localAgentID)
		if err != nil || !eligible {
			return nil, errors.New("only an active ordinary local agent may be exported")
		}
	}
	policy, err := m.GetPeerRBACPolicy(ctx, remoteChainID)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, errors.New("agent exports require an active peer policy binding")
	}
	ss := m.syncStore()
	if ss == nil {
		return nil, errors.New("agent exports require the SQLite store backend")
	}
	releaseDelivery := m.beginPeerLinkedAuthorizationMutation(remoteChainID)
	defer releaseDelivery()
	return ss.PutBoundFederatedAgentExportCAS(ctx, store.FederatedAgentExport{
		RemoteChainID:     remoteChainID,
		LocalAgentID:      localAgentID,
		PeerAgentID:       policy.PeerAgentID,
		PolicyEpoch:       policy.PolicyEpoch,
		RemoteCAPin:       policy.RemoteCAPin,
		MaxClassification: maxClassification,
		DomainExclusions:  domainExclusions,
		Revision:          expectedRevision + 1,
		State:             state,
	}, expectedRevision)
}

// peerAgentExportCeiling resolves the requested domain's live owner and checks
// whether that exact active ordinary local agent is explicitly exported to the
// authenticated peer. Ownership and standing are re-evaluated on every plan,
// query and record filter; stale membership never follows a transferred domain.
func (m *Manager) peerAgentExportCeiling(
	ctx context.Context,
	peer *peerIdentity,
	policy *store.PeerRBACPolicy,
	domain string,
) (uint8, bool, error) {
	if peer == nil || policy == nil || m.badger == nil || domain == "" {
		return 0, false, nil
	}
	owner, owningDomain, err := m.badger.ResolveAppV23OwningAncestor(domain)
	if err != nil {
		return 0, false, err
	}
	if owner == "" || owningDomain == "" || !isCanonicalAgentID(owner) {
		return 0, false, nil
	}
	owner = strings.ToLower(owner)
	shared, err := m.badger.IsAppV23SharedDomain(owningDomain)
	if err != nil || shared {
		return 0, false, err
	}
	ss := m.syncStore()
	if ss == nil {
		return 0, false, errors.New("agent exports require the SQLite store backend")
	}
	export, err := ss.GetFederatedAgentExport(ctx, peer.ChainID, owner)
	if err != nil || export == nil {
		return 0, false, err
	}
	if export.State != store.FederatedAgentExportStateActive ||
		export.PeerAgentID != policy.PeerAgentID ||
		export.PolicyEpoch != policy.PolicyEpoch ||
		export.RemoteCAPin != policy.RemoteCAPin {
		return 0, false, nil
	}
	eligible, err := m.localFederatedGuestAgentEligible(owner)
	if err != nil || !eligible {
		return 0, false, err
	}
	for _, excluded := range export.DomainExclusions {
		// An ancestor query can return a denied child, so either-direction
		// overlap is denied. Sibling subtrees remain independent.
		if DomainAllowed([]string{excluded}, domain) || DomainAllowed([]string{domain}, excluded) {
			return 0, false, nil
		}
	}
	return export.MaxClassification, true, nil
}

func (m *Manager) peerDomainExportCeiling(
	ctx context.Context,
	peer *peerIdentity,
	agreement *store.CrossFedRecord,
	domain string,
) (uint8, error) {
	policy, err := m.getPeerRBACPolicyForAgreement(ctx, agreement)
	if err != nil {
		return 0, err
	}
	if policy == nil || policy.Paused {
		return 0, errors.New("peer Read export is inactive")
	}
	if peerRBACAllowsRead(policy, domain) {
		return uint8(store.ClearanceTopSecret), nil
	}
	ceiling, allowed, err := m.peerAgentExportCeiling(ctx, peer, policy, domain)
	if err != nil {
		return 0, err
	}
	if !allowed {
		return 0, fmt.Errorf("domain %q is not exported to this peer", domain)
	}
	return ceiling, nil
}
