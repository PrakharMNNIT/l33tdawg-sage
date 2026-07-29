const CANONICAL_AGENT_ID = /^[a-f0-9]{64}$/;

export function appV23MessagePairKey(remoteChainID, remoteAgentID, localAgentID) {
    return `${remoteChainID}\u0000${remoteAgentID}\u0000${localAgentID}`;
}

function canonicalMessagePrincipal(remoteChainID, remoteAgentID, localAgentID) {
    return typeof remoteChainID === 'string' &&
        remoteChainID.length > 0 &&
        remoteChainID.length <= 50 &&
        CANONICAL_AGENT_ID.test(remoteAgentID || '') &&
        CANONICAL_AGENT_ID.test(localAgentID || '');
}

// Build only exact, currently proven receiver-local messaging pairs.
// Generic directory/read-link candidates never enter this projection.
export function appV23BuildMessageCandidates({
    selectedLinkedRemote,
    linkedLinks = [],
    groups = [],
    localAgentID,
    peerHostedOffers = [],
}) {
    const candidates = new Map();
    const localID = String(localAgentID || '');
    const remoteChainID = String(selectedLinkedRemote?.remote_chain_id || '');
    const remoteAgentID = String(selectedLinkedRemote?.remote_agent_id || '');

    if (canonicalMessagePrincipal(remoteChainID, remoteAgentID, localID)) {
        const groupIDs = linkedLinks
            .filter(link => {
                const guest = link?.guest || {};
                if (link?.effective_state !== 'active' || link?.binding_current !== true ||
                    guest.state !== 'active' ||
                    guest.remote_chain_id !== remoteChainID ||
                    guest.remote_agent_id !== remoteAgentID) return false;
                const group = groups.find(item => item?.group_id === guest.group_id);
                return Array.isArray(group?.members) && group.members.includes(localID);
            })
            .map(link => link.guest.group_id)
            .sort();
        if (groupIDs.length) {
            const key = appV23MessagePairKey(remoteChainID, remoteAgentID, localID);
            candidates.set(key, {
                key,
                remote_chain_id: remoteChainID,
                remote_agent_id: remoteAgentID,
                local_agent_id: localID,
                label: selectedLinkedRemote.label || `Linked agent ${remoteAgentID.slice(0, 8)}`,
                peer_name: selectedLinkedRemote.peer_name || remoteChainID,
                group_ids: groupIDs,
                authorization_source: 'local_hosted_link',
            });
        }
    }

    for (const offer of peerHostedOffers) {
        const offerChainID = String(offer?.remote_chain_id || '');
        const offerRemoteID = String(offer?.remote_agent_id || '');
        const offerLocalID = String(offer?.local_agent_id || '');
        if (offerLocalID !== localID ||
            !canonicalMessagePrincipal(offerChainID, offerRemoteID, offerLocalID) ||
            !Array.isArray(offer.group_ids) || offer.group_ids.length === 0) continue;
        const key = appV23MessagePairKey(offerChainID, offerRemoteID, offerLocalID);
        if (!candidates.has(key)) {
            candidates.set(key, {
                ...offer,
                key,
                remote_chain_id: offerChainID,
                remote_agent_id: offerRemoteID,
                local_agent_id: offerLocalID,
                group_ids: [...offer.group_ids].sort(),
                label: offer.label || `Linked member ${offerRemoteID.slice(0, 8)}`,
                peer_name: offer.peer_name || offerChainID,
                authorization_source: 'peer_hosted_offer',
            });
        }
    }

    return Array.from(candidates.values()).sort((a, b) =>
        `${a.peer_name}/${a.label}/${a.remote_agent_id}`
            .localeCompare(`${b.peer_name}/${b.label}/${b.remote_agent_id}`));
}

export function appV23MessagePairIsProven(candidate, localAgentID) {
    if (!candidate || candidate.local_agent_id !== localAgentID) return false;
    if (!canonicalMessagePrincipal(
        candidate.remote_chain_id,
        candidate.remote_agent_id,
        candidate.local_agent_id,
    )) return false;
    return candidate.authorization_source === 'local_hosted_link' ||
        candidate.authorization_source === 'peer_hosted_offer';
}
