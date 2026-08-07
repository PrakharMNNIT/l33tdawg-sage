const FEDERATED_AGENT_CAPABILITIES = Object.freeze({
    peerExportRead: 'federated-peer-export-read-v1',
    queryAvailability: 'federated-query-availability-v1',
    pipeline: 'federated-pipeline-v1',
    linkedDirectory: 'linked-message-directory-enumeration-v1',
});

// Interpret only the authenticated live peer-status projection. Capability
// advertisement is compatibility metadata, not proof of authorization,
// presence, or delivery. An offline/unchecked peer therefore has no observed
// compatibility state and must not be mislabeled as an old peer.
export function federationPeerAgentCompatibility(status) {
    if (!status || status.reachable !== true) {
        return {
            observed: false,
            exportedRead: false,
            agentMessaging: false,
            linkedDirectory: false,
            fullySupported: false,
            missing: [],
        };
    }

    const capabilities = new Set(
        (Array.isArray(status.capabilities) ? status.capabilities : [])
            .filter(capability => typeof capability === 'string'),
    );
    const exportedRead = capabilities.has(FEDERATED_AGENT_CAPABILITIES.peerExportRead)
        && capabilities.has(FEDERATED_AGENT_CAPABILITIES.queryAvailability);
    const agentMessaging = capabilities.has(FEDERATED_AGENT_CAPABILITIES.pipeline);
    const linkedDirectory = capabilities.has(FEDERATED_AGENT_CAPABILITIES.linkedDirectory);
    const missing = [];
    if (!exportedRead) missing.push('default cross-SAGE reading');
    if (!agentMessaging) missing.push('agent messaging');
    if (!linkedDirectory) missing.push('federated recipient discovery');

    return {
        observed: true,
        exportedRead,
        agentMessaging,
        linkedDirectory,
        fullySupported: missing.length === 0,
        missing,
    };
}
