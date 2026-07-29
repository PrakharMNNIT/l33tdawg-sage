// Canonical app-v23 policy transitions. Named roles and profiles are security
// presets, not labels layered over hidden capability bits: choosing one must
// produce its complete safe policy instead of retaining privileges from the
// previous selection.

export const APPV23_PROFILE_LEGACY_RESTRICTED = 'legacy_restricted';
export const APPV23_SELECTABLE_PROFILES = Object.freeze([
    'standard',
    'companion',
    'read_only',
]);

export function appV23ProfileIsSelectable(profile) {
    return APPV23_SELECTABLE_PROFILES.includes(profile);
}

export function appV23ProfileNeedsReview(agent) {
    return agent?.profile === APPV23_PROFILE_LEGACY_RESTRICTED;
}

export function appV23PolicyDraft(agent) {
    const profile = agent.profile || 'standard';
    if (profile === APPV23_PROFILE_LEGACY_RESTRICTED) {
        const recordedCapabilities = Number(agent.capabilities ?? 0);
        return {
            role: 'member',
            profile,
            clearance: Math.max(0, Math.min(4, Number(agent.clearance ?? 1))),
            capabilities: Number.isFinite(recordedCapabilities)
                ? Math.max(0, Math.trunc(recordedCapabilities))
                : 0,
            // A migration-only profile describes existing consensus state. Do
            // not invent a home domain or silently normalize it into a fresh
            // selectable policy before the operator reviews it.
            home_domain: agent.home_domain || '',
        };
    }
    const role = profile === 'companion' || profile === 'read_only'
        ? 'member'
        : (agent.role === 'admin' || agent.role === 'manager' ? agent.role : 'member');
    return {
        role,
        profile,
        clearance: role === 'admin' ? 4 : Math.max(0, Math.min(4, Number(agent.clearance ?? 1))),
        capabilities: profile === 'companion' ? 15 : (profile === 'read_only' || role === 'admin') ? 1 : 0,
        home_domain: profile === 'read_only'
            ? (agent.home_domain || '')
            : (agent.home_domain || `agent-${String(agent.agent_id || '').slice(0, 12)}`),
    };
}

export function appV23ProfileDefaults(profile, role) {
    if (!appV23ProfileIsSelectable(profile)) {
        throw new TypeError(`Profile "${profile}" is not selectable`);
    }
    if (profile === 'companion') {
        return { profile, role: 'member', capabilities: 15 };
    }
    if (profile === 'read_only') {
        return { profile, role: 'member', capabilities: 1 };
    }
    if (role === 'admin') {
        return { profile: 'standard', role, clearance: 4, capabilities: 1 };
    }
    if (role === 'manager') {
        return { profile: 'standard', role, capabilities: 0 };
    }
    return { profile: 'standard', role: 'member', capabilities: 0 };
}

export function appV23RoleDefaults(role) {
    if (role === 'admin') {
        return { role, profile: 'standard', clearance: 4, capabilities: 1 };
    }
    if (role === 'manager') {
        return { role, profile: 'standard', capabilities: 0 };
    }
    return { role: 'member', profile: 'standard', capabilities: 0 };
}

export const APPV23_CAPABILITY_INDICATORS = Object.freeze([
    Object.freeze({
        bit: 1,
        name: 'Local read scope',
        desc: 'Clearance is always enforced.',
        enabledLabel: 'All local domains',
        disabledLabel: 'Role and groups',
    }),
    Object.freeze({
        bit: 2,
        name: 'Shared-domain writes',
        desc: 'A hard block cannot be overridden by a group or grant.',
        enabledLabel: 'Blocked',
        disabledLabel: 'Policy-controlled',
    }),
    Object.freeze({
        bit: 4,
        name: 'Domain claims',
        desc: 'Controls whether the agent may claim an unowned domain.',
        enabledLabel: 'Blocked',
        disabledLabel: 'Policy-controlled',
    }),
    Object.freeze({
        bit: 8,
        name: 'Foreign-domain writes',
        desc: 'A hard block cannot be overridden by a group or grant.',
        enabledLabel: 'Blocked',
        disabledLabel: 'Role / grant',
    }),
    Object.freeze({
        bit: 16,
        name: 'Federated inbox',
        desc: 'Local notes remain available when the federated inbox is blocked.',
        enabledLabel: 'Blocked',
        disabledLabel: 'Available',
    }),
]);

// Raw capability bits are an audit view, never an independent editor. Named
// profiles are strict consensus presets, so indicators are derived from the
// selected role/profile and deliberately ignore arbitrary incoming bit mixes.
export function appV23CapabilityIndicators(policy) {
    if (appV23ProfileNeedsReview(policy)) {
        // legacy_restricted is migration evidence, not a named preset. Its raw
        // mask must not recreate the old checkbox wall in the primary UI.
        return [];
    }
    const capabilities = appV23PolicyDraft(policy || {}).capabilities;
    return APPV23_CAPABILITY_INDICATORS.map(item => ({
        ...item,
        enabled: (capabilities & item.bit) !== 0,
    }));
}

export function appV23NeedsHomeReapproval(currentPolicy, draftPolicy) {
    if (currentPolicy?.enrollment_active !== true ||
        draftPolicy?.profile === 'read_only') {
        return false;
    }
    if (currentPolicy?.profile === 'read_only') {
        return true;
    }
    return currentPolicy?.profile === APPV23_PROFILE_LEGACY_RESTRICTED
        && !currentPolicy?.home_domain
        && appV23ProfileIsSelectable(draftPolicy?.profile);
}

export function appV23PolicyChanged(currentPolicy, draftPolicy) {
    const current = appV23PolicyDraft(currentPolicy || {});
    const next = appV23PolicyDraft({ ...(currentPolicy || {}), ...(draftPolicy || {}) });
    const recordedCapabilities = Number.isFinite(Number(currentPolicy?.capabilities))
        ? Number(currentPolicy.capabilities)
        : current.capabilities;
    return current.role !== next.role
        || current.profile !== next.profile
        || current.clearance !== next.clearance
        || recordedCapabilities !== next.capabilities
        || current.home_domain !== next.home_domain;
}

export const APPV23_ROOT_HANDOVER_PHRASE = 'ROTATE CEREBRUM ROOT';

export function appV23RootHandoverReady(stage, typedPhrase) {
    return stage === 2 && typedPhrase === APPV23_ROOT_HANDOVER_PHRASE;
}

export function appV23LinkedClearanceCeiling(value) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? Math.max(0, Math.min(4, Math.trunc(parsed))) : 0;
}

export function appV23ClampLinkedClearance(requested, agreementCeiling) {
    return Math.min(
        appV23LinkedClearanceCeiling(requested),
        appV23LinkedClearanceCeiling(agreementCeiling),
    );
}

export function appV23GroupDropKind(localAgentID, remoteCandidateKey) {
    if (remoteCandidateKey) return 'linked_reader';
    if (localAgentID) return 'local_member';
    return '';
}
