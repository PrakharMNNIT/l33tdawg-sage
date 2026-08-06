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
const APPV23_DENY_FEDERATED_PIPE = 16;

export function appV23FederatedInboxEnabled(capabilities) {
    const recorded = Number(capabilities ?? 0);
    return Number.isFinite(recorded) &&
        (Math.max(0, Math.trunc(recorded)) & APPV23_DENY_FEDERATED_PIPE) === 0;
}

export function appV23FederatedInboxDefaults(enabled, currentCapabilities = 0) {
    const recorded = Number(currentCapabilities ?? 0);
    const capabilities = Number.isFinite(recorded)
        ? Math.max(0, Math.trunc(recorded))
        : 0;
    return {
        capabilities: enabled
            ? capabilities & ~APPV23_DENY_FEDERATED_PIPE
            : capabilities | APPV23_DENY_FEDERATED_PIPE,
    };
}

// Keep the Access Controls render boundary total even when an older node or a
// historical consensus row represents an empty Go slice as JSON null.
export function appV23NormalizeAccessState(state) {
    const source = state && typeof state === 'object' ? state : {};
    const groups = Array.isArray(source.groups) ? source.groups : [];
    return {
        ...source,
        agents: Array.isArray(source.agents) ? source.agents : [],
        groups: groups.map(group => ({
            ...(group && typeof group === 'object' ? group : {}),
            members: Array.isArray(group?.members) ? group.members : [],
        })),
    };
}

function appV23FederatedPipeRestriction(capabilities) {
    const recorded = Number(capabilities ?? 0);
    return Number.isFinite(recorded) &&
        (Math.max(0, Math.trunc(recorded)) & APPV23_DENY_FEDERATED_PIPE) !== 0
        ? APPV23_DENY_FEDERATED_PIPE
        : 0;
}

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
    const baseCapabilities = profile === 'companion' ? 15 :
        (profile === 'read_only' || role === 'admin') ? 1 : 0;
    const recordedCapabilities = Number.isFinite(Number(agent.capabilities))
        ? Math.max(0, Math.trunc(Number(agent.capabilities)))
        : baseCapabilities;
    // Preserve the independent pipe restriction only from an otherwise
    // canonical named policy. Pending mask 30 and contradictory legacy mixes
    // are review inputs, not permission overlays on a freshly chosen preset.
    const federatedPipeRestriction =
        (recordedCapabilities & ~APPV23_DENY_FEDERATED_PIPE) === baseCapabilities
            ? appV23FederatedPipeRestriction(recordedCapabilities)
            : 0;
    return {
        role,
        profile,
        clearance: role === 'admin' ? 4 : Math.max(0, Math.min(4, Number(agent.clearance ?? 1))),
        capabilities: baseCapabilities | federatedPipeRestriction,
        home_domain: profile === 'read_only'
            ? (agent.home_domain || '')
            : (agent.home_domain || `agent-${String(agent.agent_id || '').slice(0, 12)}`),
    };
}

export function appV23ProfileDefaults(profile, role, currentCapabilities = 0) {
    if (!appV23ProfileIsSelectable(profile)) {
        throw new TypeError(`Profile "${profile}" is not selectable`);
    }
    const federatedPipeRestriction = appV23FederatedPipeRestriction(currentCapabilities);
    if (profile === 'companion') {
        return {
            profile,
            role: 'member',
            // A companion/voice bridge exists to receive work. Choosing this
            // preset is an explicit reset to the useful default; an operator
            // can still apply the independent emergency inbox block afterward.
            capabilities: 15,
        };
    }
    if (profile === 'read_only') {
        return {
            profile,
            role: 'member',
            capabilities: 1 | federatedPipeRestriction,
        };
    }
    if (role === 'admin') {
        return {
            profile: 'standard',
            role,
            clearance: 4,
            capabilities: 1 | federatedPipeRestriction,
        };
    }
    if (role === 'manager') {
        return {
            profile: 'standard',
            role,
            capabilities: federatedPipeRestriction,
        };
    }
    return {
        profile: 'standard',
        role: 'member',
        capabilities: federatedPipeRestriction,
    };
}

export function appV23RoleDefaults(role, currentCapabilities = 0) {
    const federatedPipeRestriction = appV23FederatedPipeRestriction(currentCapabilities);
    if (role === 'admin') {
        return {
            role,
            profile: 'standard',
            clearance: 4,
            capabilities: 1 | federatedPipeRestriction,
        };
    }
    if (role === 'manager') {
        return {
            role,
            profile: 'standard',
            capabilities: federatedPipeRestriction,
        };
    }
    return {
        role: 'member',
        profile: 'standard',
        capabilities: federatedPipeRestriction,
    };
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

// A direct local drop is deliberately a narrow pair relationship. Dropping A
// onto B must not silently add A to every group B happens to belong to: that
// could reveal domains belonging to teammates the operator never chose. If
// the pair already shares a group, use it; otherwise create a deterministic
// two-member Access Group that the operator may rename or extend afterwards.
export function appV23DirectLocalGroupPlan(groups, source, target) {
    const sourceID = String(source?.agent_id || '').trim();
    const targetID = String(target?.agent_id || '').trim();
    if (!sourceID || !targetID || sourceID === targetID ||
        source?.enrollment_active !== true || target?.enrollment_active !== true) {
        return null;
    }

    const members = [sourceID, targetID].sort();
    const existing = (Array.isArray(groups) ? groups : [])
        .filter(group => Array.isArray(group?.members) &&
            members.every(id => group.members.includes(id)))
        .sort((a, b) => String(a.group_id || '').localeCompare(String(b.group_id || '')))[0];
    if (existing) {
        return {
            action: 'existing',
            group_id: existing.group_id,
            name: existing.name || existing.group_id,
            members,
        };
    }

    const agentByID = new Map([
        [sourceID, source],
        [targetID, target],
    ]);
    const labels = members.map(id => {
        const name = String(agentByID.get(id)?.name || '').trim();
        return name || `Agent ${id.slice(0, 8)}`;
    });
    const base = `pair-${members[0].slice(0, 12)}-${members[1].slice(0, 12)}`;
    const occupied = new Set((Array.isArray(groups) ? groups : [])
        .map(group => String(group?.group_id || '').trim())
        .filter(Boolean));
    let groupID = base;
    let suffix = 2;
    while (occupied.has(groupID)) groupID = `${base.slice(0, 60)}-${suffix++}`;
    return {
        action: 'create',
        group_id: groupID,
        name: `${labels[0]} + ${labels[1]}`.slice(0, 128),
        members,
    };
}
