import assert from 'node:assert/strict';
import test from 'node:test';

import {
    appV23PolicyDraft,
    appV23NormalizeAccessState,
    appV23CapabilityIndicators,
    appV23NeedsHomeReapproval,
    appV23PolicyChanged,
    appV23FederatedInboxDefaults,
    appV23FederatedInboxEnabled,
    appV23ProfileDefaults,
    appV23ProfileIsSelectable,
    appV23ProfileNeedsReview,
    appV23RoleDefaults,
    appV23ClampLinkedClearance,
    appV23DirectLocalGroupPlan,
    appV23GroupDropKind,
    appV23LinkedClearanceCeiling,
    APPV23_ROOT_HANDOVER_PHRASE,
    APPV23_PROFILE_LEGACY_RESTRICTED,
    APPV23_SELECTABLE_PROFILES,
    appV23RootHandoverReady,
} from '../web/static/js/appv23-policy.js';

test('Access Controls normalizes null members before rendering an empty group', () => {
    const input = {
        agents: null,
        groups: [{ group_id: 'empty-team', name: 'Empty team', members: null }],
    };
    const normalized = appV23NormalizeAccessState(input);

    assert.deepEqual(normalized.agents, []);
    assert.deepEqual(normalized.groups[0].members, []);
    assert.equal(normalized.groups[0].members.length, 0);
    assert.deepEqual(normalized.groups[0].members.map(String), []);
    assert.equal(normalized.groups[0].members.includes('agent-id'), false);
    assert.equal(input.groups[0].members, null, 'normalization must not mutate the fetched payload');
});

test('demoting Admin to Member removes hidden read-all capability', () => {
    const admin = { role: 'admin', profile: 'standard', clearance: 4, capabilities: 1 };
    const member = { ...admin, ...appV23RoleDefaults('member') };

    assert.equal(member.role, 'member');
    assert.equal(member.profile, 'standard');
    assert.equal(member.capabilities, 0);
});

test('choosing Standard after Companion clears the companion deny mask', () => {
    const companion = { role: 'member', profile: 'companion', clearance: 1, capabilities: 15 };
    const standard = { ...companion, ...appV23ProfileDefaults('standard', companion.role) };

    assert.equal(standard.profile, 'standard');
    assert.equal(standard.role, 'member');
    assert.equal(standard.capabilities, 0);
});

test('Admin and Companion presets remain exact and mutually exclusive', () => {
    assert.deepEqual(appV23RoleDefaults('admin'), {
        role: 'admin', profile: 'standard', clearance: 4, capabilities: 1,
    });
    assert.deepEqual(appV23ProfileDefaults('companion', 'admin'), {
        role: 'member', profile: 'companion', capabilities: 15,
    });
});

test('choosing Companion enables its connected-SAGE inbox by default', () => {
    assert.deepEqual(appV23ProfileDefaults('companion', 'member', 31), {
        role: 'member', profile: 'companion', capabilities: 15,
    });
    assert.equal(
        appV23FederatedInboxEnabled(appV23ProfileDefaults('companion', 'member', 31).capabilities),
        true,
    );
});

test('Read-only is the explicit reviewed read-all profile without write authority bits', () => {
    assert.deepEqual(
        appV23ProfileDefaults('read_only', 'manager'),
        { profile: 'read_only', role: 'member', capabilities: 1 },
    );
    const draft = appV23PolicyDraft({
        agent_id: 'abcdef',
        profile: 'read_only', role: 'member', capabilities: 30, clearance: 2,
    });
    assert.equal(draft.capabilities, 1);
    assert.equal(draft.home_domain, '', 'Read-only must not invent a home domain');
});

test('legacy restrictions are migration-only review state, never a fresh preset', () => {
    const legacy = {
        agent_id: 'abcdef',
        role: 'member',
        profile: APPV23_PROFILE_LEGACY_RESTRICTED,
        capabilities: 30,
        clearance: 2,
        home_domain: 'existing-home',
    };
    const draft = appV23PolicyDraft(legacy);

    assert.equal(appV23ProfileNeedsReview(legacy), true);
    assert.equal(appV23ProfileIsSelectable(APPV23_PROFILE_LEGACY_RESTRICTED), false);
    assert.deepEqual(APPV23_SELECTABLE_PROFILES, ['standard', 'companion', 'read_only']);
    assert.equal(draft.profile, APPV23_PROFILE_LEGACY_RESTRICTED);
    assert.equal(draft.capabilities, 30, 'migration evidence must remain unchanged until review');
    assert.equal(draft.home_domain, 'existing-home');
    assert.equal(
        appV23PolicyDraft({ ...legacy, home_domain: '' }).home_domain,
        '',
        'domainless legacy state must not receive a browser-invented home',
    );
    assert.deepEqual(appV23CapabilityIndicators(legacy), [],
        'legacy masks must not recreate a raw capability wall');
    assert.throws(
        () => appV23ProfileDefaults(APPV23_PROFILE_LEGACY_RESTRICTED, 'member'),
        /not selectable/,
    );
    assert.equal(appV23PolicyChanged(legacy, draft), false);
    assert.equal(
        appV23PolicyChanged(legacy, {
            ...draft,
            ...appV23ProfileDefaults('standard', 'member'),
        }),
        true,
    );
});

test('raw capability indicators are derived and read-only from named policy', () => {
    const standard = appV23CapabilityIndicators({
        profile: 'standard', role: 'member', capabilities: 31, clearance: 2,
    });
    assert.equal(standard.every(item => item.enabled === false), true);

    const companion = appV23CapabilityIndicators({
        profile: 'companion', role: 'member', capabilities: 0, clearance: 2,
    });
    assert.deepEqual(
        companion.filter(item => item.enabled).map(item => item.bit),
        [1, 2, 4, 8],
    );
    assert.equal(
        Object.hasOwn(companion[0], 'onChange'),
        false,
        'audit indicators must not expose an independent bit mutation surface',
    );
    assert.equal(companion[0].enabledLabel, 'All local domains');
    assert.equal(companion[1].enabledLabel, 'Blocked');
    assert.equal(standard[1].disabledLabel, 'Policy-controlled');
});

test('named policy editing preserves the independent federated-pipe hard restriction', () => {
    const standard = {
        agent_id: 'standard-agent',
        profile: 'standard',
        role: 'member',
        clearance: 1,
        capabilities: 16,
        home_domain: 'standard-home',
    };
    const companion = {
        agent_id: 'companion-agent',
        profile: 'companion',
        role: 'member',
        clearance: 1,
        capabilities: 31,
        home_domain: 'companion-home',
    };
    const readOnly = {
        agent_id: 'read-only-agent',
        profile: 'read_only',
        role: 'member',
        clearance: 1,
        capabilities: 17,
        home_domain: '',
    };

    assert.equal(appV23PolicyDraft(standard).capabilities, 16);
    assert.equal(appV23PolicyDraft(companion).capabilities, 31);
    assert.equal(appV23PolicyDraft(readOnly).capabilities, 17);
    assert.equal(appV23PolicyChanged(companion, appV23PolicyDraft(companion)), false);
    assert.equal(
        appV23CapabilityIndicators(companion).find(item => item.bit === 16).enabled,
        true,
    );
    assert.equal(
        appV23RoleDefaults('manager', companion.capabilities).capabilities,
        16,
    );
    assert.equal(
        appV23ProfileDefaults('read_only', 'member', companion.capabilities).capabilities,
        17,
    );
    assert.equal(
        appV23PolicyDraft({
            agent_id: 'pending-agent',
            profile: '',
            role: 'member',
            clearance: 1,
            capabilities: 30,
        }).capabilities,
        0,
        'pending mask 30 must not turn the explicitly selected Companion preset into mask 31',
    );
});

test('the operator can explicitly toggle the independent federated inbox restriction', () => {
    assert.equal(appV23FederatedInboxEnabled(15), true);
    assert.equal(appV23FederatedInboxEnabled(31), false);
    assert.deepEqual(appV23FederatedInboxDefaults(true, 31), { capabilities: 15 });
    assert.deepEqual(appV23FederatedInboxDefaults(false, 15), { capabilities: 31 });
    assert.deepEqual(appV23FederatedInboxDefaults(true, 17), { capabilities: 1 });
    assert.deepEqual(appV23FederatedInboxDefaults(false, 1), { capabilities: 17 });
});

test('policy change detection avoids meaningless consensus saves', () => {
    const current = {
        agent_id: 'abcdef',
        profile: 'standard',
        role: 'member',
        clearance: 1,
        capabilities: 0,
        home_domain: 'agent-abcdef',
    };
    assert.equal(appV23PolicyChanged(current, appV23PolicyDraft(current)), false);
    assert.equal(
        appV23PolicyChanged(current, { ...appV23PolicyDraft(current), role: 'manager' }),
        true,
    );
    assert.equal(
        appV23PolicyChanged({ ...current, capabilities: 30 }, appV23PolicyDraft(current)),
        true,
        'a non-canonical recorded mask must remain repairable through its named policy',
    );
});

test('leaving an active Read-only profile requires consent and a home-domain reapproval', () => {
    const current = { enrollment_active: true, profile: 'read_only' };
    assert.equal(
        appV23NeedsHomeReapproval(current, { profile: 'standard' }),
        true,
    );
    assert.equal(
        appV23NeedsHomeReapproval(current, { profile: 'companion' }),
        true,
    );
    assert.equal(
        appV23NeedsHomeReapproval(current, { profile: 'read_only' }),
        false,
    );
    assert.equal(
        appV23NeedsHomeReapproval(
            { enrollment_active: false, profile: 'read_only' },
            { profile: 'standard' },
        ),
        false,
    );
    assert.equal(
        appV23NeedsHomeReapproval(
            {
                enrollment_active: true,
                profile: APPV23_PROFILE_LEGACY_RESTRICTED,
                home_domain: '',
            },
            { profile: 'standard' },
        ),
        true,
        'domainless migration state needs a consent-bound home when selecting a writable preset',
    );
    assert.equal(
        appV23NeedsHomeReapproval(
            {
                enrollment_active: true,
                profile: APPV23_PROFILE_LEGACY_RESTRICTED,
                home_domain: 'existing-home',
            },
            { profile: 'standard' },
        ),
        false,
    );
    assert.equal(
        appV23NeedsHomeReapproval(
            {
                enrollment_active: true,
                profile: APPV23_PROFILE_LEGACY_RESTRICTED,
                home_domain: '',
            },
            { profile: 'read_only' },
        ),
        false,
    );
});

test('Linked-reader classification is capped by the federation agreement', () => {
    assert.equal(appV23LinkedClearanceCeiling(9), 4);
    assert.equal(appV23LinkedClearanceCeiling('not-a-number'), 0);
    assert.equal(appV23ClampLinkedClearance(4, 2), 2);
});

test('federated drops remain linked readers instead of local group members', () => {
    assert.equal(appV23GroupDropKind('local-id', 'remote-chain\u0000remote-id'), 'linked_reader');
    assert.equal(appV23GroupDropKind('local-id', ''), 'local_member');
});

test('dropping an approved local agent onto another creates a narrow deterministic pair group', () => {
    const alpha = { agent_id: 'a'.repeat(64), name: 'Alpha', enrollment_active: true };
    const bravo = { agent_id: 'b'.repeat(64), name: 'Bravo', enrollment_active: true };
    const plan = appV23DirectLocalGroupPlan([], bravo, alpha);

    assert.deepEqual(plan, {
        action: 'create',
        group_id: `pair-${'a'.repeat(12)}-${'b'.repeat(12)}`,
        name: 'Alpha + Bravo',
        members: ['a'.repeat(64), 'b'.repeat(64)],
    });
});

test('direct local drop reuses an existing shared group without widening another relationship', () => {
    const alpha = { agent_id: 'a'.repeat(64), name: 'Alpha', enrollment_active: true };
    const bravo = { agent_id: 'b'.repeat(64), name: 'Bravo', enrollment_active: true };
    const charlie = 'c'.repeat(64);
    const plan = appV23DirectLocalGroupPlan([
        { group_id: 'broad-team', name: 'Broad team', members: [alpha.agent_id, charlie] },
        { group_id: 'alpha-bravo', name: 'Alpha and Bravo', members: [alpha.agent_id, bravo.agent_id] },
    ], alpha, bravo);

    assert.deepEqual(plan, {
        action: 'existing',
        group_id: 'alpha-bravo',
        name: 'Alpha and Bravo',
        members: [alpha.agent_id, bravo.agent_id],
    });
});

test('direct local drop never creates a group for a pending or identical agent', () => {
    const alpha = { agent_id: 'a'.repeat(64), name: 'Alpha', enrollment_active: true };
    const pending = { agent_id: 'b'.repeat(64), name: 'Bravo', enrollment_active: false };
    assert.equal(appV23DirectLocalGroupPlan([], alpha, pending), null);
    assert.equal(appV23DirectLocalGroupPlan([], alpha, alpha), null);
});

test('Root handover final action requires the exact second-stage phrase', () => {
    assert.equal(APPV23_ROOT_HANDOVER_PHRASE, 'ROTATE CEREBRUM ROOT');
    assert.equal(appV23RootHandoverReady(1, APPV23_ROOT_HANDOVER_PHRASE), false);
    assert.equal(appV23RootHandoverReady(2, 'rotate cerebrum root'), false);
    assert.equal(appV23RootHandoverReady(2, APPV23_ROOT_HANDOVER_PHRASE), true);
});
