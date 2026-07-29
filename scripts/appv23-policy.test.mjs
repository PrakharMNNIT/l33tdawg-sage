import assert from 'node:assert/strict';
import test from 'node:test';

import {
    appV23PolicyDraft,
    appV23CapabilityIndicators,
    appV23NeedsHomeReapproval,
    appV23PolicyChanged,
    appV23ProfileDefaults,
    appV23ProfileIsSelectable,
    appV23ProfileNeedsReview,
    appV23RoleDefaults,
    appV23ClampLinkedClearance,
    appV23GroupDropKind,
    appV23LinkedClearanceCeiling,
    APPV23_ROOT_HANDOVER_PHRASE,
    APPV23_PROFILE_LEGACY_RESTRICTED,
    APPV23_SELECTABLE_PROFILES,
    appV23RootHandoverReady,
} from '../web/static/js/appv23-policy.js';

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

test('Root handover final action requires the exact second-stage phrase', () => {
    assert.equal(APPV23_ROOT_HANDOVER_PHRASE, 'ROTATE CEREBRUM ROOT');
    assert.equal(appV23RootHandoverReady(1, APPV23_ROOT_HANDOVER_PHRASE), false);
    assert.equal(appV23RootHandoverReady(2, 'rotate cerebrum root'), false);
    assert.equal(appV23RootHandoverReady(2, APPV23_ROOT_HANDOVER_PHRASE), true);
});
