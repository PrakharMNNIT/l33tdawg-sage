import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';

import {
    accessControlDisplayNameDirty,
    accessControlModalInertTargets,
    accessControlNavigationSnapshot,
    accessControlHash,
    accessControlRouteState,
    confirmAccessControlHashNavigation,
    createAccessControlHistoryNavigator,
    discardedAccessControlDraft,
    filterSortAccessAgents,
    filterSortAccessGroups,
    filterSortFederatedAgents,
    protectAccessControlTransition,
    registerAccessControlNavigationGuard,
} from '../web/static/js/access-controls-ui.js';

class HistoryModel {
    constructor(hash = '#/brain') {
        this.entries = [{ hash, state: null }];
        this.index = 0;
        this.pendingGo = [];
    }

    get hash() { return this.entries[this.index].hash; }
    get state() { return this.entries[this.index].state; }

    replace(state, hash) {
        this.entries[this.index] = { state, hash };
    }

    push(state, hash) {
        this.entries.splice(this.index + 1);
        this.entries.push({ state, hash });
        this.index += 1;
    }

    pushHash(hash) {
        this.push(this.state, hash);
    }

    go(delta) {
        this.pendingGo.push(delta);
    }

    async traverse(delta, navigator) {
        this.index += delta;
        assert.ok(this.index >= 0 && this.index < this.entries.length, 'history traversal left the model');
        await navigator.handlePopState(this.state);
        await navigator.handleHashChange();
        await this.flush(navigator);
    }

    async flush(navigator) {
        while (this.pendingGo.length) {
            const delta = this.pendingGo.shift();
            this.index += delta;
            assert.ok(this.index >= 0 && this.index < this.entries.length, 'history restoration left the model');
            await navigator.handlePopState(this.state);
            await navigator.handleHashChange();
        }
    }
}

test('Access Controls route state preserves tab and exact selected item', () => {
    assert.deepEqual(accessControlRouteState('#/access?tab=groups&item=team-a'), {
        tab: 'groups', item: 'team-a', remoteChain: '', remoteAgent: '', inbox: false,
    });
    const remoteKey = `chain-b\u0000${'a'.repeat(64)}`;
    const hash = accessControlHash({ tab: 'federation', item: remoteKey });
    assert.match(hash, /^\/access\?tab=federation&item=/);
    assert.equal(accessControlRouteState(`#${hash}`).item, remoteKey);
    assert.equal(accessControlRouteState(`#${hash}`).remoteChain, 'chain-b');
    assert.equal(accessControlRouteState(`#${hash}`).remoteAgent, 'a'.repeat(64));
});

test('legacy Access Controls deep links route to the correct modern tab', () => {
    assert.equal(accessControlRouteState('#/access?agent=local-a&inbox=1').tab, 'agents');
    assert.equal(accessControlRouteState('#/access?agent=local-a&inbox=1').inbox, true);
    assert.equal(accessControlRouteState(`#/access?remote_chain=chain-b&remote_agent=${'b'.repeat(64)}`).tab, 'federation');
});

test('compact Access Controls lists search and sort without mutating source arrays', () => {
    const agents = [
        { name: 'Zulu', agent_id: 'z', role: 'member' },
        { name: 'Alpha', agent_id: 'a', role: 'admin', needs_reauthorization: true },
    ];
    assert.deepEqual(filterSortAccessAgents(agents, '', 'status').map(item => item.agent_id), ['a', 'z']);
    assert.deepEqual(filterSortAccessAgents(agents, 'member').map(item => item.agent_id), ['z']);
    assert.deepEqual(agents.map(item => item.agent_id), ['z', 'a']);

    const groups = [
        { name: 'Small', group_id: 's', members: ['a'], member_authority: 'read' },
        { name: 'Large', group_id: 'l', members: ['a', 'b'], member_authority: 'write' },
    ];
    assert.deepEqual(filterSortAccessGroups(groups, '', 'members').map(item => item.group_id), ['l', 's']);

    const remote = [
        { label: 'Beta', peer_name: 'Zulu node', remote_agent_id: 'b', remote_chain_id: 'z' },
        { label: 'Alpha', peer_name: 'Alpha node', remote_agent_id: 'a', remote_chain_id: 'a' },
    ];
    assert.deepEqual(filterSortFederatedAgents(remote, 'alpha').map(item => item.remote_agent_id), ['a']);
});

test('dirty Access Controls hash navigation cancels without losing the exact accepted route', async () => {
    let confirmations = 0;
    const unregister = registerAccessControlNavigationGuard({
        currentHash: () => '#/access?tab=agents&item=agent-a&agent=agent-a',
        confirmDiscard: async () => {
            confirmations += 1;
            return false;
        },
    });
    try {
        assert.deepEqual(accessControlNavigationSnapshot(), {
            active: true,
            currentHash: '#/access?tab=agents&item=agent-a&agent=agent-a',
        });
        assert.equal(await confirmAccessControlHashNavigation(), false);
        assert.equal(confirmations, 1);
        assert.equal(accessControlNavigationSnapshot().currentHash,
            '#/access?tab=agents&item=agent-a&agent=agent-a');
    } finally {
        unregister();
    }
    assert.deepEqual(accessControlNavigationSnapshot(), { active: false, currentHash: '' });
});

test('confirmed discard restores saved name and policy so reopening cannot resurrect edits', async () => {
    const savedPolicy = {
        role: 'member', profile: 'standard', clearance: 1, capabilities: 0, home_domain: 'agent-a-home',
    };
    let editor = {
        draft: { ...savedPolicy, role: 'admin', clearance: 4, capabilities: 1 },
        displayNameDraft: 'Unsaved renamed agent',
    };
    let dirty = true;
    const unregister = registerAccessControlNavigationGuard({
        currentHash: () => '#/access?tab=agents&item=agent-a&agent=agent-a',
        confirmDiscard: async () => {
            if (!dirty) return true;
            editor = discardedAccessControlDraft(savedPolicy, 'Saved agent name');
            dirty = false;
            return true;
        },
    });
    try {
        assert.equal(await confirmAccessControlHashNavigation(), true);
        assert.equal(dirty, false);
        assert.deepEqual(editor, {
            draft: savedPolicy,
            displayNameDraft: 'Saved agent name',
        });
        assert.notEqual(editor.draft, savedPolicy, 'discard must create a fresh saved-policy draft');

        // Model returning to the same agent after a tab/sidebar round trip: the
        // state left behind by confirmation is canonical, not the old edits.
        assert.equal(editor.draft.role, 'member');
        assert.equal(editor.draft.clearance, 1);
        assert.equal(editor.displayNameDraft, 'Saved agent name');
        assert.equal(await confirmAccessControlHashNavigation(), true);
    } finally {
        unregister();
    }
});

test('clearing a saved display name remains a protected dirty edit', () => {
    assert.equal(accessControlDisplayNameDirty('Alice', ''), true);
    assert.equal(accessControlDisplayNameDirty('Alice', '   '), true);
    assert.equal(accessControlDisplayNameDirty(' Alice ', 'Alice'), false);
    assert.equal(accessControlDisplayNameDirty('', ''), false);
});

test('cancelled sidebar, direct-hash, and Back navigation preserve the real history stack', async () => {
    const history = new HistoryModel('#/brain');
    let allow = true;
    const applied = [];
    const navigator = createAccessControlHistoryNavigator({
        getHash: () => history.hash,
        getState: () => history.state,
        replaceState: (state, hash) => history.replace(state, hash),
        pushState: (state, hash) => history.push(state, hash),
        go: delta => history.go(delta),
        confirmNavigation: async () => allow,
        applyHash: hash => applied.push(hash),
    });

    assert.equal(await navigator.navigate('#/access?tab=agents&item=alice'), true);
    const acceptedEntries = history.entries.map(entry => entry.hash);
    allow = false;

    assert.equal(await navigator.navigate('#/settings'), false, 'sidebar navigation should be stopped before push');
    assert.deepEqual(history.entries.map(entry => entry.hash), acceptedEntries);
    assert.equal(history.hash, '#/access?tab=agents&item=alice');

    await history.traverse(-1, navigator);
    assert.equal(history.hash, '#/access?tab=agents&item=alice', 'cancelled Back must return to the exact entry');
    assert.deepEqual(history.entries.map(entry => entry.hash), acceptedEntries,
        'cancelled Back must not overwrite the prior URL or create a duplicate Access entry');

    history.pushHash('#/settings');
    assert.equal(await navigator.handleHashChange(), false);
    await history.flush(navigator);
    assert.equal(history.hash, '#/access?tab=agents&item=alice');
    assert.deepEqual(history.entries.map(entry => entry.hash), [
        '#/brain', '#/access?tab=agents&item=alice', '#/settings',
    ], 'a cancelled direct hash push remains a forward entry instead of becoming duplicate Access history');

    allow = true;
    await history.traverse(-1, navigator);
    assert.equal(history.hash, '#/brain');
    assert.deepEqual(applied, ['#/access?tab=agents&item=alice', '#/brain']);
});

test('Access drawer inerting includes exposed rails, tabs, and application siblings', () => {
    const makeNode = name => ({ name, children: [], parentElement: null, inert: false });
    const append = (parent, ...children) => {
        for (const child of children) {
            child.parentElement = parent;
            parent.children.push(child);
        }
    };
    const app = makeNode('app');
    const sidebar = makeNode('sidebar');
    const main = makeNode('main');
    const tabs = makeNode('tabs');
    const grid = makeNode('grid');
    const rail = makeNode('agent-rail');
    const drawer = makeNode('drawer');
    append(app, sidebar, main);
    append(main, tabs, grid);
    append(grid, rail, drawer);

    assert.deepEqual(
        accessControlModalInertTargets(drawer, app).map(node => node.name).sort(),
        ['agent-rail', 'sidebar', 'tabs'],
    );
});

test('dirty editor denial blocks the drag-to-group transition before mutation', async () => {
    let mutations = 0;
    if (await protectAccessControlTransition(async () => false)) mutations += 1;
    assert.equal(mutations, 0);
    if (await protectAccessControlTransition(async () => true)) mutations += 1;
    assert.equal(mutations, 1);

    const app = await readFile(new URL('../web/static/js/app.js', import.meta.url), 'utf8');
    const directGroup = app.slice(
        app.indexOf('const createDirectLocalGroup = async'),
        app.indexOf('const removeDraggedMemberFromSourceGroup = async'),
    );
    assert.match(directGroup, /await protectAccessControlTransition\(confirmAccessNavigation\)/,
        'the actual drag/drop mutation must pass through the shared dirty guard');
});

test('stale guard cleanup cannot unregister the currently mounted editor', async () => {
    const unregisterOld = registerAccessControlNavigationGuard({
        currentHash: () => '#/access?tab=agents&item=old',
        confirmDiscard: async () => false,
    });
    const unregisterCurrent = registerAccessControlNavigationGuard({
        currentHash: () => '#/access?tab=groups&item=current',
        confirmDiscard: async () => true,
    });
    unregisterOld();
    assert.equal(accessControlNavigationSnapshot().currentHash, '#/access?tab=groups&item=current');
    assert.equal(await confirmAccessControlHashNavigation(), true);
    unregisterCurrent();
});
