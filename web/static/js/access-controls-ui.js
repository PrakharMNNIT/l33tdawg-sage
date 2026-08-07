export const ACCESS_CONTROL_TABS = Object.freeze(['agents', 'groups', 'federation']);
const ACCESS_HISTORY_INDEX = '__sage_access_history_index';

let activeNavigationGuard = null;

// Access Controls is mounted below the application router, so hash/sidebar
// navigation must ask the mounted editor before the router unmounts it. Keep
// the registration module-local rather than exposing mutable state on window.
export function registerAccessControlNavigationGuard({ confirmDiscard, currentHash }) {
    if (typeof confirmDiscard !== 'function' || typeof currentHash !== 'function') {
        throw new TypeError('Access Controls navigation guard requires confirmDiscard and currentHash');
    }
    const registration = { confirmDiscard, currentHash };
    activeNavigationGuard = registration;
    return () => {
        if (activeNavigationGuard === registration) activeNavigationGuard = null;
    };
}

export function accessControlNavigationSnapshot() {
    if (!activeNavigationGuard) return { active: false, currentHash: '' };
    return {
        active: true,
        currentHash: String(activeNavigationGuard.currentHash() || ''),
    };
}

export async function confirmAccessControlHashNavigation() {
    if (!activeNavigationGuard) return true;
    return (await activeNavigationGuard.confirmDiscard()) === true;
}

export function discardedAccessControlDraft(savedDraft, savedDisplayName = '') {
    return {
        draft: savedDraft ? { ...savedDraft } : null,
        displayNameDraft: String(savedDisplayName || ''),
    };
}

export function accessControlDisplayNameDirty(savedDisplayName = '', draftDisplayName = '') {
    return String(draftDisplayName || '').trim() !== String(savedDisplayName || '').trim();
}

export async function protectAccessControlTransition(confirmNavigation) {
    if (typeof confirmNavigation !== 'function') {
        throw new TypeError('Access Controls transition requires a confirmation function');
    }
    return (await confirmNavigation()) === true;
}

// Access drawers are themselves fixed modal surfaces rather than dialogs
// nested inside a separate overlay. Return every sibling outside the dialog's
// ancestor path so the caller can make the complete background inert.
export function accessControlModalInertTargets(dialog, app) {
    const targets = [];
    let branch = dialog;
    while (branch && branch !== app) {
        const parent = branch.parentElement;
        if (!parent) break;
        for (const child of parent.children || []) {
            if (child !== branch) targets.push(child);
        }
        branch = parent;
    }
    return targets;
}

function historyIndex(state) {
    const value = state && state[ACCESS_HISTORY_INDEX];
    return Number.isSafeInteger(value) ? value : null;
}

function indexedHistoryState(state, index) {
    const base = state && typeof state === 'object' ? state : {};
    return { ...base, [ACCESS_HISTORY_INDEX]: index };
}

// Hash assignment pushes a history entry; Back/Forward traverses one. Blocking
// either after the URL changed must reverse the traversal, never replace the
// destination entry (which duplicates or destroys the user's history).
export function createAccessControlHistoryNavigator({
    getHash,
    getState,
    replaceState,
    pushState,
    go,
    confirmNavigation,
    applyHash,
}) {
    for (const dependency of [getHash, getState, replaceState, pushState, go, confirmNavigation, applyHash]) {
        if (typeof dependency !== 'function') {
            throw new TypeError('Access Controls history navigator requires complete history adapters');
        }
    }

    const normalizedHash = () => String(getHash() || '#/');
    let acceptedHash = normalizedHash();
    let acceptedIndex = historyIndex(getState());
    if (acceptedIndex === null) {
        acceptedIndex = 0;
        replaceState(indexedHistoryState(getState(), acceptedIndex), acceptedHash);
    }
    let restoringIndex = null;
    let skipHashChange = '';
    let navigationGeneration = 0;

    const mayNavigate = async (requestedHash, generation) => {
        const allowed = (await confirmNavigation(requestedHash)) === true;
        return generation === navigationGeneration && allowed;
    };

    const accept = (requestedHash, requestedIndex) => {
        acceptedHash = requestedHash;
        acceptedIndex = requestedIndex;
        applyHash(requestedHash);
    };

    return {
        async navigate(requested) {
            const requestedHash = String(requested || '#/');
            if (requestedHash === acceptedHash) return true;
            const generation = ++navigationGeneration;
            if (!await mayNavigate(requestedHash, generation)) return false;
            const requestedIndex = acceptedIndex + 1;
            pushState(indexedHistoryState(getState(), requestedIndex), requestedHash);
            accept(requestedHash, requestedIndex);
            return true;
        },

        async handleHashChange() {
            const requestedHash = normalizedHash();
            if (skipHashChange === requestedHash) {
                skipHashChange = '';
                return true;
            }
            if (requestedHash === acceptedHash) return true;

            const requestedIndex = acceptedIndex + 1;
            replaceState(indexedHistoryState(getState(), requestedIndex), requestedHash);
            const generation = ++navigationGeneration;
            if (await mayNavigate(requestedHash, generation)) {
                accept(requestedHash, requestedIndex);
                return true;
            }
            restoringIndex = acceptedIndex;
            go(acceptedIndex - requestedIndex);
            return false;
        },

        async handlePopState(state) {
            const requestedHash = normalizedHash();
            skipHashChange = requestedHash;
            let requestedIndex = historyIndex(state);
            if (requestedIndex === null) {
                // Entries older than this SPA session can be reached only by
                // traversing backwards from the first indexed entry.
                requestedIndex = acceptedIndex - 1;
                replaceState(indexedHistoryState(state, requestedIndex), requestedHash);
            }
            if (restoringIndex !== null && requestedIndex === restoringIndex) {
                restoringIndex = null;
                return true;
            }

            const generation = ++navigationGeneration;
            if (await mayNavigate(requestedHash, generation)) {
                accept(requestedHash, requestedIndex);
                return true;
            }
            restoringIndex = acceptedIndex;
            const delta = acceptedIndex - requestedIndex;
            if (delta) go(delta);
            return false;
        },

        snapshot() {
            return { acceptedHash, acceptedIndex, restoringIndex };
        },
    };
}

export function accessControlRouteState(hash = '') {
    const query = new URLSearchParams(String(hash).split('?')[1] || '');
    const remoteChain = query.get('remote_chain') || '';
    const remoteAgent = query.get('remote_agent') || '';
    const requestedTab = query.get('tab') || '';
    const tab = ACCESS_CONTROL_TABS.includes(requestedTab)
        ? requestedTab
        : (remoteChain && remoteAgent ? 'federation' : 'agents');
    return {
        tab,
        item: query.get('item') || query.get('agent') || query.get('group') ||
            (remoteChain && remoteAgent ? `${remoteChain}\u0000${remoteAgent}` : ''),
        remoteChain,
        remoteAgent,
        inbox: query.get('inbox') === '1',
    };
}

export function accessControlHash({ tab = 'agents', item = '', inbox = false } = {}) {
    const safeTab = ACCESS_CONTROL_TABS.includes(tab) ? tab : 'agents';
    const query = new URLSearchParams({ tab: safeTab });
    if (item) query.set('item', item);
    if (safeTab === 'agents' && item) query.set('agent', item);
    if (safeTab === 'groups' && item) query.set('group', item);
    if (safeTab === 'federation' && item.includes('\u0000')) {
        const [remoteChain, remoteAgent] = item.split('\u0000');
        if (remoteChain && remoteAgent) {
            query.set('remote_chain', remoteChain);
            query.set('remote_agent', remoteAgent);
        }
    }
    if (inbox) query.set('inbox', '1');
    return `/access?${query.toString()}`;
}

function normalized(value) {
    return String(value || '').trim().toLocaleLowerCase();
}

export function filterSortAccessAgents(agents = [], query = '', sort = 'name') {
    const needle = normalized(query);
    return [...agents]
        .filter(agent => !needle || [
            agent?.name,
            agent?.registered_name,
            agent?.agent_id,
            agent?.role,
            agent?.profile,
        ].some(value => normalized(value).includes(needle)))
        .sort((left, right) => {
            if (sort === 'status') {
                const rank = agent => agent?.needs_reauthorization ? 0
                    : (agent?.needs_approval || agent?.profile_needs_review) ? 1 : 2;
                const delta = rank(left) - rank(right);
                if (delta) return delta;
            }
            if (sort === 'role') {
                const delta = normalized(left?.role).localeCompare(normalized(right?.role));
                if (delta) return delta;
            }
            return normalized(left?.name || left?.registered_name || left?.agent_id)
                .localeCompare(normalized(right?.name || right?.registered_name || right?.agent_id));
        });
}

export function filterSortAccessGroups(groups = [], query = '', sort = 'name') {
    const needle = normalized(query);
    return [...groups]
        .filter(group => !needle || [group?.name, group?.group_id, group?.member_authority]
            .some(value => normalized(value).includes(needle)))
        .sort((left, right) => {
            if (sort === 'members') {
                const delta = Number(right?.members?.length || 0) - Number(left?.members?.length || 0);
                if (delta) return delta;
            }
            if (sort === 'authority') {
                const rank = { read: 0, write: 1, modify: 2 };
                const delta = (rank[left?.member_authority] ?? 0) - (rank[right?.member_authority] ?? 0);
                if (delta) return delta;
            }
            return normalized(left?.name || left?.group_id).localeCompare(normalized(right?.name || right?.group_id));
        });
}

export function filterSortFederatedAgents(agents = [], query = '', sort = 'peer') {
    const needle = normalized(query);
    return [...agents]
        .filter(agent => !needle || [
            agent?.label,
            agent?.peer_name,
            agent?.remote_agent_id,
            agent?.remote_chain_id,
            agent?.source,
        ].some(value => normalized(value).includes(needle)))
        .sort((left, right) => {
            if (sort === 'status') {
                const delta = Number(right?.link_count || 0) - Number(left?.link_count || 0);
                if (delta) return delta;
            }
            const leftKey = sort === 'name'
                ? `${left?.label || ''}/${left?.peer_name || ''}`
                : `${left?.peer_name || ''}/${left?.label || ''}`;
            const rightKey = sort === 'name'
                ? `${right?.label || ''}/${right?.peer_name || ''}`
                : `${right?.peer_name || ''}/${right?.label || ''}`;
            return normalized(leftKey).localeCompare(normalized(rightKey));
        });
}
