// Small pure helpers shared by the federation ceremony UI and its behavioral
// tests. The Go API deliberately uses protocol constants such as "ABORTED";
// browser decisions should not depend on their presentation casing.
export function normalizeFederationJoinState(value) {
    return String(value || '').trim().toLowerCase();
}

// Own exactly one long JOIN scan request. Starting a replacement aborts the
// previous fetch, and abort() is safe to call from a component unmount cleanup.
// The request function receives the AbortSignal as its final argument.
export function createFederationJoinScanLifecycle(request) {
    if (typeof request !== 'function') throw new TypeError('JOIN scan request must be a function');
    let active = null;
    return {
        run(...args) {
            if (active) active.abort();
            const controller = new AbortController();
            active = controller;
            let pending;
            try {
                pending = request(...args, controller.signal);
            } catch (error) {
                pending = Promise.reject(error);
            }
            return Promise.resolve(pending).finally(() => {
                if (active === controller) active = null;
            });
        },
        abort() {
            if (!active) return false;
            const controller = active;
            active = null;
            controller.abort();
            return true;
        },
    };
}
