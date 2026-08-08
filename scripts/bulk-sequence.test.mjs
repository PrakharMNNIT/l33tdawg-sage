import assert from 'node:assert/strict';
import test from 'node:test';

const {
    runSequential,
    summarizeClearedTasks,
    summarizeDroppedTasks,
    summarizeForgottenMemories,
} = await import('../web/static/js/bulk-sequence.js');

// Build an operation that records overlap: it fails the assertion the moment a
// second call starts before the previous one finished.
function serialityProbe(behaviour = () => ({ status: 'consensus_submitted' })) {
    const order = [];
    let inFlight = 0;
    return {
        order,
        async operation(id) {
            inFlight += 1;
            assert.equal(inFlight, 1, `two submissions overlapped at ${id}`);
            // Yield to the microtask queue twice; a Promise.all-style fan-out
            // would have started every sibling by now.
            await Promise.resolve();
            await new Promise((resolve) => setTimeout(resolve, 0));
            order.push(id);
            inFlight -= 1;
            return behaviour(id);
        },
    };
}

test('runSequential submits one id at a time, in order', async () => {
    const probe = serialityProbe();
    const results = await runSequential(['a', 'b', 'c', 'd'], probe.operation);

    assert.deepEqual(probe.order, ['a', 'b', 'c', 'd'],
        'submission order must match id order: a descending nonce arrival is Code 4 "nonce too low"');
    assert.deepEqual(results.map((entry) => entry.id), ['a', 'b', 'c', 'd']);
    assert.ok(results.every((entry) => entry.status === 'fulfilled'));
});

test('a mid-list failure does not discard its siblings', async () => {
    // The exact defect in the old Promise.all branch: 'b' throws, and every
    // other card's outcome was lost with it.
    const attempted = [];
    const results = await runSequential(['a', 'b', 'c'], async (id) => {
        attempted.push(id);
        if (id === 'b') throw new Error('consensus rejected');
        return { status: 'consensus_submitted' };
    });

    assert.deepEqual(attempted, ['a', 'b', 'c'], 'the run must continue past a failure');
    assert.deepEqual(results.map((entry) => entry.status), ['fulfilled', 'rejected', 'fulfilled']);
    assert.equal(results[1].reason.message, 'consensus rejected');
});

test('runSequential tolerates a missing id list', async () => {
    assert.deepEqual(await runSequential(undefined, async () => 1), []);
});

test('cleared-column toast precedence: rejection outranks challenge outranks settling', async () => {
    const rejected = { id: 'r', status: 'rejected', reason: new Error('nonce too low') };
    const challenged = { id: 'c', status: 'fulfilled', value: { status: 'challenge_opened' } };
    const ok = { id: 'o', status: 'fulfilled', value: { status: 'consensus_submitted' } };

    // A rejection wins even when a challenge and a still-settling card coexist,
    // and the cleared count comes from the reconciled board, not the results.
    const hard = summarizeClearedTasks({
        results: [rejected, challenged, ok],
        remaining: [{ memory_id: 'r' }],
        total: 3,
        label: 'Done',
    });
    assert.equal(hard.tone, 'error');
    assert.equal(hard.message, '2 tasks cleared; 1 needs attention: nonce too low');

    const challenge = summarizeClearedTasks({
        results: [challenged, ok], remaining: [{ memory_id: 'c' }], total: 2, label: 'Done',
    });
    assert.equal(challenge.tone, 'warning');
    assert.equal(challenge.message,
        '1 task needs confirmation from another eligible domain manager before removal.');

    const settling = summarizeClearedTasks({
        results: [ok, ok], remaining: [{ memory_id: 'o' }, { memory_id: 'o2' }], total: 2, label: 'Done',
    });
    assert.equal(settling.tone, 'warning');
    assert.equal(settling.message,
        'SAGE is still confirming 2 tasks; the board will keep them visible until confirmation finishes.');

    const clean = summarizeClearedTasks({ results: [ok, ok], remaining: [], total: 2, label: 'Done' });
    assert.deepEqual(clean, { tone: 'success', message: 'Cleared 2 Done tasks' });

    const single = summarizeClearedTasks({ results: [ok], remaining: [], total: 1, label: 'Dropped' });
    assert.equal(single.message, 'Cleared 1 Dropped task');
});

test('cleared-column rejection names the first failure and falls back when it has no message', () => {
    const first = { id: 'a', status: 'rejected', reason: new Error('first cause') };
    const second = { id: 'b', status: 'rejected', reason: new Error('second cause') };
    assert.match(
        summarizeClearedTasks({ results: [first, second], remaining: [], total: 2, label: 'Done' }).message,
        /first cause$/,
    );
    assert.match(
        summarizeClearedTasks({
            results: [{ id: 'a', status: 'rejected', reason: undefined }],
            remaining: [{ memory_id: 'a' }],
            total: 1,
            label: 'Done',
        }).message,
        /a request was rejected$/,
    );
});

test('dropped-column reports partial success instead of losing it', () => {
    const ok = { id: 'a', status: 'fulfilled', value: {} };
    assert.deepEqual(
        summarizeDroppedTasks({ results: [ok, ok, ok], total: 3, label: 'Planned' }),
        { tone: 'success', message: 'Moved 3 Planned tasks to Dropped' },
    );

    // Regression: the old Promise.all threw on the first failure, so the two
    // cards that DID move were never mentioned and could not be reconciled.
    const partial = summarizeDroppedTasks({
        results: [ok, { id: 'b', status: 'rejected', reason: new Error('task is terminal') }, ok],
        total: 3,
        label: 'Planned',
    });
    assert.equal(partial.tone, 'error');
    assert.equal(partial.message, '2 tasks moved to Dropped; 1 needs attention: task is terminal');

    const allFailed = summarizeDroppedTasks({
        results: [
            { id: 'a', status: 'rejected', reason: new Error('offline') },
            { id: 'b', status: 'rejected', reason: new Error('offline') },
        ],
        total: 2,
        label: 'Planned',
    });
    assert.equal(allFailed.message, '0 tasks moved to Dropped; 2 need attention: offline');
});

test('bulk forget stays silent on full success so runBulk keeps its own message', () => {
    const ok = { id: 'a', status: 'fulfilled', value: { status: 'deprecated' } };
    assert.equal(summarizeForgottenMemories([ok, ok]), null);

    const partial = summarizeForgottenMemories([
        ok,
        { id: 'b', status: 'rejected', reason: new Error('memory deprecation was rejected') },
    ]);
    assert.equal(partial.tone, 'error');
    assert.equal(partial.message,
        '1 memory forgotten; 1 needs attention: memory deprecation was rejected');
});

// --- regression coverage -------------------------------------------------
//
// The tests above feed the summarizers hand-written result literals, which
// leaves the seam between runSequential and the summarizers unpinned: change
// the entry shape runSequential emits (drop `value`, rename `reason`) and every
// summarizer test still passes while every toast in CEREBRUM silently
// degrades. The tests below drive the summarizers with results runSequential
// actually produced, from operations that return what api.js returns.

test('a rejection does not break sequencing for the ids after it', async () => {
    // The old Promise.all abandoned the batch at the first failure. The
    // replacement must keep going AND keep going one-at-a-time: resuming
    // concurrently after a failure would reintroduce the same-key nonce race
    // for the remaining cards.
    const probe = serialityProbe();
    const results = await runSequential(['a', 'b', 'c', 'd'], async (id) => {
        if (id === 'b') {
            // Fail on a real turn of the event loop, not synchronously, so a
            // broken implementation cannot accidentally stay ordered.
            await new Promise((resolve) => setTimeout(resolve, 0));
            throw new Error('tx rejected in FinalizeBlock (code 4): nonce too low');
        }
        return probe.operation(id);
    });

    assert.deepEqual(probe.order, ['a', 'c', 'd'],
        'the ids after a failure must still be submitted strictly in order');
    assert.deepEqual(results.map((entry) => entry.id), ['a', 'b', 'c', 'd'],
        'every id must be reported, in id order, regardless of which one failed');
    assert.deepEqual(results.map((entry) => entry.status),
        ['fulfilled', 'rejected', 'fulfilled', 'fulfilled']);
});

test('clearing a terminal column reports the real fan-out end to end', async () => {
    // deleteMemory's three real outcomes in one batch: accepted, a multi-holder
    // challenge, and a consensus rejection.
    const submitted = [];
    const results = await runSequential(['m1', 'm2', 'm3'], async (id) => {
        submitted.push(id);
        if (id === 'm2') return { status: 'challenge_opened' };
        if (id === 'm3') throw new Error('tx rejected in FinalizeBlock (code 4): nonce too low');
        return { status: 'deprecated' };
    });

    assert.deepEqual(submitted, ['m1', 'm2', 'm3']);
    // m3 never cleared, so reconcileClearedTasks still finds it on the board.
    const outcome = summarizeClearedTasks({
        results, remaining: [{ memory_id: 'm3' }], total: 3, label: 'Done',
    });
    assert.equal(outcome.tone, 'error');
    assert.equal(outcome.message,
        '2 tasks cleared; 1 needs attention: tx rejected in FinalizeBlock (code 4): nonce too low');
});

test('a challenge raised by the real fan-out outranks cards still settling', async () => {
    const results = await runSequential(['m1', 'm2'], async (id) => (
        id === 'm2' ? { status: 'challenge_opened' } : { status: 'deprecated' }
    ));
    const outcome = summarizeClearedTasks({
        results, remaining: [{ memory_id: 'm2' }], total: 2, label: 'Done',
    });
    assert.equal(outcome.tone, 'warning');
    assert.equal(outcome.message,
        '1 task needs confirmation from another eligible domain manager before removal.');
});

test('a fan-out that resolves without a body is not mistaken for a challenge', async () => {
    // updateMemory-style endpoints can resolve to undefined/null. That must read
    // as "accepted", not as an opened challenge.
    const results = await runSequential(['m1', 'm2'], async () => undefined);
    assert.deepEqual(
        summarizeClearedTasks({ results, remaining: [], total: 2, label: 'Done' }),
        { tone: 'success', message: 'Cleared 2 Done tasks' },
    );
});

test('clearing a non-terminal column reports partial success end to end', async () => {
    // This is the branch that was Promise.all: 'p2' rejecting used to throw out
    // of clearColumn, discarding the fact that p1 and p3 DID move to Dropped and
    // leaving the operator with a generic "could not clear column".
    const submitted = [];
    const results = await runSequential(['p1', 'p2', 'p3'], async (id) => {
        submitted.push(id);
        if (id === 'p2') throw new Error('task is already terminal');
        return { status: 'dropped' };
    });

    assert.deepEqual(submitted, ['p1', 'p2', 'p3'],
        'a mid-list failure must not stop the remaining cards from being submitted');
    const outcome = summarizeDroppedTasks({ results, total: 3, label: 'Planned' });
    assert.equal(outcome.tone, 'error');
    assert.equal(outcome.message, '2 tasks moved to Dropped; 1 needs attention: task is already terminal');
    assert.notEqual(outcome.tone, 'success',
        'a non-success tone is what makes clearColumn reload the board so the operator sees which cards stayed');
});

test('bulk forget end to end: silent on success, specific on partial failure', async () => {
    const allOK = await runSequential(['a', 'b'], async () => ({ status: 'deprecated' }));
    assert.equal(summarizeForgottenMemories(allOK), null,
        'full success must fall through to runBulk\'s own "Forgot %n memories"');

    const partial = await runSequential(['a', 'b', 'c'], async (id) => {
        if (id === 'b') throw new Error('not authorized to forget this memory');
        return { status: 'deprecated' };
    });
    const outcome = summarizeForgottenMemories(partial);
    assert.equal(outcome.tone, 'error');
    assert.equal(outcome.message, '2 memories forgotten; 1 needs attention: not authorized to forget this memory');
});

test('a non-Error rejection still produces a usable toast', async () => {
    // fetch() wrappers in api.js throw Errors, but a rejected promise can carry
    // anything; the summary must not become "undefined" or throw.
    const results = await runSequential(['a'], async () => { throw 'plain string'; });
    assert.equal(results[0].status, 'rejected');
    assert.equal(
        summarizeDroppedTasks({ results, total: 1, label: 'Planned' }).message,
        '0 tasks moved to Dropped; 1 needs attention: a request was rejected',
    );
});
