// Sequencing and outcome-reporting for CEREBRUM's multi-record actions
// (clearing a board column, bulk-forgetting selected memories), extracted so
// both the ordering and the toast precedence are unit-testable.
//
// Why these fan out ONE AT A TIME. Every one of these actions used to issue N
// concurrent requests that all reach the node with the same signing key. Each
// one stamps a strictly-increasing app-v9 replay nonce, but nothing tied that
// nonce to the moment the transaction was actually submitted, so the batch
// could arrive out of order and consensus rejected the late-arriving lower
// nonce ("nonce too low", Code 4) — a random subset of the cards failed while
// the rest cleared. internal/tx.WithNonceLease now makes the server correct
// regardless of what the browser does, but it does so by SERIALIZING same-key
// submissions internally: firing N concurrent requests would just pile N
// browser connections and N server goroutines up behind that lease, each
// holding a commit-confirmed broadcast open while every predecessor commits,
// and the tail requests are the ones that time out. Sequencing here costs the
// same wall-clock time, keeps the queue where it is cheap, and is what makes
// per-record partial success reportable at all.

// Run operation over ids strictly one at a time, settling every id.
//
// Returns one entry per id, in id order, shaped like Promise.allSettled's
// results plus the id itself: { id, status: 'fulfilled', value } or
// { id, status: 'rejected', reason }. Never rejects — a mid-list failure must
// not discard its siblings' outcomes, which is exactly what Promise.all did.
export async function runSequential(ids, operation) {
    const list = Array.isArray(ids) ? ids : [];
    const results = [];
    for (const id of list) {
        try {
            results.push({ id, status: 'fulfilled', value: await operation(id) });
        } catch (reason) {
            results.push({ id, status: 'rejected', reason });
        }
    }
    return results;
}

function rejections(results) {
    return (Array.isArray(results) ? results : []).filter(entry => entry.status === 'rejected');
}

// The first failure by id order is the one worth naming: the operator sees the
// cards in that order, and a batch usually fails for one shared reason.
function firstFailureDetail(rejected) {
    return rejected[0]?.reason?.message || 'a request was rejected';
}

// Toast for a terminal (Done/Dropped) column clear.
//
// `remaining` is what reconcileClearedTasks still saw on the board after the
// bounded settle wait. Precedence is deliberate and unchanged: a hard rejection
// outranks an opened challenge, which outranks records that are merely still
// settling — the operator must hear about the thing that needs them first.
export function summarizeClearedTasks({ results, remaining, total, label }) {
    const rejected = rejections(results);
    const stillVisible = Array.isArray(remaining) ? remaining.length : 0;

    if (rejected.length) {
        // Count from the board, not from the results: a request can fail after
        // consensus already accepted it, and the reconciled board is the truth.
        const resolved = total - stillVisible;
        return {
            tone: 'error',
            message: `${resolved} task${resolved === 1 ? '' : 's'} cleared; `
                + `${rejected.length} need${rejected.length === 1 ? 's' : ''} attention: `
                + firstFailureDetail(rejected),
        };
    }
    const challenges = (Array.isArray(results) ? results : []).filter(entry =>
        entry.status === 'fulfilled' && entry.value && entry.value.status === 'challenge_opened');
    if (challenges.length) {
        return {
            tone: 'warning',
            message: `${challenges.length} task${challenges.length === 1 ? ' needs' : 's need'} `
                + 'confirmation from another eligible domain manager before removal.',
        };
    }
    if (stillVisible) {
        return {
            tone: 'warning',
            message: `SAGE is still confirming ${stillVisible} task${stillVisible === 1 ? '' : 's'}; `
                + 'the board will keep them visible until confirmation finishes.',
        };
    }
    return { tone: 'success', message: `Cleared ${total} ${label} task${total !== 1 ? 's' : ''}` };
}

// Toast for a non-terminal column clear (move every card to Dropped).
//
// This branch used to be a Promise.all, so one failure threw away every
// sibling's outcome and the operator was told only "could not clear column" —
// with no way to know which cards actually moved. Report partial success the
// way the terminal branch does.
export function summarizeDroppedTasks({ results, total, label }) {
    const rejected = rejections(results);
    if (!rejected.length) {
        return { tone: 'success', message: `Moved ${total} ${label} task${total !== 1 ? 's' : ''} to Dropped` };
    }
    const moved = total - rejected.length;
    return {
        tone: 'error',
        message: `${moved} task${moved === 1 ? '' : 's'} moved to Dropped; `
            + `${rejected.length} need${rejected.length === 1 ? 's' : ''} attention: `
            + firstFailureDetail(rejected),
    };
}

// Toast for bulk memory forget. Returns null when every id succeeded, which
// tells runBulk to keep its own flat success message; a summary is produced
// only when there is partial failure to describe.
export function summarizeForgottenMemories(results) {
    const rejected = rejections(results);
    if (!rejected.length) return null;
    const forgotten = (Array.isArray(results) ? results.length : 0) - rejected.length;
    return {
        tone: 'error',
        message: `${forgotten} ${forgotten === 1 ? 'memory' : 'memories'} forgotten; `
            + `${rejected.length} need${rejected.length === 1 ? 's' : ''} attention: `
            + firstFailureDetail(rejected),
    };
}
