const GOVERNANCE_COOLDOWN = /proposer [0-9a-f]+ is in cooldown until block (\d+) \(current: (\d+)\)/i;

export function parseGovernanceCooldown(error) {
    const message = String(error?.message || error || '');
    const match = GOVERNANCE_COOLDOWN.exec(message);
    if (!match) return null;
    const until = Number(match[1]);
    const current = Number(match[2]);
    if (!Number.isSafeInteger(until) || !Number.isSafeInteger(current) || until <= current) return null;
    return { until, current };
}

const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

// An idle SAGE deliberately emits no empty blocks. A rejected proposal still
// commits a block, so an explicitly confirmed bulk operation can progress
// through the existing cooldown. Only the exact cooldown is retried.
export async function runWithGovernanceCooldown(operation, {
    onCooldown = () => {},
    sleep = pause,
    retryDelayMs = 250,
    maxRetries = 64,
} = {}) {
    let retries = 0;
    let previousCurrent = -1;
    while (true) {
        try {
            return await operation();
        } catch (error) {
            const cooldown = parseGovernanceCooldown(error);
            if (!cooldown || retries >= maxRetries || cooldown.current < previousCurrent) throw error;
            previousCurrent = cooldown.current;
            retries += 1;
            onCooldown({ ...cooldown, retries });
            await sleep(retryDelayMs);
        }
    }
}

let transferQueueTail = Promise.resolve();
let transferQueueDepth = 0;

// The queue belongs to the loaded CEREBRUM application, not to an Access
// Controls component. Hash-route navigation can unmount the initiating panel
// without cancelling its confirmed transfer, and a later confirmation joins
// the same serial governance lane instead of racing the active proposal.
export function enqueueGovernedTransfer(operation) {
    const position = transferQueueDepth + 1;
    transferQueueDepth += 1;
    const promise = transferQueueTail
        .catch(() => {})
        .then(operation)
        .finally(() => { transferQueueDepth -= 1; });
    transferQueueTail = promise;
    return { position, promise };
}
