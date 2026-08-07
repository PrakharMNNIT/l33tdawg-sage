import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';

import {
    createFederationJoinScanLifecycle,
    normalizeFederationJoinState,
} from '../web/static/js/federation-flow.js';

test('join terminal states are handled independently of protocol casing', () => {
    assert.equal(normalizeFederationJoinState('ABORTED'), 'aborted');
    assert.equal(normalizeFederationJoinState('EXPIRED'), 'expired');
    assert.equal(normalizeFederationJoinState(' active '), 'active');
    assert.equal(normalizeFederationJoinState(null), '');
});

test('closing or replacing the JOIN screen aborts its live scan request', async () => {
    const signals = [];
    const request = (_name, signal) => new Promise((resolve, reject) => {
        signals.push(signal);
        signal.addEventListener('abort', () => {
            const error = new Error('scan cancelled');
            error.name = 'AbortError';
            reject(error);
        }, { once: true });
    });
    const lifecycle = createFederationJoinScanLifecycle(request);

    const first = lifecycle.run('first');
    assert.equal(signals[0].aborted, false);
    const second = lifecycle.run('second');
    await assert.rejects(first, { name: 'AbortError' });
    assert.equal(signals[0].aborted, true, 'a replacement scan must cancel the old dial');
    assert.equal(signals[1].aborted, false);

    assert.equal(lifecycle.abort(), true, 'component unmount should cancel the active scan');
    await assert.rejects(second, { name: 'AbortError' });
    assert.equal(signals[1].aborted, true);
    assert.equal(lifecycle.abort(), false, 'unmount cleanup must be idempotent');
});

test('revoked connections are paired again and past rows can be hidden locally', async () => {
    const app = await readFile(new URL('../web/static/js/app.js', import.meta.url), 'utf8');

    assert.match(app, /Pair again with/);
    assert.match(app, /requires a new connection code and approval from both people/);
    assert.match(app, /Hide from this list/);
    assert.match(app, /sage-fed-hidden-past-connections/);
    assert.match(app, /activeChains[\s\S]*key\.startsWith\(chain \+ ':'\)/,
        'a fresh active pairing must clear old local dismissals for that peer generation');
});
