import test from 'node:test';
import assert from 'node:assert/strict';

import { refreshTaskSnapshot } from '../web/static/js/task-refresh.js';

function stateHarness() {
  const state = { tasks: [], domains: [], error: null };
  return {
    state,
    sinks: {
      setTasks: value => { state.tasks = value; },
      setDomains: value => { state.domains = value; },
      setError: value => { state.error = value; },
    },
  };
}

test('a silent success clears a prior visible task-load error', async () => {
  const { state, sinks } = stateHarness();
  const failure = new Error('offline');

  await assert.rejects(refreshTaskSnapshot({
    fetcher: async () => { throw failure; },
    silent: false,
    ...sinks,
  }), failure);
  assert.match(state.error, /could not load your task list/i);

  const tasks = [{ memory_id: 'm1', domain_tag: 'ops' }];
  const result = await refreshTaskSnapshot({
    fetcher: async () => ({ tasks }),
    silent: true,
    ...sinks,
  });
  assert.deepEqual(result, tasks);
  assert.deepEqual(state.tasks, tasks);
  assert.deepEqual(state.domains, ['ops']);
  assert.equal(state.error, null);
});

test('a silent task refresh rejects instead of fabricating an empty snapshot', async () => {
  const { state, sinks } = stateHarness();
  state.tasks = [{ memory_id: 'existing', domain_tag: 'ops' }];
  const failure = new Error('projection unavailable');

  await assert.rejects(refreshTaskSnapshot({
    fetcher: async () => { throw failure; },
    silent: true,
    ...sinks,
  }), failure);
  assert.deepEqual(state.tasks, [{ memory_id: 'existing', domain_tag: 'ops' }]);
  assert.equal(state.error, null, 'background failure must not replace the mounted board with an error surface');
});

test('settling tasks stay hidden while the canonical snapshot remains available to reconciliation', async () => {
  const { state, sinks } = stateHarness();
  const tasks = [
    { memory_id: 'settling', domain_tag: 'ops' },
    { memory_id: 'visible', domain_tag: 'eng' },
  ];

  const result = await refreshTaskSnapshot({
    fetcher: async () => ({ tasks }),
    settlingIDs: new Set(['settling']),
    silent: true,
    ...sinks,
  });
  assert.deepEqual(result, tasks);
  assert.deepEqual(state.tasks, [tasks[1]]);
  assert.deepEqual(state.domains, ['eng', 'ops']);
});

test('an older response cannot overwrite a newer task snapshot', async () => {
  const { state, sinks } = stateHarness();
  const resolvers = [];
  const fetcher = () => new Promise(resolve => resolvers.push(resolve));
  let generation = 0;

  const oldGeneration = ++generation;
  const oldRequest = refreshTaskSnapshot({
    fetcher,
    isCurrent: () => oldGeneration === generation,
    ...sinks,
  });
  const newGeneration = ++generation;
  const newRequest = refreshTaskSnapshot({
    fetcher,
    isCurrent: () => newGeneration === generation,
    ...sinks,
  });

  const newer = [{ memory_id: 'new', domain_tag: 'current' }];
  resolvers[1]({ tasks: newer });
  assert.deepEqual(await newRequest, newer);
  resolvers[0]({ tasks: [{ memory_id: 'old', domain_tag: 'stale' }] });
  assert.equal(await oldRequest, undefined, 'superseded responses are not authoritative');
  assert.deepEqual(state.tasks, newer);
  assert.deepEqual(state.domains, ['current']);
  assert.equal(state.error, null);
});

test('an older success cannot clear an error from a newer visible refresh', async () => {
  const { state, sinks } = stateHarness();
  let resolveOld;
  let generation = 0;
  const oldGeneration = ++generation;
  const oldRequest = refreshTaskSnapshot({
    fetcher: () => new Promise(resolve => { resolveOld = resolve; }),
    silent: true,
    isCurrent: () => oldGeneration === generation,
    ...sinks,
  });

  const newGeneration = ++generation;
  const failure = new Error('offline');
  await assert.rejects(refreshTaskSnapshot({
    fetcher: async () => { throw failure; },
    isCurrent: () => newGeneration === generation,
    ...sinks,
  }), failure);
  assert.match(state.error, /could not load your task list/i);

  resolveOld({ tasks: [{ memory_id: 'old' }] });
  assert.equal(await oldRequest, undefined);
  assert.match(state.error, /could not load your task list/i);
  assert.deepEqual(state.tasks, []);
});
