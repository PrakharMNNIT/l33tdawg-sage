import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const expectedDashboardEvents = [
  'remember', 'recall', 'forget', 'vote', 'consensus', 'agent',
  'import', 'update', 'governance', 'task', 'recovery', 'access',
  'connectome', 'reinstate', 'cocommit', 'search', 'hybrid',
  'pipeline_send', 'pipeline_complete', 'redeploy',
];

const source = readFileSync(new URL('../web/static/js/sse.js', import.meta.url), 'utf8');
let importSequence = 0;

async function captureSubscriptions(moduleSource) {
  class FakeEventSource {
    static latest;

    constructor(url) {
      this.url = url;
      this.listeners = new Map();
      FakeEventSource.latest = this;
    }

    addEventListener(name, callback) {
      const callbacks = this.listeners.get(name) || [];
      callbacks.push(callback);
      this.listeners.set(name, callbacks);
    }

    dispatch(name, data) {
      for (const callback of this.listeners.get(name) || []) {
        callback({ data: JSON.stringify(data) });
      }
    }

    close() {}
  }

  const previous = globalThis.EventSource;
  globalThis.EventSource = FakeEventSource;
  try {
    const encoded = Buffer.from(moduleSource).toString('base64');
    const module = await import(`data:text/javascript;base64,${encoded}#${importSequence++}`);
    const client = new module.SSEClient('/v1/dashboard/events');
    client.connect();
    const eventSource = FakeEventSource.latest;
    return {
      client,
      eventSource,
      names: [...eventSource.listeners.keys()].sort(),
    };
  } finally {
    globalThis.EventSource = previous;
  }
}

test('dashboard SSE client subscribes behaviorally to the exact 20-event registry', async () => {
  const capture = await captureSubscriptions(source);
  assert.deepEqual(capture.names, [...expectedDashboardEvents].sort());
  assert.equal(new Set(capture.names).size, 20);

  const delivered = [];
  const any = [];
  for (const eventName of expectedDashboardEvents) {
    capture.client.on(eventName, payload => delivered.push([eventName, payload.event]));
  }
  capture.client.on('any', payload => any.push(payload.event));

  for (const eventName of expectedDashboardEvents) {
    capture.eventSource.dispatch(eventName, { event: eventName });
  }

  assert.deepEqual(delivered, expectedDashboardEvents.map(name => [name, name]));
  assert.deepEqual(any, expectedDashboardEvents);
});

test('behavior harness rejects inert listener-loop substring decoys', async () => {
  const marker = 'for (const type of eventTypes) {';
  assert.equal(source.split(marker).length - 1, 1);
  const mutated = source.replace(
    marker,
    `if (false) ${marker}`,
  ) + `
const inertDecoy = "for (const type of eventTypes) { this.es.addEventListener(type, () => {}); }";
void inertDecoy;
`;
  const capture = await captureSubscriptions(mutated);
  assert.deepEqual(capture.names, []);
  assert.notDeepEqual(capture.names, [...expectedDashboardEvents].sort());
});

test('behavior harness rejects pre-loop registry mutation and executable decoys', async () => {
  const marker = 'for (const type of eventTypes) {';
  const mutated = source.replace(
    marker,
    `eventTypes.splice(0, eventTypes.length, 'decoy');\n        ${marker}`,
  );
  const capture = await captureSubscriptions(mutated);
  assert.deepEqual(capture.names, ['decoy']);
  assert.notDeepEqual(capture.names, [...expectedDashboardEvents].sort());
});
