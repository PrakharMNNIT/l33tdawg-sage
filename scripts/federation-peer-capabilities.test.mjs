import assert from 'node:assert/strict';
import test from 'node:test';

import { federationPeerAgentCompatibility } from '../web/static/js/federation-peer-capabilities.js';

const currentCapabilities = [
  'federated-peer-export-read-v1',
  'federated-query-availability-v1',
  'federated-pipeline-v1',
  'linked-message-directory-enumeration-v1',
];

test('current peer advertises complete federated-agent compatibility', () => {
  const compatibility = federationPeerAgentCompatibility({
    reachable: true,
    capabilities: [...currentCapabilities, 'future-additive-capability-v1'],
  });

  assert.equal(compatibility.observed, true);
  assert.equal(compatibility.exportedRead, true);
  assert.equal(compatibility.agentMessaging, true);
  assert.equal(compatibility.linkedDirectory, true);
  assert.equal(compatibility.fullySupported, true);
  assert.deepEqual(compatibility.missing, []);
});

for (const missingReadCapability of [
  'federated-peer-export-read-v1',
  'federated-query-availability-v1',
]) {
  test(`exported reading requires ${missingReadCapability}`, () => {
    const compatibility = federationPeerAgentCompatibility({
      reachable: true,
      capabilities: currentCapabilities.filter(capability => capability !== missingReadCapability),
    });

    assert.equal(compatibility.exportedRead, false);
    assert.equal(compatibility.agentMessaging, true);
    assert.deepEqual(compatibility.missing, ['default cross-SAGE reading']);
  });
}

test('read and messaging compatibility remain independent', () => {
  const compatibility = federationPeerAgentCompatibility({
    reachable: true,
    capabilities: currentCapabilities.filter(capability => capability !== 'federated-pipeline-v1'),
  });

  assert.equal(compatibility.exportedRead, true);
  assert.equal(compatibility.agentMessaging, false);
  assert.equal(compatibility.linkedDirectory, true);
  assert.deepEqual(compatibility.missing, ['agent messaging']);
});

test('linked directory compatibility is reported independently', () => {
  const compatibility = federationPeerAgentCompatibility({
    reachable: true,
    capabilities: currentCapabilities.filter(capability => capability !== 'linked-message-directory-enumeration-v1'),
  });

  assert.equal(compatibility.exportedRead, true);
  assert.equal(compatibility.agentMessaging, true);
  assert.equal(compatibility.linkedDirectory, false);
  assert.deepEqual(compatibility.missing, ['federated recipient discovery']);
});

test('reachable legacy and malformed responses fail closed as unsupported', () => {
  for (const capabilities of [undefined, null, {}, [1, null, {}]]) {
    const compatibility = federationPeerAgentCompatibility({ reachable: true, capabilities });
    assert.equal(compatibility.observed, true);
    assert.equal(compatibility.fullySupported, false);
    assert.deepEqual(compatibility.missing, [
      'default cross-SAGE reading',
      'agent messaging',
      'federated recipient discovery',
    ]);
  }
});

test('offline or unchecked peers do not produce a mixed-version diagnosis', () => {
  for (const status of [undefined, null, {}, { reachable: false, capabilities: currentCapabilities }]) {
    const compatibility = federationPeerAgentCompatibility(status);
    assert.equal(compatibility.observed, false);
    assert.equal(compatibility.fullySupported, false);
    assert.deepEqual(compatibility.missing, []);
  }
});
