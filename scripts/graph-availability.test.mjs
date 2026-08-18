import test from 'node:test';
import assert from 'node:assert/strict';

import { graphAvailabilityAfterFailure } from '../web/static/js/graph-availability.js';

test('same-mode refresh failure keeps the last verified graph available', () => {
  assert.equal(graphAvailabilityAfterFailure(true, 'memory', 'memory'), 'ready');
  assert.equal(graphAvailabilityAfterFailure(true, 'connectome', 'connectome'), 'ready');
});

test('same-mode post-render initialization failure keeps the verified core graph available', () => {
  // The caller passes true only after ForceGraph has adopted the verified bytes.
  // Optional HUD/hull/control setup can fail after that boundary without turning
  // the already-visible brain into a synthetic cold failure.
  assert.equal(graphAvailabilityAfterFailure(true, 'memory', 'memory'), 'ready');
});

test('cold failures and failed mode switches remain unavailable', () => {
  assert.equal(graphAvailabilityAfterFailure(false, null, 'memory'), 'unavailable');
  assert.equal(graphAvailabilityAfterFailure(true, 'connectome', 'memory'), 'unavailable');
  assert.equal(graphAvailabilityAfterFailure(true, 'memory', 'connectome'), 'unavailable');
});
