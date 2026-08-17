import test from 'node:test';
import assert from 'node:assert/strict';

import { graphAvailabilityAfterFailure } from '../web/static/js/graph-availability.js';

test('same-mode refresh failure keeps the last verified graph available', () => {
  assert.equal(graphAvailabilityAfterFailure(true, 'memory', 'memory'), 'ready');
  assert.equal(graphAvailabilityAfterFailure(true, 'connectome', 'connectome'), 'ready');
});

test('cold failures and failed mode switches remain unavailable', () => {
  assert.equal(graphAvailabilityAfterFailure(false, null, 'memory'), 'unavailable');
  assert.equal(graphAvailabilityAfterFailure(true, 'connectome', 'memory'), 'unavailable');
  assert.equal(graphAvailabilityAfterFailure(true, 'memory', 'connectome'), 'unavailable');
});
