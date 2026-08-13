import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { createModeHull } from '../web/static/js/mode-hull.js';

// Per-view skull-opacity state for the CEREBRUM brain. These tests pin the four
// behaviours the review called for: correct initial per-view defaults, the slider
// reflecting the active view's value, a manual adjustment persisting across a mode
// round trip, and per-view state staying independent. Half the coverage is the
// pure state machine (createModeHull); half is source wiring in mri-brain.js, so
// reverting EITHER the module logic OR its wiring fails a test — the regression the
// first cut of this change lacked.

const DEFAULTS = { memory: 0.08, connectome: 0.03 };

test('initial per-view values are the defaults', () => {
  const h = createModeHull(DEFAULTS);
  assert.equal(h.valueFor('memory'), 0.08);
  assert.equal(h.valueFor('connectome'), 0.03);
});

test('a recorded manual value persists across a mode round trip', () => {
  const h = createModeHull(DEFAULTS);
  // operator drags the SKULL slider while in the connectome
  h.record('connectome', 0.2);
  // ... toggles to memory and back — the connectome value must survive
  assert.equal(h.valueFor('memory'), 0.08);
  assert.equal(h.valueFor('connectome'), 0.2, 'manual choice retained across the round trip');
});

test('per-view state is independent — recording one view never moves the other', () => {
  const h = createModeHull(DEFAULTS);
  h.record('memory', 0.5);
  assert.equal(h.valueFor('memory'), 0.5);
  assert.equal(h.valueFor('connectome'), 0.03, 'connectome untouched by a memory adjustment');
  h.record('connectome', 0.01);
  assert.equal(h.valueFor('memory'), 0.5, 'memory untouched by a connectome adjustment');
  assert.equal(h.valueFor('connectome'), 0.01);
});

test('unknown modes fall back to a default rather than undefined', () => {
  const h = createModeHull(DEFAULTS);
  assert.equal(h.valueFor('nope'), 0.08);
  h.record('nope', 0.9);                 // no-op for an unknown view
  assert.equal(h.valueFor('memory'), 0.08);
  assert.equal(h.valueFor('connectome'), 0.03);
});

test('defaults() returns a copy, not the live state', () => {
  const h = createModeHull(DEFAULTS);
  const d = h.defaults();
  d.memory = 999;
  assert.equal(h.valueFor('memory'), 0.08, 'mutating the returned defaults must not leak into state');
});

// --- Source wiring: mri-brain.js must USE the state, not slam a fixed default ---
const mriSource = await readFile(new URL('../web/static/js/mri-brain.js', import.meta.url), 'utf8');

test('mri-brain seeds per-view defaults (memory 0.08, connectome 0.03) via createModeHull', () => {
  assert.match(mriSource, /createModeHull\(\s*\{\s*memory:\s*0\.08,\s*connectome:\s*0\.03\s*\}\s*\)/,
    'the two initial defaults must come from createModeHull');
});

test('mode toggle recalls the view value (not a constant) and reflects it on the slider', () => {
  // setMode reads hullState.valueFor(...) then updates the .b-op slider + hull
  assert.match(mriSource, /hullState\.valueFor\(mode\)/, 'setMode/init must read the remembered value');
  assert.match(mriSource, /opEl\.value\s*=\s*sliderUnits\(/, 'the slider must reflect the recalled value');
});

test('a manual slider adjustment is recorded for the active view', () => {
  // the .b-op oninput handler must persist the operator choice per view
  assert.match(mriSource, /\.b-op'\)\.oninput=function\(\)\{[^}]*hullState\.record\(mode,/,
    'dragging the SKULL slider must record the value for the active view');
});

test('the initial hull opacity is seeded from the state, not a hardcoded 0.08', () => {
  assert.match(mriSource, /curOpacity\s*=\s*hullState\.valueFor\(mode\)/,
    'curOpacity must initialize from the per-view state');
});

// Extract a function body by brace matching, so a wiring assertion is SCOPED to
// that function — a whole-file grep would still pass if the call had drifted into
// a different function, which is exactly the gap this closes.
function functionBody(src, name) {
  const start = src.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name}() not found in source`);
  const open = src.indexOf('{', start);
  let depth = 0;
  let i = open;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) break;
  }
  return src.slice(open + 1, i);
}

// The regression the previous cut missed: setMode() must APPLY the recalled
// opacity to the visible hull, not merely move the slider. Scoped to the setMode
// body and bound to the SAME nextOpacity variable, so deleting or substituting
// setHullOpacity(nextOpacity) fails — the slider and the 3D hull cannot drift
// apart on a mode toggle.
test('setMode binds the recalled opacity through BOTH the slider and the hull material', () => {
  const body = functionBody(mriSource, 'setMode');
  assert.match(body, /const nextOpacity\s*=\s*hullState\.valueFor\(mode\)/,
    'setMode must recall the per-view opacity into nextOpacity');
  assert.match(body, /opEl\.value\s*=\s*sliderUnits\(nextOpacity\)/,
    'the slider must reflect the recalled nextOpacity');
  assert.match(body, /setHullOpacity\(nextOpacity\)/,
    'the visible hull must be updated with the SAME nextOpacity — deleting or substituting this must fail');
});
