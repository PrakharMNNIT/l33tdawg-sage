import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { synapsePlasticity } from '../web/static/js/connectome-map.js';

// Resting-weight plasticity ("use it or lose it"): a synapse's retained strength
// decays from its raw weight toward a floor the longer it sits idle, and snaps back
// as it fires. These tests pin the decay curve (pure synapsePlasticity) and the
// mri-brain wiring that renders it, scoped so reverting either fails.

const HL = 1800000; // 30 min default half-life
const FLOOR = 0.15;
const T0 = Date.parse('2026-08-14T12:00:00Z');

test('a just-fired synapse is at full strength (1.0)', () => {
  assert.equal(synapsePlasticity('2026-08-14T12:00:00Z', T0), 1);
});

test('one half-life of idleness decays halfway from 1 toward the floor', () => {
  const v = synapsePlasticity('2026-08-14T11:30:00Z', T0);      // 30 min idle
  assert.ok(Math.abs(v - (FLOOR + (1 - FLOOR) * 0.5)) < 1e-9, `got ${v}`); // 0.575
});

test('two half-lives decay a quarter of the way up from the floor', () => {
  const v = synapsePlasticity('2026-08-14T11:00:00Z', T0);      // 60 min idle
  assert.ok(Math.abs(v - (FLOOR + (1 - FLOOR) * 0.25)) < 1e-9, `got ${v}`); // 0.3625
});

test('decay is monotonic and bounded in [floor, 1]', () => {
  let prev = 1.0001;
  for (let mins = 0; mins <= 600; mins += 15) {
    const iso = new Date(T0 - mins * 60000).toISOString();
    const v = synapsePlasticity(iso, T0);
    assert.ok(v <= 1 && v >= FLOOR, `out of range at ${mins}m: ${v}`);
    assert.ok(v <= prev, `not monotonic at ${mins}m: ${v} > ${prev}`);
    prev = v;
  }
});

test('a long-idle synapse asymptotes to the floor but never below it', () => {
  const v = synapsePlasticity('2020-01-01T00:00:00Z', T0);      // years idle
  assert.ok(v >= FLOOR && v < FLOOR + 0.001, `got ${v}`);
});

test('missing or unparseable last_fired is treated as fully idle (floor)', () => {
  assert.equal(synapsePlasticity('', T0), FLOOR);
  assert.equal(synapsePlasticity(null, T0), FLOOR);
  assert.equal(synapsePlasticity(undefined, T0), FLOOR);
  assert.equal(synapsePlasticity('not-a-date', T0), FLOOR);
});

test('a future last_fired (clock skew) clamps to full strength, not >1', () => {
  assert.equal(synapsePlasticity('2026-08-14T12:05:00Z', T0), 1);
});

test('half-life and floor are configurable', () => {
  // custom floor 0.3, custom half-life 10 min; at 10 min idle → 0.3 + 0.7*0.5 = 0.65
  const v = synapsePlasticity('2026-08-14T11:50:00Z', T0, { halfLifeMs: 600000, floor: 0.3 });
  assert.ok(Math.abs(v - 0.65) < 1e-9, `got ${v}`);
});

// --- Source wiring: mri-brain must RENDER the decayed weight, not raw _w ---
const mriSource = await readFile(new URL('../web/static/js/mri-brain.js', import.meta.url), 'utf8');

function functionBody(src, name) {
  const start = src.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `${name}() not found`);
  const open = src.indexOf('{', start);
  let depth = 0, i = open;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) break;
  }
  return src.slice(open + 1, i);
}

test('restingWeight is the raw weight scaled by the plasticity factor', () => {
  assert.match(mriSource, /restingWeight\s*=\s*l\s*=>\s*\(l\._w\|\|0\)\s*\*\s*plasticityOf\(l\)/,
    'restingWeight must be _w * plasticityOf(l)');
  assert.match(mriSource, /plasticityOf\s*=\s*l\s*=>\s*synapsePlasticity\(/,
    'plasticityOf must call synapsePlasticity');
});

test('synapse width renders the DECAYED resting weight, not raw _w', () => {
  const body = functionBody(mriSource, 'linkWidthFor');
  assert.match(body, /link_type==='synapse'/);
  assert.match(body, /restingWeight\(l\)\*2\.4/,
    'the synapse width term must use restingWeight(l), so deleting plasticity fails');
  assert.doesNotMatch(body, /\(l\._w\|\|0\)\*2\.4/,
    'width must NOT fall back to the raw undecayed _w term');
});

test('synapse colour alpha rides the plasticity factor so idle edges dim', () => {
  const body = functionBody(mriSource, 'linkColorFor');
  assert.match(body, /link_type==='synapse'/);
  assert.match(body, /plasticityOf\(l\)/,
    'the synapse colour alpha must scale with plasticityOf(l)');
});

test('an idle connectome re-reads its accessors on a timer, cleaned up on dispose', () => {
  const body = functionBody(mriSource, 'startPlasticityDecay');
  assert.match(body, /setInterval/, 'plasticity decay must run on an interval');
  assert.match(body, /mode\s*!==\s*'connectome'/, 'the timer must self-gate to connectome mode');
  assert.match(body, /linkWidth\(linkWidthFor\)\.linkColor\(linkColorFor\)/,
    'the refresh must re-apply the decayed width AND colour');
  assert.match(mriSource, /clearInterval\(plasticityTimer\)/,
    'the plasticity timer must be cleared on cleanup');
});

// Particle COUNT and SPEED both carry the Hebbian signal, so both must render the
// decayed restingWeight with no raw-_w fallback — otherwise idle synapses keep
// firing particles at full historical rate while only their width fades.
test('synapse particle count renders restingWeight, not raw _w', () => {
  const body = functionBody(mriSource, 'linkParticlesFor');
  assert.match(body, /link_type==='synapse'/);
  assert.match(body, /restingWeight\(l\)\*5/,
    'particle count must scale on restingWeight(l), so reverting to _w fails');
  assert.doesNotMatch(body, /\(l\._w\|\|0\)\*5/,
    'particle count must NOT fall back to the raw undecayed _w term');
});

test('synapse particle speed renders restingWeight, not raw _w', () => {
  const body = functionBody(mriSource, 'linkParticleSpeedFor');
  assert.match(body, /link_type==='synapse'/);
  assert.match(body, /restingWeight\(l\)\*0\.02/,
    'particle speed must scale on restingWeight(l), so reverting to _w fails');
  assert.doesNotMatch(body, /\(l\._w\|\|0\)\*0\.02/,
    'particle speed must NOT fall back to the raw undecayed _w term');
});

test('the plasticity refresh re-applies the particle accessor, not just width/colour', () => {
  const body = functionBody(mriSource, 'startPlasticityDecay');
  assert.match(body, /linkDirectionalParticles\(linkParticlesFor\)/,
    'dropping linkDirectionalParticles from the refresh must fail — particle count is decayed too');
});
