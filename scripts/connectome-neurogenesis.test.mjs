import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { neuronDormancy, createNeuronBirthTracker, mapConnectome, neuronTint, isLater, diffConnectomeActivity, instantKey } from '../web/static/js/connectome-map.js';

// Rung 5 — neurogenesis + pruning. New agents grow in; dormant ones grey out.
// Pure coverage of the dormancy ramp, the birth-diff tracker, and the per-neuron
// activity mapping, plus scoped mri-brain wiring so reverting the render fails.

const T0 = Date.parse('2026-08-14T12:00:00Z');
const HOUR = 3600000;

// --- neuronDormancy ---
test('a neuron active within liveMs is fully lively (0)', () => {
  assert.equal(neuronDormancy(new Date(T0 - 10 * 60000).toISOString(), T0), 0); // 10 min ago
});

test('a neuron idle past coldMs is fully dormant (1)', () => {
  assert.equal(neuronDormancy(new Date(T0 - 24 * HOUR).toISOString(), T0), 1);
});

test('dormancy ramps linearly between liveMs and coldMs', () => {
  // default live=1h, cold=12h; at 6.5h idle → (6.5-1)/(12-1) = 0.5
  const v = neuronDormancy(new Date(T0 - 6.5 * HOUR).toISOString(), T0);
  assert.ok(Math.abs(v - 0.5) < 1e-9, `got ${v}`);
});

test('a neuron that never fired (no activity) is fully dormant', () => {
  assert.equal(neuronDormancy('', T0), 1);
  assert.equal(neuronDormancy(null, T0), 1);
  assert.equal(neuronDormancy('not-a-date', T0), 1);
});

test('dormancy is bounded [0,1] and monotonic in idle time', () => {
  let prev = -1;
  for (let h = 0; h <= 24; h += 1) {
    const v = neuronDormancy(new Date(T0 - h * HOUR).toISOString(), T0);
    assert.ok(v >= 0 && v <= 1, `out of range at ${h}h: ${v}`);
    assert.ok(v >= prev, `not monotonic at ${h}h`);
    prev = v;
  }
});

test('live/cold thresholds are configurable', () => {
  // live=10min, cold=70min; at 40min → (40-10)/(70-10)=0.5
  const v = neuronDormancy(new Date(T0 - 40 * 60000).toISOString(), T0, { liveMs: 600000, coldMs: 4200000 });
  assert.ok(Math.abs(v - 0.5) < 1e-9, `got ${v}`);
});

// --- createNeuronBirthTracker ---
test('the first observation only seeds the baseline (no whole-graph birth)', () => {
  const t = createNeuronBirthTracker();
  assert.deepEqual(t.observe(['a', 'b', 'c']), []);
});

test('subsequent observations return only newly-appeared ids', () => {
  const t = createNeuronBirthTracker();
  t.observe(['a', 'b']);
  assert.deepEqual(t.observe(['a', 'b', 'c']).sort(), ['c']);
  assert.deepEqual(t.observe(['a', 'b', 'c']), [], 'no re-birth for existing ids');
  assert.deepEqual(t.observe(['a', 'b', 'c', 'd', 'e']).sort(), ['d', 'e']);
});

test('a removed id that returns later counts as a new birth again', () => {
  const t = createNeuronBirthTracker();
  t.observe(['a', 'b']);
  t.observe(['a']);                 // b left
  assert.deepEqual(t.observe(['a', 'b']), ['b'], 're-registration is a new birth');
});

test('reset clears the baseline so the next observe seeds again', () => {
  const t = createNeuronBirthTracker();
  t.observe(['a']);
  t.reset();
  assert.deepEqual(t.observe(['a', 'b']), [], 'post-reset observe re-seeds, no births');
});

// --- mapConnectome _activity ---
test('a neuron _activity is the most recent last_fired across its incident edges', () => {
  const g = mapConnectome({
    neurons: [{ agent_id: 'a' }, { agent_id: 'b' }, { agent_id: 'lonely' }],
    synapses: [
      { from_agent: 'a', to_agent: 'b', count: 1, last_fired: '2026-08-14T09:00:00Z' },
      { from_agent: 'b', to_agent: 'a', count: 1, last_fired: '2026-08-14T11:00:00Z' },
    ],
  });
  const by = Object.fromEntries(g.nodes.map(n => [n.agent_id, n]));
  assert.equal(by.a._activity, '2026-08-14T11:00:00Z', 'latest across both directions');
  assert.equal(by.b._activity, '2026-08-14T11:00:00Z');
  assert.equal(by.lonely._activity, '', 'a neuron with no edges has never fired');
});

// --- scoped mri-brain wiring ---
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

// --- neuronTint: pin the blend by NUMBERS so a no-op cannot survive ---
const HUE = [255, 107, 157]; // a domain hue

test('a lively neuron keeps its domain hue (no grey, no flare)', () => {
  const t = neuronTint(HUE, 0, 0, 0);
  assert.deepEqual([t.r, t.g, t.b], HUE);
  assert.equal(t.a, 0.72);
});

test('a fully dormant neuron greys toward the deprecated grey and loses alpha', () => {
  const t = neuronTint(HUE, 0, 1, 0);
  assert.deepEqual([t.r, t.g, t.b], [108, 120, 145], 'dorm=1 must land on the grey');
  assert.ok(Math.abs(t.a - 0.30) < 1e-9, `alpha must drop (0.72-0.42=0.30), got ${t.a}`);
});

test('a newborn neuron flares toward the bright accent at near-full alpha', () => {
  const t = neuronTint(HUE, 0, 0, 1);
  // flares most of the way toward the [120,235,255] accent: green + blue rise
  // sharply, red falls — a no-op blend (keeping the base hue) fails this.
  assert.ok(t.g > 200 && t.b > 220 && t.r < HUE[0], `expected a flare toward the accent, got ${t.r},${t.g},${t.b}`);
  assert.equal(t.a, 0.9, 'birth must lift alpha to near-full');
});

test('degree brightens a lively neuron toward white', () => {
  const t = neuronTint(HUE, 1, 0, 0);
  assert.ok(t.r > HUE[0] - 1 && t.g > HUE[1] && t.b > HUE[2], 'brighter than the base hue');
  assert.equal(t.a, 1);
});

test('nodeColorRGBA composes the neuron colour through neuronTint(dormancy, birth)', () => {
  const body = functionBody(mriSource, 'nodeColorRGBA');
  assert.match(body, /neuronTint\(hexToRgb\(domainColor\(n\.domain\)\),\s*n\._deg,\s*dormancyOf\(n\),\s*neuronBirthGlow\(n\)\)/,
    'the neuron branch must pass dormancy AND birth into neuronTint');
});

test('newborn neurons swell (nodeVal reads the birth glow)', () => {
  assert.match(mriSource, /n\.isNeuron[\s\S]{0,80}neuronBirthGlow\(n\)/,
    'the neuron nodeVal branch must add a birth-glow swell');
});

// --- births actually happen: stamped, CALLED from both load paths, live on SSE ---
test('markConnectomeBirths stamps _bornAt from the birth tracker', () => {
  const body = functionBody(mriSource, 'markConnectomeBirths');
  assert.match(body, /neuronBirths\.observe\(/, 'must diff neuron ids via the birth tracker');
  assert.match(body, /_bornAt = now/, 'newly-appeared neurons must be stamped _bornAt');
});

test('both load paths invoke markConnectomeBirths (deleting the call must fail)', () => {
  assert.match(functionBody(mriSource, 'load'), /markConnectomeBirths\(d\)/,
    'the reload path must run neurogenesis');
  assert.match(functionBody(mriSource, 'initializeGraph'), /markConnectomeBirths\(data\)/,
    'the initial acquisition must run neurogenesis');
});

test('a committed agent registration triggers a connectome-gated refetch', () => {
  // the new agent grows in only if the "agent" SSE event drives an authorized reload
  assert.match(mriSource, /opts\.sse\.on\('agent',\s*grow\)/, 'must subscribe to the agent SSE event');
  const src = mriSource;
  const gi = src.indexOf('const grow =');
  assert.notEqual(gi, -1, 'grow handler must exist');
  const grow = src.slice(gi, src.indexOf('};', gi));
  assert.match(grow, /mode !== 'connectome'/, 'refetch must self-gate to connectome');
  assert.match(grow, /load\(\)/, 'must refetch via the load path (cleanup/in-flight/retry owned there)');
  assert.match(src, /subs\.push\(\(\) => clearTimeout\(at\)\)/, 'the agent debounce timer must be cleaned up');
});

// --- timer re-application (both accessors the timer is responsible for) ---
test('the dormancy timer re-applies node colour, cleaned up on dispose', () => {
  const dorm = functionBody(mriSource, 'startDormancyDecay');
  assert.match(dorm, /setInterval/);
  assert.match(dorm, /mode\s*!==\s*'connectome'/, 'dormancy refresh must self-gate to connectome');
  assert.match(dorm, /Graph\.nodeColor\(nodeColorRGBA\)/, 'dropping the recolor from the timer must fail');
  assert.match(mriSource, /clearInterval\(dormancyTimer\)/, 'dormancy timer cleared on cleanup');
});

test('the birth-decay timer re-applies BOTH nodeVal and node colour', () => {
  const body = functionBody(mriSource, 'markConnectomeBirths');
  assert.match(body, /Graph\.nodeVal\(nodeVal\)\.nodeColor\(nodeColorRGBA\)/,
    'the birth glow must decay via both accessors, or the swell lingers');
  assert.match(mriSource, /clearTimeout\(birthDecayTimer\)/, 'birth timer cleared on cleanup');
});

// --- isLater / fractional-precision regression (finding 3) ---
test('isLater compares by instant, not lexically', () => {
  // '…00.1Z' (100ms) is lexically greater than '…00.12Z' (120ms) but earlier in time
  assert.equal(isLater('2026-08-14T12:00:00.12Z', '2026-08-14T12:00:00.1Z'), true);
  assert.equal(isLater('2026-08-14T12:00:00.1Z', '2026-08-14T12:00:00.12Z'), false);
  assert.equal(isLater('2026-08-14T12:00:00Z', ''), true, 'a real instant beats empty');
  assert.equal(isLater('', '2026-08-14T12:00:00Z'), false, 'empty is never later');
  assert.equal(isLater('nonsense', '2026-08-14T12:00:00Z'), false);
});

test('isLater resolves SUB-MILLISECOND nanosecond differences (Date.parse would flatten them)', () => {
  // exact witness from review: 2ns later than 1ns, same millisecond
  assert.equal(isLater('2026-08-14T12:00:00.000000002Z', '2026-08-14T12:00:00.000000001Z'), true);
  assert.equal(isLater('2026-08-14T12:00:00.000000001Z', '2026-08-14T12:00:00.000000002Z'), false);
  // sanity: Date.parse alone truly cannot tell these apart
  assert.equal(Date.parse('2026-08-14T12:00:00.000000002Z'), Date.parse('2026-08-14T12:00:00.000000001Z'));
  // equal instants are not "later" in either direction
  assert.equal(isLater('2026-08-14T12:00:00.5Z', '2026-08-14T12:00:00.500000000Z'), false);
});

test('diffConnectomeActivity registers a nanosecond-only firing (same ms, same count)', () => {
  const prev = [{ source: 'a', target: 'b', count: 3, last_fired: '2026-08-14T12:00:00.000000001Z' }];
  const next = [{ source: 'a', target: 'b', count: 3, last_fired: '2026-08-14T12:00:00.000000002Z' }];
  assert.deepEqual(diffConnectomeActivity(prev, next), ['a b'], 'a 1ns-later instant is a real pulse');
  // backward: an earlier nanosecond is not a firing
  assert.deepEqual(diffConnectomeActivity(next, prev), [], 'an earlier nanosecond must not phantom-fire');
});

test('instantKey rejects malformed RFC3339Nano that Date.parse would permit', () => {
  const bad = [
    '2026-02-30T00:00:00Z',        // impossible calendar date (Feb 30)
    '2026-13-01T00:00:00Z',        // month 13
    '2026-08-14 12:00:00Z',        // space separator, not T
    '2026-08-14T12:00:00.5',       // fractional but no zone
    '2026-08-14T12:00:00.1234567890Z', // 10 fractional digits (>9)
    '2026-08-14T25:00:00Z',        // hour 25
    '2026-08-14T12:00:00+25:00',   // offset hour 25
    '2026-08-14T12:00:00',         // no zone at all
    'Aug 14 2026 12:00:00',        // not RFC3339 at all
  ];
  for (const s of bad) assert.equal(instantKey(s), null, `must reject ${s}`);
  // and a real one still parses
  assert.notEqual(instantKey('2026-08-14T12:00:00.123456789Z'), null);
  assert.notEqual(instantKey('2026-08-14T12:00:00+05:30'), null, 'valid offsets accepted');
});

test('a malformed NEXT last_fired never fires a pulse against a valid baseline', () => {
  // baseline early in the year, so each malformed value — if Date.parse were
  // trusted — rolls/parses to a LATER instant and would wrongly fire.
  const base = [{ source: 'a', target: 'b', count: 4, last_fired: '2026-01-01T00:00:00Z' }];
  for (const bad of [
    '2026-02-30T00:00:00Z',   // impossible day → Date.parse rolls to Mar 2 (later than Jan 1)
    '2026-13-01T00:00:00Z',   // month 13
    '2026-06-14 13:00:00Z',   // space separator
    '2026-06-14T13:00:00',    // no zone
  ]) {
    const next = [{ source: 'a', target: 'b', count: 4, last_fired: bad }];
    assert.deepEqual(diffConnectomeActivity(base, next), [], `malformed ${bad} must not fire`);
  }
});

test('a malformed last_fired never replaces a valid neuron _activity', () => {
  const g = mapConnectome({
    neurons: [{ agent_id: 'a' }, { agent_id: 'b' }],
    synapses: [
      { from_agent: 'a', to_agent: 'b', count: 1, last_fired: '2026-01-01T00:00:00Z' },  // valid, early
      { from_agent: 'b', to_agent: 'a', count: 1, last_fired: '2026-02-30T00:00:00Z' },  // Feb 30 → rolls to Mar 2 (later) if trusted
    ],
  });
  const a = g.nodes.find(n => n.agent_id === 'a');
  assert.equal(a._activity, '2026-01-01T00:00:00Z', 'the rolled-later impossible date must not win');
});

test('a valid future instant is still ordered later (intended behavior preserved)', () => {
  assert.equal(isLater('2027-01-01T00:00:00.000000001Z', '2026-08-14T12:00:00Z'), true);
  assert.notEqual(instantKey('2027-01-01T00:00:00Z'), null);
});

test('a neuron _activity picks the true latest instant across varied precision', () => {
  const g = mapConnectome({
    neurons: [{ agent_id: 'a' }, { agent_id: 'b' }],
    synapses: [
      { from_agent: 'a', to_agent: 'b', count: 1, last_fired: '2026-08-14T12:00:00.12Z' }, // 120ms — later
      { from_agent: 'b', to_agent: 'a', count: 1, last_fired: '2026-08-14T12:00:00.1Z' },  // 100ms — earlier
    ],
  });
  const a = g.nodes.find(n => n.agent_id === 'a');
  assert.equal(a._activity, '2026-08-14T12:00:00.12Z', 'must not pick the lexically-larger .1Z');
});

test('diffConnectomeActivity detects a firing across mixed fractional precision', () => {
  const prev = [{ source: 'a', target: 'b', count: 5, last_fired: '2026-08-14T12:00:00.1Z' }];   // 100ms
  const next = [{ source: 'a', target: 'b', count: 5, last_fired: '2026-08-14T12:00:00.12Z' }];  // 120ms, later, same count
  // lexically '…00.12Z' < '…00.1Z', so a string compare MISSES this real pulse
  assert.deepEqual(diffConnectomeActivity(prev, next), ['a\u0000b'], 'a later instant must register as fired');
});

test('diffConnectomeActivity does not invent a firing when the instant goes backward', () => {
  const prev = [{ source: 'a', target: 'b', count: 5, last_fired: '2026-08-14T12:00:00.12Z' }];  // 120ms
  const next = [{ source: 'a', target: 'b', count: 5, last_fired: '2026-08-14T12:00:00.1Z' }];   // 100ms, earlier, same count
  assert.deepEqual(diffConnectomeActivity(prev, next), [], 'an earlier instant is not a new firing');
});
