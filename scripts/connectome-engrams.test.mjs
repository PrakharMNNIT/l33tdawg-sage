import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { mapEngrams, stripBloom } from '../web/static/js/connectome-map.js';

// Agent-as-lobe (#182): clicking a neuron blooms its authored memories. mapEngrams
// projects the /memory/engrams payload into transient memory nodes that orbit the
// author neuron; these tests pin the projection and the mri-brain wiring.

test('empty / null / malformed payloads yield no engrams', () => {
  for (const p of [null, undefined, {}, { engrams: null }, { engrams: 'nope' }]) {
    assert.deepEqual(mapEngrams(p), []);
  }
});

test('engrams map to transient memory nodes with sensible fallbacks', () => {
  const nodes = mapEngrams({
    agent_id: 'alice',
    engrams: [
      { id: 'm1', content: 'a fact', domain: 'ops', confidence: 0.9, status: 'committed', corroboration_count: 3, memory_type: 'observation' },
      { id: 'm2' }, // everything defaulted
    ],
  });
  assert.equal(nodes.length, 2);
  const m1 = nodes[0];
  assert.equal(m1.id, 'm1');
  assert.equal(m1.label, 'a fact');       // label from content
  assert.equal(m1.domain, 'ops');
  assert.equal(m1.confidence, 0.9);
  assert.equal(m1.corroboration_count, 3);
  assert.equal(m1._added, true, 'transient: stripped on exit-focus');
  assert.equal(m1._engram, true, 'tagged as an author-anchored memory');
  // fallbacks
  assert.equal(nodes[1].label, 'm2');     // label falls back to id
  assert.equal(nodes[1].domain, 'unknown');
  assert.equal(nodes[1].confidence, 0.5);
  assert.equal(nodes[1].corroboration_count, 0);
  assert.equal(nodes[1]._added, true);
});

test('an engram is NOT a neuron (renders via the memory node path, not neuronTint)', () => {
  const [n] = mapEngrams({ engrams: [{ id: 'm1', content: 'x' }] });
  assert.notEqual(n.isNeuron, true, 'no isNeuron flag → memory styling, not a neuron');
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

test('bloomEngrams fetches one agent from /memory/engrams and maps the result', () => {
  const body = functionBody(mriSource, 'bloomEngrams');
  assert.match(body, /ENGRAMS_URL \+ '\?agent=' \+ encodeURIComponent\(n\.id\)/,
    'must fetch a single agent on demand, not the whole brain');
  assert.match(body, /mapEngrams\(payload\)/, 'must project via mapEngrams');
});

test('engram tethers use node OBJECTS so they render under the pinned layout', () => {
  const body = functionBody(mriSource, 'bloomEngrams');
  assert.match(body, /gd\.links\.push\(\{\s*source:\s*n,\s*target:\s*em,\s*link_type:\s*'focus'\s*\}\)/,
    'source/target must be node objects (string ids go unresolved once forces are nulled — #188)');
});

test('stripBloom removes _added engram nodes and focus tethers, keeps everything else', () => {
  const gd = {
    nodes: [{ id: 'neuron', isNeuron: true }, { id: 'm1', _added: true }, { id: 'm2', _added: true }],
    links: [{ source: 'a', target: 'b', link_type: 'synapse' }, { source: 'neuron', target: 'm1', link_type: 'focus' }],
  };
  const out = stripBloom(gd);
  assert.deepEqual(out.nodes.map(n => n.id), ['neuron'], 'transient _added engrams removed, neuron kept');
  assert.deepEqual(out.links.map(l => l.link_type), ['synapse'], 'focus tethers removed, real synapses kept');
});

test('clearBloom applies stripBloom — a no-op clear must fail this', () => {
  const body = functionBody(mriSource, 'clearBloom');
  assert.match(body, /Graph\.graphData\(stripBloom\(Graph\.graphData\(\)\)\)/,
    'clearBloom must actually strip the bloom via stripBloom, not be a no-op');
});

test('bloomEngrams clears the prior lobe BEFORE fetching — no stale bloom on failure or supersede', () => {
  const body = functionBody(mriSource, 'bloomEngrams');
  assert.match(body, /if \(disposed \|\| !Graph[\s\S]{0,60}mode !== 'connectome'\) return;/,
    'a disposed/mode guard must gate entry so a post-cleanup deep-link cannot touch Graph');
  const clearIdx = body.indexOf('clearBloom()');
  const fetchIdx = body.indexOf('await fetch');
  assert.ok(clearIdx !== -1 && fetchIdx !== -1 && clearIdx < fetchIdx,
    'clearBloom() must run before the fetch, so a failed/superseded request leaves nothing stranded');
  assert.match(body, /focusId !== n\.id\) return/,
    'a superseded response (another neuron clicked mid-flight) must be dropped, not bloomed');
});

test('the 50ms deep-link bloom timer is tracked and cleared on dispose', () => {
  assert.match(mriSource, /deepLinkTimer = setTimeout\(\(\) => \{ if \(!disposed\) bloomEngrams/,
    'the deep-link timer must be assigned (trackable) and guard disposed');
  assert.match(mriSource, /clearTimeout\(deepLinkTimer\)/,
    'the deep-link timer must be cleared in cleanup');
});

test('only a NEURON click blooms engrams — clicking a bloomed engram does not re-bloom', () => {
  // clicking an engram (a memory node) must not re-run bloomEngrams with a memory
  // id as ?agent, which would strip the lobe and leave a focus ring on a removed
  // node. Guard: connectome click blooms only when n.isNeuron.
  assert.match(mriSource, /mode==='connectome'\)\s*\{\s*if \(n\.isNeuron\) bloomEngrams\(n\); \}\s*else exploreNode\(n\)/,
    'connectome click must bloom only neurons; memory-mode click keeps exploreNode');
});
