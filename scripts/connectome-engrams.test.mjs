import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  agentNodeID,
  applyEngramBloom,
  createEngramBloomCoordinator,
  engramNodeID,
  mapConnectome,
  mapEngrams,
  stripBloom,
} from '../web/static/js/connectome-map.js';

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
  assert.equal(m1.id, 'memory:m1');
  assert.equal(m1.memory_id, 'm1');
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

// --- distributed engram (Phase B): corroborator bridges ---

test('mapEngrams carries the server-disclosed corroborators; defaults to []', () => {
  const [withCorr, without, bad] = mapEngrams({
    engrams: [
      { id: 'm1', content: 'shared', corroborators: ['bob', 'carol'] },
      { id: 'm2', content: 'solo' },
      { id: 'm3', content: 'malformed', corroborators: 'nope' },
    ],
  });
  assert.deepEqual(withCorr.corroborators, ['bob', 'carol'], 'the RBAC-filtered corroborators pass through');
  assert.deepEqual(without.corroborators, [], 'a solitary memory defaults to no corroborators');
  assert.deepEqual(bad.corroborators, [], 'a non-array corroborators field is coerced to []');
});

test('stripBloom removes engram-bridge links (transient), keeps real synapses', () => {
  const gd = {
    nodes: [{ id: 'author', isNeuron: true }, { id: 'peer', isNeuron: true }, { id: 'm1', _added: true }],
    links: [
      { source: 'a', target: 'b', link_type: 'synapse' },
      { source: 'author', target: 'm1', link_type: 'focus' },
      { source: 'm1', target: 'peer', link_type: 'engram-bridge' },
    ],
  };
  const out = stripBloom(gd);
  assert.deepEqual(out.links.map(l => l.link_type), ['synapse'],
    'both focus tethers AND engram-bridges are stripped; the real synapse stays');
  assert.deepEqual(out.nodes.map(n => n.id), ['author', 'peer'],
    'permanent neurons kept, transient engram removed');
});

test('agent and memory identities are structurally namespaced on an exact raw-ID collision', () => {
  const rawID = 'same-id';
  const connectome = mapConnectome({
    neurons: [{ agent_id: rawID, name: 'Author' }, { agent_id: 'peer', name: 'Peer' }],
    synapses: [],
  });
  const [engram] = mapEngrams({
    engrams: [{ id: rawID, content: 'memory', corroborators: ['peer'] }],
  });
  const author = connectome.nodes.find(node => node.agent_id === rawID);
  const composed = applyEngramBloom(connectome, [engram], author, new Set([author.id]));

  assert.equal(author.id, agentNodeID(rawID));
  assert.equal(engram.id, engramNodeID(rawID));
  assert.notEqual(author.id, engram.id);
  assert.deepEqual(composed.graphData.nodes.map(node => node.id).sort(),
    [agentNodeID(rawID), agentNodeID('peer'), engramNodeID(rawID)].sort());
  const bridge = composed.graphData.links.find(link => link.link_type === 'engram-bridge');
  assert.equal(bridge.source, engram, 'the bridge must use the inserted memory node object');
  assert.equal(bridge.target.agent_id, 'peer');
});

test('bloom generations reject an older response for the same neuron', () => {
  const loads = createEngramBloomCoordinator();
  const older = loads.begin('alice');
  const newer = loads.begin('alice');
  assert.equal(loads.isCurrent(older, 'alice'), false);
  assert.equal(loads.isCurrent(newer, 'alice'), true);
  loads.invalidate();
  assert.equal(loads.isCurrent(newer, 'alice'), false,
    'background exit, mode change, or disposal must invalidate the in-flight bloom');
});

test('bloom generations fence cross-agent and access-invalidated responses', () => {
  const loads = createEngramBloomCoordinator();
  const alice = loads.begin('alice');
  const bob = loads.begin('bob');
  assert.equal(loads.isCurrent(alice, 'alice'), false,
    'selecting another agent must reject the older agent response');
  assert.equal(loads.isCurrent(bob, 'alice'), false,
    'a current generation is still bound to its raw agent identity');
  assert.equal(loads.isCurrent(bob, 'bob'), true);
  loads.invalidate();
  assert.equal(loads.isCurrent(bob, 'bob'), false,
    'an access invalidation must reject a response even when agent identity did not change');
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
  assert.match(body, /ENGRAMS_URL \+ '\?agent=' \+ encodeURIComponent\(agentID\)/,
    'must fetch a single raw agent identity, not the namespaced renderer id');
  assert.match(body, /mapEngrams\(payload\)/, 'must project via mapEngrams');
});

test('renderer applies the behavior-tested bloom composition', () => {
  const body = functionBody(mriSource, 'bloomEngrams');
  assert.match(body, /applyEngramBloom\(Graph\.graphData\(\), engrams, current, focusSet, placeNear\)/,
    'renderer must use the pure composition whose object endpoints and collisions are tested');
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

test('bloomEngrams clears a fresh selection but preserves a live-refresh snapshot until replacement', () => {
  const body = functionBody(mriSource, 'bloomEngrams');
  assert.match(body, /if \(disposed \|\| !Graph[\s\S]{0,60}mode !== 'connectome'\) return;/,
    'a disposed/mode guard must gate entry so a post-cleanup deep-link cannot touch Graph');
  const clearIdx = body.indexOf('if (!preserve) clearBloom()');
  const fetchIdx = body.indexOf('await fetch');
  assert.ok(clearIdx !== -1 && fetchIdx !== -1 && clearIdx < fetchIdx,
    'fresh selections clear before fetch while same-agent live refreshes retain the last verified bloom');
  assert.match(body, /selectedMemoryState = preserve \? \{ \.\.\.prior, status:'updating' \} : \{ status:'loading' \}/,
    'live refresh must be explicit updating state rather than pretending cached cards are current');
  assert.match(body, /selectedMemoryState=preserve\?\{\.\.\.prior,status:'stale'\}:\{status:'error'\}/,
    'a failed refresh must keep and label the last verified result');
  assert.match(body, /!bloomLoads\.isCurrent\(bloomRequest, agentID\)\) return/,
    'a superseded response, including the same neuron, must be generation-fenced');
});

test('stale bloom responses are rejected before mapping, rendering, or replacing the verified bloom', () => {
  const body = functionBody(mriSource, 'bloomEngrams');
  const fence = body.indexOf('!bloomLoads.isCurrent(bloomRequest, agentID)) return');
  const map = body.indexOf('const engrams = mapEngrams(payload)');
  const ready = body.indexOf("selectedMemoryState = { status:'ready'");
  const replacementClear = body.indexOf('clearBloom()', map);
  const apply = body.indexOf('applyEngramBloom(', map);
  assert.ok(fence !== -1 && map !== -1 && fence < map,
    'moving the generation fence after payload projection must fail');
  assert.ok(fence < ready && fence < replacementClear && fence < apply,
    'a stale payload must not change cards, clear the verified bloom, or compose graph nodes');
  assert.match(body,
    /const current = selectedAgentNode && selectedAgentNode\.agent_id===agentID \? selectedAgentNode : n;/,
    'an accepted refresh must bind to the newest graph snapshot rather than its pre-reload node object');
  assert.match(body,
    /focusId = current\.id; focusSet = composed\.focusSet;[\s\S]*setFocusMarkerNode\(current\)/,
    'every accepted replacement must move both graph focus and marker to the rebound node');
});

test('every renderer focus-exit path strips bridges and invalidates in-flight blooms', () => {
  const body = functionBody(mriSource, 'exitFocus');
  assert.match(body, /bloomLoads\.invalidate\(\)/);
  assert.match(body, /Graph\.graphData\(stripBloom\(Graph\.graphData\(\)\)\)/,
    'background exit must remove focus and distributed-engram links together');
});

test('failed graph replacements cannot strand a distributed-engram bloom', async () => {
  const bloom = {
    nodes: [{ id: 'agent:alice', isNeuron: true }, { id: 'memory:m1', _added: true }],
    links: [
      { source: 'agent:alice', target: 'memory:m1', link_type: 'focus' },
      { source: 'memory:m1', target: 'agent:bob', link_type: 'engram-bridge' },
    ],
  };
  let graphData = bloom;
  let focusId = 'agent:alice';
  let focusSet = new Set(['agent:alice', 'memory:m1', 'agent:bob']);
  let invalidated = 0;
  let hidden = 0;
  let markerCleared = 0;
  const Graph = { graphData(next) { if (arguments.length) graphData = next; return graphData; } };
  const bloomLoads = { invalidate() { invalidated++; } };
  const clearBloom = () => Graph.graphData(stripBloom(Graph.graphData()));
  const hideExplorePanel = () => { hidden++; };
  const clearFocusMarker = () => { markerCleared++; };
  const body = functionBody(mriSource, 'leaveFocusForGraphReplacement');
  const run = new Function(
    'bloomLoads', 'clearBloom', 'hideExplorePanel', 'clearFocusMarker', 'focusId', 'focusSet',
    `${body}\nreturn { focusId, focusSet };`,
  );

  const state = run(bloomLoads, clearBloom, hideExplorePanel, clearFocusMarker, focusId, focusSet);
  focusId = state.focusId;
  focusSet = state.focusSet;
  await assert.rejects(Promise.reject(new Error('replacement unavailable')));

  assert.equal(focusId, null);
  assert.equal(focusSet, null);
  assert.equal(invalidated, 1);
  assert.equal(hidden, 1);
  assert.equal(markerCleared, 1);
  assert.deepEqual(graphData.nodes.map(node => node.id), ['agent:alice']);
  assert.deepEqual(graphData.links, [], 'focus and engram-bridge artifacts are gone before rejection');
});

test('reload and mode-switch replacement paths tear down the bloom before fetching', () => {
  const loadBody = functionBody(mriSource, 'load');
  const reloadCleanup = loadBody.indexOf('leaveFocusForGraphReplacement()');
  const reloadFetch = loadBody.indexOf('fetchActive(request.mode)');
  assert.ok(reloadCleanup !== -1 && reloadFetch !== -1 && reloadCleanup < reloadFetch,
    'an SSE/domain reload must strip its bloom before the fallible replacement fetch');

  const modeBody = functionBody(mriSource, 'setMode');
  const modeCleanup = modeBody.indexOf('leaveFocusForGraphReplacement()');
  const modeFetch = modeBody.indexOf('load()');
  assert.ok(modeCleanup !== -1 && modeFetch !== -1 && modeCleanup < modeFetch,
    'a mode switch must strip its bloom before the fallible replacement load');
});

test('the 50ms deep-link bloom timer is tracked and cleared on dispose', () => {
  assert.match(mriSource, /deepLinkTimer = setTimeout\(\(\) => \{ if \(!disposed\) selectNeuron/,
    'the deep-link timer must select the agent persistently and remain trackable');
  assert.match(mriSource, /clearTimeout\(deepLinkTimer\)/,
    'the deep-link timer must be cleared in cleanup');
});

test('only a NEURON click blooms engrams — clicking a bloomed engram does not re-bloom', () => {
  // clicking an engram (a memory node) must not re-run bloomEngrams with a memory
  // id as ?agent, which would strip the lobe and leave a focus ring on a removed
  // node. Guard: connectome click blooms only when n.isNeuron.
  assert.match(mriSource, /mode==='connectome'\)\s*\{\s*if \(n\.isNeuron\) selectNeuron\(n\); \}\s*else exploreNode\(n\)/,
    'connectome click must select only neurons; selectNeuron owns the single bloom while memory mode keeps exploreNode');
  const selectBody = functionBody(mriSource, 'selectNeuron');
  assert.match(selectBody, /bloomEngrams\(n\)/, 'one selection must preserve the existing engram bloom');
});

test('bloom composition bridges only rendered peer neurons and strips on background exit', () => {
  const connectome = mapConnectome({
    neurons: [{ agent_id: 'alice' }, { agent_id: 'bob' }],
    synapses: [{ from_agent: 'alice', to_agent: 'bob', count: 1 }],
  });
  const author = connectome.nodes.find(node => node.agent_id === 'alice');
  const [engram] = mapEngrams({
    engrams: [{ id: 'm1', corroborators: ['alice', 'bob', 'not-rendered'] }],
  });
  const composed = applyEngramBloom(connectome, [engram], author, new Set([author.id]));
  const bridges = composed.graphData.links.filter(link => link.link_type === 'engram-bridge');
  assert.equal(bridges.length, 1, 'self and absent corroborators must not create bridges');
  assert.equal(bridges[0].source, engram);
  assert.equal(bridges[0].target.agent_id, 'bob');
  assert.equal(composed.graphData.links.find(link => link.link_type === 'focus').target, engram);
  assert.equal(composed.focusSet.has(agentNodeID('bob')), true,
    'a bridged corroborator must stay lit with the distributed engram');

  const exited = stripBloom(composed.graphData);
  assert.deepEqual(exited.nodes.map(node => node.id).sort(),
    [agentNodeID('alice'), agentNodeID('bob')].sort());
  assert.deepEqual(exited.links.map(link => link.link_type), ['synapse']);
});
