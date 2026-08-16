import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { createGraphLoadCoordinator, mapConnectome, diffConnectomeActivity, createConnectomeActivityTracker, createConnectomeReloadIntent } from '../web/static/js/connectome-map.js';

const mriSource = await readFile(new URL('../web/static/js/mri-brain.js', import.meta.url), 'utf8');
const appSource = await readFile(new URL('../web/static/js/app.js', import.meta.url), 'utf8');
const cssSource = await readFile(new URL('../web/static/css/sage.css', import.meta.url), 'utf8');
const mriPageSource = await readFile(new URL('../web/static/mri.html', import.meta.url), 'utf8');

function bracedBlock(source, marker, from = 0) {
  const start = source.indexOf(marker, from);
  assert.notEqual(start, -1, `${marker} not found`);
  const open = source.indexOf('{', start + marker.length);
  assert.notEqual(open, -1, `${marker} block did not open`);
  let depth = 0;
  for (let i = open; i < source.length; i++) {
    if (source[i] === '{') depth++;
    else if (source[i] === '}' && --depth === 0) {
      return { body: source.slice(open + 1, i), start, end: i + 1 };
    }
  }
  assert.fail(`${marker} block did not close`);
}

function cssDeclarations(source, exactSelector) {
  const executable = source.replace(/\/\*[\s\S]*?\*\//g, '');
  let cursor = 0;
  let found = null;
  while (cursor < executable.length) {
    const open = executable.indexOf('{', cursor);
    if (open === -1) break;
    const close = executable.indexOf('}', open + 1);
    if (close === -1) break;
    const boundary = Math.max(executable.lastIndexOf('}', open - 1), executable.lastIndexOf('{', open - 1));
    const selector = executable.slice(boundary + 1, open).trim();
    if (selector === exactSelector) found = executable.slice(open + 1, close);
    cursor = close + 1;
  }
  assert.notEqual(found, null, `${exactSelector} rule not found`);
  return Object.fromEntries(found.split(';').map(part => part.trim()).filter(Boolean).map(part => {
    const colon = part.indexOf(':');
    assert.ok(colon > 0, `invalid declaration in ${exactSelector}: ${part}`);
    return [part.slice(0, colon).trim(), part.slice(colon + 1).trim()];
  }));
}

// The CEREBRUM connectome view renders the agent message-bus in the brain hull.
// mapConnectome() is the pure projection from the /network/synapses payload onto
// the MRI render contract; these tests pin the invariants the renderer relies on:
// neuron degree + synapse weight normalization, ghost-edge rejection, and a safe
// empty state.

const payload = {
  neurons: [
    { agent_id: 'alice', name: 'Alice', role: 'planner', domain: 'ops' },
    { agent_id: 'bob',   name: 'Bob',   role: 'worker',  domain: 'ops' },
    { agent_id: 'carol', name: 'Carol', role: 'worker',  domain: 'research' },
  ],
  synapses: [
    { from_agent: 'alice', to_agent: 'bob',   count: 5, last_fired: '2026-08-12T10:00:00Z' },
    { from_agent: 'bob',   to_agent: 'alice', count: 2, last_fired: '2026-08-12T09:00:00Z' },
    { from_agent: 'bob',   to_agent: 'carol', count: 1, last_fired: '2026-08-12T08:00:00Z' },
  ],
};

test('neurons become nodes with normalized degree (busiest = 1)', () => {
  const g = mapConnectome(payload);
  assert.equal(g.nodes.length, 3);
  const by = Object.fromEntries(g.nodes.map(n => [n.agent_id, n]));
  // total traffic (in+out): bob 5+2+1=8 (busiest), alice 5+2=7, carol 1
  assert.equal(by.bob._w, 8);
  assert.equal(by.alice._w, 7);
  assert.equal(by.carol._w, 1);
  assert.equal(by.bob._deg, 1);
  assert.equal(by.alice._deg, 7 / 8);
  assert.equal(by.carol._deg, 1 / 8);
  assert.ok(g.nodes.every(n => n.isNeuron === true));
});

test('node fields map from the payload with sensible fallbacks', () => {
  const g = mapConnectome({
    neurons: [
      { agent_id: 'x', name: 'X', role: 'r', domain: 'd' },
      { agent_id: 'y' }, // no name/role/domain
    ],
    synapses: [],
  });
  const by = Object.fromEntries(g.nodes.map(n => [n.agent_id, n]));
  assert.equal(by.x.label, 'X');
  assert.equal(by.x.domain, 'd');
  assert.equal(by.x.agent_domain, 'd');
  assert.equal(by.x.role, 'r');
  // label falls back to agent_id, domain falls back to role then 'agent'
  assert.equal(by.y.label, 'y');
  assert.equal(by.y.domain, 'agent');
  assert.equal(by.y.agent_domain, '', 'display details must not mislabel the role fallback as a real domain');
  assert.equal(by.y.role, '');
});

test('synapses become weighted links normalized by the busiest edge', () => {
  const g = mapConnectome(payload);
  assert.equal(g.links.length, 3);
  const by = Object.fromEntries(g.links.map(l => [`${l.source}>${l.target}`, l]));
  assert.equal(by['agent:alice>agent:bob'].count, 5);
  assert.equal(by['agent:alice>agent:bob']._w, 1);        // busiest edge
  assert.equal(by['agent:bob>agent:alice']._w, 2 / 5);
  assert.equal(by['agent:bob>agent:carol']._w, 1 / 5);
  assert.ok(g.links.every(l => l.link_type === 'synapse'));
  assert.equal(by['agent:alice>agent:bob'].last_fired, '2026-08-12T10:00:00Z');
});

test('direction is preserved: A->B is distinct from B->A', () => {
  const g = mapConnectome(payload);
  const keys = g.links.map(l => `${l.source}>${l.target}`);
  assert.ok(keys.includes('agent:alice>agent:bob'));
  assert.ok(keys.includes('agent:bob>agent:alice'));
});

test('nodes expose visible directional traffic, distinct peers, and strongest connection', () => {
  const g = mapConnectome(payload);
  const by = Object.fromEntries(g.nodes.map(n => [n.agent_id, n]));
  assert.deepEqual(
    { incoming:by.alice._incoming, outgoing:by.alice._outgoing, peers:by.alice._peers },
    { incoming:2, outgoing:5, peers:1 },
  );
  assert.deepEqual(
    { incoming:by.bob._incoming, outgoing:by.bob._outgoing, peers:by.bob._peers },
    { incoming:5, outgoing:3, peers:2 },
  );
  assert.equal(by.bob._strongest_peer, 'alice');
  assert.equal(by.bob._strongest_peer_traffic, 7,
    'strongest connection combines retained traffic in both directions');
  assert.deepEqual(
    { incoming:by.carol._incoming, outgoing:by.carol._outgoing, peers:by.carol._peers },
    { incoming:1, outgoing:0, peers:1 },
  );
});

test('a self-synapse contributes directional traffic but not a connected peer', () => {
  const [node] = mapConnectome({
    neurons:[{agent_id:'solo'}],
    synapses:[{from_agent:'solo',to_agent:'solo',count:3}],
  }).nodes;
  assert.equal(node._incoming,3); assert.equal(node._outgoing,3);
  assert.equal(node._peers,0); assert.equal(node._strongest_peer,'');
});

test('edges to unknown agents are dropped (no ghost nodes)', () => {
  const g = mapConnectome({
    neurons: [{ agent_id: 'alice', name: 'Alice' }],
    synapses: [
      { from_agent: 'alice', to_agent: 'ghost', count: 9 }, // ghost not registered
      { from_agent: 'ghost', to_agent: 'alice', count: 9 },
    ],
  });
  assert.equal(g.nodes.length, 1);
  assert.equal(g.links.length, 0, 'both endpoints must be registered neurons');
  // a dropped edge must not leak into the neuron's traffic weight
  assert.equal(g.nodes[0]._w, 0);
});

test('empty / null / malformed payloads yield a safe empty connectome', () => {
  for (const p of [null, undefined, {}, { neurons: null, synapses: 'nope' }]) {
    const g = mapConnectome(p);
    assert.deepEqual(g.nodes, []);
    assert.deepEqual(g.links, []);
    assert.equal(g.total, 0);
    assert.equal(g.connectome, true);
  }
});

test('a connectome with neurons but zero traffic degrades gracefully', () => {
  const g = mapConnectome({
    neurons: [{ agent_id: 'a', name: 'A' }, { agent_id: 'b', name: 'B' }],
    synapses: [],
  });
  assert.equal(g.nodes.length, 2);
  assert.ok(g.nodes.every(n => n._deg === 0 && n._w === 0));
  assert.equal(g.links.length, 0);
});

test('mode switches invalidate initial and reload responses from the old view', () => {
  const loads = createGraphLoadCoordinator();
  const initialMemory = loads.begin('memory');
  loads.invalidate();
  const connectome = loads.begin('connectome');

  assert.equal(loads.isCurrent(initialMemory, 'connectome'), false,
    'a slow initial memory response must not render after switching to connectome');
  assert.equal(loads.isCurrent(connectome, 'connectome'), true);

  const slowReload = loads.begin('connectome');
  loads.invalidate();
  const memory = loads.begin('memory');
  assert.equal(loads.isCurrent(slowReload, 'memory'), false,
    'a slow connectome reload must not render after switching back to memory');
  assert.equal(loads.isCurrent(memory, 'memory'), true);
});

test('renderer wires mode invalidation into both initial acquisition and reloads', () => {
  const initialStart = mriSource.indexOf('function acquireInitialGraph()');
  const initialEnd = mriSource.indexOf('\n  acquireInitialGraph();', initialStart);
  assert.ok(initialStart >= 0 && initialEnd > initialStart, 'initial graph acquisition must remain explicit');
  const initialAcquire = mriSource.slice(initialStart, initialEnd);
  assert.match(initialAcquire, /const request = graphLoads\.begin\(mode\);/,
    'initial acquisition must capture its source mode and generation');
  assert.match(initialAcquire, /fetchActive\(request\.mode\)/,
    'initial acquisition must fetch from the captured mode');
  assert.match(initialAcquire, /graphLoads\.isCurrent\(request, mode\)/,
    'a stale initial response must fail closed after a mode change');
  assert.match(mriSource, /function setMode\(next\)\{[\s\S]*graphLoads\.invalidate\(\);[\s\S]*else acquireInitialGraph\(\);/,
    'a toggle must invalidate old work and refetch even before Graph exists');
});

test('connectome guidance is reachable without adding another floating panel', () => {
  const templateStart = mriSource.indexOf('root.innerHTML = `');
  const templateEnd = mriSource.indexOf('`;\n  container.appendChild(root);', templateStart);
  assert.ok(templateStart >= 0 && templateEnd > templateStart, 'renderer root template must remain inspectable');
  const rootTemplate = mriSource.slice(templateStart, templateEnd);

  const panelClasses = [...rootTemplate.matchAll(/class="panel ([^"]+)"/g)].map(match => match[1]).sort();
  assert.deepEqual(panelClasses, ['hud', 'legend', 'scan'],
    'the renderer must retain only its established scan, legend, and HUD panels');
  assert.doesNotMatch(rootTemplate, /\bmodeCap\b|mode-cap/,
    'connectome mode must not create a free-floating explanatory panel');
  const executableMri = mriSource
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/.*$/gm, '');
  const childMutations = [...executableMri.matchAll(
    /\b(root|container)\.(appendChild|append|prepend|insertBefore|replaceChildren|insertAdjacentElement|insertAdjacentHTML|before|after|replaceWith)\s*\(([^;\n]*)\)/g,
  )].map(match => `${match[1]}.${match[2]}(${match[3].trim()})`);
  assert.deepEqual(childMutations, ['container.appendChild(root)', 'root.appendChild(p)'],
    'the mount root and established Explore panel are the only root-level insertions, through any DOM insertion API');
  assert.match(mriSource, /p\.className = 'panel explore'; root\.appendChild\(p\)/,
    'the dynamic-root allow-list must stay bound to the click-to-explore panel');

  assert.match(rootTemplate, /class="lg-detail guide-connectome" hidden>[\s\S]*Agents are neurons[\s\S]*Click one to bloom its memories/i,
    'standalone MRI must keep connectome guidance inside its existing reading legend');
  const modeChromeStart = mriSource.indexOf('function updateModeChrome(');
  const modeChromeEnd = mriSource.indexOf('function setMode(', modeChromeStart);
  assert.doesNotMatch(mriSource.slice(modeChromeStart,modeChromeEnd), /legend\.hidden\s*=|\.legend[^\n]*hidden/,
    'connectome mode must not hide the standalone reading guide to make room for agent details');
  const standaloneMountStart = mriPageSource.indexOf("mountMriBrain(document.getElementById('mount')");
  const standaloneMountEnd = mriPageSource.indexOf('});', standaloneMountStart);
  assert.ok(standaloneMountStart >= 0 && standaloneMountEnd > standaloneMountStart,
    'standalone MRI mount options must remain inspectable');
  const standaloneMount = mriPageSource.slice(standaloneMountStart, standaloneMountEnd);
  assert.match(standaloneMount, /showScan:\s*true/);
  assert.doesNotMatch(standaloneMount, /showDomainLegend:\s*false|allowConnectome:\s*false/,
    'standalone MRI must keep both the connectome toggle and its reading guide enabled');
  assert.match(rootTemplate, /<button type="button" class="lg-toggle" aria-expanded="false">/,
    'the standalone reading guide must be keyboard reachable');
  assert.match(rootTemplate, /<button type="button" class="btn b-mode" aria-label="Connectome view" aria-pressed="false">/,
    'the mode toggle must be a keyboard-reachable button');
  assert.match(mriSource, /class="sr-status" role="status" aria-live="polite"/,
    'mode changes must have a non-visual screen-reader announcement target');

  const guideStart = appSource.indexOf('showGuide && html`<section class="brain-domain-guide"');
  const guideEnd = appSource.indexOf('</section>`}', guideStart);
  assert.ok(guideStart >= 0 && guideEnd > guideStart, 'dashboard guide template must remain inspectable');
  const dashboardGuide = appSource.slice(guideStart, guideEnd);
  assert.match(dashboardGuide, /<b>Connectome mode:<\/b> agents are neurons/,
    'the dashboard How to read guide must retain the connectome explanation');
  assert.match(appSource, /class="brain-domain-reset"/,
    'the mobile-only action hiding rule needs an explicit Reset target');
  const executableCss = cssSource.replace(/\/\*[\s\S]*?\*\//g, '');
  const mobileBlocks = [];
  let mobileCursor = 0;
  while ((mobileCursor = executableCss.indexOf('@media (max-width: 760px)', mobileCursor)) !== -1) {
    const block = bracedBlock(executableCss, '@media (max-width: 760px)', mobileCursor);
    mobileBlocks.push(block.body);
    mobileCursor = block.end;
  }
  const inventoryMobile = mobileBlocks.find(block => block.includes('.brain-domain-head-actions .brain-domain-reset'));
  assert.ok(inventoryMobile, 'the executable 760px mobile block must target Reset explicitly');
  assert.equal(cssDeclarations(inventoryMobile, '.brain-domain-head-actions .brain-domain-reset').display, 'none',
    'mobile may hide Reset, not the How to read button');
  assert.doesNotMatch(executableCss, /\.brain-domain-head-actions button:first-child\s*\{\s*display:\s*none;/,
    'mobile must not hide whichever action happens to be first');
});

test('connectome exposes persistent, keyboard-reachable agent identity details', () => {
  assert.match(mriSource, /<aside class="agent-inspector" aria-label="Connectome agent details" aria-hidden="true">/,
    'selected details must be a labelled nonmodal landmark');
  assert.match(mriSource, /<select class="ai-select" aria-label="Browse agents">/,
    'canvas-only neurons need a keyboard and touch selection path');
  assert.match(mriSource, /<button type="button" class="ai-close" aria-label="Close agent details">/,
    'persistent details need a real accessible close button');
  assert.match(mriSource, /class="tip" role="tooltip" aria-hidden="true"/,
    'transient hover details must expose tooltip semantics');
  assert.match(mriSource, /\.onNodeClick\([^\n]*selectNeuron\(n\)/,
    'a canvas click must enter the same persistent selection path as the picker');
  assert.match(mriSource, /const onKeyDown=e=>\{ if\(e\.key==='Escape' && selectedAgentID\)/,
    'Escape must dismiss a selected agent');
  assert.match(mriSource, /subs\.push\(\(\)=>document\.removeEventListener\('keydown',onKeyDown\)\)/,
    'the global Escape listener must be cleaned up with the renderer');
});

test('selection dismissal hides the large inspector and returns keyboard focus to the picker', () => {
  const renderStart=mriSource.indexOf('function renderAgentInspector(');
  const renderEnd=mriSource.indexOf('function clearAgentSelection(',renderStart);
  const render=mriSource.slice(renderStart,renderEnd);
  assert.match(render,/classList\.toggle\('visible', mode === 'connectome' && chosen\)/,
    'the expanded panel must exist only while an agent is selected');
  assert.match(mriSource,/\.ai-close'\)\.onclick=\(\)=>\{ exitFocus\(\); \$\('\.ai-select'\)\.focus\(\); \}/);
  assert.match(mriSource,/e\.key==='Escape'[\s\S]{0,100}exitFocus\(\); \$\('\.ai-select'\)\.focus\(\)/);
  assert.match(mriSource,/t\.closest\('\.panel,\.agent-browser,\.agent-inspector'\)/,
    'picker events must be chrome, never graph-background dismissal');
});

test('a live reload restores cached selected memories or restarts an interrupted bloom', () => {
  const start=mriSource.indexOf('function restoreSelectedAgent(');
  const end=mriSource.indexOf('function setHullOpacity(',start);
  const body=mriSource.slice(start,end);
  assert.match(body,/applyEngramBloom\(Graph\.graphData\(\), selectedMemoryState\.memories\|\|\[\], selected, focusSet, placeNear\)/,
    'ready memories must be recomposed after graph replacement strips transient nodes');
  assert.match(body,/selectedMemoryState=\{status:'loading'\}[\s\S]*bloomEngrams\(selected\)/,
    'an invalidated in-flight bloom must restart instead of leaving the inspector loading forever');
  assert.match(body,/else if \(selectedMemoryState && selectedMemoryState\.status==='loading'\)/,
    'explicit engram errors must wait for Retry rather than hammering the endpoint on every live tick');
  assert.match(mriSource,/restoreSelectedAgent\(d\)/,
    'successful reload reconciliation must invoke the tested restore path');
});

test('empty memory results retain projection and continuation caveats', () => {
  const start=mriSource.indexOf('function renderMemoryState(');
  const end=mriSource.indexOf('function renderAgentInspector(',start);
  const body=mriSource.slice(start,end);
  assert.match(body,/!memories\.length[\s\S]*state\.partial[\s\S]*temporarily hidden/);
  assert.match(body,/!memories\.length[\s\S]*state\.continuation[\s\S]*More may exist/);
});

test('agent tooltip is clamped, escaped, and includes identity plus visible traffic', () => {
  const showStart = mriSource.indexOf('function showTip(');
  const showEnd = mriSource.indexOf('function onMove(', showStart);
  const show = mriSource.slice(showStart, showEnd);
  assert.match(show, /escapeHtml\(agentName\(n\)\)/);
  assert.match(show, /escapeHtml\(agentRole\(n\)\)/);
  assert.match(show, /escapeHtml\(agentDomain\(n\)\)/);
  assert.match(show, /escapeHtml\(id\)/, 'canonical agent identity must be escaped');
  assert.match(show, /n\._incoming/); assert.match(show, /n\._outgoing/); assert.match(show, /n\._peers/);
  const positionStart = mriSource.indexOf('function positionTip(');
  const positionEnd = mriSource.indexOf('function showTip(', positionStart);
  const position = mriSource.slice(positionStart, positionEnd);
  assert.match(position, /tip\.offsetWidth/); assert.match(position, /tip\.offsetHeight/);
  assert.match(position, /Math\.max\(pad,Math\.min\(r\.width-tip\.offsetWidth-pad,left\)\)/,
    'horizontal tooltip placement must stay inside the renderer');
  assert.match(position, /Math\.max\(pad,Math\.min\(r\.height-tip\.offsetHeight-pad,top\)\)/,
    'vertical tooltip placement must stay inside the renderer');
});

test('connectome mode suppresses memory-only empty and unavailable overlays', () => {
  assert.match(mriSource,
    /container\.dispatchEvent\(new CustomEvent\('sage:mri-mode-change',[\s\S]{0,100}detail: \{ mode \}/,
    'the renderer must expose its actual active mode to the host');
  assert.match(appSource,
    /element\.addEventListener\('sage:mri-mode-change', onModeChange\)/,
    'the dashboard must subscribe to renderer mode changes');
  assert.match(appSource, /const showingMemoryView = mriMode === 'memory'/);
  const overlayStart = appSource.indexOf('const showingMemoryView = mriMode');
  const overlayEnd = appSource.indexOf('// Global tooltips state', overlayStart);
  const overlayBlock = appSource.slice(overlayStart, overlayEnd);
  assert.equal((overlayBlock.match(/showingMemoryView &&/g) || []).length, 3,
    'all three memory-only overlays must be gated by the active MRI mode');
});

test('mode controls retain visible pressed and keyboard-focus styling in both themes', () => {
  const styleStart = mriSource.indexOf('const STYLE = `');
  const styleEnd = mriSource.indexOf('`;\n\nfunction injectStyleOnce', styleStart);
  assert.ok(styleStart >= 0 && styleEnd > styleStart, 'the executable MRI stylesheet must remain inspectable');
  const style = mriSource.slice(styleStart, styleEnd);
  const darkPressed = cssDeclarations(style, '.mrib .hud .b-mode[aria-pressed="true"]');
  const lightPressed = cssDeclarations(style, ':root[data-theme="light"] .mrib .hud .b-mode[aria-pressed="true"]');
  const focus = cssDeclarations(style, '.mrib .hud .btn:focus-visible,.mrib .lg-toggle:focus-visible');

  assert.deepEqual(darkPressed, { background: '#0e2943', 'border-color': '#39d0ff' });
  assert.deepEqual(lightPressed, { background: '#dff5fb', 'border-color': '#0e7490' });
  assert.deepEqual(focus, { outline: '2px solid #39d0ff', 'outline-offset': '2px' });
});

test('mode chrome exposes coherent toggle state, active guidance, and live status', () => {
  const functionBody = name => {
    const start = mriSource.indexOf(`function ${name}(`);
    assert.notEqual(start, -1, `${name}() not found`);
    const open = mriSource.indexOf('{', start);
    let depth = 0;
    for (let i = open; i < mriSource.length; i++) {
      if (mriSource[i] === '{') depth++;
      else if (mriSource[i] === '}' && --depth === 0) return mriSource.slice(open + 1, i);
    }
    assert.fail(`${name}() body did not close`);
  };

  const body = functionBody('updateModeChrome');
  const runChrome = new Function('$', 'root', 'mode', 'announce', 'hideTip', 'renderAgentInspector', 'selectedAgentNode', body);
  const elements = {
    '.b-mode': { textContent: '', attrs: {}, setAttribute(k, v) { this.attrs[k] = v; } },
    '.lg-title': { textContent: '' },
    '.guide-memory': { hidden: false },
    '.guide-connectome': { hidden: true },
    '.sr-status': { textContent: '' },
  };
  const labels = [{ textContent: '' }, { textContent: '' }, { textContent: '' }];
  const root = { querySelectorAll: () => labels };
  const $ = selector => elements[selector];

  runChrome($, root, 'connectome', true, () => {}, () => {}, null);
  assert.equal(elements['.b-mode'].textContent, '◉ connectome',
    'a toggle button keeps one visible label; aria-pressed carries its state');
  assert.equal(elements['.b-mode'].attrs['aria-label'], 'Connectome view',
    'aria-pressed needs a stable toggle name, not a changing action label');
  assert.equal(elements['.b-mode'].attrs['aria-pressed'], 'true');
  assert.match(mriSource, /\.b-mode\[aria-pressed="true"\]\{[^}]*background:/,
    'pressed state must remain visible without changing the toggle label');
  assert.equal(elements['.guide-memory'].hidden, true);
  assert.equal(elements['.guide-connectome'].hidden, false);
  assert.match(elements['.sr-status'].textContent, /Connectome view/);
  assert.deepEqual(labels.map(label => label.textContent), ['neurons', 'synapses', 'hubs']);

  runChrome($, root, 'memory', true, () => {}, () => {}, null);
  assert.equal(elements['.b-mode'].textContent, '◉ connectome');
  assert.equal(elements['.b-mode'].attrs['aria-label'], 'Connectome view');
  assert.equal(elements['.b-mode'].attrs['aria-pressed'], 'false');
  assert.equal(elements['.guide-memory'].hidden, false);
  assert.equal(elements['.guide-connectome'].hidden, true);
  assert.match(elements['.sr-status'].textContent, /Memory view/);

  const executableSetMode = functionBody('setMode')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/.*$/gm, '');
  const modeAnnouncements = [];
  const runSetMode = new Function(
    'next', 'mode', 'allowConnectome', 'graphLoads', 'bloomLoads', 'connectomeActivity',
    'connectomeReloadIntent', 'neuronBirths', 'currentDomain', 'container', 'CustomEvent', 'leaveFocusForGraphReplacement', 'clearAgentSelection',
    'hideExplorePanel', 'clearFocusMarker', 'updateModeChrome', 'hullState', '$',
    'sliderUnits', 'setHullOpacity', 'Graph', 'load', 'zoomOut', 'acquireInitialGraph',
    executableSetMode,
  );
  const resettable = () => ({ reset() {} });
  let focusLeaves = 0;
  const modeEvents = [];
  function FakeCustomEvent(type, init) { this.type = type; this.detail = init.detail; }
  runSetMode(
    'connectome', 'memory', true, { invalidate() {} }, { invalidate() {} }, resettable(),
    resettable(), resettable(), null, { dispatchEvent(event) { modeEvents.push(event); } }, FakeCustomEvent,
    () => { focusLeaves++; }, () => {}, () => {}, () => {},
    announce => modeAnnouncements.push(announce), { valueFor: () => 0.03 }, () => null,
    value => value, () => {}, null, () => {}, () => {}, () => {},
  );
  assert.deepEqual(modeAnnouncements, [true],
    'the executable mode transition must invoke the announcing chrome path exactly once');
  assert.equal(focusLeaves, 1,
    'the executable mode transition must strip any distributed-engram bloom exactly once');
  assert.deepEqual(modeEvents.map(event => [event.type, event.detail.mode]),
    [['sage:mri-mode-change', 'connectome']],
    'the host must receive the actual active mode so memory-only overlays can hide');
});

// Live firing pulses only the synapses that actually carried a message. The
// server tick is contentless by design, so which edges fired is derived here by
// diffing two AUTHORIZED snapshots — meaning a client can only ever pulse an
// edge the RBAC-filtered endpoint was willing to show it.
test('diffConnectomeActivity reports a brand new synapse as fired', () => {
  const fired = diffConnectomeActivity(
    [],
    [{ source: 'a', target: 'b', count: 1, last_fired: '2026-01-01T00:00:00Z' }],
  );
  assert.deepEqual(fired, ['a\u0000b']);
});

test('diffConnectomeActivity reports a risen count as fired', () => {
  const prev = [{ source: 'a', target: 'b', count: 1, last_fired: 't1' }];
  const next = [{ source: 'a', target: 'b', count: 2, last_fired: 't1' }];
  assert.deepEqual(diffConnectomeActivity(prev, next), ['a\u0000b']);
});

// Needed because a burst can land inside one timestamp granularity, and a send
// that coincides with a retention prune can leave the count unmoved.
test('diffConnectomeActivity reports an advanced last_fired as fired', () => {
  const prev = [{ source: 'a', target: 'b', count: 5, last_fired: '2026-01-01T00:00:00Z' }];
  const next = [{ source: 'a', target: 'b', count: 5, last_fired: '2026-01-01T00:00:09Z' }];
  assert.deepEqual(diffConnectomeActivity(prev, next), ['a\u0000b']);
});

test('diffConnectomeActivity reports an unchanged synapse as quiet', () => {
  const same = [{ source: 'a', target: 'b', count: 3, last_fired: 't9' }];
  assert.deepEqual(diffConnectomeActivity(same, same), []);
});

// Retained-row pruning lowers a count without any message being sent. Treating
// that as activity would animate traffic that did not happen.
test('diffConnectomeActivity does not treat a pruned count as firing', () => {
  const prev = [{ source: 'a', target: 'b', count: 9, last_fired: 't1' }];
  const next = [{ source: 'a', target: 'b', count: 2, last_fired: 't1' }];
  assert.deepEqual(diffConnectomeActivity(prev, next), []);
});

// After force-simulation binding, link endpoints are node objects rather than
// id strings. The diff must key identically in both shapes or every edge would
// read as new on the first pulse after a render.
test('diffConnectomeActivity keys object endpoints the same as string ids', () => {
  const prev = [{ source: 'a', target: 'b', count: 4, last_fired: 't1' }];
  const next = [{ source: { id: 'a' }, target: { id: 'b' }, count: 4, last_fired: 't1' }];
  assert.deepEqual(diffConnectomeActivity(prev, next), []);
});

test('initial connectome acquisition establishes a baseline without firing', () => {
  const activity = createConnectomeActivityTracker();
  const initial = [{ source: 'a', target: 'b', count: 7, last_fired: 't7' }];
  assert.deepEqual(activity.observe(initial, false), []);
});

test('ordinary reload updates the baseline without firing', () => {
  const activity = createConnectomeActivityTracker();
  activity.observe([{ source: 'a', target: 'b', count: 1, last_fired: 't1' }], false);
  assert.deepEqual(activity.observe(
    [{ source: 'a', target: 'b', count: 2, last_fired: 't2' }], false,
  ), []);
});

test('connectome tick fires only edges changed since the latest authorized baseline', () => {
  const activity = createConnectomeActivityTracker();
  activity.observe([{ source: 'a', target: 'b', count: 1, last_fired: 't1' }], false);
  assert.deepEqual(activity.observe(
    [{ source: 'a', target: 'b', count: 2, last_fired: 't2' }], true,
  ), ['a\u0000b']);
});

test('tick arriving during an ordinary load keeps the pre-tick baseline', () => {
  const activity = createConnectomeActivityTracker();
  const before = [{ source: 'a', target: 'b', count: 1, last_fired: 't1' }];
  const after = [{ source: 'a', target: 'b', count: 2, last_fired: 't2' }];
  activity.observe(before, false);
  assert.deepEqual(activity.observe(after, false, true), [],
    'ordinary response must not pulse or consume a pending tick');
  assert.deepEqual(activity.observe(after, true), ['a\u0000b'],
    'queued tick refetch must still observe the firing transition');
});

test('tick intent survives failed retry and an ordinary reload during backoff', () => {
  const activity = createConnectomeActivityTracker();
  const intent = createConnectomeReloadIntent();
  const before = [{ source: 'a', target: 'b', count: 1, last_fired: 't1' }];
  const after = [{ source: 'a', target: 'b', count: 2, last_fired: 't2' }];
  activity.observe(before, false);

  intent.requestTick();
  const failedTickGeneration = intent.begin('connectome');
  assert.equal(failedTickGeneration, 1);
  intent.settle('connectome', failedTickGeneration, false);
  assert.equal(intent.isPending('connectome'), true,
    'failed tick fetch must retain intent throughout retry backoff');

  // A remember/forget refresh can cancel the retry timer. It must inherit the
  // pending tick instead of advancing the baseline as an ordinary reload.
  const ordinaryDuringBackoff = intent.begin('connectome');
  assert.equal(ordinaryDuringBackoff, 1);
  assert.deepEqual(activity.observe(after, ordinaryDuringBackoff > 0), ['a\u0000b']);
  intent.settle('connectome', ordinaryDuringBackoff, true);
  assert.equal(intent.isPending('connectome'), false);
  assert.deepEqual(activity.observe(after, intent.begin('connectome')), [],
    'a satisfied tick must pulse exactly once');
});

test('a second tick is not acknowledged by an older in-flight generation', () => {
  const activity = createConnectomeActivityTracker();
  const intent = createConnectomeReloadIntent();
  const before = [{ source: 'a', target: 'b', count: 1, last_fired: 't1' }];
  const afterTick1 = [{ source: 'a', target: 'b', count: 2, last_fired: 't2' }];
  const afterTick2 = [{ source: 'a', target: 'b', count: 3, last_fired: 't3' }];
  activity.observe(before, false);

  intent.requestTick();
  const generation1 = intent.begin('connectome');
  intent.requestTick();
  assert.deepEqual(activity.observe(afterTick1, generation1 > 0), ['a\u0000b']);
  intent.settle('connectome', generation1, true);
  assert.equal(intent.isPending('connectome'), true,
    'tick 1 response must not consume tick 2, which arrived after it began');

  const generation2 = intent.begin('connectome');
  assert.equal(generation2, 2);
  assert.deepEqual(activity.observe(afterTick2, generation2 > 0), ['a\u0000b']);
  intent.settle('connectome', generation2, true);
  assert.equal(intent.isPending('connectome'), false);
});

// The renderer subscribes to the contentless tick and refetches the authorized
// snapshot; it must never read edge data off the event itself.
test('mri-brain refetches the authorized snapshot on a connectome tick', () => {
  assert.match(mriSource, /opts\.sse\.on\('connectome'/,
    'the renderer must subscribe to the connectome tick');
  assert.match(mriSource, /load\(true\)/,
    'only the connectome tick path may request a firing diff');
  assert.match(mriSource, /markConnectomeFiring\(d, tickAware, connectomeReloadIntent\.isPending\(request\.mode\) && !tickAware\)/,
    'the fired-edge diff must run on the applied snapshot');
  assert.match(mriSource, /if \(fromConnectomeTick\) connectomeReloadIntent\.requestTick\(\)/,
    'the event must persist tick intent independently of a retry timer');
  assert.match(mriSource, /scheduleGraphRetry\(load\)/,
    'retries must consult persistent tick intent when they begin');
  assert.match(mriSource, /connectomeReloadIntent\.settle\(request\.mode, tickGeneration, true\)/,
    'a successful production fetch must acknowledge exactly its captured generation');
});
