// mri-brain.js — the 3D "MRI" memory-brain renderer, shared by the standalone
// /ui/mri.html page and the in-dashboard MRI mode (no iframe; dashboard
// X-Frame-Options/CSP correctly forbid embedding, so we render natively).
//
// Three.js + 3d-force-graph + the UnrealBloomPass addon are pre-bundled into one
// self-contained local module (vendor/sage-graph.bundle.js) - no CDN, no importmap,
// so the packaged app renders the brain fully offline. Everything shares the SINGLE
// Three instance baked into that bundle (no "multiple instances of Three.js" warning).
// Call mountMriBrain(container, opts) -> returns a cleanup function.
//
// The complementary-learning-systems reading (SAGE_AGI_BRAIN_ANALOGY.md):
//   size+glow = corroboration (consolidation) · fade = confidence (decay)
//   grey = challenged/deprecated (pruning) · colour = domain (lobe)
//   edge colour = sage_link type (the connectome)
// No embeddings or full content cross the wire — content is truncated
// server-side and the graph respects the same RBAC isolation as every read.

import { THREE, ForceGraph3D, UnrealBloomPass } from '/ui/js/vendor/sage-graph.bundle.js';
import { MRI_LAYOUT, mriDepthForAge, mriVerticalPosition } from '/ui/js/mri-layout.js';
import { createGraphLoadCoordinator, createEngramBloomCoordinator, mapConnectome, createConnectomeActivityTracker, createConnectomeReloadIntent, synapsePlasticity, neuronDormancy, createNeuronBirthTracker, neuronTint, mapEngrams, stripBloom, applyEngramBloom } from '/ui/js/connectome-map.js';
import { createModeHull } from '/ui/js/mode-hull.js';

const LINK_TYPES = {
  supports:    { color: '#5ee2a0', label: 'supports',    typed: true },
  contradicts: { color: '#ff5c6c', label: 'contradicts', typed: true },
  causes:      { color: '#5ab0ff', label: 'causes',      typed: true },
  precedes:    { color: '#ffd166', label: 'precedes',    typed: true },
  refines:     { color: '#c08bff', label: 'refines',     typed: true },
  related:     { color: '#42587a', label: 'related',     typed: true },
  parent:      { color: '#243450', label: 'lineage',     typed: false },
  domain:      { color: '#1b2942', label: 'same domain', typed: false },
  focus:       { color: '#39d0ff', label: 'train of thought', typed: false },
  // Connectome mode: a directed agent→agent message-bus channel. Width/particles
  // scale with traffic (Hebbian weight), so this one entry is styled dynamically
  // by the link accessors rather than by a fixed width like the memory link types.
  synapse:     { color: '#39d0ff', label: 'synapse',     typed: true },
  // Connectome mode: a "distributed engram" bridge — a memory (engram) that a
  // second neuron has also corroborated, drawn from the engram to that
  // corroborating neuron. One memory bridged to several neurons is the same
  // knowledge consolidated across cells. Kept faint so the neuron synapses stay
  // dominant; styled dynamically by the width accessor like the synapse.
  'engram-bridge': { color: '#d98cff', label: 'distributed engram', typed: false },
};
const PALETTE = ['#ff6b9d','#ffd166','#5ee2a0','#5ab0ff','#c08bff','#ff9f5a','#4dd6c4','#f7748a','#9ad14b','#7aa0ff'];
function hexToRgb(h){ const n = parseInt(h.slice(1), 16); return [n >> 16 & 255, n >> 8 & 255, n & 255]; }
function fmtN(n){ n = n||0; return n >= 1000 ? (n/1000).toFixed(n >= 10000 ? 0 : 1) + 'k' : '' + n; }

// Minimal OBJ → BufferGeometry (positions + fan-triangulated faces). Lets us
// drop a CC0 brain mesh at /ui/assets/brain.obj with no extra loader library.
function parseOBJ(text) {
  const pos = [], idx = [];
  for (const line of text.split('\n')) {
    if (line[0] === 'v' && line[1] === ' ') {
      const p = line.split(/\s+/); pos.push(+p[1], +p[2], +p[3]);
    } else if (line[0] === 'f' && line[1] === ' ') {
      const f = line.trim().split(/\s+/).slice(1).map(s => parseInt(s, 10) - 1);
      for (let i = 1; i < f.length - 1; i++) idx.push(f[0], f[i], f[i + 1]);
    }
  }
  const g = new THREE.BufferGeometry();
  g.setAttribute('position', new THREE.Float32BufferAttribute(pos, 3));
  if (idx.length) g.setIndex(idx);
  g.computeVertexNormals();
  return g;
}

// Procedural brain-shaped wireframe hull: a densely-subdivided sphere displaced
// into two hemispheres (a sagittal longitudinal fissure) with multi-octave
// gyri/sulci folding, a cerebellum bulge, and brain proportions. License-free
// (generated), and reads convincingly as a brain. Overridden by an anatomical
// /ui/assets/brain.obj if one is present.
function makeBrainGeometry() {
  // detail 6 (~82k tris) — a much finer, more filament-like wireframe than the
  // old detail-5; still a one-time, zero-per-frame cost.
  const g = new THREE.IcosahedronGeometry(1, 6);
  const p = g.attributes.position, v = new THREE.Vector3();
  for (let i = 0; i < p.count; i++) {
    v.fromBufferAttribute(p, i).normalize();
    const x = v.x, y = v.y, z = v.z;
    // Cortical folding — six octaves of gyri/sulci, increasingly fine, so the
    // surface reads as convoluted cortex rather than a lumpy ball.
    let r = 1
      + 0.052 * Math.sin(8 * z + 3 * y)
      + 0.044 * Math.sin(10 * y + 4 * x)
      + 0.040 * Math.sin(12 * x + 6 * z)
      + 0.028 * Math.sin(17 * z) * Math.cos(15 * y)
      + 0.020 * Math.sin(23 * y + 14 * x)
      + 0.014 * Math.sin(29 * x + 19 * z);
    // Deep sagittal fissure splitting the two hemispheres along the midline.
    r -= Math.exp(-(x * x) * 60) * 0.20 * Math.max(0, y);
    // Cerebellum: a tightly-folded bulge tucked under the posterior-inferior.
    const cb = Math.exp(-((z + 0.8) * (z + 0.8) * 5 + (y + 0.5) * (y + 0.5) * 6 + x * x * 3));
    r += cb * (0.035 + 0.045 * Math.abs(Math.sin(38 * z + 22 * x)));
    v.multiplyScalar(r);
    v.x *= 0.86; v.y *= 0.80; v.z *= 1.20;                // brain proportions (long front-back, narrow across)
    if (v.y < -0.3) v.y = -0.3 + (v.y + 0.3) * 0.5;       // flatten the underside
    p.setXYZ(i, v.x, v.y, v.z);
  }
  p.needsUpdate = true; g.computeVertexNormals();
  return g;
}

function makeFocusRingTexture() {
  const c = document.createElement('canvas');
  c.width = 256; c.height = 256;
  const ctx = c.getContext('2d');
  ctx.clearRect(0, 0, 256, 256);
  ctx.save();
  ctx.translate(128, 128);
  ctx.shadowColor = 'rgba(57,208,255,0.95)';
  ctx.shadowBlur = 16;
  ctx.strokeStyle = 'rgba(255,255,255,0.98)';
  ctx.lineWidth = 12;
  ctx.beginPath();
  ctx.arc(0, 0, 82, 0, Math.PI * 2);
  ctx.stroke();
  ctx.shadowBlur = 0;
  ctx.strokeStyle = 'rgba(57,208,255,0.70)';
  ctx.lineWidth = 3;
  ctx.beginPath();
  ctx.arc(0, 0, 104, 0, Math.PI * 2);
  ctx.stroke();
  ctx.restore();
  const tex = new THREE.CanvasTexture(c);
  tex.needsUpdate = true;
  return tex;
}

// Theme-aware MRI canvas colors. The brain wireframe uses additive blending so it
// glows on black at very low opacity; additive washes to white on a light background,
// so light mode switches to normal blending with a near-black wire color AND a much
// higher effective opacity (mriHullOpacity) so the dense wireframe actually reads.
function mriIsLight(){ try { return document.documentElement.getAttribute('data-theme') === 'light'; } catch(e){ return false; } }
function mriBgColor(){ return mriIsLight() ? '#eef2f7' : '#040406'; }
function mriWireColor(){ return mriIsLight() ? 0x24406e : 0x4aa3ff; }
function mriWireBlend(){ return mriIsLight() ? THREE.NormalBlending : THREE.AdditiveBlending; }
// Light mode writes depth so the FRONT shell occludes the back layers — no
// doubled-up "gray veil" on the edge-on shell — which lets us use a higher
// opacity for genuinely dark, crisp lines. Dark mode keeps depthWrite off so the
// additive wireframe layers freely into its glow.
function mriDepthWrite(){ return mriIsLight(); }
function mriHullOpacity(o){ return mriIsLight() ? Math.min(0.4, 0.24 + o * 0.16) : o; }

const STYLE = `
.mrib{position:absolute;inset:0;overflow:hidden;background:radial-gradient(1200px 800px at 70% 18%,#08090c 0%,#040406 60%);
  font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#cfe3ff}
.mrib-graph{position:absolute;inset:0}
.mrib .panel{position:absolute;background:rgba(10,16,28,.78);border:1px solid #15233b;border-radius:12px;backdrop-filter:blur(8px);box-shadow:0 8px 40px #0008;z-index:5}
.mrib .legend{top:16px;right:16px;width:max-content;padding:13px 15px;max-height:90%;overflow:auto;resize:vertical;min-width:240px;max-width:600px;min-height:150px}
.mrib .legend.collapsed .lg-detail{display:none}
.mrib .legend.collapsed{max-height:70%}
.mrib .lg-head{display:flex;align-items:center;justify-content:space-between;gap:8px}
.mrib .lg-toggle{cursor:pointer;color:#39d0ff;font-size:10px;letter-spacing:1px;text-transform:uppercase;border:1px solid #15233b;border-radius:7px;padding:3px 8px;user-select:none;white-space:nowrap}
.mrib .lg-toggle:hover{background:#0e1b30}
.mrib .lobes .more{color:#5d7395;font-size:11px;margin-top:7px}
.mrib .legend h4{margin:0 0 4px;font-size:11px;letter-spacing:1.5px;color:#39d0ff;text-transform:uppercase}
.mrib .legend .cls{color:#5d7395;font-size:11px;margin:0 0 11px;border-bottom:1px solid #15233b;padding-bottom:9px}
.mrib .legend .row{display:flex;align-items:center;gap:9px;margin:6px 0;white-space:nowrap}
.mrib .legend .row .k{width:16px;text-align:center}
.mrib .legend .row .t b{color:#dceaff;font-weight:600}
.mrib .legend .row .t span{color:#5d7395}
.mrib .legend .seg{margin:11px 0 3px;color:#9fb6d8;font-size:10px;letter-spacing:1.5px;text-transform:uppercase}
.mrib .dot{width:12px;height:12px;border-radius:50%;display:inline-block}
.mrib .bar{width:16px;height:3px;border-radius:2px;display:inline-block}
.mrib .hud{bottom:16px;left:16px;padding:10px 14px;display:flex;gap:16px;align-items:center}
.mrib .hud .n{color:#eaf4ff;font-size:17px;font-weight:700}
.mrib .hud .l{color:#5d7395;font-size:10px;letter-spacing:1px;text-transform:uppercase}
.mrib .hud .btn{cursor:pointer;color:#39d0ff;border:1px solid #15233b;border-radius:8px;padding:6px 11px;user-select:none}
.mrib .hud .btn:hover{background:#0e1b30}
.mrib .hud .sld{display:flex;align-items:center;gap:7px;color:#5d7395;font-size:10px;letter-spacing:1px;text-transform:uppercase}
.mrib .hud .sld input{width:84px;accent-color:#39d0ff;cursor:pointer}
.mrib .scan{position:absolute;top:16px;left:16px;padding:10px 14px}
.mrib .scan b{color:#eaf4ff;font-size:14px;letter-spacing:.5px}
.mrib .scan .s{color:#39d0ff;font-size:11px;letter-spacing:2px;margin-top:4px}
.mrib .tip{position:absolute;pointer-events:none;display:none;max-width:280px;padding:8px 11px;background:rgba(6,11,20,.96);border:1px solid #15233b;border-radius:9px;z-index:9;font-size:12px}
.mrib .tip .h{color:#eaf4ff;font-weight:700;margin-bottom:2px}
.mrib .tip .m{color:#5d7395;font-size:11px}
.mrib .tip .chip{font-size:10px;padding:1px 6px;border-radius:6px;background:#0e1b30;color:#aecbf0;margin-right:4px}
.mrib .flag{position:absolute;bottom:16px;right:16px;color:#3a4a66;font-size:10px;letter-spacing:1px}
.mrib .boot{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:#5d7395;letter-spacing:2px;font-size:12px}
.mrib .explore{--ex-font:12px;display:none;left:16px;right:306px;bottom:14px;height:47%;min-height:210px;max-height:72%;flex-direction:column;padding:0;overflow:hidden}
.mrib .explore .ex-resize{position:absolute;top:0;left:12px;right:12px;height:10px;cursor:ns-resize;z-index:2}
.mrib .explore .ex-resize:before{content:'';position:absolute;top:3px;left:50%;width:52px;height:3px;transform:translateX(-50%);border-radius:3px;background:#263b5e}
.mrib .explore .ex-resize:hover:before{background:#dceaff}
.mrib .explore .ex-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:12px 16px;border-bottom:1px solid #15233b}
.mrib .explore .ex-head-l{min-width:0}
.mrib .explore .ex-title{color:#39d0ff;font-size:11px;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:5px}
.mrib .explore .ex-src{color:#dceaff;font-size:12px;line-height:1.45;max-height:36px;overflow:hidden}
.mrib .explore .ex-actions{display:flex;align-items:center;gap:8px;flex:none}
.mrib .explore .ex-font{display:flex;align-items:center;gap:3px;border:1px solid #15233b;border-radius:8px;padding:2px}
.mrib .explore .ex-font button{cursor:pointer;border:0;background:transparent;color:#9fb6d8;font:700 11px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:4px 7px;border-radius:6px}
.mrib .explore .ex-font button:hover:not(:disabled){background:#0e1b30;color:#eaf4ff}
.mrib .explore .ex-font button:disabled{cursor:not-allowed;color:#33445f}
.mrib .explore .ex-back{flex:none;color:#39d0ff;font-size:11px;cursor:pointer;border:1px solid #15233b;border-radius:8px;padding:6px 11px;user-select:none;white-space:nowrap}
.mrib .explore .ex-back:hover{background:#0e1b30}
.mrib .explore .ex-board{flex:1;min-height:0;display:flex;gap:10px;padding:12px}
.mrib .explore .ex-col{flex:1;min-width:0;display:flex;flex-direction:column;background:rgba(6,11,20,.45);border:1px solid #12203a;border-radius:10px;overflow:hidden}
.mrib .explore .ex-col-head{display:flex;align-items:center;gap:7px;padding:9px 11px;font-size:11px;letter-spacing:.5px;text-transform:uppercase;font-weight:600;border-bottom:1px solid #12203a}
.mrib .explore .ex-col-glyph{font-size:12px}
.mrib .explore .ex-col-n{margin-left:auto;color:#5d7395;font-weight:400}
.mrib .explore .k-do .ex-col-head{color:#5ee2a0} .mrib .explore .k-do{border-color:rgba(94,226,160,.28)}
.mrib .explore .k-dont .ex-col-head{color:#ff7a88} .mrib .explore .k-dont{border-color:rgba(255,122,136,.28)}
.mrib .explore .k-observation .ex-col-head{color:#5ab0ff} .mrib .explore .k-observation{border-color:rgba(90,176,255,.28)}
.mrib .explore .k-note .ex-col-head{color:#aecbf0}
.mrib .explore .ex-col-list{flex:1;min-height:0;overflow:auto;padding:7px}
.mrib .explore .ex-card{padding:8px 9px;border-radius:8px;cursor:pointer;margin-bottom:6px;background:rgba(14,27,48,.5);border:1px solid transparent}
.mrib .explore .ex-card:hover{background:#12213a;border-color:#1e3252}
.mrib .explore .ex-c{color:#dceaff;font-size:var(--ex-font);line-height:1.38;max-height:calc(var(--ex-font) * 5.2);overflow:hidden}
.mrib .explore .ex-m{margin-top:5px;font-size:10px;color:#5d7395;display:flex;gap:6px;align-items:center}
.mrib .explore .ex-m .dot{width:8px;height:8px;flex:none}
.mrib .explore .ex-cc{color:#7f93b5;margin-left:auto}
.mrib .explore .ex-empty{color:#3a4a66;padding:10px;text-align:center;font-size:12px}
.mrib .explore .ex-empty-big{padding:40px;color:#5d7395}

/* Light theme: the 3D canvas is transparent (#05070d00), so lightening the .mrib
   container background lets the light page show through the brain; the chrome
   (panels/legend/HUD/explore) is re-tinted for light. The brain wireframe + node
   colors are left as-is. */
:root[data-theme="light"] .mrib{background:radial-gradient(1200px 800px at 70% 18%,#ffffff 0%,#e9eef4 62%);color:#334155}
:root[data-theme="light"] .mrib .panel{background:rgba(255,255,255,.9);border-color:#dbe3ec;box-shadow:0 8px 32px rgba(15,23,42,.12)}
:root[data-theme="light"] .mrib .legend h4,
:root[data-theme="light"] .mrib .lg-toggle,
:root[data-theme="light"] .mrib .scan .s,
:root[data-theme="light"] .mrib .hud .btn,
:root[data-theme="light"] .mrib .explore .ex-title,
:root[data-theme="light"] .mrib .explore .ex-back{color:#0e7490;border-color:#cbd5e1}
:root[data-theme="light"] .mrib .lg-toggle:hover,
:root[data-theme="light"] .mrib .hud .btn:hover,
:root[data-theme="light"] .mrib .explore .ex-back:hover,
:root[data-theme="light"] .mrib .explore .ex-font button:hover:not(:disabled){background:#e9eef4;color:#0e7490}
:root[data-theme="light"] .mrib .legend .cls,
:root[data-theme="light"] .mrib .legend .row .t span,
:root[data-theme="light"] .mrib .lobes .more,
:root[data-theme="light"] .mrib .hud .l,
:root[data-theme="light"] .mrib .hud .sld,
:root[data-theme="light"] .mrib .explore .ex-col-n,
:root[data-theme="light"] .mrib .explore .ex-m,
:root[data-theme="light"] .mrib .tip .m{color:#64748b}
:root[data-theme="light"] .mrib .legend .row .t b,
:root[data-theme="light"] .mrib .hud .n,
:root[data-theme="light"] .mrib .scan b,
:root[data-theme="light"] .mrib .explore .ex-src,
:root[data-theme="light"] .mrib .explore .ex-c,
:root[data-theme="light"] .mrib .tip .h{color:#1e293b}
:root[data-theme="light"] .mrib .legend h4,
:root[data-theme="light"] .mrib .legend .cls{border-color:#e2e8f0}
:root[data-theme="light"] .mrib .tip{background:rgba(255,255,255,.97);border-color:#dbe3ec}
:root[data-theme="light"] .mrib .explore .ex-col{background:rgba(255,255,255,.6);border-color:#e2e8f0}
:root[data-theme="light"] .mrib .explore .ex-card{background:rgba(240,244,249,.7)}
:root[data-theme="light"] .mrib .explore .ex-card:hover{background:#e9eef4;border-color:#cbd5e1}
:root[data-theme="light"] .mrib .flag{color:#94a3b8}
:root[data-theme="light"] .mrib .hud .sld input{accent-color:#0891b2}
`;

function injectStyleOnce() {
  if (document.getElementById('mrib-style')) return;
  const s = document.createElement('style');
  s.id = 'mrib-style';
  s.textContent = STYLE;
  document.head.appendChild(s);
}

export const DEFAULT_MRI_NODE_LIMIT = 1500;

async function loadGraph(fetchUrl) {
  try {
    const r = await fetch(fetchUrl, { credentials: 'same-origin' });
    if (!r.ok) throw new Error('HTTP '+r.status);
    const g = await r.json();
    // Empty (no memories yet) is a valid state — render a blank brain, never
    // synthetic/placeholder data. Guard every field against a null body.
    const srcNodes = (g && Array.isArray(g.nodes)) ? g.nodes : [];
    const srcEdges = (g && Array.isArray(g.edges)) ? g.edges : [];
    return { live: true,
      nodes: srcNodes.map(n=>({ id:n.id, domain:n.domain||'unknown', label:n.content||n.id,
        status:n.status||'committed', corroboration_count:n.corroboration_count||0,
        confidence: typeof n.confidence==='number'?n.confidence:0.5, memory_type:n.memory_type||'',
        created_at:n.created_at||'' })),
      links: srcEdges.map(e=>({ source:e.source, target:e.target, link_type:e.type||'related' })),
      total: (g && g.total) || 0, domainCounts: (g && g.domain_counts) || null,
      domainLast: (g && g.domain_last) || null };
  } catch (err) {
    // A transport or parse failure is not an empty brain. Let the renderer keep
    // its previous verified graph (or its initial loading state) and surface an
    // explicit unavailable signal to CEREBRUM.
    console.warn('[mri] live graph unavailable:', err.message);
    throw err;
  }
}

// Connectome loader: fetch the agent message-bus and hand it to the pure
// mapConnectome() mapper (connectome-map.js), which projects {neurons, synapses}
// onto the same internal {nodes, links} contract the memory view renders. A
// transport/parse failure is surfaced (not treated as an empty brain), matching
// loadGraph.
async function loadSynapses(fetchUrl) {
  try {
    const r = await fetch(fetchUrl, { credentials: 'same-origin' });
    if (!r.ok) throw new Error('HTTP '+r.status);
    return mapConnectome(await r.json());
  } catch (err) {
    console.warn('[mri] connectome unavailable:', err.message);
    throw err;
  }
}

export function mountMriBrain(container, opts = {}) {
  injectStyleOnce();
  const fetchUrl = opts.fetchUrl || `/v1/dashboard/memory/graph?status=all&limit=${DEFAULT_MRI_NODE_LIMIT}`;
  const showScan = opts.showScan !== false;
  const showDomainLegend = opts.showDomainLegend !== false;
  // View mode: 'memory' (the CLS memory graph, default/unchanged) or 'connectome'
  // (the agent message-bus as neurons + weighted synapses). A HUD toggle swaps
  // between them at runtime; the memory path is byte-for-byte what it was.
  const SYNAPSE_URL = opts.synapseUrl || '/v1/dashboard/network/synapses';
  const ENGRAMS_URL = opts.engramsUrl || '/v1/dashboard/memory/engrams';
  // Optional deep-link: open straight to one agent's lobe (its engrams bloomed).
  const focusAgent = opts.focusAgent || '';
  let autoBloomed = false;
  let deepLinkTimer = null;
  const allowConnectome = opts.allowConnectome !== false;
  let mode = opts.mode === 'connectome' ? 'connectome' : 'memory';
  // Per-view skull opacity. The memory graph keeps the anatomical hull prominent
  // (0.08); the connectome's payload is the WIRING, so it starts dimmer (0.03) so
  // synapses read on open. These are only INITIAL defaults — a manual SKULL
  // adjustment is remembered per view and recalled on the next toggle back, so a
  // round trip never discards the operator's choice (see mode-hull.js).
  const hullState = createModeHull({ memory: 0.08, connectome: 0.03 });
  const sliderUnits = o => String(Math.round(o * 100));

  const root = document.createElement('div');
  root.className = 'mrib';
  root.innerHTML = `
    <div class="mrib-graph"></div>
    <div class="boot">◉ ACQUIRING HIPPOCAMPAL FIELD…</div>
    ${showScan ? '<div class="panel scan"><b>CEREBRUM · MRI</b><div class="s">◉ SCANNING</div></div>' : ''}
    ${showDomainLegend ? `<div class="panel legend">
      <div class="lg-head"><h4>Domain tags</h4><span class="lg-toggle"></span></div>
      <div class="lg-detail">
        <div class="cls">A complementary-learning-systems view: SAGE is the <b>hippocampus</b>
          (episodic capture); corroboration + decay is the <b>sleep/consolidation</b> cycle.</div>
        <div class="seg">Nodes — memories</div>
        <div class="row"><span class="k">◍</span><div class="t"><b>Size + glow = corroboration</b><br><span>settled knowledge glows brighter</span></div></div>
        <div class="row"><span class="k">◌</span><div class="t"><b>Fade = confidence decay</b><br><span>the forgetting curve</span></div></div>
        <div class="row"><span class="k">⊘</span><div class="t"><b>Greyed = challenged / pruned</b><br><span>synaptic pruning</span></div></div>
        <div class="seg">Position</div>
        <div class="row"><span class="k">⊙</span><div class="t"><b>Depth = age</b><br><span>rim = fresh ideas (easy to reach) → stem / core = oldest</span></div></div>
        <div class="row"><span class="k">✦</span><div class="t"><b>Glowing halo = fresh idea</b><br><span>created today, pulled to the surface</span></div></div>
        <div class="row"><span class="k">◈</span><div class="t"><b>Angle = domain</b><br><span>each topic is a radial stream</span></div></div>
        <div class="row"><span class="k">◉</span><div class="t"><b>Click a memory</b><br><span>see its train of thought</span></div></div>
      </div>
      <div class="seg">Lobes — domains</div><div class="lobes"></div>
      <div class="lg-detail"><div class="seg">Connectome — typed links</div><div class="linktypes"></div></div>
    </div>` : ''}
    <div class="panel hud">
      <div><div class="n nn">0</div><div class="l">memories</div></div>
      <div><div class="n ne">0</div><div class="l">synapses</div></div>
      <div><div class="n nc">0</div><div class="l">consolidated</div></div>
      <div class="btn b-rot">⏸ pause</div>
      <div class="btn b-flow">⚡ flow: on</div>
      ${allowConnectome ? '<div class="btn b-mode">◉ connectome</div>' : ''}
      <label class="sld">skull <input class="b-op" type="range" min="0" max="60" value="8"></label>
    </div>
    <div class="tip"></div>
    <div class="flag"></div>`;
  container.appendChild(root);
  // Reflect the active view's skull opacity on the slider from the start.
  { const _op = root.querySelector('.b-op'); if (_op) _op.value = sliderUnits(hullState.valueFor(mode)); }
  const $ = s => root.querySelector(s);
  const escapeHtml = s => String(s==null?'':s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

  // The reading panel collapses to just the domain lobes (the default) so it
  // stops covering the brain; the full how-to-read detail is one click away.
  const LEGEND_KEY = 'sage-mri-legend';
  let legendMode = 'domains';
  try { legendMode = localStorage.getItem(LEGEND_KEY) === 'full' ? 'full' : 'domains'; } catch(e){}
  function applyLegendMode(){
    const lg = $('.legend'); if (!lg) return;
    lg.classList.toggle('collapsed', legendMode !== 'full');
    const t = $('.lg-toggle');
    if (t) t.textContent = legendMode === 'full' ? '▴ less' : '▾ how to read';
  }
  applyLegendMode();
  const lgToggle = $('.lg-toggle');
  if (lgToggle) lgToggle.onclick = () => {
    legendMode = legendMode === 'full' ? 'domains' : 'full';
    try { localStorage.setItem(LEGEND_KEY, legendMode); } catch(e){}
    applyLegendMode();
  };

  // Draggable "Domain tags" panel: grab its header to reposition it anywhere in
  // the view (clamped to the container). Clicking the collapse toggle still works.
  function makeDraggable(panel, handle){
    if (!panel || !handle) return;
    handle.style.cursor = 'move';
    handle.style.userSelect = 'none'; // don't select the header text while dragging
    let drag = false, sx = 0, sy = 0, ol = 0, ot = 0;
    // Document-level move/up (robust vs pointer-capture) + a loose clamp that only
    // keeps a grabbable strip on-screen, so a panel taller/wider than the view can
    // still be dragged down/around instead of being pinned to the top-right.
    const onMove = e => {
      if (!drag) return;
      const cw = root.clientWidth, ch = root.clientHeight;
      let nl = ol + (e.clientX - sx), nt = ot + (e.clientY - sy);
      nl = Math.max(80 - panel.offsetWidth, Math.min(cw - 80, nl));
      nt = Math.max(48 - panel.offsetHeight, Math.min(ch - 48, nt));
      panel.style.left = nl + 'px'; panel.style.top = nt + 'px';
      e.preventDefault();
    };
    const onUp = () => {
      drag = false;
      document.removeEventListener('pointermove', onMove);
      document.removeEventListener('pointerup', onUp);
    };
    handle.addEventListener('pointerdown', e => {
      if (e.target.closest('.lg-toggle')) return; // let the collapse toggle click through
      drag = true; ol = panel.offsetLeft; ot = panel.offsetTop;
      panel.style.right = 'auto'; panel.style.left = ol + 'px'; panel.style.top = ot + 'px';
      sx = e.clientX; sy = e.clientY;
      document.addEventListener('pointermove', onMove);
      document.addEventListener('pointerup', onUp);
      e.preventDefault(); e.stopPropagation();
    });
  }
  { const _lg = $('.legend'), _h = _lg && _lg.querySelector('.lg-head'); makeDraggable(_lg, _h); }

  // Click-to-explore ("train of thought") focus state. focusSet null = full brain.
  let focusId = null, focusSet = null;

  const domainColors = {}; let seq = 0;
  const domainColor = k => { if(!k) k='unknown'; if(!domainColors[k]){ domainColors[k]=PALETTE[seq%PALETTE.length]; seq++; } return domainColors[k]; };

  // Instanced node styling — one draw call for ALL dots (scales to thousands),
  // vs the old mesh+sprite per node. size = corroboration+confidence; colour =
  // domain brightened toward white by corroboration (so the bloom pass makes
  // consolidated memories glow); alpha = confidence (decay); challenged/
  // deprecated greyed.
  // Rung 5 — neurogenesis + pruning. A newly-registered agent (id absent from the
  // previous snapshot) is stamped with _bornAt and briefly swells + glows as it
  // grows in; the boost decays over NEURON_BIRTH_MS so birth reads as an event, not
  // a permanent size. Dormancy greys a neuron in proportion to how long its circuit
  // has been silent (neuronDormancy over _activity), reusing the existing grey.
  const NEURON_BIRTH_MS = 3200;
  const NEURON_DORMANCY = opts.neuronDormancy || { liveMs: 3600000, coldMs: 43200000 };
  function neuronBirthGlow(n){
    if (!n || !n._bornAt) return 0;
    const age = Date.now() - n._bornAt;
    if (age < 0 || age > NEURON_BIRTH_MS) return 0;
    return 1 - (age / NEURON_BIRTH_MS);
  }
  const dormancyOf = n => neuronDormancy(n && n._activity, Date.now(), NEURON_DORMANCY);

  // Memory nodes size by corroboration+confidence+freshness; neurons size by
  // degree (total traffic) so hubs read as large cells, plus a transient birth swell.
  const nodeVal = n => n.isNeuron
    ? 1.6 + (n._deg||0)*7 + neuronBirthGlow(n)*4
    : 1.4 + (n.corroboration_count||0)*1.1 + (n.confidence||0)*0.8 + (n._fresh||0)*2.2;
  function nodeColorRGBA(n){
    // Focus mode: everything outside the clicked node's neighbourhood fades back.
    if(focusSet && !focusSet.has(n.id)) return n.isNeuron ? 'rgba(96,110,135,0.10)' : 'rgba(96,110,135,0.08)';
    // Neurons: domain hue, brightened toward the glow by degree so hub agents pop.
    if(n.isNeuron){
      // Domain hue brightened by degree, greyed by dormancy (pruning), flared on
      // birth (neurogenesis) — composed by the pure neuronTint so the blend is
      // pinned by numbers, not just wiring.
      const t=neuronTint(hexToRgb(domainColor(n.domain)), n._deg, dormancyOf(n), neuronBirthGlow(n));
      return `rgba(${t.r},${t.g},${t.b},${t.a})`;
    }
    if(n.status==='deprecated') return 'rgba(108,120,145,0.30)';
    if(n.status==='challenged') return 'rgba(150,162,185,0.55)';
    const [r,g,b]=hexToRgb(domainColor(n.domain));
    const boost=Math.min(1,(n.corroboration_count||0)/8);
    let br=r+(255-r)*boost*0.5, bg=g+(255-g)*boost*0.5, bb=b+(255-b)*boost*0.5;
    let a=0.6+(n.confidence||0)*0.4;
    // Freshness halo: "fresh ideas" (memories from the last day) are pushed toward a
    // bright accent at full opacity so the bloom pass gives them an outer glow, fading
    // out over ~24h as the idea settles.
    const fr=n._fresh||0;
    if(fr>0){ br+=(90-br)*0.72*fr; bg+=(220-bg)*0.72*fr; bb+=(255-bb)*0.72*fr; a=Math.max(a,0.85+0.15*fr); }
    return `rgba(${br|0},${bg|0},${bb|0},${a.toFixed(2)})`;
  }

  // Link accessors are mode-aware via the datum's link_type. In the memory view
  // every link is a typed memory edge (unchanged formulas); in the connectome a
  // synapse's normalized weight _w drives Hebbian thickness, particle count and
  // pulse speed — heavier, hotter channels read thicker and fire faster.
  // A synapse that just carried a message is briefly thickened and given extra
  // particles. The boost decays on its own so a burst reads as firing rather
  // than as a permanent weight change — the retained weight already covers that.
  const SYNAPSE_PULSE_MS = 2600;
  function synapsePulse(l){
    if (!l || !l._firedAt) return 0;
    const age = Date.now() - l._firedAt;
    if (age < 0 || age > SYNAPSE_PULSE_MS) return 0;
    return 1 - (age / SYNAPSE_PULSE_MS);
  }
  // Resting-weight plasticity ("use it or lose it"): the RETAINED weight decays
  // toward a floor while a synapse sits idle and climbs back as it fires, keyed on
  // last_fired. Distinct from synapsePulse (the seconds-long firing flash) — this is
  // the slow drift of the resting weight, so idle channels thin and dim while busy
  // ones stay bright. restingWeight() is what the accessors render instead of raw _w.
  const PLASTICITY = opts.plasticity || { halfLifeMs: 1800000, floor: 0.15 };
  const plasticityOf = l => synapsePlasticity(l && l.last_fired, Date.now(), PLASTICITY);
  const restingWeight = l => (l._w||0) * plasticityOf(l);
  function linkWidthFor(l){
    if(l.link_type==='synapse') return 0.25 + restingWeight(l)*2.4 + synapsePulse(l)*2.0;
    if(l.link_type==='engram-bridge') return 0.5;
    return l.link_type==='focus'?0.8 : l.link_type==='contradicts'?0.6 : (LINK_TYPES[l.link_type]||{}).typed?0.35:0.18;
  }
  function linkParticlesFor(l){
    if(l.link_type==='synapse') return flow ? Math.min(8, 1+Math.round(restingWeight(l)*5)+Math.round(synapsePulse(l)*2)) : 0;
    return l.link_type==='focus'?3 : (flow&&(LINK_TYPES[l.link_type]||{}).typed?2:0);
  }
  function linkParticleSpeedFor(l){
    if(l.link_type==='synapse') return 0.004 + restingWeight(l)*0.02;
    return 0.006;
  }
  // Idle synapses also dim: alpha rides the plasticity factor so a cold channel
  // recedes and a warm one stands out. Non-synapse links keep their typed colour.
  const SYNAPSE_RGB = '57,208,255';
  function linkColorFor(l){
    if(l.link_type==='synapse') return `rgba(${SYNAPSE_RGB},${(0.40 + 0.60*plasticityOf(l)).toFixed(2)})`;
    return (LINK_TYPES[l.link_type]||LINK_TYPES.related).color;
  }

  // Clicking a neuron lights its synaptic neighbourhood (the clicked cell + every
  // agent it exchanges with); everything else fades via focusSet, reusing the
  // memory view's focus fade. No network fetch — purely the graph already loaded.
  function focusNeuron(n){
    if(!Graph || !rendered) return;
    const nb=new Set([n.id]);
    rendered.links.forEach(l=>{
      const s=(l.source&&l.source.id)||l.source, t=(l.target&&l.target.id)||l.target;
      if(s===n.id) nb.add(t); else if(t===n.id) nb.add(s);
    });
    focusId=n.id; focusSet=nb;
    Graph.nodeColor(nodeColorRGBA);
    setFocusMarkerNode(n);
  }

  // Agent-as-lobe (#182): clicking a neuron blooms its authored memories — the
  // "engrams" that re-anchor to their author. Lights the synaptic circle first
  // (responsive), then fetches this one agent's memories from /memory/engrams and
  // orbits them around the neuron as transient (_added) memory nodes tethered by
  // focus links. Disclosure is the memory graph's, partitioned by author. On-demand
  // per neuron, so it never fans out across every agent.
  // Strip any bloomed engrams (_added nodes + focus tethers) and repaint. The
  // removal is the pure stripBloom() so it can't silently become a no-op.
  function clearBloom(){
    if (!Graph) return;
    Graph.graphData(stripBloom(Graph.graphData()));
  }
  async function bloomEngrams(n){
    if (disposed || !Graph || !rendered || mode !== 'connectome') return;
    const agentID = n.agent_id || n.id;
    const bloomRequest = bloomLoads.begin(agentID);
    focusNeuron(n);
    // Clear any prior bloom IMMEDIATELY, before the fetch — so a failed, errored,
    // or superseded request never strands the previous agent's engrams under this
    // neuron's focus. Every early-return below leaves the view cleared, not stale.
    clearBloom();
    let payload;
    try {
      const resp = await fetch(ENGRAMS_URL + '?agent=' + encodeURIComponent(agentID), { credentials: 'same-origin' });
      if (!resp.ok) return;
      payload = await resp.json();
    } catch (e) { console.warn('[mri] engrams unavailable:', e.message); return; }
    // Superseded (another neuron clicked while this was in flight) or torn down:
    // drop the stale response rather than bloom it under the wrong focus.
    if (disposed || !Graph || mode !== 'connectome' || focusId !== n.id ||
        !bloomLoads.isCurrent(bloomRequest, agentID)) return;
    const engrams = mapEngrams(payload);
    const composed = applyEngramBloom(Graph.graphData(), engrams, n, focusSet, placeNear);
    focusId = n.id; focusSet = composed.focusSet;
    Graph.graphData(composed.graphData);
    Graph.nodeColor(nodeColorRGBA);
    setFocusMarkerNode(n);
  }

  // Deterministic placement — NO force simulation. domain -> azimuthal lobe (each
  // topic is a radial stream), AGE -> radial depth: the NEWEST memories ("fresh
  // ideas") sit on the outer cortex surface (large, easy to click, glowing) and
  // memories settle INWARD toward the stem/core as they age; memories from the same
  // period share a narrow depth band regardless of topic. Positions are pinned
  // (fx/fy/fz), so the layout is a pure formula, stable across reloads, with zero
  // per-tick cost.
  // Node placement ellipsoid, sized to use the brain's interior without crossing its
  // folded surface. The hull (mesh scale 185, proportions x0.86/y0.80/z1.20) has smooth
  // half-extents ~159/148/222. At max depth 0.89 these extents produce ~138/120/191,
  // leaving clearance for cortical folds and the flattened underside while occupying
  // substantially more of the visible brain than the old ~111/93/152 cloud.
  //
  // A one-year age window is deliberate. The previous 90-day clamp collapsed every
  // older memory onto the same tiny inner shell; on a long-lived 10k-memory brain that
  // made thousands of dots crowd the centre. The wider window plus deterministic radial
  // jitter spreads historical memories through the interior while keeping age legible:
  // fresh memories remain near the cortex and the oldest remain closest to the core.
  const EX=MRI_LAYOUT.halfExtentX, EZ=MRI_LAYOUT.halfExtentZ;
  const DAY=86400000, AGE_WINDOW=MRI_LAYOUT.ageWindowDays*DAY;
  const hsh=(s,seed)=>{ s=s||''; let h=(seed>>>0)||1; for(let i=0;i<s.length;i++) h=Math.imul(h^s.charCodeAt(i),16777619); return ((h>>>0)%10000)/10000; };
  function placeNodes(nodes){
    const ds=[...new Set(nodes.map(n=>n.domain))], nd=Math.max(1,ds.length), di={};
    ds.forEach((k,i)=>{ di[k]=i; domainColor(k); });
    const now=Date.now();
    nodes.forEach(n=>{
      const t=Date.parse(n.created_at);
      // AGE over a fixed recency WINDOW (last year): today -> 0 (fresh, outer
      // surface), anything 365+ days old -> 1 (clamped to the inner stem/core). A fixed
      // window (not min/max of ALL history) spreads the relevant-recent memories across
      // the full radius instead of crushing them into a thin outer band.
      const age=isNaN(t)?1:Math.max(0, Math.min(1, (now-t)/AGE_WINDOW));
      n._age=age;
      n._fresh=isNaN(t)?0:Math.max(0, Math.min(1, 1-(now-t)/DAY)); // 1 = created in the last 24h
      const recency=1-age;
      const az=((di[n.domain]||0)/nd)*Math.PI*2 + (hsh(n.id,1)-0.5)*(Math.PI*2/nd)*0.82;
      const el=(hsh(n.id,2)-0.5)*Math.PI*0.96;
      // Radius grows with RECENCY, with a small stable per-memory offset so thousands of
      // same-age memories occupy a volume instead of one overlapping shell. The final
      // 0.20..0.89 range stays inside the folded cortical surface.
      const depth=mriDepthForAge(age,hsh(n.id,3));
      const ce=Math.cos(el);
      n.fx=n.x=EX*depth*ce*Math.cos(az);
      // Age also bends the trajectory toward the lower inner brainstem: fresh memories
      // retain the full cortical spread, while the oldest cohort settles visibly below
      // the centre instead of forming an undifferentiated ball around the origin.
      n.fy=n.y=mriVerticalPosition(depth,Math.sin(el),age);
      n.fz=n.z=EZ*depth*ce*Math.sin(az);
    });
  }

  // Connectome placement — same deterministic ellipsoid, but neurons have no age.
  // domain -> azimuthal lobe (as memories), and DEGREE (total traffic) -> radial
  // depth: hub neurons sink toward the core/stem (the brain's deep structure),
  // peripheral neurons sit on the cortex. Degree maps onto exactly the radial
  // scale age uses for memories, so the two views share one spatial language.
  function placeNeurons(nodes){
    const ds=[...new Set(nodes.map(n=>n.domain))], nd=Math.max(1,ds.length), di={};
    ds.forEach((k,i)=>{ di[k]=i; domainColor(k); });
    nodes.forEach(n=>{
      const deg=Math.max(0,Math.min(1,n._deg||0));
      const az=((di[n.domain]||0)/nd)*Math.PI*2 + (hsh(n.id,1)-0.5)*(Math.PI*2/nd)*0.82;
      const el=(hsh(n.id,2)-0.5)*Math.PI*0.96;
      const depth=mriDepthForAge(deg,hsh(n.id,3));
      const ce=Math.cos(el);
      n.fx=n.x=EX*depth*ce*Math.cos(az);
      n.fy=n.y=mriVerticalPosition(depth,Math.sin(el),deg);
      n.fz=n.z=EZ*depth*ce*Math.sin(az);
    });
  }
  const placeActive = nodes => mode==='connectome' ? placeNeurons(nodes) : placeNodes(nodes);

  // ForceGraph3D resolves string link endpoints to node objects lazily, via the
  // d3 'link' force — which this renderer nulls (node positions are pinned). For
  // the memory view that is fine (its value is in node placement/glow), but the
  // connectome's synapses ARE the payload, so resolve their endpoints to the node
  // objects up front; otherwise every synapse would reference an unresolved id and
  // render nothing. No-op for the memory view.
  function resolveConnectomeLinks(d){
    if (mode !== 'connectome' || !d || !Array.isArray(d.links)) return;
    const byId = new Map(d.nodes.map(n => [n.id, n]));
    d.links.forEach(l => {
      if (typeof l.source === 'string' && byId.has(l.source)) l.source = byId.get(l.source);
      if (typeof l.target === 'string' && byId.has(l.target)) l.target = byId.get(l.target);
    });
  }

  let Graph = null, controls = null, disposed = false, flow = true, scanning = true;
  let lastNodeClickAt = 0, graphPointerDown = null;
  let hullMat = null, brainMat = null, surfMat = null, curOpacity = hullState.valueFor(mode);
  let focusMarker = null, focusRingTexture = null;
  let currentDomain = null;                 // drill-down lobe (null = overview)
  const baseUrl = fetchUrl;
  const urlFor = () => baseUrl + (currentDomain ? '&domain=' + encodeURIComponent(currentDomain) : '');
  // Mode-aware source: the memory graph (domain-drillable) or the connectome.
  const fetchActive = requestMode => requestMode === 'connectome' ? loadSynapses(SYNAPSE_URL) : loadGraph(urlFor());
  const graphLoads = createGraphLoadCoordinator();
  const bloomLoads = createEngramBloomCoordinator();
  let rendered = null;   // last graph data handed to ForceGraph (for neuron focus)
  const subs = [];
  let graphRetryTimer = null;
  let graphRetryDelay = 2000;
  let graphLoadInFlight = false;
  let graphReloadPending = false;
  const resetGraphRetry = () => { graphRetryDelay = 2000; };
  const scheduleGraphRetry = callback => {
    clearTimeout(graphRetryTimer);
    const delay = graphRetryDelay;
    graphRetryDelay = Math.min(graphRetryDelay * 2, 30000);
    graphRetryTimer = setTimeout(callback, delay);
  };
  const reportGraphAvailability = state => {
    container.dispatchEvent(new CustomEvent('sage:mri-graph-availability', {
      detail: { state },
    }));
  };

  function setHullOpacity(o){
    curOpacity = o;
    const eo = mriHullOpacity(o);
    if (brainMat) { brainMat.opacity = eo; if (surfMat) surfMat.opacity = eo * 0.5; if (hullMat) hullMat.opacity = 0; }
    else if (hullMat) { hullMat.opacity = eo; }
  }

  function ensureFocusMarker(){
    if (!Graph) return null;
    if (!focusMarker) {
      focusRingTexture = focusRingTexture || makeFocusRingTexture();
      focusMarker = new THREE.Sprite(new THREE.SpriteMaterial({
        map: focusRingTexture,
        color: 0xffffff,
        transparent: true,
        opacity: 0.96,
        depthTest: false,
        depthWrite: false,
      }));
      focusMarker.renderOrder = 999;
      focusMarker.visible = false;
      Graph.scene().add(focusMarker);
    }
    return focusMarker;
  }

  function setFocusMarkerNode(n){
    const m = ensureFocusMarker();
    if (!m || !n) return;
    m.position.set(n.x || 0, n.y || 0, n.z || 0);
    const s = Math.max(30, Math.min(48, 28 + nodeVal(n) * 2.4));
    m.scale.set(s, s, 1);
    m.visible = true;
  }

  function clearFocusMarker(){
    if (focusMarker) focusMarker.visible = false;
  }

  function refreshCounts(d){
    if (mode==='connectome') {
      // neurons / synapses / hubs (busiest half of the traffic distribution).
      $('.nn').textContent = fmtN(d.nodes.length);
      $('.ne').textContent = fmtN(d.links.length);
      $('.nc').textContent = fmtN(d.nodes.filter(n=>(n._deg||0)>=0.5).length);
      $('.flag').textContent = d.nodes.length ? '' : (d.live === false ? 'no live data' : 'no agents registered yet');
      return;
    }
    // .nn shows the TRUE total (operator view), not just the rendered sample.
    $('.nn').textContent = fmtN(d.total && d.total > d.nodes.length ? d.total : d.nodes.length);
    $('.ne').textContent = fmtN(d.links.length);
    $('.nc').textContent = fmtN(d.nodes.filter(n=>(n.corroboration_count||0)>=4 && n.status==='committed').length);
    const dom = currentDomain && d.domainCounts && d.domainCounts[currentDomain];
    if (currentDomain) {
      $('.flag').textContent = `${currentDomain} · showing ${d.nodes.length}${dom?` of ${fmtN(dom)}`:''}`;
    } else if (d.total && d.total > d.nodes.length) {
      $('.flag').textContent = `showing ${d.nodes.length} of ${fmtN(d.total)} · representative sample`;
    } else {
      $('.flag').textContent = d.live === false ? 'no live data' : (d.nodes.length ? '' : 'no memories yet');
    }
  }

  // Lobe legend with per-domain counts; click a lobe to drill into it, "← all
  // lobes" to return. Built from the true domain set so every lobe stays
  // navigable even while only a sample is shown.
  const MAX_LOBES = 30;
  function buildLobes(d){
    const dc = d.domainCounts || {};
    const dl = d.domainLast || {};
    // Most recently active first (last committed memory), alpha tiebreak;
    // capped to the newest 30 - the full list lives in Search.
    const all = (Object.keys(dc).length ? Object.keys(dc) : [...new Set(d.nodes.map(n=>n.domain))])
      .sort((a,b) => String(dl[b]||'').localeCompare(String(dl[a]||'')) || a.localeCompare(b));
    const doms = all.slice(0, MAX_LOBES);
    const lobes = $('.lobes');
    if (!lobes) return;
    lobes.innerHTML = '';
    if (currentDomain) {
      const back = document.createElement('div');
      back.className = 'row'; back.style.cursor = 'pointer';
      back.innerHTML = '<span class="k">←</span><div class="t"><b>all lobes</b></div>';
      back.onclick = () => { currentDomain = null; load(); zoomOut(); };
      lobes.appendChild(back);
    }
    // The connectome endpoint is not domain-drillable, so there its lobes are a
    // pure colour legend; the memory view keeps click-to-drill.
    const drill = mode !== 'connectome';
    doms.forEach(k => {
      const row = document.createElement('div');
      row.className = 'row'; if (drill) row.style.cursor = 'pointer';
      if (currentDomain === k) row.style.background = 'rgba(57,208,255,0.10)';
      row.innerHTML = `<span class="dot" style="background:${domainColor(k)}"></span><div class="t"><b>${escapeHtml(k)}</b>${dc[k]?` <span style="color:#5d7395">· ${fmtN(dc[k])}</span>`:''}</div>`;
      if (drill) row.onclick = () => { if (currentDomain !== k) { currentDomain = k; load(); } };
      lobes.appendChild(row);
    });
    if (all.length > doms.length) {
      const more = document.createElement('div');
      more.className = 'more';
      more.textContent = `+ ${all.length - doms.length} older domains - find them in Search`;
      lobes.appendChild(more);
    }
  }

  // Re-fetch (respecting the drill domain) and re-render. Deterministic placement
  // keeps existing nodes put; no re-heat.
  // The tracker retains the previous AUTHORIZED snapshot. The diff runs on
  // what this client was actually allowed to fetch, so a pulse can never be
  // shown for an edge the snapshot withheld.
  const connectomeActivity = createConnectomeActivityTracker();
  let pulseDecayTimer = null;
  function markConnectomeFiring(d, fromConnectomeTick, tickPending = false){
    if (mode !== 'connectome' || !d || !Array.isArray(d.links)) return;
    const fired = new Set(connectomeActivity.observe(
      d.links, fromConnectomeTick, tickPending,
    ));
    if (!fired.size) return;
    const now = Date.now();
    for (const l of d.links) {
      const src = typeof l.source === 'object' ? l.source.id : l.source;
      const tgt = typeof l.target === 'object' ? l.target.id : l.target;
      if (fired.has(`${src}\u0000${tgt}`)) l._firedAt = now;
    }
    // Re-read the accessors once the pulse has decayed so the boost does not
    // linger until some unrelated redraw happens to clear it.
    clearTimeout(pulseDecayTimer);
    pulseDecayTimer = setTimeout(() => {
      if (disposed || !Graph) return;
      Graph.linkWidth(linkWidthFor).linkDirectionalParticles(linkParticlesFor);
    }, SYNAPSE_PULSE_MS + 100);
  }

  // Resting-weight plasticity is time-based, so an idle connectome must re-read its
  // synapse accessors on a slow cadence to visibly settle (thin + dim) even when no
  // message fires. Cheap — it re-applies the accessor functions; node positions are
  // pinned — and self-gated to connectome mode, so the memory view never pays for it.
  const PLASTICITY_REFRESH_MS = 30000;
  let plasticityTimer = null;
  function startPlasticityDecay(){
    if (plasticityTimer) return;
    plasticityTimer = setInterval(() => {
      if (disposed || !Graph || mode !== 'connectome') return;
      Graph.linkWidth(linkWidthFor).linkColor(linkColorFor).linkDirectionalParticles(linkParticlesFor);
    }, PLASTICITY_REFRESH_MS);
  }
  startPlasticityDecay();

  // Neurogenesis: stamp _bornAt on agents that appeared since the last snapshot so
  // they grow in, then re-read the node accessors once the birth swell has decayed.
  // The first snapshot only seeds the baseline (no whole-graph birth flash).
  const neuronBirths = createNeuronBirthTracker();
  let birthDecayTimer = null;
  function markConnectomeBirths(d){
    if (mode !== 'connectome' || !d || !Array.isArray(d.nodes)) return;
    const born = new Set(neuronBirths.observe(d.nodes.map(n => n.id)));
    if (!born.size) return;
    const now = Date.now();
    for (const n of d.nodes) { if (born.has(n.id)) n._bornAt = now; }
    clearTimeout(birthDecayTimer);
    birthDecayTimer = setTimeout(() => {
      if (disposed || !Graph) return;
      Graph.nodeVal(nodeVal).nodeColor(nodeColorRGBA);
    }, NEURON_BIRTH_MS + 120);
  }
  // Dormancy drifts over minutes, so an idle connectome re-reads its node colour on
  // a slow cadence to let cold agents grey out even with no new events. Self-gated
  // to connectome mode; cleared on dispose.
  const DORMANCY_REFRESH_MS = 30000;
  let dormancyTimer = null;
  function startDormancyDecay(){
    if (dormancyTimer) return;
    dormancyTimer = setInterval(() => {
      if (disposed || !Graph || mode !== 'connectome') return;
      Graph.nodeColor(nodeColorRGBA);
    }, DORMANCY_REFRESH_MS);
  }
  startDormancyDecay();

  const connectomeReloadIntent = createConnectomeReloadIntent();
  function load(fromConnectomeTick = false){
    if (fromConnectomeTick) connectomeReloadIntent.requestTick();
    if (graphLoadInFlight) {
      graphReloadPending = true;
      return;
    }
    graphLoadInFlight = true;
    const request = graphLoads.begin(mode);
    const tickGeneration = connectomeReloadIntent.begin(request.mode);
    const tickAware = tickGeneration > 0;
    // A drill / reload leaves focus mode.
    focusId = null; focusSet = null; hideExplorePanel(); clearFocusMarker();
    fetchActive(request.mode).then(d => {
      if (disposed || !Graph || !graphLoads.isCurrent(request, mode)) return;
      clearTimeout(graphRetryTimer);
      resetGraphRetry();
      reportGraphAvailability('ready');
      placeActive(d.nodes);
      resolveConnectomeLinks(d);
      markConnectomeFiring(d, tickAware, connectomeReloadIntent.isPending(request.mode) && !tickAware);
      markConnectomeBirths(d);
      Graph.graphData(d);
      rendered = d;
      refreshCounts(d);
      buildLobes(d);
      connectomeReloadIntent.settle(request.mode, tickGeneration, true);
    }).catch(() => {
      if (disposed || !graphLoads.isCurrent(request, mode)) return;
      reportGraphAvailability('unavailable');
      if (!graphReloadPending) scheduleGraphRetry(load);
    }).finally(() => {
      graphLoadInFlight = false;
      if (graphReloadPending && !disposed) {
        graphReloadPending = false;
        clearTimeout(graphRetryTimer);
        load();
      }
    });
  }

  // The CEREBRUM home page owns the consolidated domain-source panel. It can
  // drive this renderer without duplicating a second domain legend inside the
  // canvas. An empty domain restores the whole-brain view.
  const onExternalDomainSelect = event => {
    const next = String(event && event.detail && event.detail.domain || '');
    if (currentDomain === (next || null)) return;
    currentDomain = next || null;
    if (Graph) {
      load();
      if (!currentDomain) zoomOut();
    }
  };
  container.addEventListener('sage:mri-domain-select', onExternalDomainSelect);
  subs.push(() => container.removeEventListener('sage:mri-domain-select', onExternalDomainSelect));

  // --- Click-to-explore: a memory's "train of thought" ----------------------
  // Clicking a node fetches its top related memories, blooms them as a labelled
  // constellation around it (adding any that aren't in the sample), dims the
  // rest of the brain, and lists them in a side panel. Click the background or
  // "back" to return to the full brain.
  const relatedBase = fetchUrl.split('/memory/')[0] + '/memory/';

  function placeNear(node, anchor, i){
    const rr = 40 + (i % 10) * 7;
    const a = hsh(node.id, 1) * Math.PI * 2, el = (hsh(node.id, 2) - 0.5) * Math.PI;
    const ce = Math.cos(el);
    node.fx = node.x = anchor.x + rr * ce * Math.cos(a);
    node.fy = node.y = anchor.y + rr * Math.sin(el);
    node.fz = node.z = anchor.z + rr * ce * Math.sin(a);
  }

  // Return the camera to the framing shot. Used when leaving focus and when
  // jumping back to all lobes - but NEVER from load() itself, which SSE
  // reloads also call (yanking the camera on every new memory would fight
  // the user's hand).
  function zoomOut(){
    if (Graph) Graph.cameraPosition({ x: 0, y: 60, z: 620 }, { x: 0, y: 0, z: 0 }, 900);
  }

  function exitFocus(){
    if (!focusId) return;
    bloomLoads.invalidate();
    focusId = null; focusSet = null;
    clearFocusMarker();
    if (Graph) {
      Graph.graphData(stripBloom(Graph.graphData()));
      Graph.nodeColor(nodeColorRGBA);
    }
    hideExplorePanel();
    zoomOut();
  }

  async function exploreNode(n){
    if (!Graph) return;
    let data;
    try {
      const resp = await fetch(relatedBase + encodeURIComponent(n.id) + '/related?k=50', { credentials: 'same-origin' });
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      data = await resp.json();
    } catch (e) { console.warn('[mri] related fetch failed:', e.message); return; }
    if (disposed) return;
    const relatedAll = (data && Array.isArray(data.related)) ? data.related : [];
    // Second re-rank pass over the similarity results: raw similarity mixes
    // unrelated tags, so scope the train of thought to the clicked memory's
    // OWN lobe plus adjacent lobes (domains the current connectome shows
    // typed links into from this domain).
    const homeDomain = n.domain || 'unknown';
    const adjacent = (() => {
      const adj = new Set();
      const gd0 = Graph.graphData();
      const domOf = {}; gd0.nodes.forEach(nn => { domOf[nn.id] = nn.domain || 'unknown'; });
      gd0.links.forEach(l => {
        if (l.link_type === 'domain' || l.link_type === 'focus') return; // typed links only
        const a = domOf[typeof l.source === 'object' ? l.source.id : l.source];
        const b = domOf[typeof l.target === 'object' ? l.target.id : l.target];
        if (!a || !b || a === b) return;
        if (a === homeDomain) adj.add(b);
        if (b === homeDomain) adj.add(a);
      });
      return adj;
    })();
    const related = relatedAll.filter(rr => {
      const d = rr.domain || 'unknown';
      return d === homeDomain || adjacent.has(d);
    });
    focusId = n.id;
    focusSet = new Set([n.id]);
    related.forEach(rr => focusSet.add(rr.id));

    const gd = Graph.graphData();
    gd.nodes = gd.nodes.filter(nn => !nn._added);
    gd.links = gd.links.filter(l => l.link_type !== 'focus');
    const present = new Set(gd.nodes.map(nn => nn.id));
    related.forEach((rr, i) => {
      if (!present.has(rr.id)) {
        const node = { id: rr.id, domain: rr.domain || 'unknown', label: rr.content || rr.id,
          status: rr.status || 'committed', corroboration_count: rr.corroboration_count || 0,
          confidence: typeof rr.confidence === 'number' ? rr.confidence : 0.5, memory_type: '', _added: true };
        placeNear(node, n, i);
        gd.nodes.push(node);
        present.add(rr.id);
      }
      gd.links.push({ source: n.id, target: rr.id, link_type: 'focus' });
    });
    Graph.graphData(gd);
    Graph.nodeColor(nodeColorRGBA);
    setFocusMarkerNode(n);
    renderExplorePanel(data, related);
    // Frame the whole train of thought at a fixed, reliable distance (the
    // constellation spans ~110 units around the clicked node): pull the camera
    // out along the node's radial direction and look at it.
    const r = Math.hypot(n.x, n.y, n.z) || 1, d = 300;
    Graph.cameraPosition({ x: n.x*(1+d/r), y: n.y*(1+d/r), z: n.z*(1+d/r) }, n, 900);
  }

  // The board columns: a memory's train of thought, bucketed by kind.
  const KINDS = [
    { key: 'do',          label: "Do's",         glyph: '✓' },
    { key: 'dont',        label: "Don'ts",       glyph: '✗' },
    { key: 'observation', label: 'Observations', glyph: '◉' },
    { key: 'note',        label: 'Notes',        glyph: '▪' },
  ];
  const EX_FONT_KEY = 'sage-mri-explore-font';
  const EX_HEIGHT_KEY = 'sage-mri-explore-height';
  const EX_FONT_MIN = 12, EX_FONT_MAX = 18;
  let exploreFont = EX_FONT_MIN;
  try {
    const saved = parseInt(localStorage.getItem(EX_FONT_KEY) || '', 10);
    if (Number.isFinite(saved)) exploreFont = Math.max(EX_FONT_MIN, Math.min(EX_FONT_MAX, saved));
  } catch(e){}

  function applyExplorePrefs(p){
    p.style.setProperty('--ex-font', exploreFont + 'px');
    try {
      const savedHeight = parseInt(localStorage.getItem(EX_HEIGHT_KEY) || '', 10);
      if (Number.isFinite(savedHeight) && savedHeight > 0) {
        const maxH = Math.max(230, Math.round(root.clientHeight * 0.72));
        p.style.height = Math.max(210, Math.min(maxH, savedHeight)) + 'px';
      }
    } catch(e){}
    p.querySelectorAll('[data-font]').forEach(btn => {
      const dir = btn.getAttribute('data-font');
      btn.disabled = (dir === 'down' && exploreFont <= EX_FONT_MIN) || (dir === 'up' && exploreFont >= EX_FONT_MAX);
    });
  }

  function changeExploreFont(delta){
    exploreFont = Math.max(EX_FONT_MIN, Math.min(EX_FONT_MAX, exploreFont + delta));
    try { localStorage.setItem(EX_FONT_KEY, String(exploreFont)); } catch(e){}
    const p = $('.explore');
    if (p) applyExplorePrefs(p);
  }

  function wireExploreResize(p){
    const handle = p.querySelector('.ex-resize');
    if (!handle) return;
    handle.onpointerdown = ev => {
      ev.preventDefault();
      handle.setPointerCapture(ev.pointerId);
      const startY = ev.clientY;
      const startH = p.getBoundingClientRect().height;
      const maxH = Math.max(230, Math.round(root.clientHeight * 0.72));
      const minH = 210;
      const move = e => {
        const h = Math.max(minH, Math.min(maxH, startH + (startY - e.clientY)));
        p.style.height = Math.round(h) + 'px';
      };
      const up = e => {
        handle.releasePointerCapture(e.pointerId);
        handle.removeEventListener('pointermove', move);
        handle.removeEventListener('pointerup', up);
        handle.removeEventListener('pointercancel', up);
        try { localStorage.setItem(EX_HEIGHT_KEY, String(Math.round(p.getBoundingClientRect().height))); } catch(err){}
      };
      handle.addEventListener('pointermove', move);
      handle.addEventListener('pointerup', up);
      handle.addEventListener('pointercancel', up);
    };
  }

  function renderExplorePanel(data, related){
    let p = $('.explore');
    if (!p) { p = document.createElement('div'); p.className = 'panel explore'; root.appendChild(p); }
    const groups = { do: [], dont: [], observation: [], note: [] };
    related.forEach(rr => (groups[rr.kind] || groups.note).push(rr));
    const card = rr => `
      <div class="ex-card" data-id="${escapeHtml(rr.id)}">
        <div class="ex-c">${escapeHtml(cleanContent(rr.content) || rr.id)}</div>
        <div class="ex-m"><span class="dot" style="background:${domainColor(rr.domain)}"></span>
          <span class="ex-dom">${escapeHtml(rr.domain||'')}</span>${rr.corroboration_count?` <span class="ex-cc">◍${rr.corroboration_count}</span>`:''}</div>
      </div>`;
    const columns = KINDS.map(k => {
      const items = groups[k.key] || [];
      return `<div class="ex-col k-${k.key}">
        <div class="ex-col-head"><span class="ex-col-glyph">${k.glyph}</span>${k.label}<span class="ex-col-n">${items.length}</span></div>
        <div class="ex-col-list">${items.map(card).join('') || '<div class="ex-empty">None yet</div>'}</div>
      </div>`;
    }).join('');
    p.innerHTML = `
      <div class="ex-resize" title="Resize panel"></div>
      <div class="ex-head">
        <div class="ex-head-l">
          <div class="ex-title">◉ Train of thought</div>
          <div class="ex-src">${escapeHtml(cleanContent(data.content) || '')}</div>
        </div>
        <div class="ex-actions">
          <div class="ex-font" aria-label="Note font size">
            <button type="button" data-font="down" title="Decrease note font size">A-</button>
            <button type="button" data-font="up" title="Increase note font size">A+</button>
          </div>
          <div class="ex-back">← back to full brain</div>
        </div>
      </div>
      ${related.length ? `<div class="ex-board">${columns}</div>` : '<div class="ex-empty ex-empty-big">No related memories in this lobe or its neighbours.</div>'}`;
    applyExplorePrefs(p);
    wireExploreResize(p);
    p.querySelector('.ex-back').onclick = exitFocus;
    p.querySelector('[data-font="down"]').onclick = () => changeExploreFont(-1);
    p.querySelector('[data-font="up"]').onclick = () => changeExploreFont(1);
    p.querySelectorAll('.ex-card').forEach(el => {
      el.onclick = () => {
        const rid = el.getAttribute('data-id');
        const gn = (Graph.graphData().nodes || []).find(nn => nn.id === rid);
        if (gn) exploreNode(gn);
      };
    });
    p.style.display = 'flex';
  }
  // cleanContent strips the leading [DO]/[DON'T]/[TAG] bracket (shown by the
  // column) so cards read cleanly.
  function cleanContent(s){ return String(s||'').replace(/^\s*\[[^\]]{1,24}\]\s*/, '').trim() || String(s||''); }
  function hideExplorePanel(){ const p = $('.explore'); if (p) p.style.display = 'none'; }

  function initializeGraph(data) {
    if (disposed) return;
    clearTimeout(graphRetryTimer);
    resetGraphRetry();
    reportGraphAvailability('ready');
    $('.boot').style.display = 'none';
    placeActive(data.nodes);
    resolveConnectomeLinks(data);
    markConnectomeFiring(data, false);
    markConnectomeBirths(data);
    rendered = data;
    Graph = ForceGraph3D({ controlType:'orbit' })($('.mrib-graph'))
      .backgroundColor(mriBgColor())
      .graphData(data).nodeId('id').nodeLabel(()=>'' )
      .nodeVal(nodeVal).nodeColor(nodeColorRGBA).nodeRelSize(2.4).nodeResolution(10).nodeOpacity(0.9)
      .linkColor(linkColorFor)
      .linkWidth(linkWidthFor)
      .linkOpacity(0.32)
      .linkDirectionalParticles(linkParticlesFor)
      .linkDirectionalParticleWidth(1.1).linkDirectionalParticleSpeed(linkParticleSpeedFor)
      .warmupTicks(1).cooldownTicks(6)
      .onNodeHover(showTip)
      .onNodeClick(n=>{ lastNodeClickAt = performance.now(); if (mode==='connectome') { if (n.isNeuron) bloomEngrams(n); } else exploreNode(n); })
      .onBackgroundClick(()=>{ exitFocus(); });

    // Positions are pinned by placeNodes() (fx/fy/fz), so disable the force
    // simulation entirely — zero per-tick cost regardless of node count.
    ['charge','link','center','lobe'].forEach(f=>{ try{ Graph.d3Force(f, null); }catch(e){ /* noop */ } });

    // Consolidation glow via a single bloom pass — scales to ANY node count (far
    // cheaper than the old halo-sprite-per-node). Bright (corroborated, white-
    // shifted) nodes bloom; the faint brain wireframe barely does.
    // ONLY enable the bloom composer if the GPU can hold the extra post-processing render
    // targets. On a small MAX_RENDERBUFFER_SIZE (observed 2048) at hi-DPI, the composer target
    // (logical × devicePixelRatio, e.g. 1462×2≈2924) exceeds the ceiling → renderbufferStorage
    // fails (GL_INVALID_VALUE) → COLOR_ATTACHMENT0 "no width or height" → the WHOLE scene is
    // black. In that case we never touch postProcessingComposer() at all, so ForceGraph3D renders
    // straight to the (pixel-ratio-clamped, always-safe) canvas — a glow-less brain beats a black
    // one. Capable GPUs (maxRB 8192+) keep the glow exactly as before.
    let bloom = null;
    try {
      const _r = Graph.renderer(), _gl = _r && _r.getContext && _r.getContext();
      const _maxRB = (_gl && _gl.getParameter(_gl.MAX_RENDERBUFFER_SIZE)) || 8192;
      const _rW = root.clientWidth||1280, _rH = root.clientHeight||720;
      if ((window.devicePixelRatio||1) * Math.max(_rW, _rH) <= _maxRB) {
        bloom = new UnrealBloomPass(new THREE.Vector2(_rW, _rH), mriIsLight()?0:0.55, 0.5, 0.32);
        Graph.postProcessingComposer().addPass(bloom);
      } else {
        console.warn('[mri] bloom disabled: MAX_RENDERBUFFER_SIZE', _maxRB, 'too small for',
          (window.devicePixelRatio||1)+'× DPR — rendering without glow (avoids a black canvas)');
      }
    } catch(e){ console.warn('[mri] bloom unavailable', e); }

    // --- WebGL surface-sizing fix --------------------------------------------
    // ForceGraph3D defaults its renderer + post-processing composer to the FULL
    // window × devicePixelRatio. On hi-DPI / large viewports that product blows
    // past the GPU's MAX_RENDERBUFFER_SIZE (the bloom pass's multisampled targets
    // ~double it), so the framebuffer is created incomplete (COLOR_ATTACHMENT0
    // has no width/height) and nothing draws — a black canvas that only recovers
    // when a `window` resize fires (e.g. opening DevTools shrinks the viewport).
    // FG3D also only listens to WINDOW resize, never the container, so a 0-sized
    // container at first paint never self-corrects. Fix: size to the CONTAINER,
    // clamp the pixel ratio + clamp to the GPU max, and observe the container so
    // it's valid on first paint and on layout changes — not just window resize.
    const gel = $('.mrib-graph');
    function fitGraph(){
      if (disposed || !Graph || !gel) return;
      const W = gel.clientWidth, H = gel.clientHeight;
      if (!W || !H) return; // container not laid out yet — ResizeObserver/rAF/timers will retry
      try {
        const renderer = Graph.renderer();
        const gl = renderer && renderer.getContext && renderer.getContext();
        const maxRB = (gl && gl.getParameter(gl.MAX_RENDERBUFFER_SIZE)) || 8192;
        let pr = Math.min(window.devicePixelRatio || 1, 1.5);
        pr = Math.min(pr, (maxRB / 2) / Math.max(W, H)); // stay under the GPU renderbuffer ceiling
        pr = Math.max(0.5, pr);
        if (renderer && renderer.setPixelRatio) renderer.setPixelRatio(pr);
        Graph.width(W).height(H); // FG3D renderer size
        // THE FIX: ForceGraph3D does NOT resize the EffectComposer or its passes,
        // so the bloom render targets stay at their (often 0x0) first-paint size →
        // COLOR_ATTACHMENT0 "no width or height" → incomplete framebuffer → black.
        // Resize the composer AND the bloom pass explicitly.
        // Only when bloom is active. Calling postProcessingComposer() LAZILY CREATES the
        // composer, so we must not touch it when post-processing was deliberately disabled for a
        // low-MAX_RENDERBUFFER_SIZE GPU — that would resurrect the oversized composer and re-black
        // the canvas. No bloom → FG3D renders straight to the clamped renderer.
        if (bloom) {
          const comp = Graph.postProcessingComposer && Graph.postProcessingComposer();
          if (comp) { if (comp.setPixelRatio) comp.setPixelRatio(pr); if (comp.setSize) comp.setSize(W, H); }
          if (bloom.setSize) bloom.setSize(W, H);
        }
      } catch(e){ /* noop */ }
    }
    fitGraph();
    requestAnimationFrame(fitGraph);
    [120, 400, 1000].forEach(t => setTimeout(fitGraph, t)); // catch late iframe/panel layout
    if (typeof ResizeObserver === 'function' && gel){
      const ro = new ResizeObserver(() => fitGraph());
      ro.observe(gel);
      subs.push(() => ro.disconnect());
    }

    try { const sc=Graph.scene();
      // Procedural brain-shaped wireframe hull (default — no external asset).
      // Additive blending makes overlapping wireframe lines accumulate into a
      // glow (amplified by the bloom pass), so the dense fold structure reads as
      // a luminous neural tangle rather than a flat mesh.
      const hull=new THREE.Mesh(makeBrainGeometry(),
        new THREE.MeshBasicMaterial({color:mriWireColor(),wireframe:true,transparent:true,opacity:mriHullOpacity(curOpacity),depthWrite:mriDepthWrite(),blending:mriWireBlend()}));
      hull.scale.setScalar(185); sc.add(hull); hullMat=hull.material;
      // Re-tint the brain + canvas live when the app theme toggles: additive-glow
      // blue on the dark canvas, normal-blended darker blue on the light canvas.
      const themeObs=new MutationObserver(()=>{ try{
        if(Graph) Graph.backgroundColor(mriBgColor());
        [hullMat,brainMat].forEach(m=>{ if(m){ m.color.set(mriWireColor()); m.blending=mriWireBlend(); m.depthWrite=mriDepthWrite(); m.needsUpdate=true; } });
        setHullOpacity(curOpacity); // re-apply opacity — normal vs additive blend need very different values
        if(bloom) bloom.strength = mriIsLight() ? 0 : 0.55; // glow is a dark-canvas effect; kill it on light
      }catch(e){ /* noop */ } });
      themeObs.observe(document.documentElement,{attributes:true,attributeFilter:['data-theme']});
      subs.push(()=>themeObs.disconnect());
      // Optional real anatomical mesh override at /ui/assets/brain.obj. No mesh
      // ships with SAGE, so this normally 404s and we keep the procedural hull.
      // NOTE: the static server SPA-falls-back to index.html (HTTP 200) for a
      // missing asset, so r.ok is NOT enough — parseOBJ would yield empty
      // geometry and we'd hide the procedural hull, leaving no brain at all.
      // Guard on a real vertex+face count before swapping.
      fetch('/ui/assets/brain.obj').then(r=>{ if(!r.ok) throw 0; return r.text(); }).then(txt=>{
        if(disposed||!Graph) return;
        const g=parseOBJ(txt); g.center(); g.computeBoundingSphere();
        const pos=g.getAttribute('position');
        if(!pos || pos.count<3 || !g.index || !g.index.count){ g.dispose(); return; } // not a real mesh (e.g. SPA 200 fallback) — keep procedural
        const s=255/((g.boundingSphere&&g.boundingSphere.radius)||1); // enclose the node cloud
        brainMat=new THREE.MeshBasicMaterial({color:0x6cc0ff,wireframe:true,transparent:true,opacity:curOpacity,depthWrite:false,blending:THREE.AdditiveBlending}); // additive → the dense anatomical wireframe glows under the bloom pass
        const wf=new THREE.Mesh(g,brainMat); wf.scale.setScalar(s); sc.add(wf);
        surfMat=new THREE.MeshBasicMaterial({color:0x14304e,transparent:true,opacity:curOpacity*0.5,side:THREE.BackSide,depthWrite:false});
        const surf=new THREE.Mesh(g,surfMat); surf.scale.setScalar(s); sc.add(surf);
        setHullOpacity(curOpacity); // hide the procedural hull now that the real mesh is in
      }).catch(()=>{ /* no override — keep the procedural brain */ });
    } catch(e){ /* hull optional */ }

    buildLobes(data);
    const lt=$('.linktypes');
    if (lt) Object.values(LINK_TYPES).filter(t=>t.typed).forEach(t=>lt.insertAdjacentHTML('beforeend',
      `<div class="row"><span class="bar" style="background:${t.color}"></span><div class="t"><span>${t.label}</span></div></div>`));
    refreshCounts(data);

    // Frame the brain once, then gentle auto-rotate via OrbitControls.
    // autoRotate respects user zoom/pan/drag — unlike setting cameraPosition
    // every frame, which previously clobbered all interaction.
    Graph.cameraPosition({ x: 0, y: 60, z: 620 }); // frame the whole brain + cloud
    controls = Graph.controls();
    if (controls) { controls.autoRotate = scanning; controls.autoRotateSpeed = 0.45; }

    // Centre the brain in the VISIBLE area. A standalone renderer may include the
    // right legend, while CEREBRUM uses its consolidated left domain-source panel. A
    // camera view-offset shifts the projection left/up WITHOUT rotating, so the brain
    // sits centred and autoRotate still spins around it (no orbit-centre drift).
    function centerView(){
      if (disposed || !Graph) return;
      try {
        const cam = Graph.camera();
        const W = root.clientWidth || 1280, H = root.clientHeight || 720;
        // setViewOffset with POSITIVE x pans the rendered image left, so the
        // brain centres in the space the right-hand reading panel leaves
        // visible (the old negative offset shoved it UNDER the panel).
        const lg = $('.legend');
        const occl = lg ? Math.min(lg.offsetWidth + 32, W * 0.4) : 0;
        cam.setViewOffset(W, H, occl / 2, 0, W, H);
        cam.updateProjectionMatrix();
      } catch(e){ /* noop */ }
    }
    centerView();
    const onResize = () => centerView();
    window.addEventListener('resize', onResize);
    subs.push(() => window.removeEventListener('resize', onResize));

    // Live population — re-pull on remember/forget. placeNodes() is deterministic,
    // so existing nodes keep their exact spot and new memories land in place; no
    // re-heat, no reshuffle, no per-node position bookkeeping.
    if (opts.sse && typeof opts.sse.on === 'function') {
      let t = null;
      // A busy agent can commit every second. Wait for a short quiet window and
      // collapse the burst into one graph refresh instead of revalidating the
      // encrypted projection for every individual event.
      const reload = () => { clearTimeout(t); t = setTimeout(load, 3000); };
      subs.push(() => clearTimeout(t));
      subs.push(opts.sse.on('remember', reload));
      subs.push(opts.sse.on('forget', reload));

      // LIVE CONNECTOME FIRING. The tick carries nothing, so the data comes
      // from re-fetching the AUTHORIZED snapshot through the existing load
      // path — the same RBAC-filtered endpoint the view already uses. That
      // keeps the edge guard the single enforcement point: a client can only
      // pulse an edge it was allowed to fetch. load() already reports
      // 'unavailable' and retries if the refetch fails, so a dropped tick or a
      // failed fetch never leaves the view asserting it is live.
      let ct = null;
      const pulse = () => {
        if (mode !== 'connectome') return;
        clearTimeout(ct);
        ct = setTimeout(() => load(true), 900);
      };
      subs.push(() => clearTimeout(ct));
      subs.push(() => clearTimeout(pulseDecayTimer));
      subs.push(opts.sse.on('connectome', pulse));

      // NEUROGENESIS. A committed agent registration emits the 'agent' SSE event
      // but carries no connectome data, so — like a firing tick — the new neuron
      // arrives by re-fetching the AUTHORIZED snapshot through the existing load
      // path (same RBAC gate); markConnectomeBirths then stamps whatever id is new.
      // Connectome-mode only and debounced; load() owns in-flight coalescing and
      // the unavailable/retry path, so a dropped or failed registration refetch
      // never leaves the view mid-birth. Cleaned up with the other subs.
      let at = null;
      const grow = () => {
        if (mode !== 'connectome') return;
        clearTimeout(at);
        at = setTimeout(() => load(), 900);
      };
      subs.push(() => clearTimeout(at));
      subs.push(opts.sse.on('agent', grow));
    }
  }

  function acquireInitialGraph() {
    reportGraphAvailability('loading');
    const request = graphLoads.begin(mode);
    fetchActive(request.mode).then(d => {
      if (disposed || !graphLoads.isCurrent(request, mode)) return;
      initializeGraph(d);
      // Deep-link: auto-bloom a requested agent's lobe on first connectome paint.
      if (focusAgent && !autoBloomed && mode === 'connectome' && rendered) {
        const target = rendered.nodes.find(nd => nd.isNeuron && (nd.agent_id || nd.id) === focusAgent);
        if (target) { autoBloomed = true; deepLinkTimer = setTimeout(() => { if (!disposed) bloomEngrams(target); }, 50); }
      }
    }).catch(() => {
      if (disposed || !graphLoads.isCurrent(request, mode)) return;
      const boot = $('.boot');
      if (boot) boot.textContent = '◉ MEMORY GRAPH TEMPORARILY UNAVAILABLE — RETRYING…';
      reportGraphAvailability('unavailable');
      scheduleGraphRetry(acquireInitialGraph);
    });
  }
  acquireInitialGraph();

  function showTip(n){ const tip=$('.tip'); if(!n){ tip.style.display='none'; return; }
    tip.style.display='block';
    if(n.isNeuron){
      tip.innerHTML=`<div class="h">${escapeHtml((n.label||'').slice(0,90))}</div><div class="m">neuron · ${escapeHtml(n.role||'agent')}${n.domain?` · ${escapeHtml(n.domain)}`:''}</div>
        <div style="margin-top:5px"><span class="chip">traffic ${n._w|0}</span><span class="chip">${(n._deg||0)>=0.5?'hub':'node'}</span></div>`;
      return;
    }
    tip.innerHTML=`<div class="h">${escapeHtml((n.label||'').slice(0,90))}</div><div class="m">${escapeHtml(n.domain)} · ${escapeHtml(n.memory_type||'—')} · ${escapeHtml(n.status)}</div>
      <div style="margin-top:5px"><span class="chip">conf ${(+n.confidence).toFixed(2)}</span><span class="chip">corroborated ×${n.corroboration_count|0}</span></div>`; }
  function onMove(e){ const tip=$('.tip'); if(tip.style.display==='block'){ const r=root.getBoundingClientRect();
    tip.style.left=(e.clientX-r.left+14)+'px'; tip.style.top=(e.clientY-r.top+14)+'px'; } }
  function isPanelTarget(t){ return !!(t && t.closest && t.closest('.panel')); }
  function onGraphPointerDown(e){
    if (isPanelTarget(e.target)) return;
    graphPointerDown = { x: e.clientX, y: e.clientY };
  }
  function onGraphClick(e){
    if (!focusId || isPanelTarget(e.target)) return;
    if (performance.now() - lastNodeClickAt < 350) return;
    if (graphPointerDown && Math.hypot(e.clientX - graphPointerDown.x, e.clientY - graphPointerDown.y) > 6) return;
    exitFocus();
  }
  root.addEventListener('mousemove', onMove);
  root.addEventListener('pointerdown', onGraphPointerDown);
  root.addEventListener('click', onGraphClick);
  // Connectome legend caption — appended once, shown only in connectome mode.
  const modeCap = document.createElement('div');
  modeCap.className = 'panel mode-cap';
  modeCap.style.cssText = 'position:absolute;left:auto;bottom:44px;top:auto;right:12px;display:none;max-width:236px;font-size:11px;line-height:1.55';
  modeCap.innerHTML = '<b>Connectome</b> · the agent message-bus<br>◉ neuron = agent · hue = domain<br>synapse thickness + pulse = traffic (Hebbian)<br>idle synapses thin & fade · use it or lose it<br>new agents grow in · dormant ones grey out<br>hubs sink to the core · click a neuron → its memories bloom';
  root.appendChild(modeCap);

  // Relabel the stat panel + button and toggle the caption for the active mode.
  function updateModeChrome(){
    const btn=$('.b-mode'); if(btn) btn.textContent = mode==='connectome' ? '◈ memory' : '◉ connectome';
    const set = mode==='connectome' ? ['neurons','synapses','hubs'] : ['memories','synapses','consolidated'];
    root.querySelectorAll('.hud .l').forEach((el,i)=>{ if(set[i]) el.textContent=set[i]; });
    modeCap.style.display = mode==='connectome' ? '' : 'none';
  }
  updateModeChrome();

  // Swap the active view. Leaves any focus/drill state, relabels the chrome, and
  // re-runs the load path against the new source. The memory view is byte-for-byte
  // unchanged whenever mode stays 'memory'.
  function setMode(next){
    if (mode===next || (next==='connectome' && !allowConnectome)) return;
    graphLoads.invalidate();
    bloomLoads.invalidate();
    mode = next;
    connectomeActivity.reset();
    connectomeReloadIntent.reset();
    neuronBirths.reset();
    currentDomain = null;
    focusId=null; focusSet=null; hideExplorePanel(); clearFocusMarker();
    updateModeChrome();
    // Recall this view's remembered skull opacity (its default, or the operator's
    // last manual choice for this view) and reflect it on the slider, so a round
    // trip preserves each view's setting independently.
    const nextOpacity = hullState.valueFor(mode);
    const opEl = $('.b-op'); if (opEl) opEl.value = sliderUnits(nextOpacity);
    setHullOpacity(nextOpacity);
    if (Graph) { load(); zoomOut(); }
    else acquireInitialGraph();
  }

  $('.b-rot').onclick=function(){ scanning=!scanning; if(controls) controls.autoRotate=scanning; this.textContent=scanning?'⏸ pause':'▶ scan'; };
  $('.b-flow').onclick=function(){ flow=!flow; if(Graph) Graph.linkDirectionalParticles(linkParticlesFor); this.textContent=flow?'⚡ flow: on':'⚡ flow: off'; };
  $('.b-op').oninput=function(){ const o=this.value/100; setHullOpacity(o); hullState.record(mode, o); };
  if (allowConnectome) $('.b-mode').onclick=function(){ setMode(mode==='connectome'?'memory':'connectome'); };

  return function cleanup(){
    disposed = true;
    bloomLoads.invalidate();
    clearTimeout(graphRetryTimer);
    clearInterval(plasticityTimer);
    clearTimeout(birthDecayTimer);
    clearInterval(dormancyTimer);
    clearTimeout(deepLinkTimer);
    subs.forEach(u => { try { u && u(); } catch(e){ /* noop */ } });
    root.removeEventListener('mousemove', onMove);
    root.removeEventListener('pointerdown', onGraphPointerDown);
    root.removeEventListener('click', onGraphClick);
    try {
      if (focusMarker && focusMarker.parent) focusMarker.parent.remove(focusMarker);
      if (focusMarker && focusMarker.material) focusMarker.material.dispose();
      if (focusRingTexture) focusRingTexture.dispose();
    } catch(e){ /* noop */ }
    try { if (Graph && Graph._destructor) Graph._destructor(); } catch(e){ /* noop */ }
    if (root.parentNode) root.parentNode.removeChild(root);
  };
}
