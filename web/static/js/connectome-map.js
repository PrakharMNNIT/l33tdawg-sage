// Pure mapping from the /v1/dashboard/network/synapses payload onto the shared
// MRI render contract ({nodes, links, ...}). Kept dependency-free (no DOM, no
// fetch, no THREE) so it is unit-testable in isolation, mirroring mri-layout.js.
//
// Neurons become nodes carrying isNeuron + a normalized degree _deg (the neuron's
// share of the busiest neuron's total traffic, 0..1) for size and radial
// placement. Synapses become links carrying a normalized weight _w (this edge's
// share of the busiest edge's count, 0..1) for Hebbian thickness/pulse. Any edge
// whose endpoints are not BOTH in the neuron set is dropped: the server already
// both-endpoints-gates synapses by RBAC, and this keeps the renderer from minting
// ghost nodes that would have no deterministic placement.

// Normalize an RFC3339[Nano] instant to an exactly-sortable key: integer epoch
// SECONDS plus a right-padded 9-digit nanosecond string. Date.parse truncates the
// fraction to milliseconds, so it is applied ONLY to the fraction-stripped instant
// (giving an exact whole second); every sub-second digit (up to nanoseconds) is
// preserved separately. This is what makes ...000000002Z sort after ...000000001Z,
// which Date.parse alone flattens to equal. Returns null for empty/invalid input.
// Strict RFC3339Nano: date T time, 1-9 fractional digits (optional), explicit Z or
// ±HH:MM offset. Date.parse is too permissive (it accepts a space separator, a
// missing zone, >9 fractional digits, and rolls impossible dates like Feb 30 over
// instead of rejecting), so the shape and the calendar/time fields are validated
// here BEFORE any parsing — otherwise garbage could out-sort a real instant.
const RFC3339_NANO = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/;
export function instantKey(iso) {
  if (typeof iso !== 'string') return null;
  const m = RFC3339_NANO.exec(iso);
  if (!m) return null;
  const year = +m[1], month = +m[2], day = +m[3], hour = +m[4], min = +m[5], sec = +m[6];
  if (month < 1 || month > 12 || hour > 23 || min > 59 || sec > 59) return null;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  if (day < 1 || day > dim) return null;                 // rejects impossible calendar dates
  const zone = m[8];
  if (zone !== 'Z' && (+zone.slice(1, 3) > 23 || +zone.slice(4, 6) > 59)) return null;
  // Parse the fraction-free instant to an exact whole second; keep all 9 nano digits.
  const ms = Date.parse(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${zone}`);
  if (Number.isNaN(ms)) return null;
  return { seconds: Math.floor(ms / 1000), nanos: ((m[7] || '') + '000000000').slice(0, 9) };
}

// True when instant `a` is strictly later than `b`, compared at full nanosecond
// precision so variable RFC3339Nano fractions cannot mis-order. Empty/invalid `a`
// is never later; a real `a` always beats an empty/invalid `b`.
export function isLater(a, b) {
  const ka = instantKey(a);
  if (!ka) return false;
  const kb = instantKey(b);
  if (!kb) return true;
  if (ka.seconds !== kb.seconds) return ka.seconds > kb.seconds;
  return ka.nanos > kb.nanos;                  // fixed 9-digit width → lexical === numeric
}

export function mapConnectome(g) {
  const srcNeurons = (g && Array.isArray(g.neurons)) ? g.neurons : [];
  const srcSynapses = (g && Array.isArray(g.synapses)) ? g.synapses : [];
  const ids = new Set(srcNeurons.map(n => n.agent_id));

  const weight = {};
  const activity = {};   // most recent last_fired across a neuron's incident edges
  let maxWeight = 0, maxCount = 0;
  for (const s of srcSynapses) {
    if (!ids.has(s.from_agent) || !ids.has(s.to_agent)) continue;
    const c = s.count || 0;
    weight[s.from_agent] = (weight[s.from_agent] || 0) + c;
    weight[s.to_agent] = (weight[s.to_agent] || 0) + c;
    if (c > maxCount) maxCount = c;
    // Keep the most recent last_fired per neuron, compared by PARSED INSTANT, not
    // lexically: RFC3339Nano fractional precision varies, so '…00.1Z' (100ms) is
    // lexically greater than '…00.12Z' (120ms) yet chronologically earlier.
    const lf = s.last_fired || '';
    if (isLater(lf, activity[s.from_agent])) activity[s.from_agent] = lf;
    if (isLater(lf, activity[s.to_agent])) activity[s.to_agent] = lf;
  }
  for (const w of Object.values(weight)) { if (w > maxWeight) maxWeight = w; }

  const nodes = srcNeurons.map(n => ({
    id: n.agent_id,
    domain: n.domain || n.role || 'agent',
    label: n.name || n.agent_id,
    role: n.role || '',
    isNeuron: true,
    _w: weight[n.agent_id] || 0,
    _deg: maxWeight ? (weight[n.agent_id] || 0) / maxWeight : 0,
    // most recent activity across this neuron's synapses ('' = never fired), used
    // by the client to grey out dormant agents (rung 5 pruning).
    _activity: activity[n.agent_id] || '',
    // memory fields the shared render/tip paths read, given neutral values
    status: 'committed', confidence: 1, corroboration_count: 0,
    memory_type: 'agent', created_at: '',
  }));

  const links = srcSynapses
    .filter(s => ids.has(s.from_agent) && ids.has(s.to_agent))
    .map(s => ({
      source: s.from_agent, target: s.to_agent, link_type: 'synapse',
      count: s.count || 0, last_fired: s.last_fired || '',
      _w: maxCount ? (s.count || 0) / maxCount : 0,
    }));

  return { live: true, connectome: true, nodes, links,
    total: nodes.length, domainCounts: null, domainLast: null };
}

// A mode switch invalidates every request started for the previous view. The
// renderer uses this tiny coordinator for both its initial acquisition and
// later reloads so an out-of-order response can never be interpreted under a
// different mode than the one that requested it.
export function createGraphLoadCoordinator() {
  let generation = 0;
  return {
    begin(mode) { return { generation: ++generation, mode }; },
    invalidate() { generation += 1; },
    isCurrent(request, mode) {
      return request && request.generation === generation && request.mode === mode;
    },
  };
}

// diffConnectomeActivity reports which directed edges FIRED between two
// connectome snapshots, so a live pulse animates the channels that actually
// carried a message rather than flashing the whole graph.
//
// An edge counts as fired when it is new, when its retained count rose, or when
// its last_fired advanced. All three are needed: count alone misses a send that
// coincided with a retention prune, and last_fired alone misses a burst that
// lands within the same timestamp granularity.
//
// A DROP IN COUNT IS NOT A FIRING. Retained-row pruning can lower a count
// without any message being sent, and animating that would report activity that
// did not happen.
export function diffConnectomeActivity(prevLinks, nextLinks) {
  const key = (l) => `${typeof l.source === 'object' ? l.source.id : l.source}\u0000${typeof l.target === 'object' ? l.target.id : l.target}`;
  const before = new Map();
  for (const l of (Array.isArray(prevLinks) ? prevLinks : [])) {
    before.set(key(l), { count: l.count || 0, last: l.last_fired || '' });
  }
  const fired = [];
  for (const l of (Array.isArray(nextLinks) ? nextLinks : [])) {
    const k = key(l);
    const was = before.get(k);
    if (!was) { fired.push(k); continue; }
    if ((l.count || 0) > was.count) { fired.push(k); continue; }
    // Instant comparison, shared with _activity selection: a lexical compare of
    // variable-precision RFC3339Nano can rank a later '…00.12Z' below an earlier
    // '…00.1Z' and silently MISS the pulse that actually fired.
    if (isLater(l.last_fired, was.last)) { fired.push(k); }
  }
  return fired;
}

function snapshotConnectomeLinks(links) {
  return (Array.isArray(links) ? links : []).map(l => ({
    source: typeof l.source === 'object' ? l.source.id : l.source,
    target: typeof l.target === 'object' ? l.target.id : l.target,
    count: l.count || 0,
    last_fired: l.last_fired || '',
  }));
}

// Tracks the last authorized snapshot while keeping activity semantics tied to
// an actual connectome invalidation tick. Initial acquisition and ordinary
// reloads establish/update the baseline but never claim that an edge fired.
export function createConnectomeActivityTracker() {
  let baseline = null;
  return {
    observe(links, fromConnectomeTick = false, tickPending = false) {
      const next = snapshotConnectomeLinks(links);
      // A tick that arrived during an ordinary request owns the next baseline
      // transition. Do not let the older request consume that transition before
      // the queued tick refetch can turn it into a pulse.
      if (tickPending && !fromConnectomeTick) return [];
      const fired = baseline !== null && fromConnectomeTick
        ? diffConnectomeActivity(baseline, next)
        : [];
      baseline = next;
      return fired;
    },
    reset() { baseline = null; },
  };
}

// Neuron dormancy (rung 5 pruning / apoptosis): how "cold" an agent is, from its
// most recent synaptic activity. 0 = lively (fired within liveMs), ramping
// linearly to 1 = dormant (idle past coldMs). A neuron that has never fired (no
// activity timestamp) is fully dormant. Pure — caller passes `now` — so the ramp
// is unit-testable. The renderer greys a neuron in proportion to this, reusing the
// existing challenged/deprecated grey, so a cold agent visibly recedes.
export function neuronDormancy(activityISO, now, opts = {}) {
  const liveMs = opts.liveMs >= 0 ? opts.liveMs : 3600000;      // 1h fully lively
  const coldMs = opts.coldMs > liveMs ? opts.coldMs : 43200000; // 12h fully dormant
  if (!activityISO) return 1;
  const t = Date.parse(activityISO);
  if (Number.isNaN(t)) return 1;
  const age = now - t;
  if (age <= liveMs) return 0;
  if (age >= coldMs) return 1;
  return (age - liveMs) / (coldMs - liveMs);
}

// Neurogenesis: reports which neuron ids are NEW versus the previous snapshot, so
// a freshly-registered agent can be animated growing in rather than blinking into
// place. Mirrors createConnectomeActivityTracker: the first observation only
// establishes the baseline (it never claims the whole graph was just born), and
// each later observation returns just the ids that appeared since.
export function createNeuronBirthTracker() {
  let seen = null;
  return {
    observe(neuronIds) {
      const next = new Set(Array.isArray(neuronIds) ? neuronIds : []);
      if (seen === null) { seen = next; return []; }
      const born = [];
      for (const id of next) { if (!seen.has(id)) born.push(id); }
      seen = next;
      return born;
    },
    reset() { seen = null; },
  };
}

// Strip bloomed engrams (transient _added nodes) and their focus tethers from a
// {nodes, links} graph, returning the pruned copy. Pure, so the transactional
// clear is unit-testable — a no-op (returning the input unchanged) fails the
// assertions, unlike a source-only check of clearBloom.
export function stripBloom(graphData) {
  const nodes = (graphData && Array.isArray(graphData.nodes)) ? graphData.nodes : [];
  const links = (graphData && Array.isArray(graphData.links)) ? graphData.links : [];
  return {
    nodes: nodes.filter(n => !n._added),
    // Both bloom artifacts are transient: the 'focus' tethers from the neuron to
    // its engrams, and the 'engram-bridge' links from an engram to the other
    // neurons that corroborate it (the distributed engram). Real synapses stay.
    links: links.filter(l => l.link_type !== 'focus' && l.link_type !== 'engram-bridge'),
  };
}

// Maps the /v1/dashboard/memory/engrams payload (one agent's authored memories)
// into memory node objects that orbit their author neuron in the agent-as-lobe
// view. Pure. `_added` marks them transient (the renderer strips _added nodes on
// exit-focus); `_engram` tags them as author-anchored memories. They carry the
// same memory fields the shared node styling reads, so an engram renders as a
// memory dot (domain hue, confidence alpha) rather than a neuron.
export function mapEngrams(g) {
  const src = (g && Array.isArray(g.engrams)) ? g.engrams : [];
  return src.map(e => ({
    id: e.id,
    domain: e.domain || 'unknown',
    label: e.content || e.id,
    status: e.status || 'committed',
    confidence: typeof e.confidence === 'number' ? e.confidence : 0.5,
    corroboration_count: e.corroboration_count || 0,
    // The corroborating neurons the viewer is cleared to see — the endpoints the
    // agent-as-lobe view bridges this engram to (the "distributed engram"). The
    // server has already RBAC-filtered these; corroborators the viewer may not see
    // survive only inside corroboration_count as the anonymous remainder.
    corroborators: Array.isArray(e.corroborators) ? e.corroborators : [],
    memory_type: e.memory_type || '',
    created_at: e.created_at || '',
    _added: true,
    _engram: true,
  }));
}

// Pure neuron colour composition, so the dormancy grey and birth flare are pinned
// by numbers rather than a source grep (a no-op blend fails the assertions).
// domainRGB [r,g,b] is the base hue; `deg` (0..1 traffic) brightens toward white;
// `dorm` (0..1) greys toward the deprecated grey [108,120,145] and drops alpha;
// `birth` (0..1) flares toward a bright accent at near-full alpha. Returns integer
// channels + a 2-decimal alpha.
export function neuronTint(domainRGB, deg, dorm, birth) {
  const clamp = v => Math.max(0, Math.min(1, v || 0));
  const d = clamp(deg), k = clamp(dorm), bn = clamp(birth);
  let r = domainRGB[0] + (255 - domainRGB[0]) * d * 0.55;
  let g = domainRGB[1] + (255 - domainRGB[1]) * d * 0.55;
  let b = domainRGB[2] + (255 - domainRGB[2]) * d * 0.55;
  let a = 0.72 + 0.28 * d;
  if (k > 0) { r += (108 - r) * k; g += (120 - g) * k; b += (145 - b) * k; a -= 0.42 * k; }
  if (bn > 0) { r += (120 - r) * 0.85 * bn; g += (235 - g) * 0.85 * bn; b += (255 - b) * 0.85 * bn; a = Math.max(a, 0.9); }
  return { r: r | 0, g: g | 0, b: b | 0, a: +a.toFixed(2) };
}

// Retains a connectome invalidation until an authorized snapshot has actually
// satisfied it. Retry timers are deliberately not the source of truth: an
// ordinary graph refresh may cancel a timer, but while a tick is pending that
// refresh becomes the tick-aware fetch and must either pulse or preserve the
// intent for the next retry.
export function createConnectomeReloadIntent() {
  let requestedGeneration = 0;
  let satisfiedGeneration = 0;
  return {
    requestTick() { requestedGeneration += 1; },
    begin(mode) {
      return mode === 'connectome' && requestedGeneration > satisfiedGeneration
        ? requestedGeneration
        : 0;
    },
    settle(mode, generation, succeeded) {
      if (mode === 'connectome' && generation > 0 && succeeded) {
        satisfiedGeneration = Math.max(satisfiedGeneration, generation);
      }
    },
    isPending(mode) {
      return mode === 'connectome' && requestedGeneration > satisfiedGeneration;
    },
    reset() { requestedGeneration = 0; satisfiedGeneration = 0; },
  };
}

// Resting-weight plasticity ("use it or lose it"): a synapse's RETAINED strength
// decays from its raw Hebbian weight toward a floor the longer it sits idle, and
// climbs back as it fires. This is distinct from the transient firing pulse — the
// pulse is a seconds-long flash on a live message, plasticity is the slow drift of
// the resting weight over minutes/hours, keyed on how long ago the edge last fired.
//
// Returns a 0..1 multiplier to apply to the rendered weight: ~1 for an edge that
// just fired, decaying with `halfLifeMs` toward `floor` (never below it, so an idle
// channel dims but does not vanish). Pure — the caller passes `now` — so the decay
// curve is unit-testable. A missing/invalid last_fired is treated as fully idle.
export function synapsePlasticity(lastFiredISO, now, opts = {}) {
  const halfLifeMs = opts.halfLifeMs > 0 ? opts.halfLifeMs : 1800000; // 30 min
  const floor = opts.floor >= 0 && opts.floor <= 1 ? opts.floor : 0.15;
  if (!lastFiredISO) return floor;
  const t = Date.parse(lastFiredISO);
  if (Number.isNaN(t)) return floor;
  const age = now - t;
  if (age <= 0) return 1;                       // fired now (or clock skew) → full strength
  return floor + (1 - floor) * Math.pow(0.5, age / halfLifeMs);
}
