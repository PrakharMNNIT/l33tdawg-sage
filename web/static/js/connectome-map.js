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

export function mapConnectome(g) {
  const srcNeurons = (g && Array.isArray(g.neurons)) ? g.neurons : [];
  const srcSynapses = (g && Array.isArray(g.synapses)) ? g.synapses : [];
  const ids = new Set(srcNeurons.map(n => n.agent_id));

  const weight = {};
  let maxWeight = 0, maxCount = 0;
  for (const s of srcSynapses) {
    if (!ids.has(s.from_agent) || !ids.has(s.to_agent)) continue;
    const c = s.count || 0;
    weight[s.from_agent] = (weight[s.from_agent] || 0) + c;
    weight[s.to_agent] = (weight[s.to_agent] || 0) + c;
    if (c > maxCount) maxCount = c;
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
    if ((l.last_fired || '') > was.last) { fired.push(k); }
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
    observe(links, fromConnectomeTick = false) {
      const next = snapshotConnectomeLinks(links);
      const fired = baseline !== null && fromConnectomeTick
        ? diffConnectomeActivity(baseline, next)
        : [];
      baseline = next;
      return fired;
    },
    reset() { baseline = null; },
  };
}
