// Per-view skull-opacity state for the CEREBRUM brain. Each view (memory graph,
// connectome) keeps its OWN session opacity, seeded from a per-view default. The
// defaults differ — the memory graph wants a prominent anatomical hull, the
// connectome a recessed one so its synapse wiring reads — but once an operator
// drags the SKULL slider, that choice is remembered for the view they set it in
// and recalled the next time they return to it, independent of the other view.
//
// Pure and dependency-free (no DOM) so the behaviour is unit-testable in
// isolation, mirroring mri-layout.js / connectome-map.js.
//
// `defaults` maps view name -> initial opacity (0..1). `valueFor(mode)` returns
// that view's current opacity; `record(mode, opacity)` stores a manual choice for
// one view without touching the other. Unknown modes fall back to the first
// default so a caller never gets undefined.
export function createModeHull(defaults) {
  const fallback = Object.values(defaults)[0];
  const state = { ...defaults };
  return {
    valueFor(mode) {
      return Object.prototype.hasOwnProperty.call(state, mode) ? state[mode] : fallback;
    },
    record(mode, opacity) {
      if (Object.prototype.hasOwnProperty.call(state, mode)) state[mode] = opacity;
    },
    defaults() { return { ...defaults }; },
  };
}
