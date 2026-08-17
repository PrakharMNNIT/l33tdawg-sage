// Decide whether a failed graph refresh invalidates what is already visible.
// ForceGraph is reused between memory and connectome modes, so a rendered
// snapshot is safe to retain only when it belongs to the request that failed.
export function graphAvailabilityAfterFailure(hasRendered, renderedMode, requestMode) {
  return hasRendered && renderedMode === requestMode ? 'ready' : 'unavailable';
}
