package rest

import "github.com/l33tdawg/sage/internal/store"

func (s *Server) hasExactCanonicalMemoryProjection() bool {
	if s.badgerStore == nil {
		return false
	}
	health := s.badgerStore.CanonicalMemoryProjectionHealth()
	return health.Checked && health.OK && health.State == store.CanonicalMemoryProjectionExact
}

// recallIndexStatusHasExactQueryUniverse reports whether the empty response was
// produced by precisely the local semantic universe described by
// DomainSpaceCompleteness. Any narrowing filter, cursor, text arm, or federation
// request can make the result empty for reasons the local domain/status/space
// probe does not model, so those cases receive unavailable rather than a false
// complete verdict.
func recallIndexStatusHasExactQueryUniverse(req QueryMemoryRequest) bool {
	return req.StatusFilter == "committed" &&
		req.Query == "" &&
		req.Provider == "" &&
		req.MinConfidence <= 0 &&
		len(req.Tags) == 0 &&
		req.Cursor == "" &&
		!req.Federated &&
		len(req.FederateChains) == 0
}
