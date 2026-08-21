package rest

import (
	"context"

	"github.com/l33tdawg/sage/internal/store"
)

type recallProjectionRevisionProvider interface {
	MemoryProjectionRevision(context.Context) (uint64, error)
}

type recallProjectionSource struct {
	sql       uint64
	canonical uint64
}

func (s *Server) exactCanonicalMemoryProjectionSource(
	ctx context.Context,
) (recallProjectionSource, bool) {
	var source recallProjectionSource
	if s.badgerStore == nil {
		return source, false
	}
	health := s.badgerStore.CanonicalMemoryProjectionHealth()
	if !health.Checked || !health.OK ||
		health.State != store.CanonicalMemoryProjectionExact || !health.SourceBound {
		return source, false
	}
	provider, ok := s.store.(recallProjectionRevisionProvider)
	if !ok {
		return source, false
	}
	sqlRevision, err := provider.MemoryProjectionRevision(ctx)
	if err != nil {
		return source, false
	}
	canonicalRevision := s.badgerStore.CanonicalMemoryProjectionRevision()
	if sqlRevision != health.SQLRevision || canonicalRevision != health.CanonicalRevision {
		return source, false
	}
	return recallProjectionSource{sql: sqlRevision, canonical: canonicalRevision}, true
}

func (s *Server) canonicalMemoryProjectionSourceUnchanged(
	ctx context.Context,
	want recallProjectionSource,
) bool {
	provider, ok := s.store.(recallProjectionRevisionProvider)
	if !ok || s.badgerStore == nil {
		return false
	}
	sqlRevision, err := provider.MemoryProjectionRevision(ctx)
	if err != nil {
		return false
	}
	return sqlRevision == want.sql &&
		s.badgerStore.CanonicalMemoryProjectionRevision() == want.canonical
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
