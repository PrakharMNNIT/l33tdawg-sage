package rest

import (
	"net/http"

	"github.com/l33tdawg/sage/api/rest/middleware"
)

// appV23EmbedBoundary prevents a syntactically valid, attacker-generated
// Ed25519 key from turning a network-exposed SAGE node into a public embedding
// service. Ed25519AuthMiddleware proves key possession, not local enrollment.
//
// Before app-v23 the historical signed-key behavior is preserved. Once
// app-v23 is active, the caller must be a current active local agent with a
// coherent consensus role/enrollment. Root (including retired Root
// credentials), pending/inactive agents, and unknown keys are not agents and
// fail closed. The preceding appV23LocalAdminBoundary additionally keeps a
// valid promoted Admin host-local while Members and Managers retain their
// signed REST network posture.
func (s *Server) appV23EmbedBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.isPostV23ForNextTx() {
			next.ServeHTTP(w, r)
			return
		}

		allowed, err := s.appV23ActiveOrdinaryAgent(
			middleware.ContextAgentID(r.Context()),
		)
		if err != nil {
			writeProblem(w, http.StatusServiceUnavailable, "Access control unavailable",
				"Current local enrollment state is unavailable.")
			return
		}
		if !allowed {
			writeProblem(w, http.StatusForbidden, "Active local agent required",
				"Embedding is available only to an active approved agent on this SAGE node.")
			return
		}

		next.ServeHTTP(w, r)
	})
}
