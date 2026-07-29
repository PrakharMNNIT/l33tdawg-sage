package rest

import (
	"encoding/json"
	"net/http"

	"github.com/l33tdawg/sage/internal/authzdenial"
)

// writeEffectiveWriteDenial emits only the stable public taxonomy. The raw
// consensus/access error stays in server logs and never reaches the response.
func writeEffectiveWriteDenial(w http.ResponseWriter, denial authzdenial.EffectiveWriteDenial) {
	canonical, ok := authzdenial.Definition(denial.Code)
	if !ok || canonical.Retryable {
		writeProblem(w, http.StatusForbidden, "Access denied", "memory write access denied")
		return
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":        authzdenial.ProblemTypeURI,
		"title":       "Memory write access denied",
		"status":      http.StatusForbidden,
		"detail":      "This memory write is blocked by effective access policy.",
		"reason_code": canonical.Code,
		"remedy":      canonical.Remedy,
		"retryable":   canonical.Retryable,
	})
}
