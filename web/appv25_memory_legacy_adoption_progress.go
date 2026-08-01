package web

import (
	"context"
	"net/http"

	"github.com/l33tdawg/sage/internal/store"
)

type appV25LegacyAdoptionProgressProvider interface {
	GetLegacyMemoryAdoptionProgress(
		context.Context,
	) (*store.LegacyMemoryAdoptionProgress, error)
}

// handleAppV25LegacyAdoptionProgress exposes aggregate local progress only.
// Memory IDs, domains, authors, reasons, and content never leave the recovery
// store through this upgrade-status surface.
func (h *DashboardHandler) handleAppV25LegacyAdoptionProgress(
	w http.ResponseWriter,
	r *http.Request,
) {
	provider, ok := h.store.(appV25LegacyAdoptionProgressProvider)
	if !ok {
		writeJSONResp(w, http.StatusOK, map[string]any{
			"state":      "unavailable",
			"discovered": 0,
			"converted":  0,
			"remaining":  0,
			"recovery":   0,
			"message":    "Memory upgrade status is unavailable for this storage backend.",
		})
		return
	}
	progress, err := provider.GetLegacyMemoryAdoptionProgress(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable,
			"memory upgrade status is temporarily unavailable")
		return
	}
	if progress == nil {
		writeJSONResp(w, http.StatusOK, map[string]any{
			"state":      "waiting",
			"discovered": 0,
			"converted":  0,
			"remaining":  0,
			"recovery":   0,
			"message":    "SAGE will check and upgrade historical memories in the background. Normal work continues.",
		})
		return
	}
	writeJSONResp(w, http.StatusOK, progress)
}
