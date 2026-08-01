package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/l33tdawg/sage/internal/store"
)

const appV25LegacyDeprecationConfirmation = "DEPRECATE %d"

type appV25LegacyRecoveryController interface {
	GetLegacyMemoryAdoptionProgress(context.Context) (*store.LegacyMemoryAdoptionProgress, error)
	ValidateLegacyMemoryRecoverySnapshot(context.Context, uint64, int) error
	DeprecateLegacyMemoryRecoverySnapshot(context.Context, uint64, int, string) (int, error)
}

type appV25LegacyRecoveryControlRequest struct {
	ProjectionRevision uint64 `json:"projection_revision"`
	ExpectedCount      int    `json:"expected_count"`
	Confirmation       string `json:"confirmation,omitempty"`
}

func (h *DashboardHandler) appV25LegacyAdoptionWakeChannel() <-chan struct{} {
	h.appV25AdoptionWakeOnce.Do(func() {
		if h.appV25AdoptionWake == nil {
			h.appV25AdoptionWake = make(chan struct{}, 1)
		}
	})
	return h.appV25AdoptionWake
}

func (h *DashboardHandler) requestAppV25LegacyAdoptionRetry() uint64 {
	_ = h.appV25LegacyAdoptionWakeChannel()
	epoch := h.appV25AdoptionRetry.Add(1)
	select {
	case h.appV25AdoptionWake <- struct{}{}:
	default:
	}
	return epoch
}

func decodeAppV25LegacyRecoveryControlRequest(
	w http.ResponseWriter,
	r *http.Request,
) (appV25LegacyRecoveryControlRequest, bool) {
	var request appV25LegacyRecoveryControlRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid memory recovery request")
		return request, false
	}
	if request.ProjectionRevision == 0 || request.ExpectedCount <= 0 {
		writeError(w, http.StatusBadRequest,
			"projection_revision and a positive expected_count are required")
		return request, false
	}
	return request, true
}

func (h *DashboardHandler) appV25LegacyRecoveryControl(
	w http.ResponseWriter,
	r *http.Request,
) (*appV23ControlActor, appV25LegacyRecoveryController, bool) {
	if !h.appV23IsActive() {
		writeError(w, http.StatusConflict,
			"historical memory recovery control requires the governed CEREBRUM access model")
		return nil, nil, false
	}
	actor, ok := h.requireAppV23ControlActor(w, r, false)
	if !ok {
		return nil, nil, false
	}
	if !actor.IsRoot {
		writeAppV23AccessError(w, http.StatusForbidden, "current_root_required",
			"Only the current CEREBRUM Root may resolve preserved historical memories.")
		return nil, nil, false
	}
	controller, ok := h.store.(appV25LegacyRecoveryController)
	if !ok {
		writeError(w, http.StatusNotImplemented,
			"historical memory recovery control is unavailable for this storage backend")
		return nil, nil, false
	}
	return actor, controller, true
}

func (h *DashboardHandler) validateAppV25LegacyRecoveryControlSnapshot(
	ctx context.Context,
	controller appV25LegacyRecoveryController,
	request appV25LegacyRecoveryControlRequest,
) error {
	progress, err := controller.GetLegacyMemoryAdoptionProgress(ctx)
	if err != nil {
		return err
	}
	if progress == nil || progress.State != "recovery" || progress.Remaining != 0 ||
		progress.Revision != request.ProjectionRevision ||
		progress.Recovery != request.ExpectedCount {
		return store.ErrLegacyMemoryRecoverySnapshotChanged
	}
	// The durable recovery rows, their revision, and the published aggregate
	// are the exact operator-facing inventory. Do not require the *global*
	// memory projection revision or a process-local boot receipt here: ordinary
	// post-upgrade writes advance those independently and used to make an
	// unchanged recovery queue impossible to resolve forever.
	return controller.ValidateLegacyMemoryRecoverySnapshot(
		ctx, request.ProjectionRevision, request.ExpectedCount,
	)
}

func writeAppV25LegacyRecoveryControlError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrLegacyMemoryRecoverySnapshotChanged) {
		writeError(w, http.StatusConflict,
			"the historical memory recovery inventory changed; review the current count and try again")
		return
	}
	writeError(w, http.StatusServiceUnavailable,
		"historical memory recovery control is temporarily unavailable")
}

// handleAppV25LegacyAdoptionRetry asks the single background worker to discard
// its cached observation and run a fresh stable scan. It never clears rejection
// receipts, recovery rows, memory rows, or canonical state.
func (h *DashboardHandler) handleAppV25LegacyAdoptionRetry(w http.ResponseWriter, r *http.Request) {
	_, controller, ok := h.appV25LegacyRecoveryControl(w, r)
	if !ok {
		return
	}
	request, ok := decodeAppV25LegacyRecoveryControlRequest(w, r)
	if !ok {
		return
	}
	if err := h.validateAppV25LegacyRecoveryControlSnapshot(
		r.Context(), controller, request,
	); err != nil {
		writeAppV25LegacyRecoveryControlError(w, err)
		return
	}
	epoch := h.requestAppV25LegacyAdoptionRetry()
	writeJSONResp(w, http.StatusAccepted, map[string]any{
		"status":              "retry_requested",
		"projection_revision": request.ProjectionRevision,
		"expected_count":      request.ExpectedCount,
		"retry_epoch":         epoch,
		"message":             "SAGE will re-check every preserved historical record now.",
	})
}

// handleAppV25LegacyAdoptionDeprecate records a separate Root-authorized local
// disposition for the exact unresolved inventory. Original memory rows and
// chain history are preserved byte-for-byte; future adoption scans skip only
// these exact IDs. This deliberately does not fabricate canonical memory state.
func (h *DashboardHandler) handleAppV25LegacyAdoptionDeprecate(w http.ResponseWriter, r *http.Request) {
	actor, controller, ok := h.appV25LegacyRecoveryControl(w, r)
	if !ok {
		return
	}
	request, ok := decodeAppV25LegacyRecoveryControlRequest(w, r)
	if !ok {
		return
	}
	expectedConfirmation := fmt.Sprintf(
		appV25LegacyDeprecationConfirmation, request.ExpectedCount,
	)
	if request.Confirmation != expectedConfirmation {
		writeError(w, http.StatusBadRequest,
			"confirmation must exactly match "+expectedConfirmation)
		return
	}
	if err := h.validateAppV25LegacyRecoveryControlSnapshot(
		r.Context(), controller, request,
	); err != nil {
		writeAppV25LegacyRecoveryControlError(w, err)
		return
	}
	deprecated, err := controller.DeprecateLegacyMemoryRecoverySnapshot(
		r.Context(), request.ProjectionRevision, request.ExpectedCount, actor.ID,
	)
	if err != nil {
		writeAppV25LegacyRecoveryControlError(w, err)
		return
	}
	epoch := h.requestAppV25LegacyAdoptionRetry()
	progress, _ := controller.GetLegacyMemoryAdoptionProgress(r.Context())
	writeJSONResp(w, http.StatusOK, map[string]any{
		"status":              "explicitly_deprecated",
		"deprecated":          deprecated,
		"projection_revision": request.ProjectionRevision,
		"retry_epoch":         epoch,
		"history_preserved":   true,
		"progress":            progress,
		"message":             "The preserved records remain stored for audit but are retired from automatic repair and normal memory views.",
	})
}
