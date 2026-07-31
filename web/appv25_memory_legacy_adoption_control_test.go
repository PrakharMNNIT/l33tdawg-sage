package web

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
)

func appV25RecoveryControlFixture(
	t *testing.T,
) (*DashboardHandler, *store.SQLiteStore, appV23AccessFixture, uint64) {
	t.Helper()
	ctx := context.Background()
	fixture := newAppV23AccessFixture(t)
	sqlite, err := store.NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "memories.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlite.Close()) })
	content := "preserved but unverifiable"
	require.NoError(t, sqlite.InsertMemory(ctx, &memory.MemoryRecord{
		MemoryID:        "legacy-unconvertible",
		SubmittingAgent: fixture.agentID,
		Content:         content,
		ContentHash:     make([]byte, sha256.Size),
		MemoryType:      memory.TypeFact,
		DomainTag:       "historical/domain",
		Status:          memory.StatusCommitted,
	}))
	revision, err := sqlite.MemoryProjectionRevision(ctx)
	require.NoError(t, err)
	require.NotZero(t, revision)
	require.NoError(t, sqlite.SyncLegacyMemoryRecoveryQueue(ctx, revision,
		[]store.LegacyMemoryRecoveryItem{{
			MemoryID: "legacy-unconvertible", Reason: "content_hash_mismatch",
		}}))
	progress := store.LegacyMemoryAdoptionProgress{
		State: "recovery", Discovered: 1, Recovery: 1, Revision: revision,
		Message: "Preserved historical records require review.",
	}
	require.NoError(t, sqlite.PublishLegacyMemoryAdoptionProgress(ctx, progress))
	handler := NewDashboardHandler(sqlite, "test")
	handler.BadgerStore = fixture.badger
	handler.AdminSigningKey = fixture.rootKey
	handler.AppV23ActiveFn = func() bool { return true }
	handler.ConfigureAppV25Maintenance(true)
	handler.noteAppV25MaintenanceProgress(progress)
	handler.ResolveAgentKeyFn = func(id string) (ed25519.PrivateKey, bool) {
		if id == fixture.rootID {
			return fixture.rootKey, true
		}
		return nil, false
	}
	return handler, sqlite, fixture, revision
}

func appV25RecoveryControlRequest(
	t *testing.T,
	path string,
	revision uint64,
	count int,
	confirmation string,
) *http.Request {
	t.Helper()
	body, err := json.Marshal(appV25LegacyRecoveryControlRequest{
		ProjectionRevision: revision,
		ExpectedCount:      count,
		Confirmation:       confirmation,
	})
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8080")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Host = "localhost:8080"
	request.RemoteAddr = "127.0.0.1:54321"
	return request
}

func TestAppV25LegacyAdoptionRetryRequiresExactCurrentRecoverySnapshot(t *testing.T) {
	handler, _, _, revision := appV25RecoveryControlFixture(t)

	stale := appV25RecoveryControlRequest(t,
		"/v1/dashboard/memory/adoption-retry", revision+1, 1, "")
	staleRecorder := httptest.NewRecorder()
	handler.handleAppV25LegacyAdoptionRetry(staleRecorder, stale)
	require.Equal(t, http.StatusConflict, staleRecorder.Code, staleRecorder.Body.String())
	require.Zero(t, handler.appV25AdoptionRetry.Load())

	request := appV25RecoveryControlRequest(t,
		"/v1/dashboard/memory/adoption-retry", revision, 1, "")
	recorder := httptest.NewRecorder()
	handler.handleAppV25LegacyAdoptionRetry(recorder, request)
	require.Equal(t, http.StatusAccepted, recorder.Code, recorder.Body.String())
	require.Equal(t, uint64(1), handler.appV25AdoptionRetry.Load())
	select {
	case <-handler.appV25LegacyAdoptionWakeChannel():
	default:
		t.Fatal("retry did not wake the adoption worker")
	}
}

func TestAppV25LegacyAdoptionDeprecatePreservesRowsAndSkipsFuturePlans(t *testing.T) {
	handler, sqlite, fixture, revision := appV25RecoveryControlFixture(t)

	wrong := appV25RecoveryControlRequest(t,
		"/v1/dashboard/memory/adoption-deprecate", revision, 1, "DEPRECATE")
	wrongRecorder := httptest.NewRecorder()
	handler.handleAppV25LegacyAdoptionDeprecate(wrongRecorder, wrong)
	require.Equal(t, http.StatusBadRequest, wrongRecorder.Code, wrongRecorder.Body.String())
	dispositions, err := sqlite.ListLegacyMemoryRecoveryDispositions(context.Background())
	require.NoError(t, err)
	require.Empty(t, dispositions)

	request := appV25RecoveryControlRequest(t,
		"/v1/dashboard/memory/adoption-deprecate", revision, 1,
		"DEPRECATE 1")
	recorder := httptest.NewRecorder()
	handler.handleAppV25LegacyAdoptionDeprecate(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

	record, err := sqlite.GetMemory(context.Background(), "legacy-unconvertible")
	require.NoError(t, err)
	require.Equal(t, memory.StatusCommitted, record.Status,
		"explicit projection disposition must not rewrite memory lifecycle")
	require.Equal(t, "preserved but unverifiable", record.Content)
	dispositions, err = sqlite.ListLegacyMemoryRecoveryDispositions(context.Background())
	require.NoError(t, err)
	require.Equal(t, []store.LegacyMemoryRecoveryDisposition{{
		MemoryID: "legacy-unconvertible", Reason: "content_hash_mismatch",
		ProjectionRevision: revision, AuthorizedBy: fixture.rootID,
	}}, dispositions)
	progress, err := sqlite.GetLegacyMemoryAdoptionProgress(context.Background())
	require.NoError(t, err)
	require.NotNil(t, progress)
	require.Equal(t, "complete", progress.State)
	require.Zero(t, progress.Recovery)
	require.Zero(t, progress.Remaining)

	// A stale worker observation must not be able to resurrect a record that
	// Root explicitly retired from automatic repair.
	require.NoError(t, sqlite.SyncLegacyMemoryRecoveryQueue(
		context.Background(), revision, []store.LegacyMemoryRecoveryItem{{
			MemoryID: "legacy-unconvertible", Reason: "content_hash_mismatch",
		}},
	))
	recovery, err := sqlite.ListLegacyMemoryRecoveryQueue(context.Background(), false)
	require.NoError(t, err)
	require.Empty(t, recovery)

	plan, err := handler.buildAppV25LegacyAdoptionPlan(context.Background(), sqlite)
	require.NoError(t, err)
	require.Zero(t, plan.Discovered)
	require.Zero(t, plan.Unresolved)
	require.Empty(t, plan.Recovery)
	require.Empty(t, plan.Entries)

	replayed := appV25RecoveryControlRequest(t,
		"/v1/dashboard/memory/adoption-deprecate", revision, 1,
		"DEPRECATE 1")
	replayedRecorder := httptest.NewRecorder()
	handler.handleAppV25LegacyAdoptionDeprecate(replayedRecorder, replayed)
	require.Equal(t, http.StatusConflict, replayedRecorder.Code,
		replayedRecorder.Body.String())
}

func TestAppV25LegacyAdoptionDeprecateRequiresCurrentProcessProof(t *testing.T) {
	handler, sqlite, _, revision := appV25RecoveryControlFixture(t)
	handler.ConfigureAppV25Maintenance(true)

	request := appV25RecoveryControlRequest(t,
		"/v1/dashboard/memory/adoption-deprecate", revision, 1,
		"DEPRECATE 1")
	recorder := httptest.NewRecorder()
	handler.handleAppV25LegacyAdoptionDeprecate(recorder, request)
	require.Equal(t, http.StatusConflict, recorder.Code, recorder.Body.String())

	dispositions, err := sqlite.ListLegacyMemoryRecoveryDispositions(context.Background())
	require.NoError(t, err)
	require.Empty(t, dispositions)
}

func TestAppV25LegacyRecoveryControlsRejectNonLocalRequests(t *testing.T) {
	handler, _, _, revision := appV25RecoveryControlFixture(t)
	request := appV25RecoveryControlRequest(t,
		"/v1/dashboard/memory/adoption-retry", revision, 1, "")
	request.RemoteAddr = "192.0.2.10:54321"
	recorder := httptest.NewRecorder()
	handler.handleAppV25LegacyAdoptionRetry(recorder, request)
	require.Equal(t, http.StatusForbidden, recorder.Code, recorder.Body.String())
}
