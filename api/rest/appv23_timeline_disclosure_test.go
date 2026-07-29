package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/api/rest/middleware"
	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
)

func TestAppV23TimelineCountsOnlyLiveAuthorizedRecordsAcrossRawPages(t *testing.T) {
	srv, badger, readerID, ownerID, outsiderID := setupAppV23RESTAccess(t)
	memStore := &appV23PagingStore{rbacMockMemoryStore: newRBACMockMemoryStore()}
	memStore.badger = badger
	srv.store = memStore

	now := time.Date(2026, time.July, 29, 14, 25, 0, 0, time.UTC)
	for i := 0; i < 250; i++ {
		record := &memory.MemoryRecord{
			MemoryID:        fmt.Sprintf("timeline-denied-%03d", i),
			SubmittingAgent: outsiderID,
			Content:         fmt.Sprintf("denied timeline record %03d", i),
			DomainTag:       "outsider.home",
			CreatedAt:       now.Add(-time.Duration(i) * time.Second),
			Status:          memory.StatusCommitted,
		}
		memStore.listed = append(memStore.listed, record)
		publishAppV23RESTRecord(t, badger, record, 1)
	}
	visible := &memory.MemoryRecord{
		MemoryID:        "timeline-visible",
		SubmittingAgent: ownerID,
		Content:         "visible timeline record",
		DomainTag:       "owner.home",
		CreatedAt:       now,
		Status:          memory.StatusCommitted,
	}
	overClearance := &memory.MemoryRecord{
		MemoryID:        "timeline-over-clearance",
		SubmittingAgent: ownerID,
		Content:         "over-clearance timeline record",
		DomainTag:       "owner.home",
		CreatedAt:       now,
		Status:          memory.StatusCommitted,
	}
	memStore.listed = append(memStore.listed, visible, overClearance)
	publishAppV23RESTRecord(t, badger, visible, 1)
	publishAppV23RESTRecord(t, badger, overClearance, 4)

	query := url.Values{}
	query.Set("from", now.Add(-time.Hour).Format(time.RFC3339))
	query.Set("to", now.Add(time.Hour).Format(time.RFC3339))
	query.Set("bucket", "hour")
	req := httptest.NewRequest(
		http.MethodGet, "/v1/memory/timeline?"+query.Encode(), nil,
	)
	req = req.WithContext(middleware.WithAgentID(req.Context(), readerID))
	out := httptest.NewRecorder()
	srv.handleTimelineAuth(out, req)
	require.Equal(t, http.StatusOK, out.Code, out.Body.String())

	var response struct {
		Buckets []store.TimelineBucket `json:"buckets"`
		Total   int                    `json:"total"`
	}
	require.NoError(t, json.Unmarshal(out.Body.Bytes(), &response))
	require.Equal(t, []store.TimelineBucket{{
		Period: "2026-07-29T14:00:00Z",
		Count:  1,
	}}, response.Buckets)
	require.Equal(t, 1, response.Total)
}

func TestAppV23TimelineFailsClosedWhenRecordAuthorizationIsCorrupt(t *testing.T) {
	srv, badger, readerID, ownerID, _ := setupAppV23RESTAccess(t)
	memStore := &appV23PagingStore{rbacMockMemoryStore: newRBACMockMemoryStore()}
	memStore.badger = badger
	srv.store = memStore

	now := time.Date(2026, time.July, 29, 14, 25, 0, 0, time.UTC)
	record := &memory.MemoryRecord{
		MemoryID:        "timeline-corrupt-classification",
		SubmittingAgent: ownerID,
		Content:         "corrupt classification timeline record",
		DomainTag:       "owner.home",
		CreatedAt:       now,
		Status:          memory.StatusCommitted,
	}
	memStore.listed = []*memory.MemoryRecord{record}
	publishAppV23RESTRecord(t, badger, record, 1)
	require.NoError(t, badger.SetMemoryClassification(
		"timeline-corrupt-classification", 0xff,
	))

	req := httptest.NewRequest(http.MethodGet, "/v1/memory/timeline", nil)
	req = req.WithContext(middleware.WithAgentID(req.Context(), readerID))
	out := httptest.NewRecorder()
	srv.handleTimelineAuth(out, req)
	require.Equal(t, http.StatusServiceUnavailable, out.Code, out.Body.String())
	require.NotContains(t, out.Body.String(), "timeline-corrupt-classification")
	require.NotContains(t, out.Body.String(), `"count"`)
}

func TestAppV23TimelinePeriodMatchesStableSQLiteShape(t *testing.T) {
	at := time.Date(2026, time.January, 1, 13, 42, 0, 0, time.UTC)
	require.Equal(t, "2026-01-01T13:00:00Z", appV23TimelinePeriod(at, "hour", false))
	require.Equal(t, "2026-W00", appV23TimelinePeriod(at, "week", false))
	require.Equal(t, "2026-01", appV23TimelinePeriod(at, "month", false))
	require.Equal(t, "2026-01-01", appV23TimelinePeriod(at, "day", false))
}

func TestAppV23TimelinePeriodPreservesPostgresShape(t *testing.T) {
	at := time.Date(2026, time.January, 1, 13, 42, 0, 0, time.UTC)
	require.Equal(t, "2026-01-01T13:00:00Z", appV23TimelinePeriod(at, "hour", true))
	require.Equal(t, "2025-12-29T00:00:00Z", appV23TimelinePeriod(at, "week", true))
	require.Equal(t, "2026-01-01T00:00:00Z", appV23TimelinePeriod(at, "month", true))
	require.Equal(t, "2026-01-01T00:00:00Z", appV23TimelinePeriod(at, "day", true))
}

func TestAppV23TimelineRejectsUnboundedAndMalformedRanges(t *testing.T) {
	srv, _, readerID, _, _ := setupAppV23RESTAccess(t)
	for _, tc := range []struct {
		name, query string
		status      int
	}{
		{
			name:   "too wide",
			query:  "?from=2026-01-01T00%3A00%3A00Z&to=2026-03-01T00%3A00%3A00Z",
			status: http.StatusUnprocessableEntity,
		},
		{
			name:   "malformed",
			query:  "?from=not-a-time",
			status: http.StatusBadRequest,
		},
		{
			name:   "reversed",
			query:  "?from=2026-01-02T00%3A00%3A00Z&to=2026-01-01T00%3A00%3A00Z",
			status: http.StatusBadRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/memory/timeline"+tc.query, nil)
			req = req.WithContext(middleware.WithAgentID(req.Context(), readerID))
			out := httptest.NewRecorder()
			srv.handleTimelineAuth(out, req)
			require.Equal(t, tc.status, out.Code, out.Body.String())
		})
	}
}
