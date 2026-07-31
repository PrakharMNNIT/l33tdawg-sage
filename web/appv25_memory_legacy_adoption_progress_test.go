package web

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/store"
)

func TestAppV25LegacyAdoptionProgressSurfaceIsAggregateOnly(t *testing.T) {
	ctx := context.Background()
	sqlite, err := store.NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "memories.db"))
	require.NoError(t, err)
	defer func() { require.NoError(t, sqlite.Close()) }()
	require.NoError(t, sqlite.PublishLegacyMemoryAdoptionProgress(
		ctx,
		store.LegacyMemoryAdoptionProgress{
			State:      "migrating",
			Discovered: 10404,
			Converted:  512,
			Remaining:  9888,
			Recovery:   4,
			Revision:   42,
			Message:    "SAGE is upgrading memories in the background. Normal work continues.",
		},
	))
	handler := NewDashboardHandler(sqlite, "test")
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		"GET",
		"/v1/dashboard/memory/adoption-progress",
		nil,
	)
	handler.handleAppV25LegacyAdoptionProgress(recorder, request)
	require.Equal(t, 200, recorder.Code)
	var response map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	require.Equal(t, "migrating", response["state"])
	require.Equal(t, float64(10404), response["discovered"])
	require.Equal(t, float64(512), response["converted"])
	require.Equal(t, float64(9888), response["remaining"])
	require.Equal(t, float64(4), response["recovery"])
	require.NotContains(t, response, "memory_id")
	require.NotContains(t, response, "content")
	require.NotContains(t, response, "domain")
	require.NotContains(t, response, "author")
}
