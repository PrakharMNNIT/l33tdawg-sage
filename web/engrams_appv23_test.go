package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/stretchr/testify/require"
)

// TestHandleEngramsAppV23BackfillsPastHiddenPrefix is the round-4 regression: when
// the agent's HIGHEST-confidence rows are canonically hidden (committed in SQL but
// unpublished to the canonical projection, so disclosure omits them), a single
// bounded page returns only the few visible rows in it. The bounded backfill must
// page past the hidden prefix to a full lobe and still signal continuation.
func TestHandleEngramsAppV23BackfillsPastHiddenPrefix(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)

	publish := func(id, content string, conf float64) {
		seedEngramMemory(t, fixture.sql, id, "alice", content, "ops", conf, memory.StatusProposed)
		require.NoError(t, fixture.sql.UpdateStatus(context.Background(), id, memory.StatusCommitted, time.Now().UTC()))
		publishAppV23DashboardRecord(t, fixture.sql, fixture.badger, id, uint8(store.ClearanceInternal), true)
	}
	// 80 HIGH-confidence + 30 LOWER-confidence, all committed AND published so the
	// audit passes over a consistent projection.
	for i := 0; i < 80; i++ {
		publish(fmt.Sprintf("h%03d", i), fmt.Sprintf("hidden-%03d", i), 0.99)
	}
	for i := 0; i < 30; i++ {
		publish(fmt.Sprintf("v%02d", i), fmt.Sprintf("visible-%02d", i), 0.5-float64(i)*0.001)
	}
	require.NoError(t, fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background()))

	// Now canonically HIDE the 80 highest-confidence rows: tamper their SQL content
	// so it no longer matches the published hash → each is omitted on read. They sit
	// at the front of the confidence order, so a single page would surface only the
	// few visible rows behind them.
	for i := 0; i < 80; i++ {
		tamperAppV23ProjectionRow(t, fixture.dbPath,
			"UPDATE memories SET content = ? WHERE memory_id = ?",
			fmt.Sprintf("tampered-%03d", i), fmt.Sprintf("h%03d", i))
	}

	rec := requestLocalProjectionRoute(t, fixture, "/v1/dashboard/memory/engrams?agent=alice")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var body struct {
		Engrams      []engramNode `json:"engrams"`
		Continuation bool         `json:"continuation_required"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Engrams, engramPerAgentLimit,
		"backfill must page past the 80-row hidden prefix to a full lobe, not stop at the first page")
	for _, e := range body.Engrams {
		require.True(t, strings.HasPrefix(e.ID, "v"),
			"only visible (published) engrams may appear; hidden %s must not", e.ID)
	}
	require.True(t, body.Continuation, "30 visible > 24 shown → continuation_required")
}

// TestHandleEngramsAppV23ReturnsTopNOverCapacity is the over-capacity regression
// the reviewer asked for: on the APPV23 candidate path, with MORE than the display
// cap of single-domain memories, the lobe must be the highest-confidence top-N in
// order (m00..m23) — NOT the even spread representativeGraphRecords produces (which
// skipped m05 and surfaced m06 at index 5). It also asserts continuation + the
// projection health signal are surfaced.
func TestHandleEngramsAppV23ReturnsTopNOverCapacity(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)

	// 30 committed memories in ONE domain, so confidence is the only differentiator;
	// higher index = lower confidence, so the top-24 is exactly m00..m23.
	for i := 0; i < 30; i++ {
		id := fmt.Sprintf("m%02d", i)
		seedEngramMemory(t, fixture.sql, id, "alice", "content-"+id, "ops", 1.0-float64(i)*0.01, memory.StatusProposed)
		require.NoError(t, fixture.sql.UpdateStatus(context.Background(), id, memory.StatusCommitted, time.Now().UTC()))
		publishAppV23DashboardRecord(t, fixture.sql, fixture.badger, id, uint8(store.ClearanceInternal), true)
	}
	require.NoError(t, fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background()))

	rec := requestLocalProjectionRoute(t, fixture, "/v1/dashboard/memory/engrams?agent=alice")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var body struct {
		Engrams      []engramNode `json:"engrams"`
		Continuation bool         `json:"continuation_required"`
		Projection   any          `json:"projection"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Engrams, engramPerAgentLimit, "capped at the per-agent limit")
	for i := 0; i < engramPerAgentLimit; i++ {
		require.Equal(t, fmt.Sprintf("m%02d", i), body.Engrams[i].ID,
			"appV23 lobe must be the highest-confidence top-N in order (m%02d at %d), not a spread", i, i)
	}
	require.True(t, body.Continuation, "30 > 24 memories → continuation_required must be signalled")
	require.NotNil(t, body.Projection, "appV23 projection health must be surfaced, not dropped")
}
