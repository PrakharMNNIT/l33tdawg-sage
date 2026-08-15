package web

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/stretchr/testify/require"
)

func seedEngramMemory(t *testing.T, s *store.SQLiteStore, id, agent, content, domain string, conf float64, status memory.MemoryStatus) {
	t.Helper()
	// ContentHash must be sha256(Content) so the appV23 canonical projection audit
	// (which recomputes it from content) accepts the row; callers pass unique content.
	sum := sha256.Sum256([]byte(content))
	require.NoError(t, s.InsertMemory(context.Background(), &memory.MemoryRecord{
		MemoryID:        id,
		SubmittingAgent: agent,
		Content:         content,
		ContentHash:     sum[:],
		MemoryType:      memory.TypeObservation,
		DomainTag:       domain,
		ConfidenceScore: conf,
		Status:          status,
		CreatedAt:       time.Now().UTC(),
	}))
}

// TestHandleEngrams: an agent's lobe blooms ONLY that agent's committed
// memories, ordered by confidence, and never another agent's — the core
// re-anchoring + no-leak contract.
func TestHandleEngrams(t *testing.T) {
	h, s := newTestHandler(t)

	seedEngramMemory(t, s, "a1", "alice", "alpha", "ops", 0.9, memory.StatusCommitted)
	seedEngramMemory(t, s, "a2", "alice", "beta", "ops", 0.7, memory.StatusCommitted)
	seedEngramMemory(t, s, "a3", "alice", "gamma", "research", 0.8, memory.StatusCommitted)
	seedEngramMemory(t, s, "a4", "alice", "draft", "ops", 0.95, memory.StatusProposed) // not committed
	seedEngramMemory(t, s, "b1", "bob", "bobmem", "ops", 0.99, memory.StatusCommitted)

	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/memory/engrams?agent=alice", nil)
	rec := httptest.NewRecorder()
	h.handleEngrams(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body struct {
		AgentID string       `json:"agent_id"`
		Engrams []engramNode `json:"engrams"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "alice", body.AgentID)
	require.NotNil(t, body.Engrams)

	byID := map[string]engramNode{}
	for _, e := range body.Engrams {
		byID[e.ID] = e
	}
	require.Len(t, body.Engrams, 3, "only alice's three committed memories")
	require.Contains(t, byID, "a1")
	require.Contains(t, byID, "a2")
	require.Contains(t, byID, "a3")
	require.NotContains(t, byID, "a4", "a proposed memory is not a committed engram")
	require.NotContains(t, byID, "b1", "another agent's memory must never leak into this lobe")

	// ordered by confidence descending (a1 0.9, a3 0.8, a2 0.7)
	require.Equal(t, []string{"a1", "a3", "a2"}, []string{body.Engrams[0].ID, body.Engrams[1].ID, body.Engrams[2].ID})
	require.Equal(t, 0.9, byID["a1"].Confidence)
	require.Equal(t, "ops", byID["a1"].Domain)
}

// TestHandleEngramsExcludesInternalAuditDomains pins the cerebrumListOptions wrap:
// sync-audit anchors are ordinary committed records (Root-signed, minted at
// confidence 1, so they sort to the FRONT of a confidence-ordered lobe), but they
// are protocol bookkeeping that /memory/graph excludes. The lobe must exclude them
// too — this is the "disclosure identical to the graph" invariant. Removing the
// cerebrumListOptions wrap from handleEngrams fails this test.
func TestHandleEngramsExcludesInternalAuditDomains(t *testing.T) {
	h, s := newTestHandler(t)
	seedEngramMemory(t, s, "real1", "alice", "a real memory", "ops", 0.8, memory.StatusCommitted)
	seedEngramMemory(t, s, "anchor1", "alice", "audit anchor", store.SyncAuditDomainPrefix+"group1", 1.0, memory.StatusCommitted)

	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/memory/engrams?agent=alice", nil)
	rec := httptest.NewRecorder()
	h.handleEngrams(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Engrams []engramNode `json:"engrams"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	ids := map[string]bool{}
	for _, e := range body.Engrams {
		ids[e.ID] = true
	}
	require.True(t, ids["real1"], "a real memory blooms")
	require.False(t, ids["anchor1"], "an internal sync-audit anchor must not pollute the lobe")
}

// TestHandleEngramsReturnsTopNByConfidence pins the documented ordering: the lobe
// is the agent's HIGHEST-confidence memories, in descending order, capped at the
// per-agent limit — not a spread across its whole history.
func TestHandleEngramsReturnsTopNByConfidence(t *testing.T) {
	h, s := newTestHandler(t)
	// 30 committed memories; higher index = lower confidence, so m00 is the most
	// confident and the top slice is exactly m00..m23.
	for i := 0; i < 30; i++ {
		id := fmt.Sprintf("m%02d", i)
		seedEngramMemory(t, s, id, "alice", "content-"+id, "ops", 1.0-float64(i)*0.01, memory.StatusCommitted)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/memory/engrams?agent=alice", nil)
	rec := httptest.NewRecorder()
	h.handleEngrams(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Engrams []engramNode `json:"engrams"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Engrams, engramPerAgentLimit, "capped at the per-agent limit")
	for i := 0; i < engramPerAgentLimit; i++ {
		require.Equal(t, fmt.Sprintf("m%02d", i), body.Engrams[i].ID,
			"engram %d must be the #%d most-confident memory (top-N, not a sample)", i, i)
	}
}

// TestEngramFetchLimitOverfetchesAboveCap: the fetch limit must exceed the display
// cap so that, after projection disclosure removes a few top rows, the
// confidence-ordered prefix can still be backfilled to the full top-N.
func TestEngramFetchLimitOverfetchesAboveCap(t *testing.T) {
	require.GreaterOrEqual(t, engramFetchLimit, engramPerAgentLimit,
		"must over-fetch at least the display cap so disclosure thinning can be backfilled")
}

// TestEngramsSelectsTopNNotRepresentativeSpread pins the round-3 fix: the lobe must
// select the highest-confidence prefix directly, NOT route through
// appV23CanonicalDashboardCandidates whose representativeGraphRecords step spreads
// evenly (skipping higher-confidence rows). Reverting to the sampler fails this.
func TestEngramsSelectsTopNNotRepresentativeSpread(t *testing.T) {
	src, err := os.ReadFile("engrams_handler.go")
	require.NoError(t, err)
	require.NotContains(t, string(src), "h.appV23CanonicalDashboardCandidates(",
		"the lobe must not CALL the representative-spread sampler (a doc mention is fine)")
	require.Contains(t, string(src), "records[:engramPerAgentLimit]",
		"the confidence-ordered prefix must be taken as the top-N")
	// NOTE: the disclosure filter is pinned BEHAVIOURALLY, not by string presence
	// (which a doc mention would satisfy): TestHandleEngramsAppV23BackfillsPastHiddenPrefix
	// fails if filterAppV23BroadDashboardRecords is removed, because the tamper-hidden
	// rows then surface into the lobe.
}

// TestEngramsRouteRegisteredBehindOperatorGate pins the operator gate on the route:
// deleting cerebrumOperatorGate from the /memory/engrams registration (which left
// every behavioural test green, since the group's locality gate also fires) fails
// this. The route must carry the operator gate + the projection broad-read gate.
func TestEngramsRouteRegisteredBehindOperatorGate(t *testing.T) {
	src, err := os.ReadFile("handler.go")
	require.NoError(t, err)
	require.Regexp(t,
		`(?s)With\(h\.cerebrumOperatorGate, h\.appV23ProjectionBroadReadGate\)\.\s*Get\("/v1/dashboard/memory/engrams"`,
		string(src),
		"the engrams route must be registered behind cerebrumOperatorGate + appV23ProjectionBroadReadGate")
}

// TestHandleEngramsRequiresAgent: the endpoint is per-neuron; without ?agent it
// is a bad request rather than a whole-brain dump.
func TestHandleEngramsRequiresAgent(t *testing.T) {
	h, _ := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/memory/engrams", nil)
	rec := httptest.NewRecorder()
	h.handleEngrams(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}
