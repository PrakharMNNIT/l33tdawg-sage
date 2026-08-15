package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
)

// engramNode is one memory authored by an agent — an "engram" that orbits its
// author neuron in the CEREBRUM agent-as-lobe view.
type engramNode struct {
	ID                 string   `json:"id"`
	Content            string   `json:"content"`
	Domain             string   `json:"domain"`
	Confidence         float64  `json:"confidence"`
	Status             string   `json:"status"`
	MemoryType         string   `json:"memory_type"`
	CreatedAt          string   `json:"created_at"`
	CorroborationCount int      `json:"corroboration_count"`
	Tags               []string `json:"tags,omitempty"`
}

// engramPerAgentLimit caps how many memories one neuron blooms. Kept small: the
// lobe shows an agent's most-confident settled knowledge, not its whole history,
// and a small per-agent cap keeps the on-demand fetch an index-cheap seek.
const engramPerAgentLimit = 24

// engramFetchLimit over-fetches beyond the display cap so that, after projection
// disclosure removes a few of the very top rows, the confidence-ordered prefix can
// still be backfilled to engramPerAgentLimit. It is a bounded index seek (WHERE
// submitting_agent = ? ORDER BY confidence_score DESC LIMIT n), not a table scan.
const engramFetchLimit = engramPerAgentLimit * 4

// engramRawScanCap hard-bounds how many raw (pre-disclosure) rows the backfill may
// page through for one lobe, so an agent whose highest-confidence memories are
// mostly canonically hidden can never turn the fetch into a full-table walk. Each
// page is an index seek; this only caps how many pages the backfill will chase.
const engramRawScanCap = engramFetchLimit * 8

// handleEngrams returns ONE agent's authored memories — the "engrams" that
// re-anchor to their author neuron in the agent-as-lobe view. It is loaded on
// demand for a single neuron (?agent=<id>), so first paint stays neurons +
// synapses and the per-agent fetch is a bounded, index-assisted seek
// (idx_memories_submitting_agent) rather than an M-agent scan of the whole brain.
//
// Disclosure is IDENTICAL to /v1/dashboard/memory/graph, just partitioned by
// author: filterAppV23BroadDashboardRecords — the exact per-record projection
// disclosure the graph applies (directly in legacy, and inside
// appV23CanonicalDashboardCandidates under appV23) — runs on the author-filtered
// set, so this never reveals a memory the memory graph would withhold. The author
// facet alone is NOT a visibility boundary under appV23 (visibility is
// domain-derived), which is exactly why that per-record filter is still applied.
func (h *DashboardHandler) handleEngrams(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx := r.Context()

	agentID := strings.TrimSpace(r.URL.Query().Get("agent"))
	if agentID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "agent query parameter required"})
		return
	}

	allowed, seeAll := h.resolveAgentRBAC(r)

	// Neuron-visibility gate: if the caller cannot see this agent at all, do not
	// disclose the shape of its lobe — return an empty engram set, the same as a
	// neuron with no memories. Under appV23 seeAll is true and agent visibility is
	// domain-derived per-record below, so this only bites legacy RBAC.
	if !seeAll {
		visible := false
		for _, a := range allowed {
			if a == agentID {
				visible = true
				break
			}
		}
		if !visible {
			_ = json.NewEncoder(w).Encode(map[string]any{"agent_id": agentID, "engrams": []engramNode{}})
			return
		}
	}

	// The lobe is a TRUE highest-confidence top-N, not a representative spread. The
	// submitting_agent index makes "this agent's memories, best first" a bounded
	// seek, so we over-fetch a small multiple of the display cap, apply the SAME
	// projection disclosure the memory graph applies — filterAppV23BroadDashboardRecords,
	// the exact per-record step appV23CanonicalDashboardCandidates runs internally,
	// minus its even-spread representativeGraphRecords selection — and keep the
	// confidence-ordered prefix. One path serves both legacy and appV23; the index
	// keeps it off a full scan even though it never routes through the sampler.
	//
	// cerebrumListOptions appends the internal-domain exclusion (sage-syncaudit-*
	// group-removal anchors are Root-signed committed records minted at confidence 1,
	// so they would otherwise sort to the front); every other CEREBRUM memory-read
	// wraps its options this way, and omitting it made the lobe disclose rows
	// /memory/graph excludes.
	baseOpts := cerebrumListOptions(store.ListOptions{
		SubmittingAgent: agentID,
		Sort:            "confidence",
		Status:          "committed",
		StablePaging:    true,
		SkipTotal:       true,
	})
	if !seeAll {
		baseOpts.SubmittingAgents = allowed
	}

	// Bounded stable backfill: page the agent's confidence-ordered memories through
	// the submitting_agent index, apply the SAME per-record disclosure the graph
	// applies, and accumulate the VISIBLE prefix until we have one more than the
	// display cap (to detect has-more). A run of canonically hidden top rows can
	// therefore never under-fill the lobe — the previous single 96-row fetch
	// returned only the few visible rows in that page. Bounded by engramRawScanCap
	// so a mostly-hidden agent can never turn this into a full-table walk.
	want := engramPerAgentLimit + 1
	visibleRecords := make([]*memory.MemoryRecord, 0, want)
	scanned := 0
	rawExhausted := false
	var err error
	for len(visibleRecords) < want && scanned < engramRawScanCap {
		pageOpts := baseOpts
		pageOpts.Offset = scanned
		pageOpts.Limit = engramFetchLimit
		if rem := engramRawScanCap - scanned; pageOpts.Limit > rem {
			pageOpts.Limit = rem
		}
		page, _, listErr := h.store.ListMemories(ctx, pageOpts)
		if listErr != nil {
			err = listErr
			break
		}
		if len(page) == 0 {
			rawExhausted = true
			break
		}
		scanned += len(page)
		safe, filterErr := h.filterAppV23BroadDashboardRecords(page)
		if filterErr != nil {
			err = filterErr
			break
		}
		visibleRecords = append(visibleRecords, safe...)
		if len(page) < pageOpts.Limit {
			rawExhausted = true
			break
		}
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "engram read failed"})
		return
	}
	// has-more: either a visible record was found beyond the display cap, or the
	// raw scan cap was hit without exhausting the agent's rows (more may lie beyond).
	continuationRequired := len(visibleRecords) > engramPerAgentLimit ||
		(!rawExhausted && scanned >= engramRawScanCap)
	records := visibleRecords
	if len(records) > engramPerAgentLimit {
		records = records[:engramPerAgentLimit]
	}

	memIDs := make([]string, len(records))
	for i, rec := range records {
		memIDs[i] = rec.MemoryID
	}
	tagMap, tagErr := h.store.GetTagsBatch(ctx, memIDs)
	if tagErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "engram tag read failed"})
		return
	}
	corrCounts, corrErr := h.store.GetCorroborationCounts(ctx, memIDs)
	if corrErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "engram corroboration read failed"})
		return
	}

	engrams := make([]engramNode, 0, len(records))
	for _, rec := range records {
		engrams = append(engrams, engramNode{
			ID:                 rec.MemoryID,
			Content:            truncate(rec.Content, 200),
			Domain:             rec.DomainTag,
			Confidence:         rec.ConfidenceScore,
			Status:             string(rec.Status),
			MemoryType:         string(rec.MemoryType),
			CreatedAt:          rec.CreatedAt.Format(time.RFC3339),
			CorroborationCount: corrCounts[rec.MemoryID],
			Tags:               tagMap[rec.MemoryID],
		})
	}

	// Surface the same projection health + continuation signals the memory graph
	// does, so an empty/partial/quarantined lobe is distinguishable from a
	// genuinely empty one rather than serialising identically.
	resp := map[string]any{
		"agent_id": agentID,
		"engrams":  engrams,
	}
	if continuationRequired {
		resp["continuation_required"] = true
	}
	if projection := h.appV23ProjectionResponseForContext(ctx); projection != nil {
		resp["projection"] = projection
	}
	_ = json.NewEncoder(w).Encode(resp)
}
