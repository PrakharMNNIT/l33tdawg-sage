package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
)

// boundedEngramCorroborationReader is deliberately optional: a store that
// cannot apply the row bound in SQL discloses no bridge identities rather than
// falling back to an unbounded projection read. The distinct total is fetched
// separately through the required OffchainStore contract.
type boundedEngramCorroborationReader interface {
	GetCorroborationsBounded(ctx context.Context, memoryID string, limit int) ([]*store.Corroboration, error)
}

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
	// Corroborators is the subset of agents who corroborated this memory that the
	// caller is cleared to see AND that exist as neurons — the endpoints the
	// agent-as-lobe view bridges the engram to. A memory bridged to several neurons
	// is a "distributed engram": one memory consolidated across multiple cells. It
	// is RBAC-filtered exactly as the connectome synapse edge guard filters its
	// endpoints — an author's own lobe is already visible, so a corroborator is
	// disclosed only when it is itself a visible neuron. Corroborators the caller
	// may NOT see are never named; they survive only inside CorroborationCount, so
	// CorroborationCount - len(Corroborators) is the anonymous remainder the view
	// renders as "+N held elsewhere". This is a pure off-chain read of the
	// corroborations table — no consensus surface, nothing anchored.
	Corroborators []string `json:"corroborators,omitempty"`
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

// engramCorroboratorLimit caps how many corroborator bridges one engram
// discloses. A memory corroborated by hundreds of agents must not draw hundreds
// of edges; the bridges illustrate that a memory is distributed across cells, and
// CorroborationCount still carries the true total for the anonymous remainder.
const engramCorroboratorLimit = 12

// Filtering happens after the SQL read because registry membership lives in
// Badger. Bound the raw deterministic prefix as well as the rendered bridge
// count so historical duplicates or very large corroborator sets cannot turn
// one lobe request into unbounded row materialization.
const engramCorroboratorScanLimit = engramCorroboratorLimit * 8

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
	// The set of agents the caller may see, reused by both the neuron-visibility
	// gate below and the corroborator (distributed-engram) disclosure further down.
	visible := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		visible[a] = true
	}

	// Neuron-visibility gate: if the caller cannot see this agent at all, do not
	// disclose the shape of its lobe — return an empty engram set, the same as a
	// neuron with no memories. Under appV23 seeAll is true and agent visibility is
	// domain-derived per-record below, so this only bites legacy RBAC.
	if !seeAll && !visible[agentID] {
		_ = json.NewEncoder(w).Encode(map[string]any{"agent_id": agentID, "engrams": []engramNode{}})
		return
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

	// Neuron set for the distributed-engram bridges: a corroborator is only
	// disclosed if it is itself a registered neuron, because the connectome renders
	// no node for a non-registered corroborator and, more importantly, the neuron
	// registry is the disclosure boundary the whole connectome uses — an identity
	// absent from it must not be named here either. When the registry is
	// unavailable (a store without a Badger registry, or an unreadable one), we
	// disclose NO corroborators rather than risk naming an identity we cannot
	// confirm is already a visible neuron; the count still conveys distribution.
	var neuronSet map[string]bool
	if h.BadgerStore != nil {
		if regs, regErr := listCurrentConnectomeAgents(h.BadgerStore); regErr == nil {
			neuronSet = make(map[string]bool, len(regs))
			for _, a := range regs {
				neuronSet[a.AgentID] = true
			}
		}
	}
	corroborationReader, canReadBoundedCorroborations := h.store.(boundedEngramCorroborationReader)

	engrams := make([]engramNode, 0, len(records))
	for _, rec := range records {
		// Distributed-engram disclosure: the corroborators the caller is cleared to
		// see. Fetched only for a memory that actually has corroborations (most have
		// none), so a lobe of solitary memories costs no extra reads. Each disclosed
		// corroborator must be (a) a registered neuron, (b) visible to the caller
		// under the same rule the synapse edge guard applies, and (c) not the author
		// itself; the rest survive only in CorroborationCount as the anonymous "+N".
		var corroborators []string
		if neuronSet != nil && canReadBoundedCorroborations && corrCounts[rec.MemoryID] > 0 {
			// A per-engram corroborator read failure degrades to "no bridges for this
			// engram" rather than failing the whole lobe — the same fail-closed choice
			// the missing-registry path makes above, applied per record because this
			// read is in the loop. The engram still renders (it was read fine) and
			// corroboration_count still conveys the memory is distributed; only the
			// bridges are withheld. The count is a separate batch read that already
			// succeeded, so the "held across N" total is unaffected.
			corrs, cErr := corroborationReader.GetCorroborationsBounded(
				ctx, rec.MemoryID, engramCorroboratorScanLimit,
			)
			if cErr != nil {
				corrs = nil
			}
			seen := make(map[string]bool, len(corrs))
			for _, c := range corrs {
				id := c.AgentID
				if id == "" || id == rec.SubmittingAgent || seen[id] {
					continue
				}
				if !neuronSet[id] || (!seeAll && !visible[id]) {
					continue
				}
				seen[id] = true
				corroborators = append(corroborators, id)
				if len(corroborators) >= engramCorroboratorLimit {
					break
				}
			}
		}
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
			Corroborators:      corroborators,
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
