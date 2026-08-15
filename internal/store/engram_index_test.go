package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestEngramIndexDeclaredOnBothBackends: the submitting_agent index must be
// created for NEW databases (initSchema) AND EXISTING ones (the idempotent
// migration mirror) on sqlite, and on postgres — a plan test alone can't catch a
// dropped declaration, and a migration-only or new-db-only copy silently leaves
// half the fleet on a full scan.
func TestEngramIndexDeclaredOnBothBackends(t *testing.T) {
	const idx = "idx_memories_submitting_agent ON memories(submitting_agent, confidence_score)"
	sqlSrc, err := os.ReadFile("sqlite.go")
	require.NoError(t, err)
	require.GreaterOrEqual(t, strings.Count(string(sqlSrc), idx), 2,
		"sqlite must declare the index in BOTH initSchema and the migration mirror")

	pgSrc, err := os.ReadFile("postgres.go")
	require.NoError(t, err)
	require.Contains(t, string(pgSrc), "idx_memories_submitting_agent ON memories (submitting_agent, confidence_score)",
		"postgres must declare the submitting_agent index too")
}

// TestCorroborationIndexDeclaredOnBothBackends mirrors the engram-index guard for
// idx_corroborations_memory. The corroborations child FK column is not
// auto-indexed by sqlite, so the CEREBRUM distributed-engram per-memory read
// (and GetCorroborationCounts) would full-scan without it. It must be declared for
// NEW databases (initSchema) AND EXISTING ones (the migration mirror) on sqlite,
// and on postgres.
func TestCorroborationIndexDeclaredOnBothBackends(t *testing.T) {
	const idx = "idx_corroborations_memory ON corroborations(memory_id)"
	sqlSrc, err := os.ReadFile("sqlite.go")
	require.NoError(t, err)
	require.GreaterOrEqual(t, strings.Count(string(sqlSrc), idx), 2,
		"sqlite must declare the corroborations index in BOTH initSchema and the migration mirror")

	pgSrc, err := os.ReadFile("postgres.go")
	require.NoError(t, err)
	require.Contains(t, string(pgSrc), "idx_corroborations_memory ON corroborations (memory_id)",
		"postgres must declare the corroborations index too")
}

// TestCorroborationIndexServesPerMemoryRead pins the plan for GetCorroborations'
// query (WHERE memory_id = ? ORDER BY created_at): idx_corroborations_memory must
// turn the per-memory read into a SEARCH (a seek), not a full scan of every
// corroboration on the node — which is what the CEREBRUM lobe issues per
// corroborated engram.
//
// Like the engram-index test, this deliberately does NOT ANALYZE: SAGE never runs
// ANALYZE, so a real node has no sqlite_stat1. A plain equality on a single-column
// index is used without stats, but pinning it here catches a regression to a scan
// (which would need an INDEXED BY hint, per PR #181).
func TestCorroborationIndexServesPerMemoryRead(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	at := time.Unix(1_700_000_000, 0).UTC()
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("m%03d", i)
		require.NoError(t, s.InsertMemory(ctx, testMemory(id, "author", "content-"+id, "dom")))
	}
	for i := 0; i < 200; i++ {
		require.NoError(t, s.InsertCorroboration(ctx, &Corroboration{
			MemoryID:  fmt.Sprintf("m%03d", i%20),
			AgentID:   fmt.Sprintf("agent-%d", i),
			CreatedAt: at.Add(time.Duration(i) * time.Second),
		}))
	}

	rows, err := s.conn.QueryContext(ctx,
		"EXPLAIN QUERY PLAN SELECT id, memory_id, agent_id, evidence, created_at FROM corroborations WHERE memory_id = ? ORDER BY created_at",
		"m003")
	require.NoError(t, err)
	defer rows.Close() //nolint:errcheck
	var plan string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		require.NoError(t, rows.Scan(&id, &parent, &notUsed, &detail))
		plan += detail + "\n"
	}
	require.NoError(t, rows.Err())

	require.Contains(t, plan, "idx_corroborations_memory",
		"the per-memory corroborator read must SEARCH via the index, not a full scan; plan was:\n"+plan)
	require.NotContains(t, plan, "SCAN corroborations",
		"a full scan of corroborations per engram is exactly what the index must prevent; plan was:\n"+plan)
}

// The CEREBRUM agent-as-lobe read is `WHERE submitting_agent = ? [AND status = ?]
// ORDER BY confidence_score DESC LIMIT N`. idx_memories_submitting_agent
// (submitting_agent, confidence_score) must satisfy BOTH the equality and the
// order — no full table scan, no temp b-tree sort.
//
// Crucially this must hold WITHOUT ANALYZE: SAGE never runs ANALYZE, so
// sqlite_stat1 is absent on a real node, and a new index can be silently ignored
// in favour of another low-cardinality index plus a temp sort (learned on the
// pipe connectome index, PR #181). This test deliberately does not ANALYZE,
// mirroring production; if the plan ever regresses to a scan/temp-sort the query
// needs an INDEXED BY hint.
func TestEngramIndexServesAgentTopByConfidence(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Populate across several agents and statuses so the planner has a realistic
	// table (and idx_memories_status exists as a competing candidate).
	for i := 0; i < 200; i++ {
		id := fmt.Sprintf("m%03d", i)
		agent := fmt.Sprintf("agent-%d", i%8)
		require.NoError(t, s.InsertMemory(ctx, testMemory(id, agent, "content-"+id, "dom")))
	}

	queryPlan := func(sql string) string {
		rows, err := s.conn.QueryContext(ctx, "EXPLAIN QUERY PLAN "+sql, "agent-3", "committed")
		require.NoError(t, err)
		defer rows.Close() //nolint:errcheck
		var plan string
		for rows.Next() {
			var id, parent, notUsed int
			var detail string
			require.NoError(t, rows.Scan(&id, &parent, &notUsed, &detail))
			plan += detail + "\n"
		}
		require.NoError(t, rows.Err())
		return plan
	}

	// Both shapes ListMemories actually issues for the lobe: the legacy path runs
	// the plain confidence order; the appV23 path adds StablePaging's memory_id
	// tiebreak. Both must SEARCH via the index (a per-agent seek, not a full scan).
	legacy := queryPlan(`SELECT memory_id FROM memories WHERE submitting_agent = ? AND status = ? ORDER BY confidence_score DESC LIMIT 24`)
	appv23 := queryPlan(`SELECT memory_id FROM memories WHERE submitting_agent = ? AND status = ? ORDER BY confidence_score DESC, memory_id ASC LIMIT 512`)

	for name, plan := range map[string]string{"legacy": legacy, "appv23 StablePaging": appv23} {
		require.Contains(t, plan, "idx_memories_submitting_agent",
			name+" agent-lobe query must SEARCH via the submitting_agent index, not a full scan; plan was:\n"+plan)
	}
	// The legacy shape is fully index-ordered — no temp sort at all. (The appV23
	// shape may add a small sort only for the memory_id tiebreak within equal
	// confidence, over the one agent's already index-selected rows — not a scan.)
	require.NotContains(t, legacy, "TEMP B-TREE",
		"the index order must satisfy ORDER BY confidence_score — no temp sort; plan was:\n"+legacy)
}
