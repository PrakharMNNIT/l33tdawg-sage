package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestGetPipeSynapses covers the connectome aggregation: messages collapse into
// one directed edge per (from,to) with a count and the newest timestamp,
// direction is preserved, and federated (cross-chain) rows are excluded so the
// endpoint returns only the LOCAL agent connectome.
func TestGetPipeSynapses(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	base := time.Now().UTC().Truncate(time.Second)
	mk := func(id, from, to string, at time.Time) *PipelineMessage {
		return &PipelineMessage{
			PipeID:    id,
			FromAgent: from,
			ToAgent:   to,
			Payload:   "hi",
			Status:    "pending",
			CreatedAt: at,
			ExpiresAt: at.Add(time.Hour),
		}
	}

	// alice→bob x3 (newest at +2m), bob→alice x1, and one federated edge.
	require.NoError(t, s.InsertPipeline(ctx, mk("p1", "alice", "bob", base)))
	require.NoError(t, s.InsertPipeline(ctx, mk("p2", "alice", "bob", base.Add(time.Minute))))
	require.NoError(t, s.InsertPipeline(ctx, mk("p3", "alice", "bob", base.Add(2*time.Minute))))
	require.NoError(t, s.InsertPipeline(ctx, mk("p4", "bob", "alice", base)))
	// A cross-chain row as the FEDERATED SEND PATH ACTUALLY WRITES ONE. This
	// fixture previously set ToProvider="other-chain", which production never
	// does: api/rest/pipe_handler.go:548-549 CLEARS ToProvider and sets
	// DestinationChainID on the federated branch. Modelling federation with a
	// provider label made this test agree with a predicate that was wrong in
	// both directions — it hid local provider-labelled edges, and it would have
	// admitted real federated rows, whose providers are empty.
	fed := mk("p5", "alice", "remote", base)
	fed.DestinationChainID = "sage-personal-otherchain"
	require.NoError(t, s.InsertPipeline(ctx, fed))

	syn, err := s.GetPipeSynapses(ctx)
	require.NoError(t, err)

	byEdge := make(map[string]PipeSynapse, len(syn))
	for _, e := range syn {
		byEdge[e.FromAgent+"|"+e.ToAgent] = e
	}

	require.Len(t, syn, 2, "only local directed edges with a concrete to_agent")

	ab, ok := byEdge["alice|bob"]
	require.True(t, ok, "alice→bob synapse present")
	require.Equal(t, int64(3), ab.Count, "weight = message count")
	require.NotEmpty(t, ab.LastFired, "last_fired set")

	ba, ok := byEdge["bob|alice"]
	require.True(t, ok, "bob→alice is a distinct directed synapse")
	require.Equal(t, int64(1), ba.Count)

	_, hasFed := byEdge["alice|remote"]
	require.False(t, hasFed, "federated edge excluded from the local connectome")
}

// TestGetPipeSynapsesUsesCoveringIndex pins the query PLAN, not just the result.
// The aggregation returns identical rows with or without idx_pipe_synapse_local
// — it just silently becomes a scan plus a temp b-tree over a table that only
// grows, on an endpoint designed to be polled. A correctness-only test cannot
// see that regression, which is why this asserts the plan directly.
//
// Deliberately NO ANALYZE: a production SAGE node never runs ANALYZE or PRAGMA
// optimize, so sqlite_stat1 does not exist and the planner is working from no
// statistics. Running ANALYZE here would test a database shape that SAGE never
// actually has, and would hide the fact that the plan depends on the INDEXED BY
// hint. This is the real deployed configuration.
func TestGetPipeSynapsesUsesCoveringIndex(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	base := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 200; i++ {
		require.NoError(t, s.InsertPipeline(ctx, &PipelineMessage{
			PipeID:    fmt.Sprintf("plan-%d", i),
			FromAgent: fmt.Sprintf("agent-%d", i%7),
			ToAgent:   fmt.Sprintf("peer-%d", i%5),
			Payload:   "hi",
			Status:    "pending",
			CreatedAt: base,
			ExpiresAt: base.Add(time.Hour),
		}))
	}

	rows, err := s.conn.QueryContext(ctx,
		"EXPLAIN QUERY PLAN "+fmt.Sprintf(pipeSynapseAggregation, pipeSynapseIndexHint))
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

	require.Contains(t, plan, "idx_pipe_synapse_local",
		"connectome aggregation must be served by its partial covering index, plan was:\n"+plan)
	require.NotContains(t, plan, "TEMP B-TREE",
		"index order must satisfy GROUP BY without a temp b-tree, plan was:\n"+plan)
}

// TestGetPipeSynapsesFallsBackWhenIndexMissing covers the degradation path.
// migratePipeline creates indexes best-effort and discards the error, so the
// INDEXED BY hint must never become a hard dependency — an INDEXED BY naming an
// absent index is a query error, and a slower connectome beats a broken one.
// Dropping the index reproduces exactly that state.
func TestGetPipeSynapsesFallsBackWhenIndexMissing(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	base := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, s.InsertPipeline(ctx, &PipelineMessage{
		PipeID: "fb1", FromAgent: "alice", ToAgent: "bob", Payload: "hi",
		Status: "pending", CreatedAt: base, ExpiresAt: base.Add(time.Hour),
	}))

	// Precondition: the hinted query works while the index exists.
	_, err := s.conn.ExecContext(ctx, `DROP INDEX IF EXISTS idx_pipe_synapse_local`)
	require.NoError(t, err)

	// The hinted form must now genuinely fail, or this test proves nothing.
	_, hintErr := s.conn.QueryContext(ctx,
		fmt.Sprintf(pipeSynapseAggregation, pipeSynapseIndexHint))
	require.Error(t, hintErr, "INDEXED BY on a dropped index must be a query error")

	syn, err := s.GetPipeSynapses(ctx)
	require.NoError(t, err, "connectome must degrade to an unhinted scan, not fail")
	require.Len(t, syn, 1)
	require.Equal(t, int64(1), syn[0].Count)
}

// TestGetPipeSynapsesIncludesProviderBearingLocalEdges is the regression this
// aggregation shipped without, and its absence is why the connectome went out
// showing roughly a tenth of the graph.
//
// from_provider/to_provider carry the AGENT'S PROVIDER LABEL, not a federation
// marker: SAGE_PROVIDER flows from the generated MCP launcher into agent
// registration and is stamped onto every send, so ordinary local traffic
// arrives tagged "claude-code" or "codex". The original predicate restricted to
// empty providers and therefore hid almost every real edge. Measured on a live
// node before the fix: 3 edges returned out of 30, with 359 of 363 local rows
// excluded.
//
// Every edge below is LOCAL — no chain ids — and all three must be returned.
func TestGetPipeSynapsesIncludesProviderBearingLocalEdges(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	base := time.Now().UTC().Truncate(time.Second)
	mk := func(id, from, to, fromProv, toProv string) *PipelineMessage {
		return &PipelineMessage{
			PipeID: id, FromAgent: from, ToAgent: to,
			FromProvider: fromProv, ToProvider: toProv,
			Payload: "hi", Status: "pending",
			CreatedAt: base, ExpiresAt: base.Add(time.Hour),
		}
	}
	// The shapes a real node actually produces, all local.
	require.NoError(t, s.InsertPipeline(ctx, mk("lp1", "alice", "bob", "claude-code", "")))
	require.NoError(t, s.InsertPipeline(ctx, mk("lp2", "bob", "carol", "codex", "")))
	require.NoError(t, s.InsertPipeline(ctx, mk("lp3", "carol", "dave", "claude-code", "codex")))
	// And one with no provider at all, which the old predicate also allowed.
	require.NoError(t, s.InsertPipeline(ctx, mk("lp4", "dave", "erin", "", "")))

	syn, err := s.GetPipeSynapses(ctx)
	require.NoError(t, err)

	edges := make(map[string]bool, len(syn))
	for _, e := range syn {
		edges[e.FromAgent+"|"+e.ToAgent] = true
	}

	require.True(t, edges["alice|bob"], "a local edge whose sender carries a provider label must be included")
	require.True(t, edges["bob|carol"], "provider label 'codex' is not a federation marker")
	require.True(t, edges["carol|dave"], "both endpoints carrying provider labels is still a local edge")
	require.True(t, edges["dave|erin"], "the provider-less shape must keep working")
	require.Len(t, syn, 4, "every local edge is part of the local connectome, got: %v", edges)
}

// TestGetPipeSynapsesStillExcludesCrossChainEdges pins the other half of the
// contract. Widening the predicate must not turn the local connectome into a
// federated one — the fix would be just as wrong in that direction.
func TestGetPipeSynapsesStillExcludesCrossChainEdges(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	base := time.Now().UTC().Truncate(time.Second)
	mk := func(id, from, to string) *PipelineMessage {
		return &PipelineMessage{
			PipeID: id, FromAgent: from, ToAgent: to,
			Payload: "hi", Status: "pending",
			CreatedAt: base, ExpiresAt: base.Add(time.Hour),
		}
	}
	local := mk("cc-local", "alice", "bob")
	require.NoError(t, s.InsertPipeline(ctx, local))

	inbound := mk("cc-in", "remote", "bob")
	inbound.SourceChainID = "sage-personal-otherchain"
	require.NoError(t, s.InsertPipeline(ctx, inbound))

	outbound := mk("cc-out", "alice", "remote")
	outbound.DestinationChainID = "sage-personal-otherchain"
	require.NoError(t, s.InsertPipeline(ctx, outbound))

	syn, err := s.GetPipeSynapses(ctx)
	require.NoError(t, err)

	edges := make(map[string]bool, len(syn))
	for _, e := range syn {
		edges[e.FromAgent+"|"+e.ToAgent] = true
	}
	require.True(t, edges["alice|bob"], "the local edge is still returned")
	require.False(t, edges["remote|bob"], "an inbound cross-chain edge is not part of the LOCAL connectome")
	require.False(t, edges["alice|remote"], "an outbound cross-chain edge is not part of the LOCAL connectome")
	require.Len(t, syn, 1, "exactly the local edge survives, got: %v", edges)
}

// TestCanonicalLocalSendReachesConnectome drives the PRODUCTION WRITER, not
// InsertPipeline. The bug this file exists to prevent was never about how rows
// are shaped by hand — it was about what SendLocalMessage actually persists for
// a normally-installed agent, whose Provider is stamped from SAGE_PROVIDER and
// arrives as "claude-code" or "codex". A test that inserts its own rows can
// agree with a broken predicate indefinitely, which is exactly what the
// original suite did.
func TestCanonicalLocalSendReachesConnectome(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	now := time.Now().UTC()
	// The exact shape the canonical path produces for an MCP agent: a provider
	// label on the sender, no chain ids, no to_provider.
	sent, replayed, err := s.SendLocalMessage(ctx, "idem-connectome-1", &PipelineMessage{
		FromAgent:    "alice",
		FromProvider: "claude-code",
		ToAgent:      "bob",
		Intent:       "work",
		Payload:      "hi",
		Status:       "pending",
		CreatedAt:    now,
		ExpiresAt:    now.Add(time.Hour),
	})
	require.NoError(t, err)
	require.False(t, replayed)
	require.NotNil(t, sent)
	require.Equal(t, "claude-code", sent.FromProvider,
		"precondition: the canonical writer really does persist the provider label")

	syn, err := s.GetPipeSynapses(ctx)
	require.NoError(t, err)
	require.Len(t, syn, 1, "a canonical local send must appear in the connectome, got: %v", syn)
	require.Equal(t, "alice", syn[0].FromAgent)
	require.Equal(t, "bob", syn[0].ToAgent)
	require.Equal(t, int64(1), syn[0].Count)
}

// TestPipeSynapseIndexIsRedefinedAcrossRestarts covers the upgrade hazard the
// way an upgrade actually happens: a persistent database is CLOSED and REOPENED
// so the real open path runs the migrations. Calling migratePipeline directly
// would prove only that the statement executes, not that a v11.18.9 database on
// disk converges when the new binary opens it.
//
// The second reopen is not redundant. CREATE INDEX IF NOT EXISTS is a no-op
// against an index already present under the same name, so an unconditional
// DROP must be shown to be idempotent — a restart must not thrash the index or
// leave it missing.
func TestPipeSynapseIndexIsRedefinedAcrossRestarts(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "upgrade.db")

	indexDDL := func(s *SQLiteStore) string {
		var ddl string
		require.NoError(t, s.conn.QueryRowContext(ctx,
			`SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_pipe_synapse_local'`).Scan(&ddl))
		return ddl
	}

	// 1. Stand up a database and put it in the exact v11.18.9 on-disk state.
	old, err := NewSQLiteStore(ctx, dbPath)
	require.NoError(t, err)
	_, err = old.conn.ExecContext(ctx, `DROP INDEX IF EXISTS idx_pipe_synapse_local`)
	require.NoError(t, err)
	_, err = old.conn.ExecContext(ctx, `CREATE INDEX idx_pipe_synapse_local
		ON pipeline_messages(from_agent, to_agent, created_at)
		WHERE from_agent != '' AND to_agent != '' AND from_provider = '' AND to_provider = ''`)
	require.NoError(t, err)
	require.Contains(t, indexDDL(old), "from_provider", "precondition: the stale index is on disk")
	require.NoError(t, old.Close())

	// 2. Reopen with the current code — this is the upgrade.
	upgraded, err := NewSQLiteStore(ctx, dbPath)
	require.NoError(t, err)
	ddl := indexDDL(upgraded)
	require.Contains(t, ddl, "source_chain_id", "the upgrade must redefine the index")
	require.NotContains(t, ddl, "from_provider", "the stale provider restriction must not survive")

	// The upgraded index must actually serve the query, not merely exist.
	base := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 200; i++ {
		require.NoError(t, upgraded.InsertPipeline(ctx, &PipelineMessage{
			PipeID:    fmt.Sprintf("up-%d", i),
			FromAgent: fmt.Sprintf("agent-%d", i%7),
			ToAgent:   fmt.Sprintf("peer-%d", i%5),
			Payload:   "hi", Status: "pending",
			CreatedAt: base, ExpiresAt: base.Add(time.Hour),
		}))
	}
	rows, err := upgraded.conn.QueryContext(ctx,
		"EXPLAIN QUERY PLAN "+fmt.Sprintf(pipeSynapseAggregation, pipeSynapseIndexHint))
	require.NoError(t, err)
	var plan string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		require.NoError(t, rows.Scan(&id, &parent, &notUsed, &detail))
		plan += detail + "\n"
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	require.Contains(t, plan, "idx_pipe_synapse_local", "upgraded index must serve the query, plan:\n"+plan)
	require.NotContains(t, plan, "TEMP B-TREE", "plan:\n"+plan)
	require.NoError(t, upgraded.Close())

	// 3. Restart again: the unconditional DROP must be idempotent.
	restarted, err := NewSQLiteStore(ctx, dbPath)
	require.NoError(t, err)
	defer restarted.Close() //nolint:errcheck
	ddl2 := indexDDL(restarted)
	require.Equal(t, ddl, ddl2, "a second restart must leave the index definition unchanged")

	syn, err := restarted.GetPipeSynapses(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, syn, "the connectome must still resolve after two restarts")
}
