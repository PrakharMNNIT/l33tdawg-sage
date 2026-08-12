package store

import (
	"context"
	"fmt"
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
	fed := mk("p5", "alice", "remote", base)
	fed.ToProvider = "other-chain" // cross-chain → not part of the local connectome
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
