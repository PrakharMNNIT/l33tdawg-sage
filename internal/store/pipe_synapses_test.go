package store

import (
	"context"
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
