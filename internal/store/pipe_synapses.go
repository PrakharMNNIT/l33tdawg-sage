package store

import (
	"context"
	"fmt"
)

// PipeSynapse is one directed agent→agent communication edge, aggregated from
// the pipeline_messages bus. In the CEREBRUM connectome view each agent is a
// neuron and each of these edges is a synapse whose weight is its traffic.
type PipeSynapse struct {
	FromAgent string `json:"from_agent"`
	ToAgent   string `json:"to_agent"`
	// Count is the total number of messages ever sent on this directed edge —
	// the raw synaptic weight. Time-decay ("use it or lose it") is left to the
	// client, which has LastFired to age it against a chosen half-life.
	Count int64 `json:"count"`
	// LastFired is the created_at (RFC3339) of the most recent message on the
	// edge — when the synapse last transmitted.
	LastFired string `json:"last_fired"`
}

// GetPipeSynapses aggregates local agent-to-agent bus traffic into a directed
// weighted adjacency list: one row per (from_agent, to_agent) pair with a
// message count and the most-recent timestamp. Federated (cross-chain) rows —
// which carry a from_provider/to_provider or an empty local agent — are
// excluded; this is the local connectome. Pure read; touches no consensus state.
func (s *SQLiteStore) GetPipeSynapses(ctx context.Context) ([]PipeSynapse, error) {
	rows, err := s.conn.QueryContext(ctx, `
		SELECT from_agent, to_agent, COUNT(*), MAX(created_at)
		FROM pipeline_messages
		WHERE from_agent != '' AND to_agent != ''
		  AND from_provider = '' AND to_provider = ''
		GROUP BY from_agent, to_agent`)
	if err != nil {
		return nil, fmt.Errorf("get pipe synapses: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var synapses []PipeSynapse
	for rows.Next() {
		var syn PipeSynapse
		if scanErr := rows.Scan(&syn.FromAgent, &syn.ToAgent, &syn.Count, &syn.LastFired); scanErr != nil {
			return nil, fmt.Errorf("scan pipe synapse: %w", scanErr)
		}
		synapses = append(synapses, syn)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("iterate pipe synapses: %w", rowsErr)
	}
	return synapses, nil
}
