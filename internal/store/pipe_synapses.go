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
	// Count is the number of CURRENTLY RETAINED local message rows on this
	// directed edge — the raw synaptic weight. It is deliberately not a
	// lifetime counter, because the underlying rows do not share one retention
	// lifetime: terminal legacy pipe rows are pruned past a cutoff, while
	// canonical `msg-` messages are exempt from that pruning. So two edges
	// reporting the same weight may summarise different spans of history
	// depending on which transport produced them. Treat it as "retained
	// traffic", never as "messages ever sent".
	//
	// Time-decay ("use it or lose it") is left to the client, which has
	// LastFired to age the weight against a chosen half-life.
	Count int64 `json:"count"`
	// LastFired is the created_at (RFC3339) of the most recent retained message
	// on the edge — when the synapse last transmitted, as far as retained rows
	// can still attest.
	LastFired string `json:"last_fired"`
}

// pipeSynapseAggregation is the connectome aggregation. The restriction is kept
// byte-identical to the partial index idx_pipe_synapse_local: SQLite uses a
// partial index only when the query restriction matches the index restriction,
// so editing one without the other silently drops back to a full scan with a
// temp b-tree for the GROUP BY.
//
// The %s slot carries an INDEXED BY hint. It is needed rather than decorative:
// SAGE never runs ANALYZE or PRAGMA optimize, so sqlite_stat1 does not exist on
// a production node, and without statistics the planner prefers a seek on
// idx_pipe_to_provider (to_provider=”) — which matches nearly every local row —
// and then sorts through a temp b-tree. Measured on an unanalysed database the
// hint is the difference between that and a covering index-order scan.
const pipeSynapseAggregation = `
	SELECT from_agent, to_agent, COUNT(*), MAX(created_at)
	FROM pipeline_messages %s
	WHERE from_agent != '' AND to_agent != ''
	  AND source_chain_id = '' AND destination_chain_id = ''
	GROUP BY from_agent, to_agent`

const pipeSynapseIndexHint = "INDEXED BY idx_pipe_synapse_local"

// GetPipeSynapses aggregates local agent-to-agent bus traffic into a directed
// weighted adjacency list: one row per (from_agent, to_agent) pair with a
// retained-message count and the most-recent timestamp. Federated (cross-chain)
// rows are excluded; this is the local connectome. Pure read; touches no
// consensus state.
//
// LOCALITY IS KEYED ON THE CHAIN IDS, NOT ON THE PROVIDER, and the distinction
// is not cosmetic. from_provider/to_provider hold the AGENT'S PROVIDER LABEL —
// SAGE_PROVIDER flows from the generated MCP launcher into agent registration
// and is stamped onto every send — so "claude-code" or "codex" appears on
// ordinary LOCAL traffic. Restricting on empty providers therefore excluded
// almost every real local edge: on a live node it returned 3 of 30 edges and
// hid 359 of 363 local rows. source_chain_id/destination_chain_id are the
// fields that actually denote a cross-chain row, and both are NOT NULL
// DEFAULT ”, so the comparison has no NULL-semantics trap.
func (s *SQLiteStore) GetPipeSynapses(ctx context.Context) ([]PipeSynapse, error) {
	// migratePipeline creates indexes best-effort and discards the error, so the
	// hint must not become a hard dependency: an INDEXED BY naming an absent
	// index is a query error, and a slower connectome beats a broken one. The
	// fallback keeps identical semantics because only the hint differs.
	rows, err := s.conn.QueryContext(ctx, fmt.Sprintf(pipeSynapseAggregation, pipeSynapseIndexHint))
	if err != nil {
		rows, err = s.conn.QueryContext(ctx, fmt.Sprintf(pipeSynapseAggregation, ""))
	}
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
