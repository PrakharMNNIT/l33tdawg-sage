package web

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/l33tdawg/sage/internal/store"
)

// pipeSynapseProvider is implemented by SQLiteStore to expose the aggregated
// agent-to-agent bus traffic that backs the CEREBRUM connectome view. Optional,
// so a third-party or test store that does not implement it simply yields no
// synapses (an empty connectome) rather than failing the request.
type pipeSynapseProvider interface {
	GetPipeSynapses(ctx context.Context) ([]store.PipeSynapse, error)
}

// synapseNeuron is one agent — a neuron — in the connectome response.
type synapseNeuron struct {
	AgentID string `json:"agent_id"`
	Name    string `json:"name"`
	Role    string `json:"role"`
	// Domain is the agent's domain access, usable to place the neuron in the
	// brain lobe of the domain it mostly works in.
	Domain string `json:"domain,omitempty"`
}

// handleSynapses returns the agent connectome behind the CEREBRUM "agent brain"
// view: neurons (the registered agents) and synapses (directed agent→agent bus
// edges, weighted by message count). It is a pure read-aggregation over the
// pipeline_messages bus and the on-chain agent registry — no consensus surface,
// no ABCI path, nothing written.
//
// RBAC mirrors the memory-graph edge guard: a synapse is returned only when
// BOTH endpoints are visible to the caller, so no edge can reveal an agent the
// caller couldn't otherwise see. A human dashboard (no agent identity) sees all.
func (h *DashboardHandler) handleSynapses(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	allowed, seeAll := h.resolveAgentRBAC(r)
	visible := make(map[string]bool, len(allowed))
	if !seeAll {
		for _, a := range allowed {
			visible[a] = true
		}
	}

	// Neurons: every registered agent the caller may see (including ones that
	// have never fired a synapse yet — a neuron with no connections is still a
	// neuron).
	neurons := []synapseNeuron{}
	if h.BadgerStore != nil {
		if agents, err := h.BadgerStore.ListRegisteredAgents(); err == nil {
			for _, a := range agents {
				if !seeAll && !visible[a.AgentID] {
					continue
				}
				neurons = append(neurons, synapseNeuron{
					AgentID: a.AgentID,
					Name:    a.Name,
					Role:    a.Role,
					Domain:  a.DomainAccess,
				})
			}
		}
	}

	// Synapses: only when the store exposes the aggregation, and only edges with
	// both endpoints visible.
	synapses := []store.PipeSynapse{}
	if provider, ok := h.store.(pipeSynapseProvider); ok {
		edges, err := provider.GetPipeSynapses(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "synapse read failed"})
			return
		}
		for _, e := range edges {
			if !seeAll && (!visible[e.FromAgent] || !visible[e.ToAgent]) {
				continue
			}
			synapses = append(synapses, e)
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"neurons":  neurons,
		"synapses": synapses,
	})
}
