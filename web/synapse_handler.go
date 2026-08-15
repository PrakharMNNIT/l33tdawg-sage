package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
// edges, weighted by retained message count). It is a pure read-aggregation over
// the pipeline_messages bus and the on-chain agent registry — no consensus
// surface, no ABCI path, nothing written.
//
// RBAC mirrors the memory-graph edge guard: a synapse is returned only when
// BOTH endpoints are visible to the caller, so no edge can reveal an agent the
// caller couldn't otherwise see. A human dashboard (no agent identity) sees all.
//
// Both registry failure modes report the capability gap rather than serving a
// partial connectome. An empty neuron list beside a populated edge set would
// describe synapses between neurons the response never named, and — worse — an
// unreadable registry would be indistinguishable from a node where nothing has
// registered yet. "Cannot read" must never render as a legitimately empty brain.
func (h *DashboardHandler) handleSynapses(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// The registry is what makes an edge interpretable, so it is a precondition
	// for the whole response, not just for the neuron half. Normal serving
	// cannot reach this branch: a nil Badger store is fatal at node startup.
	if h.BadgerStore == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "agent registry unavailable"})
		return
	}

	agents, err := listCurrentConnectomeAgents(h.BadgerStore)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "neuron read failed"})
		return
	}
	currentNeurons := make(map[string]bool, len(agents))
	for _, agent := range agents {
		currentNeurons[agent.AgentID] = true
	}

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

	// Synapses: only when the store exposes the aggregation, and only edges with
	// both endpoints visible.
	synapses := []store.PipeSynapse{}
	if provider, ok := h.store.(pipeSynapseProvider); ok {
		edges, edgesErr := provider.GetPipeSynapses(r.Context())
		if edgesErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "synapse read failed"})
			return
		}
		for _, e := range edges {
			if !currentNeurons[e.FromAgent] || !currentNeurons[e.ToAgent] {
				continue
			}
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

// listCurrentConnectomeAgents keeps the immutable registration ledger separate
// from the current app-v23 serving roster. Before app-v23 activation every
// registration remains a neuron for compatibility. Once a Root exists, only a
// complete, active ordinary enrollment may render; pending, removed, and any
// current or retired Root credential stay outside both the neuron list and the
// distributed-engram bridge boundary.
func listCurrentConnectomeAgents(badgerStore *store.BadgerStore) ([]store.OnChainAgent, error) {
	agents, err := badgerStore.ListRegisteredAgents()
	if err != nil {
		return nil, err
	}
	root, err := badgerStore.GetAppV23Root()
	if err != nil {
		return nil, err
	}
	if root == nil {
		return agents, nil
	}

	active := make([]store.OnChainAgent, 0, len(agents))
	for _, agent := range agents {
		wasRoot, rootErr := badgerStore.IsAppV23RootCredential(agent.AgentID)
		if rootErr != nil {
			return nil, rootErr
		}
		if wasRoot || agent.AgentID == root.PrincipalID || agent.AgentID == root.CredentialID {
			continue
		}
		enrollment, enrollmentErr := badgerStore.GetAppV23Enrollment(agent.AgentID)
		role, roleErr := badgerStore.GetAppV23Role(agent.AgentID)
		if enrollmentErr != nil || roleErr != nil {
			return nil, errors.Join(enrollmentErr, roleErr)
		}
		// A post-activation self-registration remains pending until Root review.
		if enrollment == nil && role == nil {
			continue
		}
		if enrollment == nil || role == nil ||
			enrollment.AgentID != agent.AgentID || role.AgentID != agent.AgentID {
			return nil, fmt.Errorf("incomplete app-v23 Connectome policy for agent %s", agent.AgentID)
		}
		if !enrollment.Active {
			continue
		}
		if err := store.ValidateAppV23EnrollmentPolicy(
			role.Role, enrollment.Profile, enrollment.Capabilities,
			enrollment.Clearance, enrollment.Active,
		); err != nil {
			return nil, fmt.Errorf("invalid app-v23 Connectome policy for agent %s: %w", agent.AgentID, err)
		}
		active = append(active, agent)
	}
	return active, nil
}
