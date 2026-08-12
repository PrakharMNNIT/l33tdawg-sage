package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/stretchr/testify/require"
)

// newSynapseTestHandler wires the on-chain registry the connectome needs. The
// endpoint treats a missing registry as a capability gap rather than an empty
// brain, so every functional test attaches one.
func newSynapseTestHandler(t *testing.T) (*DashboardHandler, *store.SQLiteStore) {
	t.Helper()
	h, s := newTestHandler(t)
	h.BadgerStore = newGrantTestBadger(t)
	return h, s
}

func insertSynapseMessage(t *testing.T, s *store.SQLiteStore, id, from, to string, at time.Time) {
	t.Helper()
	require.NoError(t, s.InsertPipeline(context.Background(), &store.PipelineMessage{
		PipeID: id, FromAgent: from, ToAgent: to,
		Payload: "hi", Status: "pending",
		CreatedAt: at, ExpiresAt: at.Add(time.Hour),
	}))
}

type synapseBody struct {
	Neurons  []synapseNeuron     `json:"neurons"`
	Synapses []store.PipeSynapse `json:"synapses"`
}

func decodeSynapseBody(t *testing.T, rec *httptest.ResponseRecorder) synapseBody {
	t.Helper()
	var body synapseBody
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body
}

// TestHandleSynapses drives the endpoint end to end over an in-memory store: bus
// messages aggregate into directed weighted synapses in the JSON body, and the
// response carries the {neurons, synapses} connectome shape. The caller has no
// agent identity, so it is a human dashboard (seeAll) and no RBAC filtering
// applies.
func TestHandleSynapses(t *testing.T) {
	h, s := newSynapseTestHandler(t)

	base := time.Now().UTC().Truncate(time.Second)
	insertSynapseMessage(t, s, "p1", "alice", "bob", base)
	insertSynapseMessage(t, s, "p2", "alice", "bob", base.Add(time.Minute))
	insertSynapseMessage(t, s, "p3", "bob", "alice", base)

	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/network/synapses", nil)
	rec := httptest.NewRecorder()
	h.handleSynapses(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	body := decodeSynapseBody(t, rec)
	require.NotNil(t, body.Neurons, "neurons is an array, never null")
	require.NotNil(t, body.Synapses, "synapses is an array, never null")

	byEdge := make(map[string]store.PipeSynapse, len(body.Synapses))
	for _, e := range body.Synapses {
		byEdge[e.FromAgent+"|"+e.ToAgent] = e
	}
	require.Len(t, body.Synapses, 2, "two directed synapses")
	require.Equal(t, int64(2), byEdge["alice|bob"].Count, "weight = retained message count")
	require.Equal(t, int64(1), byEdge["bob|alice"].Count)
	require.NotEmpty(t, byEdge["alice|bob"].LastFired)
}

// TestHandleSynapsesFiltersEdgesForRestrictedCaller is the regression test for
// the endpoint's headline security property, which was previously asserted only
// in prose: a synapse is returned ONLY when BOTH endpoints are visible to the
// caller, so no edge can reveal an agent the caller could not otherwise see.
//
// This test is written to FAIL if the edge guard in handleSynapses is deleted.
// Deleting it makes every caller see every synapse, and the caller|hidden and
// visible|hidden assertions below both break. A test that only checked the
// caller's own edge would pass with the guard removed and is worth nothing.
func TestHandleSynapsesFiltersEdgesForRestrictedCaller(t *testing.T) {
	h, s := newSynapseTestHandler(t)

	const (
		caller  = "agent-caller"
		visible = "agent-visible"
		hidden  = "agent-hidden"
	)
	for i, id := range []string{caller, visible, hidden} {
		require.NoError(t, h.BadgerStore.RegisterAgent(id, id, "member", "", "test", "", int64(i+1)))
	}
	// The caller is a member (not admin) whose visibility list names exactly one
	// peer. Anything touching `hidden` must not appear.
	require.NoError(t, h.BadgerStore.SetAgentPermission(
		caller, 1, "", `["`+visible+`"]`, "", ""))

	base := time.Now().UTC().Truncate(time.Second)
	insertSynapseMessage(t, s, "e1", caller, visible, base)   // both visible → kept
	insertSynapseMessage(t, s, "e2", caller, hidden, base)    // to-side hidden → dropped
	insertSynapseMessage(t, s, "e3", hidden, caller, base)    // from-side hidden → dropped
	insertSynapseMessage(t, s, "e4", visible, hidden, base)   // to-side hidden → dropped
	insertSynapseMessage(t, s, "e5", hidden, "agent-x", base) // neither visible → dropped

	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/network/synapses", nil)
	req = req.WithContext(context.WithValue(req.Context(), verifiedDashboardAgentKey{}, caller))
	rec := httptest.NewRecorder()
	h.handleSynapses(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	body := decodeSynapseBody(t, rec)

	edges := make(map[string]bool, len(body.Synapses))
	for _, e := range body.Synapses {
		edges[e.FromAgent+"|"+e.ToAgent] = true
	}

	require.True(t, edges[caller+"|"+visible], "an edge between two visible agents is returned")
	require.Len(t, body.Synapses, 1, "exactly one edge survives the guard, got: %v", edges)

	// The specific leaks the guard exists to prevent. Each of these is returned
	// if the guard is removed.
	require.False(t, edges[caller+"|"+hidden], "edge must not expose a non-visible to_agent")
	require.False(t, edges[hidden+"|"+caller], "edge must not expose a non-visible from_agent")
	require.False(t, edges[visible+"|"+hidden], "edge between visible and hidden must not leak the hidden peer")
	require.False(t, edges[hidden+"|agent-x"], "edge between two non-visible agents must not appear")

	// The neuron list is filtered on the same visibility, so the response never
	// names an agent the caller may not see.
	neurons := make(map[string]bool, len(body.Neurons))
	for _, n := range body.Neurons {
		neurons[n.AgentID] = true
	}
	require.True(t, neurons[caller], "caller always sees itself")
	require.True(t, neurons[visible])
	require.False(t, neurons[hidden], "non-visible agent is not a neuron for this caller")
}

// TestHandleSynapsesReportsMissingRegistry covers the incoherent-response case.
// resolveAgentRBAC returns seeAll for a nil Badger store, which previously
// produced zero neurons beside the FULL edge set — synapses between neurons the
// response never named. Reporting the capability gap is both coherent and
// honest; normal serving cannot reach it, because a nil Badger store is fatal at
// node startup.
func TestHandleSynapsesReportsMissingRegistry(t *testing.T) {
	h, s := newTestHandler(t)
	require.Nil(t, h.BadgerStore, "precondition: no registry attached")

	base := time.Now().UTC().Truncate(time.Second)
	insertSynapseMessage(t, s, "orphan1", "alice", "bob", base)

	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/network/synapses", nil)
	rec := httptest.NewRecorder()
	h.handleSynapses(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)

	body := decodeSynapseBody(t, rec)
	require.Empty(t, body.Synapses, "no orphan edges without the neurons that name them")
	require.Empty(t, body.Neurons)
}

// TestHandleSynapsesFailsLoudlyWhenRegistryUnreadable pins the failure semantics
// that matter most on a dashboard: a registry read error must not render as a
// legitimately empty brain. Swallowing the error returns an empty neuron list,
// which is indistinguishable from "no agents are registered" — the same
// capability-gap-as-zero failure class the bus probe work exists to prevent.
func TestHandleSynapsesFailsLoudlyWhenRegistryUnreadable(t *testing.T) {
	h, s := newTestHandler(t)

	// A closed Badger store is the simplest reproduction of an unreadable
	// registry. Closed here rather than via t.Cleanup so it is not closed twice.
	badgerStore, err := store.NewBadgerStore(filepath.Join(t.TempDir(), "badger"))
	require.NoError(t, err)
	require.NoError(t, badgerStore.CloseBadger())
	h.BadgerStore = badgerStore

	_, listErr := badgerStore.ListRegisteredAgents()
	require.Error(t, listErr, "precondition: the registry read genuinely fails")

	base := time.Now().UTC().Truncate(time.Second)
	insertSynapseMessage(t, s, "loud1", "alice", "bob", base)

	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/network/synapses", nil)
	rec := httptest.NewRecorder()
	h.handleSynapses(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code,
		"an unreadable registry must be a loud failure, not an empty brain")

	body := decodeSynapseBody(t, rec)
	require.Empty(t, body.Neurons)
	require.Empty(t, body.Synapses)
}
