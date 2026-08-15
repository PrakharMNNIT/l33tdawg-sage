package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/stretchr/testify/require"
)

// seedCorroboration records that agentID corroborated memID, the off-chain
// corroborations table the distributed-engram disclosure reads (the same table
// GetCorroborationCounts already tallies for corroboration_count).
func seedCorroboration(t *testing.T, s *store.SQLiteStore, memID, agentID string, at time.Time) {
	t.Helper()
	require.NoError(t, s.InsertCorroboration(context.Background(), &store.Corroboration{
		MemoryID: memID, AgentID: agentID, CreatedAt: at,
	}))
}

// TestHandleEngramsDisclosesVisibleCorroboratorsOnly is the headline security
// property of the distributed engram: a memory's corroborators are bridged to
// their neurons, but ONLY the corroborators the caller is cleared to see — under
// exactly the both-endpoints rule the connectome synapse guard applies. A
// corroborator the caller cannot see, and a corroborator that is not a registered
// neuron, are never named; they survive only inside the true corroboration_count
// as the anonymous remainder the view renders as "+N held elsewhere".
//
// Written to FAIL if either half of the guard is removed: dropping the RBAC
// (!seeAll && !visible[id]) check leaks the hidden peer; dropping the neuronSet
// intersection leaks the non-neuron corroborator.
func TestHandleEngramsDisclosesVisibleCorroboratorsOnly(t *testing.T) {
	h, s := newSynapseTestHandler(t) // wires the on-chain neuron registry

	const (
		author   = "alice"
		cVisible = "bob"   // a neuron alice may see → bridged
		cHidden  = "carol" // a neuron alice may NOT see → count-only
		cExtern  = "ext-x" // corroborated but never a registered neuron → count-only
	)
	for i, id := range []string{author, cVisible, cHidden} {
		require.NoError(t, h.BadgerStore.RegisterAgent(id, id, "member", "", "test", "", int64(i+1)))
	}
	// alice is a member whose visibility list names exactly bob. carol is hidden.
	require.NoError(t, h.BadgerStore.SetAgentPermission(author, 1, "", `["`+cVisible+`"]`, "", ""))

	base := time.Now().UTC().Truncate(time.Second)
	seedEngramMemory(t, s, "m1", author, "a shared fact", "ops", 0.9, memory.StatusCommitted)
	seedCorroboration(t, s, "m1", cVisible, base)
	seedCorroboration(t, s, "m1", cHidden, base.Add(time.Second))
	seedCorroboration(t, s, "m1", cExtern, base.Add(2*time.Second))

	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/memory/engrams?agent="+author, nil)
	req = req.WithContext(context.WithValue(req.Context(), verifiedDashboardAgentKey{}, author))
	rec := httptest.NewRecorder()
	h.handleEngrams(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var body struct {
		Engrams []engramNode `json:"engrams"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Engrams, 1)
	e := body.Engrams[0]

	require.Equal(t, 3, e.CorroborationCount, "the true total counts every corroborator, seen or not")
	require.Equal(t, []string{cVisible}, e.Corroborators,
		"only a corroborator that is BOTH a neuron AND visible to the caller is disclosed")
	require.NotContains(t, e.Corroborators, cHidden, "a corroborator the caller may not see must never be named")
	require.NotContains(t, e.Corroborators, cExtern, "a non-neuron corroborator must never be named")
}

// TestHandleEngramsDisclosesAllNeuronCorroboratorsForHumanDashboard: a human
// dashboard (no agent identity → seeAll) bridges every corroborating NEURON, so
// the distributed engram renders in full — but a corroborator that is not a
// registered neuron is STILL never named, because the neuron registry is the
// connectome's disclosure boundary. seeAll relaxes RBAC, not the neuron gate.
func TestHandleEngramsDisclosesAllNeuronCorroboratorsForHumanDashboard(t *testing.T) {
	h, s := newSynapseTestHandler(t)

	const author, cA, cB, cExtern = "alice", "bob", "carol", "ext-x"
	for i, id := range []string{author, cA, cB} {
		require.NoError(t, h.BadgerStore.RegisterAgent(id, id, "member", "", "test", "", int64(i+1)))
	}
	base := time.Now().UTC().Truncate(time.Second)
	seedEngramMemory(t, s, "m1", author, "a widely shared fact", "ops", 0.9, memory.StatusCommitted)
	seedCorroboration(t, s, "m1", cA, base)
	seedCorroboration(t, s, "m1", cB, base.Add(time.Second))
	seedCorroboration(t, s, "m1", cExtern, base.Add(2*time.Second))

	// No verified agent → human dashboard, seeAll.
	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/memory/engrams?agent="+author, nil)
	rec := httptest.NewRecorder()
	h.handleEngrams(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var body struct {
		Engrams []engramNode `json:"engrams"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Engrams, 1)
	e := body.Engrams[0]

	require.Equal(t, 3, e.CorroborationCount)
	require.ElementsMatch(t, []string{cA, cB}, e.Corroborators,
		"a human dashboard bridges every corroborating neuron")
	require.NotContains(t, e.Corroborators, cExtern,
		"even seeAll never names a non-neuron corroborator — the neuron registry is the boundary")
}

// TestHandleEngramsWithholdsCorroboratorsWithoutRegistry: with no neuron registry
// we cannot confirm a corroborator is an already-visible neuron, so we disclose
// NONE rather than risk naming an unconfirmed identity. The count is unaffected,
// so the lobe still conveys that the memory is distributed — it just cannot draw
// the bridges. This is the fail-closed degradation, not a functional path (a nil
// Badger store is fatal at node startup).
func TestHandleEngramsWithholdsCorroboratorsWithoutRegistry(t *testing.T) {
	h, s := newTestHandler(t) // no BadgerStore
	require.Nil(t, h.BadgerStore, "precondition: no registry attached")

	base := time.Now().UTC().Truncate(time.Second)
	seedEngramMemory(t, s, "m1", "alice", "a fact", "ops", 0.9, memory.StatusCommitted)
	seedCorroboration(t, s, "m1", "bob", base)

	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/memory/engrams?agent=alice", nil)
	rec := httptest.NewRecorder()
	h.handleEngrams(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var body struct {
		Engrams []engramNode `json:"engrams"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Engrams, 1)
	require.Equal(t, 1, body.Engrams[0].CorroborationCount, "the count still reflects the corroboration")
	require.Empty(t, body.Engrams[0].Corroborators,
		"without a registry to confirm neuron membership, no corroborator is named")
}

// TestHandleEngramsCapsCorroboratorBridges: a memory corroborated by more neurons
// than the bridge cap discloses at most engramCorroboratorLimit — the bridges
// illustrate distribution, they are not an exhaustive dump — while the count still
// carries the true total.
func TestHandleEngramsCapsCorroboratorBridges(t *testing.T) {
	h, s := newSynapseTestHandler(t)

	const author = "alice"
	require.NoError(t, h.BadgerStore.RegisterAgent(author, author, "member", "", "test", "", 1))
	base := time.Now().UTC().Truncate(time.Second)
	seedEngramMemory(t, s, "m1", author, "a very widely held fact", "ops", 0.9, memory.StatusCommitted)

	total := engramCorroboratorLimit + 5
	for i := 0; i < total; i++ {
		id := "corr-" + string(rune('a'+i))
		require.NoError(t, h.BadgerStore.RegisterAgent(id, id, "member", "", "test", "", int64(i+2)))
		seedCorroboration(t, s, "m1", id, base.Add(time.Duration(i)*time.Second))
	}

	// Human dashboard so every corroborator is RBAC-visible; the cap is the only bound.
	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/memory/engrams?agent="+author, nil)
	rec := httptest.NewRecorder()
	h.handleEngrams(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var body struct {
		Engrams []engramNode `json:"engrams"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Engrams, 1)
	require.Equal(t, total, body.Engrams[0].CorroborationCount, "count is the true total")
	require.Len(t, body.Engrams[0].Corroborators, engramCorroboratorLimit,
		"bridges are capped; the remainder survives only in the count")
}
