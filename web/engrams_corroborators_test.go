package web

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/stretchr/testify/require"
)

type failingBoundedEngramStore struct {
	store.MemoryStore
	calls  int
	limits []int
}

func TestAppV23ConnectomeAndEngramBridgesExcludeInactiveAndPendingAgents(t *testing.T) {
	fixture := newAppV23AccessFixture(t)
	h, sqlStore := newTestHandler(t)
	h.BadgerStore = fixture.badger

	registerPending := func(name string, height int64) string {
		_, key, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		agentID := agentIDForKey(key)
		require.NoError(t, fixture.badger.RegisterAgentWithCapabilities(
			agentID, name, store.AppV23RoleMember, "connectome test", "test", "", height,
			store.DefaultSelfRegisteredAgentCapabilities,
		))
		return agentID
	}
	activate := func(agentID, home string, height int64) {
		require.NoError(t, fixture.badger.ApproveAppV23LocalAgent(
			store.AppV23LocalEnrollment{
				AgentID: agentID, ApprovedBy: fixture.rootID, RootGeneration: 1,
				Profile: store.AppV23ProfileStandard, HomeDomain: home,
				Clearance: 1, Capabilities: 0, Active: true, UpdatedHeight: height,
			},
			store.AppV23RoleMember, 0, 0,
		))
	}

	activePeer := registerPending("Active peer", 2)
	activate(activePeer, "active-peer-home", 3)
	inactivePeer := registerPending("Removed peer", 4)
	activate(inactivePeer, "removed-peer-home", 5)
	inactiveEnrollment, err := fixture.badger.GetAppV23Enrollment(inactivePeer)
	require.NoError(t, err)
	inactiveRole, err := fixture.badger.GetAppV23Role(inactivePeer)
	require.NoError(t, err)
	require.NoError(t, fixture.badger.ApproveAppV23LocalAgent(
		store.AppV23LocalEnrollment{
			AgentID: inactivePeer, ApprovedBy: fixture.rootID, RootGeneration: 1,
			Profile: inactiveEnrollment.Profile, HomeDomain: inactiveEnrollment.HomeDomain,
			Clearance: inactiveEnrollment.Clearance, Capabilities: inactiveEnrollment.Capabilities,
			Active: false, UpdatedHeight: 6, RetireOwnedDomainsToRoot: true,
		},
		inactiveRole.Role, inactiveEnrollment.Revision, inactiveRole.Revision,
	))
	pendingPeer := registerPending("Pending peer", 7)

	base := time.Now().UTC().Truncate(time.Second)
	insertSynapseMessage(t, sqlStore, "active-edge", fixture.agentID, activePeer, base)
	insertSynapseMessage(t, sqlStore, "inactive-edge", fixture.agentID, inactivePeer, base.Add(time.Second))
	insertSynapseMessage(t, sqlStore, "pending-edge", fixture.agentID, pendingPeer, base.Add(2*time.Second))

	synapseRec := httptest.NewRecorder()
	h.handleSynapses(synapseRec, httptest.NewRequest(http.MethodGet, "/v1/dashboard/network/synapses", nil))
	require.Equal(t, http.StatusOK, synapseRec.Code, synapseRec.Body.String())
	connectome := decodeSynapseBody(t, synapseRec)
	neurons := make(map[string]bool, len(connectome.Neurons))
	for _, neuron := range connectome.Neurons {
		neurons[neuron.AgentID] = true
	}
	require.True(t, neurons[fixture.agentID])
	require.True(t, neurons[activePeer])
	require.False(t, neurons[inactivePeer], "a removed enrollment is historical, not a current neuron")
	require.False(t, neurons[pendingPeer], "a pending registration is not a current neuron")
	require.False(t, neurons[fixture.rootID], "CEREBRUM Root is not an ordinary Connectome neuron")
	require.Len(t, connectome.Synapses, 1, "edges touching non-current neurons must be omitted")
	require.Equal(t, activePeer, connectome.Synapses[0].ToAgent)

	seedEngramMemory(t, sqlStore, "active-memory", fixture.agentID, "historical evidence", "ops", 0.9, memory.StatusCommitted)
	seedCorroboration(t, sqlStore, "active-memory", activePeer, base)
	seedCorroboration(t, sqlStore, "active-memory", inactivePeer, base.Add(time.Second))
	seedCorroboration(t, sqlStore, "active-memory", pendingPeer, base.Add(2*time.Second))
	engramRec := httptest.NewRecorder()
	h.handleEngrams(engramRec, httptest.NewRequest(
		http.MethodGet, "/v1/dashboard/memory/engrams?agent="+fixture.agentID, nil,
	))
	require.Equal(t, http.StatusOK, engramRec.Code, engramRec.Body.String())
	var engrams struct {
		Engrams []engramNode `json:"engrams"`
	}
	require.NoError(t, json.Unmarshal(engramRec.Body.Bytes(), &engrams))
	require.Len(t, engrams.Engrams, 1)
	require.Equal(t, 3, engrams.Engrams[0].CorroborationCount,
		"historical distinct evidence remains counted")
	require.Equal(t, []string{activePeer}, engrams.Engrams[0].Corroborators,
		"only current rendered neurons may be named as bridge endpoints")
}

func (s *failingBoundedEngramStore) GetCorroborationsBounded(_ context.Context, _ string, limit int) ([]*store.Corroboration, error) {
	s.calls++
	s.limits = append(s.limits, limit)
	return nil, errors.New("bounded corroboration read unavailable")
}

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

// Bridge eligibility follows the actual Connectome projection, not an unrelated
// node-local activity/status table. A registered neuron with no retained traffic
// is dormant but still rendered, so historical corroboration may bridge to it.
func TestHandleEngramBridgeEndpointsMatchRenderedConnectomeNeurons(t *testing.T) {
	h, s := newSynapseTestHandler(t)
	for i, id := range []string{"alice", "bob"} {
		require.NoError(t, h.BadgerStore.RegisterAgent(id, id, "member", "", "test", "", int64(i+1)))
	}
	seedEngramMemory(t, s, "m1", "alice", "a shared fact", "ops", 0.9, memory.StatusCommitted)
	seedCorroboration(t, s, "m1", "bob", time.Now().UTC())

	synapseRec := httptest.NewRecorder()
	h.handleSynapses(synapseRec, httptest.NewRequest(http.MethodGet, "/v1/dashboard/network/synapses", nil))
	require.Equal(t, http.StatusOK, synapseRec.Code, synapseRec.Body.String())
	connectome := decodeSynapseBody(t, synapseRec)
	rendered := make(map[string]bool, len(connectome.Neurons))
	for _, neuron := range connectome.Neurons {
		rendered[neuron.AgentID] = true
	}
	require.True(t, rendered["bob"], "a registered zero-traffic neuron remains visible as dormant")

	engramRec := httptest.NewRecorder()
	h.handleEngrams(engramRec, httptest.NewRequest(http.MethodGet, "/v1/dashboard/memory/engrams?agent=alice", nil))
	require.Equal(t, http.StatusOK, engramRec.Code, engramRec.Body.String())
	var body struct {
		Engrams []engramNode `json:"engrams"`
	}
	require.NoError(t, json.Unmarshal(engramRec.Body.Bytes(), &body))
	require.Len(t, body.Engrams, 1)
	require.Equal(t, []string{"bob"}, body.Engrams[0].Corroborators)
	for _, agentID := range body.Engrams[0].Corroborators {
		require.True(t, rendered[agentID], "every bridge endpoint must exist in the rendered Connectome")
	}
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

// A bounded per-engram identity read is optional and fail-closed. The separately
// batched total remains useful, but a store error must never trigger the legacy
// unbounded fallback or disclose an identity from a partial result.
func TestHandleEngramsWithholdsCorroboratorsWhenBoundedReadFails(t *testing.T) {
	h, s := newSynapseTestHandler(t)
	require.NoError(t, h.BadgerStore.RegisterAgent("alice", "alice", "member", "", "test", "", 1))
	require.NoError(t, h.BadgerStore.RegisterAgent("bob", "bob", "member", "", "test", "", 2))
	seedEngramMemory(t, s, "m1", "alice", "a fact", "ops", 0.9, memory.StatusCommitted)
	seedCorroboration(t, s, "m1", "bob", time.Now().UTC())

	wrapped := &failingBoundedEngramStore{MemoryStore: h.store}
	h.store = wrapped
	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/memory/engrams?agent=alice", nil)
	rec := httptest.NewRecorder()
	h.handleEngrams(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var body struct {
		Engrams []engramNode `json:"engrams"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Engrams, 1)
	require.Equal(t, 1, body.Engrams[0].CorroborationCount)
	require.Empty(t, body.Engrams[0].Corroborators)
	require.Equal(t, 1, wrapped.calls)
	require.Equal(t, []int{engramCorroboratorScanLimit}, wrapped.limits,
		"the handler must request the fixed raw-row cap")
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
