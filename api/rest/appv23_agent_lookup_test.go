package rest

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/auth"
	"github.com/l33tdawg/sage/internal/store"
)

func addAppV23LookupAgent(
	t *testing.T,
	fixture appV23RESTRouteFixture,
	name, displayName, registeredName, provider string,
	clearance uint8,
	enrolled bool,
) string {
	t.Helper()
	pub, _, err := auth.GenerateKeypair()
	require.NoError(t, err)
	id := auth.PublicKeyToAgentID(pub)
	require.NoError(t, fixture.badger.RegisterAgentWithCapabilities(
		id, displayName, store.AppV23RoleMember, "", provider, "", int64(clearance), 0,
	))
	if enrolled {
		require.NoError(t, fixture.badger.ApproveAppV23LocalAgent(
			store.AppV23LocalEnrollment{
				AgentID: id, ApprovedBy: fixture.ids["current-root"],
				RootGeneration: 2, Profile: store.AppV23ProfileStandard,
				HomeDomain: name + ".home", Clearance: clearance,
				Capabilities: 0, Active: true, UpdatedHeight: 5,
			},
			store.AppV23RoleMember, 0, 0,
		))
	}
	fixture.agents.agents[id] = &store.AgentEntry{
		AgentID: id, Name: displayName, RegisteredName: registeredName,
		Provider: provider, Role: store.AppV23RoleMember,
		Status: "active", Clearance: int(clearance),
	}
	return id
}

func decodeAgentLookup(t *testing.T, rec *httptest.ResponseRecorder) struct {
	Agents []struct {
		AgentID        string `json:"agent_id"`
		Name           string `json:"name"`
		RegisteredName string `json:"registered_name"`
		Provider       string `json:"provider"`
		Status         string `json:"status"`
		MatchKind      string `json:"match_kind"`
	} `json:"agents"`
	Total int `json:"total"`
} {
	t.Helper()
	var response struct {
		Agents []struct {
			AgentID        string `json:"agent_id"`
			Name           string `json:"name"`
			RegisteredName string `json:"registered_name"`
			Provider       string `json:"provider"`
			Status         string `json:"status"`
			MatchKind      string `json:"match_kind"`
		} `json:"agents"`
		Total int `json:"total"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&response))
	return response
}

func TestAppV23AgentLookupIsCallerScopedAndReturnsCanonicalMatches(t *testing.T) {
	fixture := newAppV23RESTRouteFixture(t)
	voiceID := addAppV23LookupAgent(
		t, fixture, "voice", "MYNAH (SAGE Voice Bridge Agent)",
		"SAGE Voice Bridge", "mynah-appliance", 4, true,
	)
	_ = addAppV23LookupAgent(
		t, fixture, "pending-mynah", "MYNAH pending", "pending-mynah",
		"mynah-pending", 1, false,
	)

	// Local pipeline messaging is not a memory disclosure. A lower-clearance
	// active Member may discover a higher-clearance active local recipient;
	// the receiver still acts only under its own authority.
	req := appV23SignedRESTRouteRequest(
		t, fixture, "member", http.MethodGet,
		"/v1/agents/lookup?name=MYNAH&limit=20", nil, false,
	)
	rec := httptest.NewRecorder()
	fixture.server.Router().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	response := decodeAgentLookup(t, rec)
	require.Equal(t, 1, response.Total)
	require.Len(t, response.Agents, 1)
	require.Equal(t, voiceID, response.Agents[0].AgentID)
	require.Equal(t, "substring", response.Agents[0].MatchKind)
	require.Equal(t, "active", response.Agents[0].Status)

	exactReq := appV23SignedRESTRouteRequest(
		t, fixture, "member", http.MethodGet,
		"/v1/agents/lookup?name=MYNAH-APPLIANCE&limit=20", nil, false,
	)
	exactRec := httptest.NewRecorder()
	fixture.server.Router().ServeHTTP(exactRec, exactReq)
	require.Equal(t, http.StatusOK, exactRec.Code, exactRec.Body.String())
	exactResponse := decodeAgentLookup(t, exactRec)
	require.Len(t, exactResponse.Agents, 1)
	require.Equal(t, "exact", exactResponse.Agents[0].MatchKind)

	// SQL discoverability cannot resurrect a consensus-inactive agent.
	inactiveReq := appV23SignedRESTRouteRequest(
		t, fixture, "member", http.MethodGet,
		"/v1/agents/lookup?name=inactive&limit=20", nil, false,
	)
	inactiveRec := httptest.NewRecorder()
	fixture.server.Router().ServeHTTP(inactiveRec, inactiveReq)
	require.Equal(t, http.StatusOK, inactiveRec.Code, inactiveRec.Body.String())
	require.Zero(t, decodeAgentLookup(t, inactiveRec).Total)
}

func TestAppV23AgentLookupRejectsUnknownInactiveAndRootCallers(t *testing.T) {
	fixture := newAppV23RESTRouteFixture(t)
	for _, actor := range []struct {
		name  string
		local bool
	}{
		{name: "inactive"},
		{name: "historical-root", local: true},
		{name: "current-root", local: true},
	} {
		t.Run(actor.name, func(t *testing.T) {
			req := appV23SignedRESTRouteRequest(
				t, fixture, actor.name, http.MethodGet,
				"/v1/agents/lookup?name=member&limit=20", nil, actor.local,
			)
			rec := httptest.NewRecorder()
			fixture.server.Router().ServeHTTP(rec, req)
			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		})
	}

	pub, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	unknownID := auth.PublicKeyToAgentID(pub)
	req := signedRequestAs(
		t, key, unknownID, http.MethodGet,
		"/v1/agents/lookup?name=member&limit=20", nil,
	)
	rec := httptest.NewRecorder()
	fixture.server.Router().ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
}
