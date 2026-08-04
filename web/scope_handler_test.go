package web

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/scope"
	"github.com/l33tdawg/sage/internal/store"
)

func TestDashboardScopeProjectionUsesLocalOperatorBoundary(t *testing.T) {
	h, _ := newTestHandler(t)
	badgerStore, err := store.NewBadgerStore(filepath.Join(t.TempDir(), "badger"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, badgerStore.CloseBadger()) })
	h.BadgerStore = badgerStore

	record := scope.Record{
		ScopeID: "scope-a", Revision: 1, State: scope.StateActive,
		ControllerValidatorID: "validator-a", CreatedHeight: 10, UpdatedHeight: 10,
		Domains: []scope.Domain{{Name: "research"}},
		Members: []scope.Member{{
			ValidatorID: "validator-a", AssignedWeight: 7,
			JoinedRevision: 1, Active: true,
		}},
	}
	require.NoError(t, badgerStore.SetScopeRecord(record))
	contentHash := sha256.Sum256([]byte("pending scoped memory"))
	require.NoError(t, badgerStore.SetScopedMemorySubmission(scope.Ballot{
		MemoryID: "memory-a", ScopeID: "scope-a", ScopeRevision: 1,
		SubmittedHeight: 11, State: scope.BallotPending,
		Members:     []scope.BallotMember{{ValidatorID: "validator-a", EffectiveWeight: 7}},
		TotalWeight: 7,
	}, scope.Content{
		MemoryID: "memory-a", ScopeID: "scope-a", ScopeRevision: 1,
		SubmittingAgentID: "agent-a", ContentHash: contentHash[:],
		MemoryType: 1, Domain: "research", ConfidenceScore: 0.9,
		Content: "pending scoped memory", SubmittedHeight: 11, SubmittedUnix: 100,
	}))
	router := testRouter(h)

	localReq := httptest.NewRequest(http.MethodGet, "/v1/dashboard/chain/scopes", nil)
	markLocalCEREBRUM(h, localReq)
	local := httptest.NewRecorder()
	router.ServeHTTP(local, localReq)
	require.Equal(t, http.StatusOK, local.Code, local.Body.String())
	var response struct {
		Scopes []dashboardScopeRecordResponse `json:"scopes"`
		Count  int                            `json:"count"`
	}
	require.NoError(t, json.Unmarshal(local.Body.Bytes(), &response))
	require.Equal(t, 1, response.Count)
	require.Len(t, response.Scopes, 1)
	assert.Equal(t, "scope-a", response.Scopes[0].ScopeID)
	assert.Len(t, response.Scopes[0].RevisionHash, 64)
	assert.Equal(t, []string{"memory-a"}, response.Scopes[0].Drain.PendingMemoryIDs)
	assert.Equal(t, []string{"validator-a"}, response.Scopes[0].Drain.BlockingValidatorIDs)

	remoteReq := httptest.NewRequest(http.MethodGet, "/v1/dashboard/chain/scopes", nil)
	remoteReq.RemoteAddr = "192.0.2.20:54321"
	remoteReq.Host = "192.0.2.10:8080"
	remote := httptest.NewRecorder()
	router.ServeHTTP(remote, remoteReq)
	assert.Equal(t, http.StatusUnauthorized, remote.Code)
}

func TestConsensusUIUsesDashboardScopeProjection(t *testing.T) {
	apiBytes, err := os.ReadFile("static/js/api.js")
	require.NoError(t, err)
	api := string(apiBytes)

	assert.Contains(t, api, "`${API_BASE}/v1/dashboard/chain/scopes`")
	assert.NotContains(t, api, "`${API_BASE}/v1/scopes`")
	assert.Equal(t, 1, strings.Count(api, "/v1/dashboard/chain/scopes"))
}
