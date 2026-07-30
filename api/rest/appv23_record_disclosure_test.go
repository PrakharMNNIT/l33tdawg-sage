package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/api/rest/middleware"
	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
)

func appV23DisclosureFixture(
	t *testing.T,
) (*Server, *rbacMockMemoryStore, *store.BadgerStore, *mockAgentStore, string, string, string) {
	t.Helper()
	srv, badger, readerID, ownerID, outsiderID := setupAppV23RESTAccess(t)
	memStore := srv.store.(*rbacMockMemoryStore)
	agents := srv.agentStore.(*mockAgentStore)
	agents.agents[readerID] = &store.AgentEntry{
		AgentID: readerID, Name: "reader", Role: store.AppV23RoleMember,
		Status: "active", Clearance: 2,
	}
	return srv, memStore, badger, agents, readerID, ownerID, outsiderID
}

func appV23DisclosureRequest(
	agentID, method, path string,
	body []byte,
) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	return req.WithContext(middleware.WithAgentID(req.Context(), agentID))
}

func publishAppV23RESTRecord(
	t *testing.T,
	badger *store.BadgerStore,
	record *memory.MemoryRecord,
	classification uint8,
) {
	t.Helper()
	require.NotNil(t, record)
	if len(record.ContentHash) == 0 {
		record.ContentHash = memory.ComputeContentHash(record.Content)
	}
	require.NoError(t, badger.SetMemoryHash(
		record.MemoryID, record.ContentHash, string(record.Status),
	))
	require.NoError(t, badger.SetMemoryDomain(record.MemoryID, record.DomainTag))
	require.NoError(t, badger.SetMemoryAuthor(record.MemoryID, record.SubmittingAgent))
	require.NoError(t, badger.SetMemoryClassification(record.MemoryID, classification))
}

func TestAppV23SelfAuthorshipDoesNotSurviveGroupRevocationAcrossRecordRoutes(t *testing.T) {
	srv, memStore, badger, _, readerID, ownerID, _ := appV23DisclosureFixture(t)
	secret := "revoked self-authored secret"
	seedMemory(t, memStore, "revoked-self", readerID, "owner.home", secret)
	rec := memStore.memories["revoked-self"]
	rec.MemoryType = memory.TypeTask
	rec.TaskStatus = memory.TaskStatusPlanned
	rec.Assignee = readerID
	require.NoError(t, badger.SetMemoryClassification(rec.MemoryID, 1))
	memStore.pendingRecords = []*memory.MemoryRecord{rec}

	before, err := srv.evaluateAppV23RecordDisclosure(readerID, rec, time.Now())
	require.NoError(t, err)
	require.True(t, before.Allowed)

	require.NoError(t, badger.MutateAppV23AccessGroup(
		appV23RESTAgentID("11"),
		"local-team",
		"Local team",
		[]string{ownerID},
		1,
		false,
		4,
	))

	type routeCase struct {
		name string
		run  func() *httptest.ResponseRecorder
	}
	routes := []routeCase{
		{
			name: "query",
			run: func() *httptest.ResponseRecorder {
				req := appV23DisclosureRequest(
					readerID, http.MethodPost, "/v1/memory/query",
					[]byte(`{"embedding":[0.1,0.2,0.3],"top_k":10}`),
				)
				out := httptest.NewRecorder()
				srv.handleQueryMemory(out, req)
				return out
			},
		},
		{
			name: "search",
			run: func() *httptest.ResponseRecorder {
				req := appV23DisclosureRequest(
					readerID, http.MethodPost, "/v1/memory/search",
					[]byte(`{"query":"revoked","top_k":10}`),
				)
				out := httptest.NewRecorder()
				srv.handleSearchMemory(out, req)
				return out
			},
		},
		{
			name: "hybrid",
			run: func() *httptest.ResponseRecorder {
				req := appV23DisclosureRequest(
					readerID, http.MethodPost, "/v1/memory/hybrid",
					[]byte(`{"query":"revoked","embedding":[0.1,0.2,0.3],"top_k":10}`),
				)
				out := httptest.NewRecorder()
				srv.handleHybridSearchMemory(out, req)
				return out
			},
		},
		{
			name: "detail",
			run: func() *httptest.ResponseRecorder {
				req := appV23DisclosureRequest(
					readerID, http.MethodGet, "/v1/memory/revoked-self", nil,
				)
				route := chi.NewRouteContext()
				route.URLParams.Add("memory_id", "revoked-self")
				req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
				out := httptest.NewRecorder()
				srv.handleGetMemory(out, req)
				return out
			},
		},
		{
			name: "tasks",
			run: func() *httptest.ResponseRecorder {
				req := appV23DisclosureRequest(
					readerID, http.MethodGet, "/v1/memory/tasks", nil,
				)
				out := httptest.NewRecorder()
				srv.handleGetOpenTasks(out, req)
				return out
			},
		},
		{
			name: "list",
			run: func() *httptest.ResponseRecorder {
				req := appV23DisclosureRequest(
					readerID, http.MethodGet, "/v1/memory/list", nil,
				)
				out := httptest.NewRecorder()
				srv.handleListMemoriesAuth(out, req)
				return out
			},
		},
		{
			name: "validator pending",
			run: func() *httptest.ResponseRecorder {
				req := appV23DisclosureRequest(
					readerID, http.MethodGet, "/v1/validator/pending", nil,
				)
				out := httptest.NewRecorder()
				srv.handleGetPending(out, req)
				return out
			},
		},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			out := route.run()
			require.NotContains(t, out.Body.String(), secret, out.Body.String())
			if route.name == "detail" {
				require.Equal(t, http.StatusForbidden, out.Code, out.Body.String())
			} else {
				require.Equal(t, http.StatusOK, out.Code, out.Body.String())
			}
		})
	}
}

func TestAppV23HashOnlyCoCommitRemainsVisibleAcrossCentralRoutes(t *testing.T) {
	srv, memStore, badger, _, readerID, ownerID, _ := appV23DisclosureFixture(t)
	record := &memory.MemoryRecord{
		MemoryID:        "hash-only-cocommit",
		SubmittingAgent: ownerID,
		ContentHash:     memory.ComputeContentHash("content retained by coauthors"),
		MemoryType:      memory.TypeFact,
		DomainTag:       "owner.home",
		ConfidenceScore: 0.9,
		Status:          memory.StatusCommitted,
		CreatedAt:       time.Now().UTC(),
	}
	memStore.memories[record.MemoryID] = record
	require.NoError(t, badger.SetMemoryHash(
		record.MemoryID, record.ContentHash, string(record.Status),
	))
	require.NoError(t, badger.SetMemoryDomain(record.MemoryID, record.DomainTag))
	require.NoError(t, badger.SetMemoryAuthor(record.MemoryID, record.SubmittingAgent))
	require.NoError(t, badger.SetMemoryClassification(record.MemoryID, 1))
	require.NoError(t, badger.SetCoCommitShared(record.MemoryID, 1))
	require.NoError(t, badger.SetCoCommitCore(
		record.MemoryID, memory.ComputeContentHash("co-commit core"),
	))

	detailReq := appV23DisclosureRequest(
		readerID, http.MethodGet, "/v1/memory/"+record.MemoryID, nil,
	)
	route := chi.NewRouteContext()
	route.URLParams.Add("memory_id", record.MemoryID)
	detailReq = detailReq.WithContext(context.WithValue(
		detailReq.Context(), chi.RouteCtxKey, route,
	))
	detail := httptest.NewRecorder()
	srv.handleGetMemory(detail, detailReq)
	require.Equal(t, http.StatusOK, detail.Code, detail.Body.String())
	require.Contains(t, detail.Body.String(), record.MemoryID)

	listReq := appV23DisclosureRequest(
		readerID, http.MethodGet, "/v1/memory/list", nil,
	)
	list := httptest.NewRecorder()
	srv.handleListMemoriesAuth(list, listReq)
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	require.Contains(t, list.Body.String(), record.MemoryID)

	timelineReq := appV23DisclosureRequest(
		readerID, http.MethodGet, "/v1/memory/timeline", nil,
	)
	timeline := httptest.NewRecorder()
	srv.handleTimelineAuth(timeline, timelineReq)
	require.Equal(t, http.StatusOK, timeline.Code, timeline.Body.String())
	require.Contains(t, timeline.Body.String(), `"total":1`)
}

func TestAppV23PrincipalHashlessProjectionIsOmittedFromBroadRoutesAndExactDetailFailsClosed(
	t *testing.T,
) {
	srv, memStore, badger, _, readerID, ownerID, _ := appV23DisclosureFixture(t)
	secret := "principal hashless content"
	seedMemory(t, memStore, "principal-hashless", ownerID, "owner.home", secret)
	record := memStore.memories["principal-hashless"]
	record.MemoryType = memory.TypeTask
	record.TaskStatus = memory.TaskStatusPlanned
	record.Assignee = readerID
	memStore.pendingRecords = []*memory.MemoryRecord{record}
	require.NoError(t, badger.SetMemoryHash(
		record.MemoryID, nil, string(record.Status),
	))
	require.NoError(t, badger.SetMemoryAuthorPrincipal(
		record.MemoryID, record.SubmittingAgent,
	))

	routes := []struct {
		name string
		run  func() *httptest.ResponseRecorder
	}{
		{
			name: "query",
			run: func() *httptest.ResponseRecorder {
				out := httptest.NewRecorder()
				srv.handleQueryMemory(out, appV23DisclosureRequest(
					readerID, http.MethodPost, "/v1/memory/query",
					[]byte(`{"embedding":[0.1,0.2,0.3],"top_k":10}`),
				))
				return out
			},
		},
		{
			name: "search",
			run: func() *httptest.ResponseRecorder {
				out := httptest.NewRecorder()
				srv.handleSearchMemory(out, appV23DisclosureRequest(
					readerID, http.MethodPost, "/v1/memory/search",
					[]byte(`{"query":"hashless","top_k":10}`),
				))
				return out
			},
		},
		{
			name: "hybrid",
			run: func() *httptest.ResponseRecorder {
				out := httptest.NewRecorder()
				srv.handleHybridSearchMemory(out, appV23DisclosureRequest(
					readerID, http.MethodPost, "/v1/memory/hybrid",
					[]byte(`{"query":"hashless","embedding":[0.1,0.2,0.3],"top_k":10}`),
				))
				return out
			},
		},
		{
			name: "list",
			run: func() *httptest.ResponseRecorder {
				out := httptest.NewRecorder()
				srv.handleListMemoriesAuth(out, appV23DisclosureRequest(
					readerID, http.MethodGet, "/v1/memory/list", nil,
				))
				return out
			},
		},
		{
			name: "tasks",
			run: func() *httptest.ResponseRecorder {
				out := httptest.NewRecorder()
				srv.handleGetOpenTasks(out, appV23DisclosureRequest(
					readerID, http.MethodGet, "/v1/memory/tasks", nil,
				))
				return out
			},
		},
		{
			name: "pending",
			run: func() *httptest.ResponseRecorder {
				out := httptest.NewRecorder()
				srv.handleGetPending(out, appV23DisclosureRequest(
					readerID, http.MethodGet, "/v1/validator/pending", nil,
				))
				return out
			},
		},
		{
			name: "timeline",
			run: func() *httptest.ResponseRecorder {
				out := httptest.NewRecorder()
				srv.handleTimelineAuth(out, appV23DisclosureRequest(
					readerID, http.MethodGet, "/v1/memory/timeline", nil,
				))
				return out
			},
		},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			out := route.run()
			require.Equal(t, http.StatusOK, out.Code, out.Body.String())
			require.NotContains(t, out.Body.String(), secret)
			require.NotContains(t, out.Body.String(), record.MemoryID)
		})
	}

	detailReq := appV23DisclosureRequest(
		readerID, http.MethodGet, "/v1/memory/"+record.MemoryID, nil,
	)
	route := chi.NewRouteContext()
	route.URLParams.Add("memory_id", record.MemoryID)
	detailReq = detailReq.WithContext(context.WithValue(
		detailReq.Context(), chi.RouteCtxKey, route,
	))
	detail := httptest.NewRecorder()
	srv.handleGetMemory(detail, detailReq)
	require.Equal(t, http.StatusServiceUnavailable, detail.Code, detail.Body.String())
	require.NotContains(t, detail.Body.String(), secret)
}

func TestAppV23LegacyTerminalHashlessProjectionRemainsReadable(t *testing.T) {
	srv, memStore, badger, _, readerID, ownerID, _ := appV23DisclosureFixture(t)
	content := "eligible legacy terminal content"
	seedMemory(t, memStore, "legacy-terminal-hashless", ownerID, "owner.home", content)
	record := memStore.memories["legacy-terminal-hashless"]
	require.NoError(t, badger.SetMemoryHash(
		record.MemoryID, nil, string(record.Status),
	))

	list := httptest.NewRecorder()
	srv.handleListMemoriesAuth(list, appV23DisclosureRequest(
		readerID, http.MethodGet, "/v1/memory/list", nil,
	))
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	require.Contains(t, list.Body.String(), record.MemoryID)
	require.Contains(t, list.Body.String(), content)

	detailReq := appV23DisclosureRequest(
		readerID, http.MethodGet, "/v1/memory/"+record.MemoryID, nil,
	)
	route := chi.NewRouteContext()
	route.URLParams.Add("memory_id", record.MemoryID)
	detailReq = detailReq.WithContext(context.WithValue(
		detailReq.Context(), chi.RouteCtxKey, route,
	))
	detail := httptest.NewRecorder()
	srv.handleGetMemory(detail, detailReq)
	require.Equal(t, http.StatusOK, detail.Code, detail.Body.String())
	require.Contains(t, detail.Body.String(), content)
}

func TestAppV23RecordDisclosureReevaluatesAllLiveAuthority(t *testing.T) {
	tests := []struct {
		name        string
		prepare     func(*testing.T, *Server, *store.BadgerStore, string, string, string, *memory.MemoryRecord)
		wantErr     bool
		wantAllowed bool
	}{
		{
			name: "group removal",
			prepare: func(t *testing.T, _ *Server, badger *store.BadgerStore, _, ownerID, _ string, _ *memory.MemoryRecord) {
				require.NoError(t, badger.MutateAppV23AccessGroup(
					appV23RESTAgentID("11"), "local-team", "Local team",
					[]string{ownerID}, 1, false, 4,
				))
			},
		},
		{
			name: "domain ownership transfer",
			prepare: func(t *testing.T, _ *Server, badger *store.BadgerStore, _, _, outsiderID string, rec *memory.MemoryRecord) {
				require.NoError(t, badger.RegisterDomain(rec.DomainTag, appV23RESTAgentID("33"), "", 4))
				require.NoError(t, badger.TransferDomainAppV23(rec.DomainTag, outsiderID, "", 5, false))
			},
		},
		{
			name: "clearance reduction",
			prepare: func(t *testing.T, _ *Server, badger *store.BadgerStore, readerID, _, _ string, rec *memory.MemoryRecord) {
				require.NoError(t, badger.SetMemoryClassification(rec.MemoryID, 2))
				enrollment, err := badger.GetAppV23Enrollment(readerID)
				require.NoError(t, err)
				role, err := badger.GetAppV23Role(readerID)
				require.NoError(t, err)
				require.NoError(t, badger.SetAppV23Policy(
					appV23RESTAgentID("11"), readerID, role.Role,
					enrollment.Profile, enrollment.Profile, 1, enrollment.Capabilities,
					role.Revision, enrollment.Revision, 5,
				))
			},
		},
		{
			name: "inactive enrollment",
			prepare: func(t *testing.T, _ *Server, badger *store.BadgerStore, readerID, _, _ string, _ *memory.MemoryRecord) {
				enrollment, err := badger.GetAppV23Enrollment(readerID)
				require.NoError(t, err)
				role, err := badger.GetAppV23Role(readerID)
				require.NoError(t, err)
				enrollment.Active = false
				enrollment.UpdatedHeight = 5
				require.NoError(t, badger.ApproveAppV23LocalAgent(
					*enrollment, role.Role, enrollment.Revision, role.Revision,
				))
			},
		},
		{
			name:    "corrupt classification",
			wantErr: true,
			prepare: func(t *testing.T, _ *Server, badger *store.BadgerStore, _, _, _ string, rec *memory.MemoryRecord) {
				require.NoError(t, badger.SetMemoryClassification(rec.MemoryID, 0xff))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, memStore, badger, _, readerID, ownerID, outsiderID :=
				appV23DisclosureFixture(t)
			domain := "owner.home"
			if tc.name == "domain ownership transfer" {
				domain = "owner.home.project"
			}
			seedMemory(t, memStore, "live-authority", readerID, domain, "live authority secret")
			rec := memStore.memories["live-authority"]
			require.NoError(t, badger.SetMemoryClassification(rec.MemoryID, 1))
			before, err := srv.evaluateAppV23RecordDisclosure(readerID, rec, time.Now())
			require.NoError(t, err)
			require.True(t, before.Allowed)

			tc.prepare(t, srv, badger, readerID, ownerID, outsiderID, rec)
			after, err := srv.evaluateAppV23RecordDisclosure(readerID, rec, time.Now())
			if tc.wantErr {
				require.Error(t, err)
				require.False(t, after.Allowed)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantAllowed, after.Allowed)
		})
	}
}

func TestAppV23LegacyVisibilityRestrictionRemainsAnAdditionalRecordGate(t *testing.T) {
	srv, memStore, badger, _, readerID, ownerID, _ := appV23DisclosureFixture(t)
	seedMemory(t, memStore, "legacy-visible", ownerID, "owner.home", "legacy visibility")
	rec := memStore.memories["legacy-visible"]
	require.NoError(t, badger.SetMemoryClassification(rec.MemoryID, 1))

	// A malformed/non-matching migrated visibility envelope must never be
	// interpreted as domain authority. The public store API guarantees sorted
	// Access Group membership; retain that invariant while exercising the
	// decision directly.
	groups, err := badger.ListAppV23AgentGroups(readerID)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.True(t, sort.StringsAreSorted(groups[0].Members))
	decision, err := srv.evaluateAppV23RecordDisclosure(readerID, rec, time.Now())
	require.NoError(t, err)
	require.True(t, decision.Allowed)

	payload, err := json.Marshal(decision)
	require.NoError(t, err)
	require.NotContains(t, string(payload), rec.Content)
}
