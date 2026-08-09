package rest

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/auth"
	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

type appV23RESTRouteFixture struct {
	server   *Server
	badger   *store.BadgerStore
	agents   *mockAgentStore
	memories *rbacMockMemoryStore
	keys     map[string]ed25519.PrivateKey
	ids      map[string]string
}

func newAppV23RESTRouteFixture(t *testing.T) appV23RESTRouteFixture {
	t.Helper()
	srv, memories, badgerStore, agents := newRBACTestServer(t)
	keys := make(map[string]ed25519.PrivateKey)
	ids := make(map[string]string)
	for _, name := range []string{
		"historical-root", "current-root", "member", "manager",
		"stale-admin", "current-admin", "inactive",
	} {
		pub, key, err := auth.GenerateKeypair()
		require.NoError(t, err)
		keys[name] = key
		ids[name] = auth.PublicKeyToAgentID(pub)
	}

	require.NoError(t, badgerStore.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: ids["historical-root"], Scope: "rest-route-matrix",
		AgentID: ids["member"], Profile: store.AppV23ProfileStandard,
		HomeDomain: "member.home", Clearance: 2, Capabilities: 0,
		Height: 1, BootstrapDigest: "rest-route-fixture",
	}))
	approve := func(
		name, role string,
		generation uint64,
		active bool,
		clearance uint8,
		capabilities store.AgentCapabilities,
	) {
		t.Helper()
		require.NoError(t, badgerStore.RegisterAgentWithCapabilities(
			ids[name], name, store.AppV23RoleMember, "", "test", "", 2, 0,
		))
		require.NoError(t, badgerStore.ApproveAppV23LocalAgent(
			store.AppV23LocalEnrollment{
				AgentID: ids[name], ApprovedBy: ids["historical-root"],
				RootGeneration: generation, Profile: store.AppV23ProfileStandard,
				HomeDomain: name + ".home", Clearance: clearance,
				Capabilities: capabilities, Active: active, UpdatedHeight: 3,
			},
			role, 0, 0,
		))
	}
	approve("manager", store.AppV23RoleManager, 1, true, 2, 0)
	approve(
		"stale-admin", store.AppV23RoleAdmin, 1, true, 4,
		store.AgentCapabilityReadAllDomains,
	)
	approve("inactive", store.AppV23RoleMember, 1, false, 2, 0)
	require.NoError(t, badgerStore.RotateAppV23RootCredential(
		1, ids["current-root"], 4,
	))
	approve(
		"current-admin", store.AppV23RoleAdmin, 2, true, 4,
		store.AgentCapabilityReadAllDomains,
	)

	for _, name := range []string{
		"historical-root", "current-root", "member", "manager",
		"stale-admin", "current-admin", "inactive",
	} {
		role := store.AppV23RoleMember
		clearance := 2
		capabilities := store.AgentCapabilities(0)
		if name == "manager" {
			role = store.AppV23RoleManager
		}
		if name == "stale-admin" || name == "current-admin" {
			role = store.AppV23RoleAdmin
			clearance = 4
			capabilities = store.AgentCapabilityReadAllDomains
		}
		agents.agents[ids[name]] = &store.AgentEntry{
			AgentID: ids[name], Name: name, Role: role, Status: "active",
			Clearance: clearance, Capabilities: capabilities,
		}
	}
	srv.SetPostV23ForNextTxAccessor(func() bool { return true })
	return appV23RESTRouteFixture{
		server: srv, badger: badgerStore, agents: agents, memories: memories,
		keys: keys, ids: ids,
	}
}

func appV23SignedRESTRouteRequest(
	t *testing.T,
	fixture appV23RESTRouteFixture,
	actor, method, path string,
	body []byte,
	local bool,
) *http.Request {
	t.Helper()
	req := signedRequestAs(
		t, fixture.keys[actor], fixture.ids[actor], method, path, body,
	)
	if local {
		req.RemoteAddr = "127.0.0.1:54321"
		req.Host = "localhost:8080"
	} else {
		req.RemoteAddr = "192.0.2.20:54321"
		req.Host = "192.0.2.10:8080"
	}
	return req
}

func TestAppV23OrdinaryTaskAPIsRejectRootAndPreserveLocalAdmin(t *testing.T) {
	fixture := newAppV23RESTRouteFixture(t)
	cache := &capturingSuppCache{}
	comet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		txHex := strings.TrimPrefix(r.URL.Query().Get("tx"), "0x")
		raw, err := hex.DecodeString(txHex)
		require.NoError(t, err)
		parsed, err := tx.DecodeTx(raw)
		require.NoError(t, err)
		require.NotNil(t, parsed.MemorySubmit)
		require.NotNil(t, cache.data)
		record := &memory.MemoryRecord{
			MemoryID:        parsed.MemorySubmit.MemoryID,
			SubmittingAgent: cache.data.Assignee,
			Content:         parsed.MemorySubmit.Content,
			ContentHash:     parsed.MemorySubmit.ContentHash,
			MemoryType:      memory.TypeTask,
			DomainTag:       parsed.MemorySubmit.DomainTag,
			Provider:        cache.data.Provider,
			ConfidenceScore: parsed.MemorySubmit.ConfidenceScore,
			Status:          memory.StatusProposed,
			TaskStatus:      memory.TaskStatus(parsed.MemorySubmit.TaskStatus),
			Assignee:        cache.data.Assignee,
			CreatedAt:       time.Now().UTC(),
		}
		fixture.memories.memories[parsed.MemorySubmit.MemoryID] = record
		require.NoError(t, fixture.badger.SetMemoryHash(
			record.MemoryID, record.ContentHash, string(record.Status),
		))
		require.NoError(t, fixture.badger.SetMemoryDomain(record.MemoryID, record.DomainTag))
		require.NoError(t, fixture.badger.SetMemoryAuthor(record.MemoryID, record.SubmittingAgent))
		require.NoError(t, fixture.badger.SetMemoryClassification(
			record.MemoryID, uint8(parsed.MemorySubmit.Classification),
		))
		require.NoError(t, fixture.badger.SetMemoryAuthorPrincipal(
			record.MemoryID, record.SubmittingAgent,
		))
		writeCometCommitFixture(t, w, r, 0, "", 0, "", 12)
	}))
	t.Cleanup(comet.Close)
	fixture.server.cometbftRPC = comet.URL
	var heightBytes [8]byte
	binary.BigEndian.PutUint64(heightBytes[:], 12)
	require.NoError(t, fixture.badger.SetState("height", heightBytes[:]))
	fixture.server.SetAppV23RootKeyResolver(
		func(credentialID string) (ed25519.PrivateKey, bool) {
			if credentialID != fixture.ids["current-root"] {
				return nil, false
			}
			return fixture.keys["current-root"], true
		},
	)
	fixture.server.SetSuppCache(cache)

	for _, tc := range []struct {
		name       string
		actor      string
		local      bool
		wantStatus int
	}{
		{
			name: "Member submits task remotely", actor: "member",
			wantStatus: http.StatusCreated,
		},
		{
			name: "Manager submits task remotely", actor: "manager",
			wantStatus: http.StatusCreated,
		},
		{
			name: "current Admin submits task locally", actor: "current-admin",
			local: true, wantStatus: http.StatusCreated,
		},
		{
			name: "current Admin cannot submit task remotely", actor: "current-admin",
			wantStatus: http.StatusForbidden,
		},
		{
			name: "current Root cannot submit through ordinary REST", actor: "current-root",
			local: true, wantStatus: http.StatusForbidden,
		},
		{
			name: "historical Root cannot submit through ordinary REST", actor: "historical-root",
			local: true, wantStatus: http.StatusForbidden,
		},
		{
			name: "stale Admin cannot submit task", actor: "stale-admin",
			local: true, wantStatus: http.StatusForbidden,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache.memoryID = ""
			cache.data = nil
			body := []byte(`{"content":"` + tc.name + `","memory_type":"task","domain_tag":"` +
				tc.actor + `.home","confidence_score":0.9,"task_status":"planned"}`)
			req := appV23SignedRESTRouteRequest(
				t, fixture, tc.actor, http.MethodPost, "/v1/memory/submit",
				body, tc.local,
			)
			rec := httptest.NewRecorder()
			fixture.server.Router().ServeHTTP(rec, req)
			require.Equal(t, tc.wantStatus, rec.Code, rec.Body.String())
			if tc.wantStatus == http.StatusCreated {
				require.NotNil(t, cache.data)
				require.Equal(t, fixture.ids[tc.actor], cache.data.Assignee)
			} else {
				require.Nil(t, cache.data)
			}
		})
	}

	for _, tc := range []struct {
		name       string
		actor      string
		local      bool
		wantStatus int
	}{
		{
			name: "Member reads open tasks remotely", actor: "member",
			wantStatus: http.StatusOK,
		},
		{
			name: "Manager reads open tasks remotely", actor: "manager",
			wantStatus: http.StatusOK,
		},
		{
			name: "current Admin reads open tasks locally", actor: "current-admin",
			local: true, wantStatus: http.StatusOK,
		},
		{
			name: "current Admin cannot read open tasks remotely", actor: "current-admin",
			wantStatus: http.StatusForbidden,
		},
		{
			name: "current Root cannot use open-task agent API", actor: "current-root",
			local: true, wantStatus: http.StatusForbidden,
		},
		{
			name: "historical Root cannot use open-task agent API", actor: "historical-root",
			local: true, wantStatus: http.StatusForbidden,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := appV23SignedRESTRouteRequest(
				t, fixture, tc.actor, http.MethodGet,
				"/v1/memory/tasks?case="+url.QueryEscape(tc.name),
				nil, tc.local,
			)
			rec := httptest.NewRecorder()
			fixture.server.Router().ServeHTTP(rec, req)
			require.Equal(t, tc.wantStatus, rec.Code, rec.Body.String())
		})
	}
}

func TestAppV23TaskSubmitFailsBeforeBroadcastWithoutAssignmentBridge(t *testing.T) {
	fixture := newAppV23RESTRouteFixture(t)
	broadcasts := 0
	comet := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		broadcasts++
	}))
	t.Cleanup(comet.Close)
	fixture.server.cometbftRPC = comet.URL

	body := []byte(`{"content":"must stay assigned","memory_type":"task","domain_tag":"member.home","confidence_score":0.9,"task_status":"planned"}`)
	req := appV23SignedRESTRouteRequest(
		t, fixture, "member", http.MethodPost, "/v1/memory/submit", body, false,
	)
	rec := httptest.NewRecorder()
	fixture.server.Router().ServeHTTP(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "task-assignment-bridge-unavailable")
	require.Zero(t, broadcasts)
}

func TestAppV23TaskSubmitPollsExactProjectionBeforeReportingCreated(t *testing.T) {
	fixture := newAppV23RESTRouteFixture(t)
	cache := &capturingSuppCache{}
	fixture.server.SetSuppCache(cache)
	comet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeCometCommitFixture(t, w, r, 0, "", 0, "", 31)
	}))
	t.Cleanup(comet.Close)
	fixture.server.cometbftRPC = comet.URL

	readbacks := 0
	fixture.memories.getOpenTasksHook = func() {
		readbacks++
		if readbacks != 2 {
			return
		}
		fixture.memories.memories[cache.memoryID] = &memory.MemoryRecord{
			MemoryID: cache.memoryID, SubmittingAgent: fixture.ids["member"],
			Content: "[TASK] delayed projection", MemoryType: memory.TypeTask,
			DomainTag: "member.home", ConfidenceScore: 0.9,
			Status: memory.StatusProposed, TaskStatus: memory.TaskStatusPlanned,
			Assignee: fixture.ids["member"], CreatedAt: time.Now().UTC(),
		}
	}

	body := []byte(`{"content":"[TASK] delayed projection","memory_type":"task","domain_tag":"member.home","confidence_score":0.9,"task_status":"planned"}`)
	req := appV23SignedRESTRouteRequest(
		t, fixture, "member", http.MethodPost, "/v1/memory/submit", body, false,
	)
	rec := httptest.NewRecorder()
	fixture.server.Router().ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var response SubmitMemoryResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	require.NotNil(t, response.ProjectionConfirmed)
	require.True(t, *response.ProjectionConfirmed)
	require.GreaterOrEqual(t, readbacks, 2)
}

func TestAppV23TaskSubmitReturnsNonRetryableCommittedUnconfirmed(t *testing.T) {
	fixture := newAppV23RESTRouteFixture(t)
	fixture.server.SetSuppCache(&capturingSuppCache{})
	fixture.memories.getOpenTasksErr = errors.New("projection unavailable")
	comet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeCometCommitFixture(t, w, r, 0, "", 0, "", 32)
	}))
	t.Cleanup(comet.Close)
	fixture.server.cometbftRPC = comet.URL

	body := []byte(`{"content":"[TASK] reconcile me","memory_type":"task","domain_tag":"member.home","confidence_score":0.9,"task_status":"planned"}`)
	req := appV23SignedRESTRouteRequest(
		t, fixture, "member", http.MethodPost, "/v1/memory/submit", body, false,
	)
	rec := httptest.NewRecorder()
	fixture.server.Router().ServeHTTP(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
	var response SubmitMemoryResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	require.True(t, response.Committed)
	require.Equal(t, "committed_unconfirmed", response.Status)
	require.NotNil(t, response.ProjectionConfirmed)
	require.False(t, *response.ProjectionConfirmed)
	require.NotNil(t, response.Retryable)
	require.False(t, *response.Retryable)
	require.Contains(t, response.Message, "do not resubmit")
}

func TestAppV23FederationAgentSurfacesRequireActiveOrdinaryIdentity(t *testing.T) {
	fixture := newAppV23RESTRouteFixture(t)
	routes := []struct {
		name         string
		method       string
		path         string
		body         func(string) []byte
		ordinaryWant int
	}{
		{
			name: "availability", method: http.MethodGet,
			path: "/v1/federation/available", ordinaryWant: http.StatusOK,
			body: func(string) []byte { return nil },
		},
		{
			name: "contact authorization", method: http.MethodPost,
			path: "/v1/federation/contacts/authorize", ordinaryWant: http.StatusOK,
			body: func(actor string) []byte {
				return []byte(`{"contacts":[{"remote_chain_id":"chain-peer","domain":"` +
					actor + `.home"}]}`)
			},
		},
		{
			name: "recall planning", method: http.MethodPost,
			path: "/v1/federation/recall-plan", ordinaryWant: http.StatusNotImplemented,
			body: func(actor string) []byte {
				return []byte(`{"domain_tag":"` + actor + `.home"}`)
			},
		},
	}
	actors := []struct {
		name  string
		local bool
		allow bool
	}{
		{name: "member", allow: true},
		{name: "manager", allow: true},
		{name: "current-admin", local: true, allow: true},
		{name: "current-admin"},
		{name: "current-root", local: true},
		{name: "historical-root", local: true},
		{name: "stale-admin", local: true},
		{name: "inactive", local: true},
	}
	for actorIndex, actor := range actors {
		for _, route := range routes {
			t.Run(actor.name+" "+route.name, func(t *testing.T) {
				body := route.body(actor.name)
				path := route.path + "?case=" +
					url.QueryEscape(actor.name+"-"+route.name+"-"+strconv.Itoa(actorIndex))
				req := appV23SignedRESTRouteRequest(
					t, fixture, actor.name, route.method, path, body, actor.local,
				)
				rec := httptest.NewRecorder()
				fixture.server.Router().ServeHTTP(rec, req)
				want := http.StatusForbidden
				if actor.allow {
					want = route.ordinaryWant
				}
				require.Equal(t, want, rec.Code, rec.Body.String())
			})
		}
	}

	for _, actor := range []string{"member", "manager", "current-admin"} {
		require.True(t, fixture.server.callerMayUseFederatedPipe(fixture.ids[actor]),
			"%s should retain pipe eligibility subject to the outer Admin locality boundary", actor)
		allowed, _ := fixture.server.federationCallerCanRead(
			t.Context(), fixture.ids[actor], actor+".home",
		)
		require.True(t, allowed, "%s should retain federated read delegation", actor)
	}
	for _, actor := range []string{
		"historical-root", "current-root", "stale-admin", "inactive",
	} {
		require.False(t, fixture.server.callerMayUseFederatedPipe(fixture.ids[actor]),
			"%s must not retain federated pipe eligibility", actor)
		allowed, _ := fixture.server.federationCallerCanRead(
			t.Context(), fixture.ids[actor], "member.home",
		)
		require.False(t, allowed, "%s must not retain federated read delegation", actor)
	}
}

func TestAppV23ListGrantsIsSelfScopedExceptCurrentLocalRootAdmin(t *testing.T) {
	fixture := newAppV23RESTRouteFixture(t)
	target := fixture.ids["member"]
	require.NoError(t, fixture.badger.SetAccessGrant(
		"member.home", target, 1, 0, target,
	))
	fixture.server.accessStore = &staleMirrorAccessStore{
		grants: []*store.AccessGrantEntry{{
			Domain: "member.home", GranteeID: target,
			GranterID: target, Level: 1, CreatedHeight: 1,
		}},
	}

	for _, tc := range []struct {
		name       string
		actor      string
		target     string
		local      bool
		wantStatus int
	}{
		{
			name: "Member lists self", actor: "member", target: "member",
			wantStatus: http.StatusOK,
		},
		{
			name: "Member cannot list another", actor: "member", target: "manager",
			wantStatus: http.StatusForbidden,
		},
		{
			name: "Manager lists self", actor: "manager", target: "manager",
			wantStatus: http.StatusOK,
		},
		{
			name: "Manager cannot list another", actor: "manager", target: "member",
			wantStatus: http.StatusForbidden,
		},
		{
			name:  "current local Admin lists another",
			actor: "current-admin", target: "member", local: true,
			wantStatus: http.StatusOK,
		},
		{
			name:  "current Admin over network denied by outer boundary",
			actor: "current-admin", target: "member",
			wantStatus: http.StatusForbidden,
		},
		{
			name:  "current local Admin cannot target current Root",
			actor: "current-admin", target: "current-root", local: true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:  "current local Admin cannot target genesis historical Root",
			actor: "current-admin", target: "historical-root", local: true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:  "stale Admin denied by outer boundary",
			actor: "stale-admin", target: "member", local: true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:  "current local Root is not an ordinary grant-list caller",
			actor: "current-root", target: "member", local: true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:  "historical Root denied by outer boundary",
			actor: "historical-root", target: "member", local: true,
			wantStatus: http.StatusForbidden,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := "/v1/access/grants/" + fixture.ids[tc.target] +
				"?case=" + url.QueryEscape(tc.name)
			req := appV23SignedRESTRouteRequest(
				t, fixture, tc.actor, http.MethodGet, path, nil, tc.local,
			)
			rec := httptest.NewRecorder()
			fixture.server.Router().ServeHTTP(rec, req)
			require.Equal(t, tc.wantStatus, rec.Code, rec.Body.String())
		})
	}
}

func TestAppV23IntermediateRetiredRootCannotActOrBeTargetedAfterTwoHandovers(t *testing.T) {
	srv, _, badgerStore, _ := newRBACTestServer(t)
	pub1, _, err := auth.GenerateKeypair()
	require.NoError(t, err)
	root1 := auth.PublicKeyToAgentID(pub1)
	pub2, root2Key, err := auth.GenerateKeypair()
	require.NoError(t, err)
	root2 := auth.PublicKeyToAgentID(pub2)
	pub3, _, err := auth.GenerateKeypair()
	require.NoError(t, err)
	root3 := auth.PublicKeyToAgentID(pub3)
	memberPub, _, err := auth.GenerateKeypair()
	require.NoError(t, err)
	memberID := auth.PublicKeyToAgentID(memberPub)
	adminPub, adminKey, err := auth.GenerateKeypair()
	require.NoError(t, err)
	adminID := auth.PublicKeyToAgentID(adminPub)

	require.NoError(t, badgerStore.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: root1, Scope: "two-handover-grants", AgentID: memberID,
		Profile: store.AppV23ProfileStandard, HomeDomain: "member.home",
		Clearance: 2, Capabilities: 0, Height: 1,
		BootstrapDigest: "two-handover-fixture",
	}))
	require.NoError(t, badgerStore.RotateAppV23RootCredential(1, root2, 2))
	require.NoError(t, badgerStore.RotateAppV23RootCredential(2, root3, 3))
	require.NoError(t, badgerStore.RegisterAgentWithCapabilities(
		adminID, "current-admin", store.AppV23RoleMember, "", "test", "", 4, 0,
	))
	require.NoError(t, badgerStore.ApproveAppV23LocalAgent(
		store.AppV23LocalEnrollment{
			AgentID: adminID, ApprovedBy: root3, RootGeneration: 3,
			Profile: store.AppV23ProfileStandard, HomeDomain: "admin.home",
			Clearance: 4, Capabilities: store.AgentCapabilityReadAllDomains,
			Active: true, UpdatedHeight: 5,
		},
		store.AppV23RoleAdmin, 0, 0,
	))
	srv.SetPostV23ForNextTxAccessor(func() bool { return true })
	srv.accessStore = &staleMirrorAccessStore{}

	for _, tc := range []struct {
		name     string
		key      ed25519.PrivateKey
		callerID string
	}{
		{
			name: "intermediate retired Root cannot self-list",
			key:  root2Key, callerID: root2,
		},
		{
			name: "current Admin cannot target intermediate retired Root",
			key:  adminKey, callerID: adminID,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := "/v1/access/grants/" + root2
			req := signedRequestAs(t, tc.key, tc.callerID, http.MethodGet, path, nil)
			req.RemoteAddr = "127.0.0.1:54321"
			req.Host = "localhost:8080"
			rec := httptest.NewRecorder()
			srv.Router().ServeHTTP(rec, req)
			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			require.Contains(t, rec.Body.String(), "Root is not an agent")
		})
	}
}

func TestPreV23ListGrantsPreservesHistoricalCrossTargetRead(t *testing.T) {
	srv, _, badgerStore, _ := newRBACTestServer(t)
	callerReq, _ := signedRequest(
		t, http.MethodGet, "/v1/access/grants/legacy-target", nil,
	)
	require.NoError(t, badgerStore.SetAccessGrant(
		"legacy.home", "legacy-target", 1, 0, "legacy-owner",
	))
	srv.accessStore = &staleMirrorAccessStore{
		grants: []*store.AccessGrantEntry{{
			Domain: "legacy.home", GranteeID: "legacy-target",
			GranterID: "legacy-owner", Level: 1, CreatedHeight: 1,
		}},
	}
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, callerReq)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestAppV23RESTTaskStatusRejectsRootHistoryAndStaleAgents(t *testing.T) {
	fixture := newAppV23RESTRouteFixture(t)
	classified := &appV23ClassifiedMemoryStore{
		rbacMockMemoryStore: newRBACMockMemoryStore(),
	}
	classified.badger = fixture.badger
	fixture.server.store = classified

	for _, actor := range []string{
		"historical-root", "current-root", "stale-admin", "inactive",
	} {
		t.Run(actor, func(t *testing.T) {
			taskID := "task-" + actor
			seedMemory(
				t, classified.rbacMockMemoryStore, taskID,
				fixture.ids["member"], "member.home", "task",
			)
			classified.memories[taskID].MemoryType = memory.TypeTask
			classified.memories[taskID].TaskStatus = memory.TaskStatusPlanned
			req := appV23RESTRequest(
				http.MethodPut, "/v1/memory/"+taskID+"/task-status",
				fixture.ids[actor], `{"task_status":"in_progress"}`,
				map[string]string{"memory_id": taskID},
			)
			rec := httptest.NewRecorder()
			fixture.server.handleUpdateTaskStatus(rec, req)
			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		})
	}

	for _, actor := range []string{"member", "current-admin"} {
		t.Run(actor, func(t *testing.T) {
			taskID := "task-" + actor
			seedMemory(
				t, classified.rbacMockMemoryStore, taskID,
				fixture.ids["member"], "member.home", "task",
			)
			classified.memories[taskID].MemoryType = memory.TypeTask
			classified.memories[taskID].TaskStatus = memory.TaskStatusPlanned
			req := appV23RESTRequest(
				http.MethodPut, "/v1/memory/"+taskID+"/task-status",
				fixture.ids[actor], `{"task_status":"in_progress"}`,
				map[string]string{"memory_id": taskID},
			)
			rec := httptest.NewRecorder()
			fixture.server.handleUpdateTaskStatus(rec, req)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		})
	}
}
