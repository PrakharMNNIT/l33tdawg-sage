package rest

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/api/rest/middleware"
	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

type appV23ClassifiedMemoryStore struct {
	*rbacMockMemoryStore
}

func (s *appV23ClassifiedMemoryStore) GetMemoryClassificationLocal(context.Context, string) (int, error) {
	return 0, nil
}

func appV23RESTRequest(
	method, path, actorID string,
	body string,
	params map[string]string,
) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	route := chi.NewRouteContext()
	for key, value := range params {
		route.URLParams.Add(key, value)
	}
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
	return req.WithContext(middleware.WithAgentID(req.Context(), actorID))
}

func TestAppV23RotatedRootPassesRESTControlHandlersWithoutSyntheticMembership(t *testing.T) {
	srv, _, badger, agents := newRBACTestServer(t)
	rootID := appV23RESTAgentID("11")
	memberID := appV23RESTAgentID("22")
	require.NoError(t, badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: rootID, Scope: "handler-rotation", AgentID: memberID,
		Profile: store.AppV23ProfileStandard, HomeDomain: "member.home",
		Clearance: 2, Capabilities: 0, Height: 1, BootstrapDigest: "bootstrap",
	}))
	newRootID := appV23RESTAgentID("77")
	require.NoError(t, badger.RotateAppV23RootCredential(1, newRootID, 2))
	srv.SetPostV23ForNextTxAccessor(func() bool { return true })
	agents.agents[rootID] = &store.AgentEntry{
		AgentID: rootID, Name: "CEREBRUM", Role: store.AppV23RoleAdmin,
		Status: "active", Clearance: 4,
	}

	var mu sync.Mutex
	var captured []*tx.ParsedTx
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := hex.DecodeString(strings.TrimPrefix(r.URL.Query().Get("tx"), "0x"))
		require.NoError(t, err)
		parsed, err := tx.DecodeTx(raw)
		require.NoError(t, err)
		mu.Lock()
		captured = append(captured, parsed)
		mu.Unlock()
		_, _ = fmt.Fprint(w, `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"CONTROL","height":"3"}}`)
	}))
	defer rpc.Close()
	srv.cometbftRPC = strictCometFixtureProxy(t, rpc.URL)

	orgReq := appV23RESTRequest(
		http.MethodPost, "/v1/org/register", newRootID,
		`{"name":"Rotated Root Org"}`, nil,
	)
	orgRec := httptest.NewRecorder()
	srv.handleOrgRegister(orgRec, orgReq)
	require.Equal(t, http.StatusCreated, orgRec.Code, orgRec.Body.String())

	orgA := "org-a"
	orgB := "org-b"
	deptReq := appV23RESTRequest(
		http.MethodPost, "/v1/org/"+orgA+"/dept", newRootID,
		`{"name":"Security"}`, map[string]string{"org_id": orgA},
	)
	deptRec := httptest.NewRecorder()
	srv.handleDeptRegister(deptRec, deptReq)
	require.Equal(t, http.StatusCreated, deptRec.Code, deptRec.Body.String())

	proposeReq := appV23RESTRequest(
		http.MethodPost, "/v1/federation/propose", newRootID,
		`{"proposer_org_id":"org-a","target_org_id":"org-b"}`, nil,
	)
	proposeRec := httptest.NewRecorder()
	srv.handleFederationPropose(proposeRec, proposeReq)
	require.Equal(t, http.StatusCreated, proposeRec.Code, proposeRec.Body.String())

	fedID := "fed-rotation"
	require.NoError(t, badger.SetFederation(
		fedID, orgA, orgB, []string{"member.home"}, 2, 0, true, "proposed",
	))
	approveReq := appV23RESTRequest(
		http.MethodPost, "/v1/federation/"+fedID+"/approve", newRootID,
		`{}`, map[string]string{"fed_id": fedID},
	)
	approveRec := httptest.NewRecorder()
	srv.handleFederationApprove(approveRec, approveReq)
	require.Equal(t, http.StatusOK, approveRec.Code, approveRec.Body.String())

	revokeReq := appV23RESTRequest(
		http.MethodPost, "/v1/federation/"+fedID+"/revoke", newRootID,
		`{"reason":"test"}`, map[string]string{"fed_id": fedID},
	)
	revokeRec := httptest.NewRecorder()
	srv.handleFederationRevoke(revokeRec, revokeReq)
	require.Equal(t, http.StatusOK, revokeRec.Code, revokeRec.Body.String())

	mu.Lock()
	require.Len(t, captured, 5)
	require.Equal(t, rootID, captured[0].OrgRegister.AdminAgent,
		"business state must use the immutable Root principal")
	require.Equal(t, []tx.TxType{
		tx.TxTypeOrgRegister, tx.TxTypeDeptRegister, tx.TxTypeFederationPropose,
		tx.TxTypeFederationApprove, tx.TxTypeFederationRevoke,
	}, []tx.TxType{
		captured[0].Type, captured[1].Type, captured[2].Type,
		captured[3].Type, captured[4].Type,
	})
	mu.Unlock()
}

func TestAppV23RotatedRootGetsAtomicPolicyDirectionFromRetiredPermissionRoute(t *testing.T) {
	srv, _, badger, _ := newRBACTestServer(t)
	rootID := appV23RESTAgentID("91")
	memberID := appV23RESTAgentID("92")
	require.NoError(t, badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: rootID, Scope: "permission-route-rotation", AgentID: memberID,
		Profile: store.AppV23ProfileStandard, HomeDomain: "member.home",
		Clearance: 2, Capabilities: 0, Height: 1, BootstrapDigest: "bootstrap",
	}))
	newRootID := appV23RESTAgentID("93")
	require.NoError(t, badger.RotateAppV23RootCredential(1, newRootID, 2))
	srv.SetPostV23ForNextTxAccessor(func() bool { return true })

	req := appV23RESTRequest(
		http.MethodPut,
		"/v1/agent/"+memberID+"/permission",
		newRootID,
		`{"clearance":3}`,
		map[string]string{"id": memberID},
	)
	rec := httptest.NewRecorder()
	srv.handleAgentSetPermission(rec, req)

	require.Equal(t, http.StatusGone, rec.Code, rec.Body.String())
	require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
	var problem struct {
		Code        string `json:"code"`
		Replacement struct {
			Method        string `json:"method"`
			Path          string `json:"path"`
			TargetAgentID string `json:"target_agent_id"`
		} `json:"replacement"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &problem))
	require.Equal(t, "app_v23_atomic_policy_required", problem.Code)
	require.Equal(t, http.MethodPut, problem.Replacement.Method)
	require.Equal(t, "/v1/dashboard/network/access/agents/{id}/policy", problem.Replacement.Path)
	require.Equal(t, memberID, problem.Replacement.TargetAgentID)
}

func TestAppV23RootCredentialsAreAbsentFromOrdinaryAgentRESTSurfaces(t *testing.T) {
	srv, _, badger, agents := newRBACTestServer(t)
	rootID := appV23RESTAgentID("a1")
	memberID := appV23RESTAgentID("b2")
	require.NoError(t, badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: rootID, Scope: "hidden-root-rest", AgentID: memberID,
		Profile: store.AppV23ProfileStandard, HomeDomain: "member.home",
		Clearance: 2, Capabilities: 0, Height: 1, BootstrapDigest: "bootstrap",
	}))
	currentCredentialID := appV23RESTAgentID("c3")
	require.NoError(t, badger.RotateAppV23RootCredential(1, currentCredentialID, 2))
	srv.SetPostV23ForNextTxAccessor(func() bool { return true })
	for _, id := range []string{rootID, currentCredentialID, memberID} {
		agents.agents[id] = &store.AgentEntry{
			AgentID: id, Name: "ordinary roster row", Status: "active",
		}
	}

	listRec := httptest.NewRecorder()
	srv.handleListRegisteredAgents(
		listRec, httptest.NewRequest(http.MethodGet, "/v1/agents", nil),
	)
	require.Equal(t, http.StatusOK, listRec.Code, listRec.Body.String())
	require.NotContains(t, listRec.Body.String(), rootID)
	require.NotContains(t, listRec.Body.String(), currentCredentialID)
	require.Contains(t, listRec.Body.String(), memberID)

	for _, id := range []string{rootID, currentCredentialID} {
		getReq := appV23RESTRequest(
			http.MethodGet, "/v1/agent/"+id, memberID, "", map[string]string{"id": id},
		)
		getRec := httptest.NewRecorder()
		srv.handleGetRegisteredAgent(getRec, getReq)
		require.Equal(t, http.StatusNotFound, getRec.Code, getRec.Body.String())

		registerReq := appV23RESTRequest(
			http.MethodPost, "/v1/agent/register", id,
			`{"name":"pretend agent","provider":"test"}`, nil,
		)
		registerRec := httptest.NewRecorder()
		srv.handleAgentRegister(registerRec, registerReq)
		require.Equal(t, http.StatusForbidden, registerRec.Code, registerRec.Body.String())
	}

	updateReq := appV23RESTRequest(
		http.MethodPut, "/v1/agent/update", currentCredentialID,
		`{"name":"pretend agent"}`, nil,
	)
	updateRec := httptest.NewRecorder()
	srv.handleAgentUpdate(updateRec, updateReq)
	require.Equal(t, http.StatusForbidden, updateRec.Code, updateRec.Body.String())

	meReq := appV23RESTRequest(http.MethodGet, "/v1/agent/me", currentCredentialID, "", nil)
	meRec := httptest.NewRecorder()
	srv.handleGetAgent(meRec, meReq)
	require.Equal(t, http.StatusNotFound, meRec.Code, meRec.Body.String())
}

func TestAppV23RotatedRootIsNotTaskAgentButRetainsMemoryControl(t *testing.T) {
	srv, baseMem, badger, agents := newRBACTestServer(t)
	rootID := appV23RESTAgentID("11")
	memberID := appV23RESTAgentID("22")
	require.NoError(t, badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: rootID, Scope: "memory-handler-rotation", AgentID: memberID,
		Profile: store.AppV23ProfileStandard, HomeDomain: "member.home",
		Clearance: 2, Capabilities: 0, Height: 1, BootstrapDigest: "bootstrap",
	}))
	newRootID := appV23RESTAgentID("77")
	require.NoError(t, badger.RotateAppV23RootCredential(1, newRootID, 2))
	srv.SetPostV23ForNextTxAccessor(func() bool { return true })
	agents.agents[rootID] = &store.AgentEntry{
		AgentID: rootID, Name: "CEREBRUM", Role: store.AppV23RoleAdmin,
		Status: "active", Clearance: 4,
	}
	classified := &appV23ClassifiedMemoryStore{rbacMockMemoryStore: baseMem}
	srv.store = classified
	seedMemory(t, baseMem, "task", memberID, "member.home", "task")
	baseMem.memories["task"].MemoryType = memory.TypeTask
	baseMem.memories["task"].TaskStatus = memory.TaskStatusPlanned
	seedMemory(t, baseMem, "source", memberID, "member.home", "source")
	seedMemory(t, baseMem, "target", memberID, "member.home", "target")
	require.NoError(t, badger.SetMemoryClassification("source", 0))
	require.NoError(t, badger.SetMemoryClassification("target", 0))

	taskReq := appV23RESTRequest(
		http.MethodPut, "/v1/memory/task/task-status", newRootID,
		`{"task_status":"in_progress"}`, map[string]string{"memory_id": "task"},
	)
	taskRec := httptest.NewRecorder()
	srv.handleUpdateTaskStatus(taskRec, taskReq)
	require.Equal(t, http.StatusForbidden, taskRec.Code, taskRec.Body.String())
	require.Contains(t, taskRec.Body.String(), "Task status is an ordinary-agent action")

	linkBody, err := json.Marshal(map[string]string{
		"source_id": "source", "target_id": "target", "link_type": "related",
	})
	require.NoError(t, err)
	linkReq := appV23RESTRequest(
		http.MethodPost, "/v1/memory/link", newRootID,
		string(linkBody), nil,
	)
	linkRec := httptest.NewRecorder()
	srv.handleLinkMemories(linkRec, linkReq)
	require.Equal(t, http.StatusOK, linkRec.Code, linkRec.Body.String())
}
