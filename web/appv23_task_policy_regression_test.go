package web

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
)

func TestAppV23DashboardTaskStatusRequiresReadAndWrite(t *testing.T) {
	fixture := newAppV23DashboardRouteFixture(t)
	router := testRouter(fixture.handler)
	const taskID = "clearance-lowered-task"
	insertTestTask(t, fixture.sql, taskID, "member.home", fixture.ids["member"])
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, taskID,
		uint8(store.ClearanceTopSecret), true,
	)
	_, err := fixture.sql.AssignTaskAndNotify(
		context.Background(), taskID, fixture.ids["member"],
	)
	require.NoError(t, err)

	body := []byte(`{"task_status":"done"}`)
	req := httptest.NewRequest(
		http.MethodPut,
		"/v1/dashboard/tasks/"+taskID+"/status",
		bytes.NewReader(body),
	)
	req.RemoteAddr = "192.0.2.20:54321"
	req.Host = "192.0.2.10:8080"
	req.Header.Set("Content-Type", "application/json")
	signAgentRequest(t, req, fixture.keys["member"], body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	task, err := fixture.sql.GetMemory(context.Background(), taskID)
	require.NoError(t, err)
	require.Equal(t, memory.TaskStatusInProgress, task.TaskStatus,
		"canonical classification must override a stale PUBLIC projection and domain write authority")
}

func TestAppV23DashboardTaskStatusFailsClosedOnCorruptCanonicalClassification(t *testing.T) {
	fixture := newAppV23DashboardRouteFixture(t)
	router := testRouter(fixture.handler)
	const taskID = "corrupt-classification-task"
	insertTestTask(t, fixture.sql, taskID, "member.home", fixture.ids["member"])
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, taskID,
		uint8(store.ClearancePublic), true,
	)
	_, err := fixture.sql.AssignTaskAndNotify(
		context.Background(), taskID, fixture.ids["member"],
	)
	require.NoError(t, err)
	require.NoError(t, fixture.badger.SetMemoryClassification(taskID, 255))

	body := []byte(`{"task_status":"done"}`)
	req := httptest.NewRequest(
		http.MethodPut,
		"/v1/dashboard/tasks/"+taskID+"/status",
		bytes.NewReader(body),
	)
	req.RemoteAddr = "192.0.2.20:54321"
	req.Host = "192.0.2.10:8080"
	req.Header.Set("Content-Type", "application/json")
	signAgentRequest(t, req, fixture.keys["member"], body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())

	task, err := fixture.sql.GetMemory(context.Background(), taskID)
	require.NoError(t, err)
	require.Equal(t, memory.TaskStatusInProgress, task.TaskStatus)
}

func TestAppV23DashboardTaskBacklogUsesImmutableMigrationDisclosure(t *testing.T) {
	ctx := context.Background()
	sqlStore, err := store.NewSQLiteStore(
		ctx, filepath.Join(t.TempDir(), "sage.db"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlStore.Close()) })
	badger, err := store.NewBadgerStore(filepath.Join(t.TempDir(), "badger"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, badger.CloseBadger()) })

	keys := make(map[string]ed25519.PrivateKey)
	ids := make(map[string]string)
	for _, name := range []string{"root", "reader", "visible-author", "hidden-author"} {
		_, key, keyErr := ed25519.GenerateKey(nil)
		require.NoError(t, keyErr)
		keys[name] = key
		ids[name] = agentIDForKey(key)
		role := store.AppV23RoleMember
		clearance := 2
		if name == "root" {
			role = store.AppV23RoleAdmin
			clearance = 4
		}
		require.NoError(t, badger.RegisterAgentWithCapabilities(
			ids[name], name, role, "", "test", "", int64(clearance), 0,
		))
		require.NoError(t, sqlStore.CreateAgent(ctx, &store.AgentEntry{
			AgentID: ids[name], Name: name, Role: role,
			Status: "active", Clearance: clearance, CreatedAt: time.Now().UTC(),
		}))
	}
	require.NoError(t, badger.SetAgentPermissionWithCapabilities(
		ids["reader"],
		1,
		`[{"domain":"legacy-allowed","read":true}]`,
		`["`+ids["visible-author"]+`"]`,
		"",
		"",
		0,
	))
	require.NoError(t, badger.RegisterDomain(
		"legacy-allowed", ids["root"], "", 3,
	))
	require.NoError(t, badger.EnsureAppV23Root(
		"dashboard-task-migration-disclosure", 100,
	))

	insertAssignedTask := func(id, author string) {
		t.Helper()
		contentHash := sha256.Sum256([]byte("[TASK] " + id))
		require.NoError(t, sqlStore.InsertMemory(ctx, &memory.MemoryRecord{
			MemoryID: id, SubmittingAgent: author, Content: "[TASK] " + id,
			ContentHash: contentHash[:], MemoryType: memory.TypeTask,
			DomainTag: "legacy-allowed", ConfidenceScore: 0.9,
			Status: memory.StatusCommitted, TaskStatus: memory.TaskStatusPlanned,
			CreatedAt: time.Now().UTC(),
		}))
		require.NoError(t, sqlStore.UpdateMemoryClassification(
			ctx, id, store.ClearanceInternal,
		))
		require.NoError(t, badger.SetMemoryClassification(
			id, uint8(store.ClearanceInternal),
		))
		publishAppV23DashboardRecord(
			t, sqlStore, badger, id,
			uint8(store.ClearanceInternal), false,
		)
		_, assignErr := sqlStore.AssignTaskAndNotify(ctx, id, ids["reader"])
		require.NoError(t, assignErr)
	}
	insertAssignedTask("visible-legacy-task", ids["visible-author"])
	insertAssignedTask("hidden-legacy-task", ids["hidden-author"])

	h := NewDashboardHandler(sqlStore, "test")
	h.BadgerStore = badger
	h.AppV23ActiveFn = func() bool { return true }
	router := testRouter(h)
	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/tasks", nil)
	req.RemoteAddr = "192.0.2.20:54321"
	req.Host = "192.0.2.10:8080"
	signAgentGET(t, req, keys["reader"])
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var response struct {
		Tasks []struct {
			MemoryID string `json:"memory_id"`
		} `json:"tasks"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	require.Equal(t, 1, response.Total)
	require.Len(t, response.Tasks, 1)
	require.Equal(t, "visible-legacy-task", response.Tasks[0].MemoryID,
		"legacy read compatibility must preserve the allowed domain while immutable visible_agents still hides excluded authors")
}

func TestAppV23DashboardTaskBacklogPagesPastDeniedPrefix(t *testing.T) {
	fixture := newAppV23DashboardRouteFixture(t)
	router := testRouter(fixture.handler)
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)

	insertAssigned := func(id string, createdAt time.Time, classification uint8) {
		t.Helper()
		contentHash := sha256.Sum256([]byte("[TASK] " + id))
		require.NoError(t, fixture.sql.InsertMemory(ctx, &memory.MemoryRecord{
			MemoryID: id, SubmittingAgent: fixture.ids["member"],
			Content: "[TASK] " + id, ContentHash: contentHash[:],
			MemoryType: memory.TypeTask, DomainTag: "member.home",
			ConfidenceScore: 0.9, Status: memory.StatusCommitted,
			TaskStatus: memory.TaskStatusPlanned,
			Assignee:   fixture.ids["member"], CreatedAt: createdAt,
		}))
		require.NoError(t, fixture.sql.UpdateMemoryClassification(
			ctx, id, store.ClearancePublic,
		))
		publishAppV23DashboardRecord(
			t, fixture.sql, fixture.badger, id, classification, true,
		)
	}
	for i := 0; i < 501; i++ {
		insertAssigned(
			fmt.Sprintf("denied-prefix-%03d", i),
			base.Add(time.Duration(600-i)*time.Second),
			uint8(store.ClearanceTopSecret),
		)
	}
	insertAssigned(
		"visible-after-denied-prefix",
		base,
		uint8(store.ClearancePublic),
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/tasks", nil)
	req.RemoteAddr = "192.0.2.20:54321"
	req.Host = "192.0.2.10:8080"
	signAgentGET(t, req, fixture.keys["member"])
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var response struct {
		Tasks []struct {
			MemoryID string `json:"memory_id"`
		} `json:"tasks"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	require.Equal(t, 1, response.Total)
	require.Len(t, response.Tasks, 1)
	require.Equal(t, "visible-after-denied-prefix", response.Tasks[0].MemoryID)
}

func TestAppV23CEREBRUMTaskWithoutConsensusRPCFailsClosed(t *testing.T) {
	fixture := newAppV23AccessFixture(t)
	sqlStore, err := store.NewSQLiteStore(
		context.Background(), filepath.Join(t.TempDir(), "sage.db"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlStore.Close()) })
	h := appV23AccessTestHandler(fixture, "", nil)
	h.store = sqlStore

	req := httptest.NewRequest(
		http.MethodPost,
		"/v1/dashboard/tasks",
		bytes.NewBufferString(`{"content":"must be durable","domain":"root-home"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	req = appV23AccessAs(req, fixture.rootID)
	rec := httptest.NewRecorder()
	h.handleCreateTaskDashboard(rec, req)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "consensus_rpc_unavailable")

	tasks, err := sqlStore.GetAllTasks(context.Background(), "", 10)
	require.NoError(t, err)
	require.Empty(t, tasks, fmt.Sprintf(
		"app-v23 must not create an off-chain-only task: %#v", tasks,
	))
}
