package abci

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/api/rest"
	"github.com/l33tdawg/sage/internal/authzdenial"
	"github.com/l33tdawg/sage/internal/embedding"
	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/metrics"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/taskidempotency"
	"github.com/l33tdawg/sage/internal/tx"
)

type appV23FailingTaskTagRepairStore struct {
	store.OffchainStore
}

func (s *appV23FailingTaskTagRepairStore) SetTags(
	context.Context,
	string,
	[]string,
) error {
	return errors.New("injected task tag repair failure")
}

func TestAppV23CompanionRESTTaskCommitsAndImmediatelyListsForExactAssignee(t *testing.T) {
	app, root, companion := directAppV23GenesisTestApp(t)

	enrollment, err := app.badgerStore.GetAppV23Enrollment(companion.id)
	require.NoError(t, err)
	require.NotNil(t, enrollment)
	require.True(t, enrollment.Active)
	require.Equal(t, store.AppV23ProfileCompanion, enrollment.Profile)
	require.Equal(t, "voice-interface", enrollment.HomeDomain)
	require.Equal(t, store.AgentCapabilities(15), enrollment.Capabilities)

	sqlite, ok := app.GetOffchainStore().(*store.SQLiteStore)
	require.True(t, ok)
	require.NoError(t, MigrateAgentsOnChain(
		context.Background(),
		sqlite,
		app.badgerStore,
		"",
		nil,
		true,
		zerolog.Nop(),
	))
	projectedCompanion, err := sqlite.GetAgent(context.Background(), companion.id)
	require.NoError(t, err)
	require.Equal(t, "active", projectedCompanion.Status)
	require.Nil(t, projectedCompanion.RemovedAt)
	require.Equal(t, store.AppV23RoleMember, projectedCompanion.Role)
	require.Equal(t, 1, projectedCompanion.Clearance)
	require.Equal(t, store.AgentCapabilities(15), projectedCompanion.Capabilities)
	_, err = sqlite.GetAgent(context.Background(), root.id)
	require.Error(t, err, "CEREBRUM Root must not be projected as an ordinary agent")

	// A lost/stale local tombstone cannot override the still-active committed
	// enrollment. Startup repair restores the serving row without changing any
	// consensus authority.
	require.NoError(t, sqlite.RemoveAgent(context.Background(), companion.id))
	require.NoError(t, MigrateAgentsOnChain(
		context.Background(),
		sqlite,
		app.badgerStore,
		"",
		nil,
		true,
		zerolog.Nop(),
	))
	projectedCompanion, err = sqlite.GetAgent(context.Background(), companion.id)
	require.NoError(t, err)
	require.Equal(t, "active", projectedCompanion.Status)
	require.Nil(t, projectedCompanion.RemovedAt)

	var broadcasts atomic.Int64
	nextHeight := activateDirectAppV24ForTest(
		t, app, time.Now().UTC().Add(-time.Minute),
	)
	firstWriteHeight := nextHeight
	cometShim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		if r.URL.Path == "/num_unconfirmed_txs" {
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": -1,
				"result": map[string]any{"n_txs": "0", "total": "0", "total_bytes": "0"},
			}))
			return
		}
		require.Equal(t, "/broadcast_tx_commit", r.URL.Path)
		raw, decodeErr := hex.DecodeString(strings.TrimPrefix(r.URL.Query().Get("tx"), "0x"))
		require.NoError(t, decodeErr)
		parsed, decodeErr := tx.DecodeTx(raw)
		require.NoError(t, decodeErr)
		broadcasts.Add(1)

		check, checkErr := app.CheckTx(r.Context(), &abcitypes.RequestCheckTx{Tx: raw})
		require.NoError(t, checkErr)
		execResult := &abcitypes.ExecTxResult{Code: check.Code, Log: check.Log}
		height := nextHeight
		if check.Code == 0 {
			finalized, finalizeErr := app.FinalizeBlock(r.Context(), &abcitypes.RequestFinalizeBlock{
				Height: height,
				Time:   time.Unix(parsed.AgentTimestamp, 0).UTC(),
				Txs:    [][]byte{raw},
			})
			require.NoError(t, finalizeErr)
			require.Len(t, finalized.TxResults, 1)
			execResult = finalized.TxResults[0]
			_, commitErr := app.Commit(context.Background(), &abcitypes.RequestCommit{})
			require.NoError(t, commitErr)
			nextHeight++
		}

		hash := sha256.Sum256(raw)
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      -1,
			"result": map[string]any{
				"check_tx": map[string]any{"code": check.Code, "log": check.Log},
				"tx_result": map[string]any{
					"code": execResult.Code, "log": execResult.Log,
					"data": base64.StdEncoding.EncodeToString(execResult.Data),
				},
				"hash":   strings.ToUpper(hex.EncodeToString(hash[:])),
				"height": strconv.FormatInt(height, 10),
			},
		}))
	}))
	t.Cleanup(cometShim.Close)

	health := metrics.NewHealthChecker()
	health.SetPostgresHealth(true)
	health.SetCometBFTHealth(true)
	restServer := rest.NewServer(
		cometShim.URL,
		app.GetOffchainStore(),
		app.GetOffchainStore(),
		app.GetBadgerStore(),
		health,
		zerolog.Nop(),
		embedding.NewHashProvider(8),
	)
	require.NoError(t, restServer.SetValidatorSigningKey(root.priv))
	restServer.SetSuppCache(app.SuppCache)
	restServer.SetPostV17ForNextTxAccessor(app.IsAppV17ActiveForNextTx)
	restServer.SetPostV20ForNextTxAccessor(app.IsAppV20ActiveForNextTx)
	restServer.SetPostV22ForNextTxAccessor(app.IsAppV22ActiveForNextTx)
	restServer.SetPostV23ForNextTxAccessor(app.IsAppV23ActiveForNextTx)

	// Startup projection alone makes the Companion discoverable even before its
	// first REST/MCP self-registration supplies a human-readable label.
	preRegistrationList := httptest.NewRecorder()
	restServer.Router().ServeHTTP(
		preRegistrationList,
		httptest.NewRequest(http.MethodGet, "/v1/agents", nil),
	)
	require.Equal(t, http.StatusOK, preRegistrationList.Code, preRegistrationList.Body.String())
	var preRegisteredAgents struct {
		Agents []*store.AgentEntry `json:"agents"`
		Total  int                 `json:"total"`
	}
	require.NoError(t, json.Unmarshal(preRegistrationList.Body.Bytes(), &preRegisteredAgents))
	require.Equal(t, 1, preRegisteredAgents.Total)
	require.Len(t, preRegisteredAgents.Agents, 1)
	require.Equal(t, companion.id, preRegisteredAgents.Agents[0].AgentID)

	registerBody := []byte(`{"name":"Mynah","provider":"mynah"}`)
	register := httptest.NewRecorder()
	restServer.Router().ServeHTTP(register, signedRESTGovernanceRequest(
		t, companion, http.MethodPost, "/v1/agent/register", registerBody, 40,
	))
	require.Equal(t, http.StatusOK, register.Code, register.Body.String())
	require.Equal(t, int64(0), broadcasts.Load(),
		"already-committed direct-genesis agent registration must remain projection-only")
	var registered struct {
		AgentID        string `json:"agent_id"`
		Name           string `json:"name"`
		RegisteredName string `json:"registered_name"`
		Provider       string `json:"provider"`
	}
	require.NoError(t, json.Unmarshal(register.Body.Bytes(), &registered))
	require.Equal(t, companion.id, registered.AgentID)
	require.Equal(t, "Mynah", registered.Name)
	require.Equal(t, "Mynah", registered.RegisteredName)
	require.Equal(t, "mynah", registered.Provider)

	agentsList := httptest.NewRecorder()
	restServer.Router().ServeHTTP(
		agentsList,
		httptest.NewRequest(http.MethodGet, "/v1/agents", nil),
	)
	require.Equal(t, http.StatusOK, agentsList.Code, agentsList.Body.String())
	var listedAgents struct {
		Agents []*store.AgentEntry `json:"agents"`
		Total  int                 `json:"total"`
	}
	require.NoError(t, json.Unmarshal(agentsList.Body.Bytes(), &listedAgents))
	require.Equal(t, 1, listedAgents.Total)
	require.Len(t, listedAgents.Agents, 1)
	require.Equal(t, companion.id, listedAgents.Agents[0].AgentID)
	require.Equal(t, "Mynah", listedAgents.Agents[0].Name)
	require.Equal(t, "mynah", listedAgents.Agents[0].Provider)

	// Startup reconciliation is idempotent and must preserve authenticated
	// display metadata while continuing to source policy from consensus.
	require.NoError(t, MigrateAgentsOnChain(
		context.Background(),
		sqlite,
		app.badgerStore,
		"",
		nil,
		true,
		zerolog.Nop(),
	))
	projectedAgain, err := sqlite.GetAgent(context.Background(), companion.id)
	require.NoError(t, err)
	require.Equal(t, "Mynah", projectedAgain.Name)
	require.Equal(t, "mynah", projectedAgain.Provider)

	submitBody, err := json.Marshal(rest.SubmitMemoryRequest{
		Content: "[TASK] Check the HDMI port and cables", MemoryType: "task",
		Provider: "mynah", ConfidenceScore: 0.9, TaskStatus: "planned",
		Tags: []string{"hardware", "urgent"},
	})
	require.NoError(t, err)
	submit := httptest.NewRecorder()
	restServer.Router().ServeHTTP(submit, signedRESTGovernanceRequest(
		t, companion, http.MethodPost, "/v1/memory/submit", submitBody, 1,
	))
	require.Equal(t, http.StatusCreated, submit.Code, submit.Body.String())
	var committed rest.SubmitMemoryResponse
	require.NoError(t, json.Unmarshal(submit.Body.Bytes(), &committed))
	require.NotEmpty(t, committed.MemoryID)
	require.NotEmpty(t, committed.TxHash)
	require.True(t, committed.Committed)
	require.Equal(t, firstWriteHeight, committed.CommittedHeight)
	require.Equal(t, "proposed", committed.Status)
	derivedKey, err := taskidempotency.SemanticKey(
		companion.id,
		"voice-interface",
		"[TASK] Check the HDMI port and cables",
	)
	require.NoError(t, err)
	require.Equal(t, derivedKey, committed.IdempotencyKey)
	require.Equal(t, int64(1), broadcasts.Load())
	projectedTags, err := sqlite.GetTags(context.Background(), committed.MemoryID)
	require.NoError(t, err)
	require.Equal(t, []string{"hardware", "urgent"}, projectedTags,
		"keyed app-v23 tags must already be durable when Commit returns")

	// Model a task written by the older post-Commit tag path (or an
	// operator-restored projection) by damaging only the local tag rows. A
	// fresh REST process must use the payload-digest-proved request as repair
	// material and must not claim the replay is confirmed until tags match.
	require.NoError(t, sqlite.SetTags(
		context.Background(), committed.MemoryID, []string{"stale"},
	))

	unrepairable := rest.NewServer(
		cometShim.URL,
		&appV23FailingTaskTagRepairStore{OffchainStore: sqlite},
		app.GetOffchainStore(),
		app.GetBadgerStore(),
		health,
		zerolog.Nop(),
		embedding.NewHashProvider(8),
	)
	require.NoError(t, unrepairable.SetValidatorSigningKey(root.priv))
	unrepairable.SetPostV17ForNextTxAccessor(app.IsAppV17ActiveForNextTx)
	unrepairable.SetPostV20ForNextTxAccessor(app.IsAppV20ActiveForNextTx)
	unrepairable.SetPostV22ForNextTxAccessor(app.IsAppV22ActiveForNextTx)
	unrepairable.SetPostV23ForNextTxAccessor(app.IsAppV23ActiveForNextTx)
	failedRepair := httptest.NewRecorder()
	unrepairable.Router().ServeHTTP(failedRepair, signedRESTGovernanceRequest(
		t, companion, http.MethodPost, "/v1/memory/submit", submitBody, 19,
	))
	require.Equal(t, http.StatusAccepted, failedRepair.Code, failedRepair.Body.String())
	var unconfirmed rest.SubmitMemoryResponse
	require.NoError(t, json.Unmarshal(failedRepair.Body.Bytes(), &unconfirmed))
	require.True(t, unconfirmed.IdempotentReplay)
	require.NotNil(t, unconfirmed.ProjectionConfirmed)
	require.False(t, *unconfirmed.ProjectionConfirmed)
	require.NotNil(t, unconfirmed.Retryable)
	require.False(t, *unconfirmed.Retryable)
	require.Equal(t, int64(1), broadcasts.Load(),
		"a tag repair failure must be explicit and must not rebroadcast")

	// A fresh REST process must reconstruct the original receipt from AppHash-
	// covered state and must not send a second transaction after a lost reply.
	restarted := rest.NewServer(
		cometShim.URL,
		app.GetOffchainStore(),
		app.GetOffchainStore(),
		app.GetBadgerStore(),
		health,
		zerolog.Nop(),
		embedding.NewHashProvider(8),
	)
	require.NoError(t, restarted.SetValidatorSigningKey(root.priv))
	restarted.SetSuppCache(app.SuppCache)
	restarted.SetPostV17ForNextTxAccessor(app.IsAppV17ActiveForNextTx)
	restarted.SetPostV20ForNextTxAccessor(app.IsAppV20ActiveForNextTx)
	restarted.SetPostV22ForNextTxAccessor(app.IsAppV22ActiveForNextTx)
	restarted.SetPostV23ForNextTxAccessor(app.IsAppV23ActiveForNextTx)

	explicitHomeBody, err := json.Marshal(rest.SubmitMemoryRequest{
		Content: "[TASK] Check the HDMI port and cables", MemoryType: "task",
		DomainTag: "voice-interface", Provider: "mynah",
		ConfidenceScore: 0.9, TaskStatus: "planned",
		Tags: []string{"hardware", "urgent"},
	})
	require.NoError(t, err)
	replay := httptest.NewRecorder()
	restarted.Router().ServeHTTP(replay, signedRESTGovernanceRequest(
		t, companion, http.MethodPost, "/v1/memory/submit", explicitHomeBody, 20,
	))
	require.Equal(t, http.StatusOK, replay.Code, replay.Body.String())
	var replayed rest.SubmitMemoryResponse
	require.NoError(t, json.Unmarshal(replay.Body.Bytes(), &replayed))
	require.True(t, replayed.IdempotentReplay)
	require.Equal(t, committed.MemoryID, replayed.MemoryID)
	require.Equal(t, committed.TxHash, replayed.TxHash)
	require.Equal(t, committed.CommittedHeight, replayed.CommittedHeight)
	require.Equal(t, int64(1), broadcasts.Load(), "authoritative receipt must suppress rebroadcast after restart")
	projectedTags, err = sqlite.GetTags(context.Background(), committed.MemoryID)
	require.NoError(t, err)
	require.Equal(t, []string{"hardware", "urgent"}, projectedTags,
		"receipt replay must verify and reconcile the exact signed canonical tags")

	// An existing AppHash-covered receipt remains replayable while the
	// process-local assignment bridge is unavailable.
	replayOnly := rest.NewServer(
		cometShim.URL,
		app.GetOffchainStore(),
		app.GetOffchainStore(),
		app.GetBadgerStore(),
		health,
		zerolog.Nop(),
		embedding.NewHashProvider(8),
	)
	require.NoError(t, replayOnly.SetValidatorSigningKey(root.priv))
	replayOnly.SetPostV17ForNextTxAccessor(app.IsAppV17ActiveForNextTx)
	replayOnly.SetPostV20ForNextTxAccessor(app.IsAppV20ActiveForNextTx)
	replayOnly.SetPostV22ForNextTxAccessor(app.IsAppV22ActiveForNextTx)
	replayOnly.SetPostV23ForNextTxAccessor(app.IsAppV23ActiveForNextTx)
	replayWithoutBridge := httptest.NewRecorder()
	replayOnly.Router().ServeHTTP(replayWithoutBridge, signedRESTGovernanceRequest(
		t, companion, http.MethodPost, "/v1/memory/submit", submitBody, 22,
	))
	require.Equal(t, http.StatusOK, replayWithoutBridge.Code, replayWithoutBridge.Body.String())
	require.Equal(t, int64(1), broadcasts.Load(), "receipt replay must not depend on the local assignment bridge")

	// The same bridge outage must fail a first keyed write before broadcast.
	newWithoutBridgeBody, err := json.Marshal(rest.SubmitMemoryRequest{
		Content: "[TASK] Must wait for assignment bridge", MemoryType: "task",
		DomainTag: "voice-interface", Provider: "mynah",
		ConfidenceScore: 0.9, TaskStatus: "planned",
		IdempotencyKey: "mynah-bridge-outage-v1",
	})
	require.NoError(t, err)
	newWithoutBridge := httptest.NewRecorder()
	replayOnly.Router().ServeHTTP(newWithoutBridge, signedRESTGovernanceRequest(
		t, companion, http.MethodPost, "/v1/memory/submit", newWithoutBridgeBody, 23,
	))
	require.Equal(t, http.StatusServiceUnavailable, newWithoutBridge.Code, newWithoutBridge.Body.String())
	require.Contains(t, newWithoutBridge.Body.String(), "task-assignment-bridge-unavailable")
	require.Equal(t, int64(1), broadcasts.Load(), "new keyed task must not bypass a missing assignment bridge")

	tagConflictBody, err := json.Marshal(rest.SubmitMemoryRequest{
		Content: "[TASK] Check the HDMI port and cables", MemoryType: "task",
		Provider: "mynah", ConfidenceScore: 0.9, TaskStatus: "planned",
		Tags:           []string{"hardware", "onsite"},
		IdempotencyKey: derivedKey,
	})
	require.NoError(t, err)
	tagConflict := httptest.NewRecorder()
	restarted.Router().ServeHTTP(tagConflict, signedRESTGovernanceRequest(
		t, companion, http.MethodPost, "/v1/memory/submit", tagConflictBody, 24,
	))
	require.Equal(t, http.StatusConflict, tagConflict.Code, tagConflict.Body.String())
	require.Equal(t, int64(1), broadcasts.Load(),
		"different tags are a different signed payload and must not repair or rebroadcast")

	conflictBody, err := json.Marshal(rest.SubmitMemoryRequest{
		Content: "[TASK] A different task", MemoryType: "task",
		Provider: "mynah", ConfidenceScore: 0.9, TaskStatus: "planned",
		Tags:           []string{"hardware", "urgent"},
		IdempotencyKey: derivedKey,
	})
	require.NoError(t, err)
	conflict := httptest.NewRecorder()
	restarted.Router().ServeHTTP(conflict, signedRESTGovernanceRequest(
		t, companion, http.MethodPost, "/v1/memory/submit", conflictBody, 21,
	))
	require.Equal(t, http.StatusConflict, conflict.Code, conflict.Body.String())
	require.Equal(t, int64(1), broadcasts.Load(), "mismatched payload must fail before broadcast")

	listPath := "/v1/memory/tasks?provider=mynah"
	list := httptest.NewRecorder()
	restServer.Router().ServeHTTP(list, signedRESTGovernanceRequest(
		t, companion, http.MethodGet, listPath, nil, 2,
	))
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	var assigned struct {
		Tasks []struct {
			MemoryID   string `json:"memory_id"`
			DomainTag  string `json:"domain_tag"`
			TaskStatus string `json:"task_status"`
			Assignee   string `json:"assignee"`
		} `json:"tasks"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(list.Body.Bytes(), &assigned))
	require.Equal(t, 1, assigned.Total)
	require.Len(t, assigned.Tasks, 1)
	require.Equal(t, committed.MemoryID, assigned.Tasks[0].MemoryID)
	require.Equal(t, "voice-interface", assigned.Tasks[0].DomainTag)
	require.Equal(t, "planned", assigned.Tasks[0].TaskStatus)
	require.Equal(t, companion.id, assigned.Tasks[0].Assignee)

	statusPath := "/v1/memory/" + committed.MemoryID + "/task-status"
	statusBody := []byte(`{"task_status":"in_progress"}`)
	status := httptest.NewRecorder()
	restServer.Router().ServeHTTP(status, signedRESTGovernanceRequest(
		t, companion, http.MethodPut, statusPath, statusBody, 3,
	))
	require.Equal(t, http.StatusOK, status.Code, status.Body.String())

	listAfterStatus := httptest.NewRecorder()
	restServer.Router().ServeHTTP(listAfterStatus, signedRESTGovernanceRequest(
		t, companion, http.MethodGet, listPath, nil, 4,
	))
	require.Equal(t, http.StatusOK, listAfterStatus.Code, listAfterStatus.Body.String())
	assigned = struct {
		Tasks []struct {
			MemoryID   string `json:"memory_id"`
			DomainTag  string `json:"domain_tag"`
			TaskStatus string `json:"task_status"`
			Assignee   string `json:"assignee"`
		} `json:"tasks"`
		Total int `json:"total"`
	}{}
	require.NoError(t, json.Unmarshal(listAfterStatus.Body.Bytes(), &assigned))
	require.Len(t, assigned.Tasks, 1)
	require.Equal(t, "in_progress", assigned.Tasks[0].TaskStatus)
	require.Equal(t, companion.id, assigned.Tasks[0].Assignee)

	for index, deniedDomain := range []struct {
		domain string
		code   authzdenial.Code
	}{
		{domain: "technical/hardware", code: authzdenial.CodeDomainClaimRestricted},
	} {
		body, marshalErr := json.Marshal(rest.SubmitMemoryRequest{
			Content: "[TASK] This must be denied", MemoryType: "task",
			DomainTag: deniedDomain.domain, Provider: "mynah",
			ConfidenceScore: 0.9, TaskStatus: "planned",
		})
		require.NoError(t, marshalErr)
		response := httptest.NewRecorder()
		restServer.Router().ServeHTTP(response, signedRESTGovernanceRequest(
			t, companion, http.MethodPost, "/v1/memory/submit", body, byte(5+index),
		))
		require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
		require.Equal(t, "application/problem+json", response.Header().Get("Content-Type"))
		var problem struct {
			Type       string `json:"type"`
			Status     int    `json:"status"`
			ReasonCode string `json:"reason_code"`
			Retryable  bool   `json:"retryable"`
			MemoryID   string `json:"memory_id"`
		}
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &problem))
		require.Equal(t, authzdenial.ProblemTypeURI, problem.Type)
		require.Equal(t, http.StatusForbidden, problem.Status)
		require.Equal(t, string(deniedDomain.code), problem.ReasonCode)
		require.False(t, problem.Retryable)
		require.Empty(t, problem.MemoryID)
		require.Equal(t, int64(1), broadcasts.Load(),
			"preflight denial must not reach CometBFT or create ambiguous delivery")
	}

	finalList := httptest.NewRecorder()
	restServer.Router().ServeHTTP(finalList, signedRESTGovernanceRequest(
		t, companion, http.MethodGet, listPath, nil, 7,
	))
	require.Equal(t, http.StatusOK, finalList.Code, finalList.Body.String())
	require.NoError(t, json.Unmarshal(finalList.Body.Bytes(), &assigned))
	require.Equal(t, 1, assigned.Total)
	require.Len(t, assigned.Tasks, 1)
	require.Equal(t, committed.MemoryID, assigned.Tasks[0].MemoryID)

	// Replaying the original create after the task reaches a terminal state
	// must return the durable current receipt. Terminal tasks are absent from
	// GetOpenTasks by design; that is not a reason to rebroadcast or call the
	// original commit unconfirmed.
	doneBody := []byte(`{"task_status":"done"}`)
	done := httptest.NewRecorder()
	restServer.Router().ServeHTTP(done, signedRESTGovernanceRequest(
		t, companion, http.MethodPut, statusPath, doneBody, 8,
	))
	require.Equal(t, http.StatusOK, done.Code, done.Body.String())

	terminalReplay := httptest.NewRecorder()
	restarted.Router().ServeHTTP(terminalReplay, signedRESTGovernanceRequest(
		t, companion, http.MethodPost, "/v1/memory/submit", submitBody, 9,
	))
	require.Equal(t, http.StatusOK, terminalReplay.Code, terminalReplay.Body.String())
	var terminalReplayed rest.SubmitMemoryResponse
	require.NoError(t, json.Unmarshal(terminalReplay.Body.Bytes(), &terminalReplayed))
	require.True(t, terminalReplayed.IdempotentReplay)
	require.True(t, terminalReplayed.Committed)
	require.NotNil(t, terminalReplayed.ProjectionConfirmed)
	require.True(t, *terminalReplayed.ProjectionConfirmed)
	require.Equal(t, "done", terminalReplayed.TaskStatus)
	require.Equal(t, committed.MemoryID, terminalReplayed.MemoryID)
	require.Equal(t, int64(1), broadcasts.Load(), "terminal replay must never rebroadcast")

	raceBody, err := json.Marshal(rest.SubmitMemoryRequest{
		Content: "[TASK] Race-safe task", MemoryType: "task",
		Provider: "mynah", ConfidenceScore: 0.9, TaskStatus: "planned",
		IdempotencyKey: "mynah-race-safe-v1",
	})
	require.NoError(t, err)
	raceRequests := []*http.Request{
		signedRESTGovernanceRequest(t, companion, http.MethodPost, "/v1/memory/submit", raceBody, 30),
		signedRESTGovernanceRequest(t, companion, http.MethodPost, "/v1/memory/submit", raceBody, 31),
	}
	raceResponses := []*httptest.ResponseRecorder{
		httptest.NewRecorder(),
		httptest.NewRecorder(),
	}
	var raceWG sync.WaitGroup
	for i := range raceRequests {
		raceWG.Add(1)
		go func(index int) {
			defer raceWG.Done()
			restarted.Router().ServeHTTP(raceResponses[index], raceRequests[index])
		}(i)
	}
	raceWG.Wait()
	require.ElementsMatch(t,
		[]int{http.StatusCreated, http.StatusOK},
		[]int{raceResponses[0].Code, raceResponses[1].Code},
	)
	var raceCreated [2]rest.SubmitMemoryResponse
	for i := range raceResponses {
		require.NoError(t, json.Unmarshal(raceResponses[i].Body.Bytes(), &raceCreated[i]))
	}
	require.Equal(t, raceCreated[0].MemoryID, raceCreated[1].MemoryID)
	require.Equal(t, int64(2), broadcasts.Load(), "two simultaneous requests must produce one additional broadcast")

	dropBody, err := json.Marshal(rest.SubmitMemoryRequest{
		Content: "[TASK] Retire the obsolete cable check", MemoryType: "task",
		Provider: "mynah", ConfidenceScore: 0.9, TaskStatus: "planned",
		IdempotencyKey: "mynah-drop-lifecycle-v1",
	})
	require.NoError(t, err)
	dropCreate := httptest.NewRecorder()
	restarted.Router().ServeHTTP(dropCreate, signedRESTGovernanceRequest(
		t, companion, http.MethodPost, "/v1/memory/submit", dropBody, 41,
	))
	require.Equal(t, http.StatusCreated, dropCreate.Code, dropCreate.Body.String())
	var droppedTask rest.SubmitMemoryResponse
	require.NoError(t, json.Unmarshal(dropCreate.Body.Bytes(), &droppedTask))
	require.NotEmpty(t, droppedTask.MemoryID)
	require.Equal(t, int64(3), broadcasts.Load())

	dropStatusPath := "/v1/memory/" + droppedTask.MemoryID + "/task-status"
	drop := httptest.NewRecorder()
	restarted.Router().ServeHTTP(drop, signedRESTGovernanceRequest(
		t,
		companion,
		http.MethodPut,
		dropStatusPath,
		[]byte(`{"task_status":"dropped"}`),
		42,
	))
	require.Equal(t, http.StatusOK, drop.Code, drop.Body.String())
	droppedProjection, err := sqlite.GetMemory(context.Background(), droppedTask.MemoryID)
	require.NoError(t, err)
	require.Equal(t, memory.TaskStatusDropped, droppedProjection.TaskStatus)
}
