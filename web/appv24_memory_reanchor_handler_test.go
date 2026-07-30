package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/governance"
	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

func insertWebReanchorCandidate(
	t *testing.T,
	fixture appV23DashboardRouteFixture,
	memoryID, content, status string,
) {
	t.Helper()
	hash := sha256.Sum256([]byte(content))
	require.NoError(t, fixture.sql.InsertMemory(context.Background(), &memory.MemoryRecord{
		MemoryID: memoryID, SubmittingAgent: fixture.ids["member"],
		Content: content, ContentHash: hash[:],
		MemoryType: memory.TypeObservation, DomainTag: "member.home",
		ConfidenceScore: 0.9, Status: memory.MemoryStatus(status),
		CreatedAt: time.Now().UTC(),
	}))
	require.NoError(t, fixture.sql.UpdateMemoryClassification(
		context.Background(), memoryID, store.ClearanceInternal,
	))
	require.NoError(t, fixture.badger.SetMemoryHash(memoryID, nil, status))
	require.NoError(t, fixture.badger.SetMemoryDomain(memoryID, "member.home"))
	require.NoError(t, fixture.badger.SetMemoryAuthor(memoryID, fixture.ids["member"]))
	require.NoError(t, fixture.badger.SetMemoryAuthorPrincipal(memoryID, fixture.ids["member"]))
	require.NoError(t, fixture.badger.SetMemoryClassification(memoryID, uint8(store.ClearanceInternal)))
}

func TestMemoryHashReanchorPlanIsCurrentRootBoundAndCanonical(t *testing.T) {
	fixture := newAppV23DashboardRouteFixture(t)
	fixture.handler.AppV24ActiveFn = func() bool { return true }
	insertWebReanchorCandidate(t, fixture, "memory-b", "content-b", "deprecated")
	insertWebReanchorCandidate(t, fixture, "memory-a", "content-a", "committed")

	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/memory-reanchor/plan", nil)
	markLocalDashboardRequest(fixture.handler, req)
	rec := httptest.NewRecorder()
	fixture.handler.handleMemoryHashReanchorPlan(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var body struct {
		Required  bool   `json:"required"`
		Operation string `json:"operation"`
		TargetID  string `json:"target_id"`
		Payload   string `json:"payload"`
		Entries   int    `json:"entries"`
		Remaining bool   `json:"remaining"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.True(t, body.Required)
	require.Equal(t, "memory_hash_reanchor", body.Operation)
	require.Equal(t, 2, body.Entries)
	require.False(t, body.Remaining)

	raw, err := base64.StdEncoding.DecodeString(body.Payload)
	require.NoError(t, err)
	payload, err := tx.DecodeMemoryHashReanchorPayload(raw)
	require.NoError(t, err)
	root, err := fixture.badger.GetAppV23Root()
	require.NoError(t, err)
	require.Equal(t, root.CredentialID, payload.RootCredentialID)
	require.Equal(t, root.Generation, payload.RootGeneration)
	require.Equal(t, []string{"memory-a", "memory-b"}, []string{
		payload.Entries[0].MemoryID, payload.Entries[1].MemoryID,
	})
	targetID, err := tx.MemoryHashReanchorTargetID(raw)
	require.NoError(t, err)
	require.Equal(t, targetID, body.TargetID)
}

func TestMemoryHashReanchorPlanFailsClosedBeforeAppV24(t *testing.T) {
	fixture := newAppV23DashboardRouteFixture(t)
	fixture.handler.AppV24ActiveFn = func() bool { return false }
	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/memory-reanchor/plan", nil)
	markLocalDashboardRequest(fixture.handler, req)
	rec := httptest.NewRecorder()
	fixture.handler.handleMemoryHashReanchorPlan(rec, req)
	require.Equal(t, http.StatusConflict, rec.Code)
}

func TestMemoryHashReanchorVoteAttestationRecomputesLocalContent(t *testing.T) {
	fixture := newAppV23DashboardRouteFixture(t)
	insertWebReanchorCandidate(t, fixture, "memory-a", "content-a", "committed")
	root, err := fixture.badger.GetAppV23Root()
	require.NoError(t, err)
	entries, _, err := store.PlanMemoryHashReanchorEntries(
		context.Background(), fixture.sql, fixture.badger, 256,
	)
	require.NoError(t, err)
	payload, err := tx.EncodeMemoryHashReanchorPayload(tx.MemoryHashReanchorPayload{
		Version:          tx.MemoryHashReanchorPayloadVersion,
		RootCredentialID: root.CredentialID, RootGeneration: root.Generation,
		Entries: []tx.MemoryHashReanchorEntry{{
			MemoryID: entries[0].MemoryID, ExpectedStatus: entries[0].ExpectedStatus,
			ContentHash: entries[0].ContentHash,
		}},
	})
	require.NoError(t, err)
	target, err := tx.MemoryHashReanchorTargetID(payload)
	require.NoError(t, err)
	proposal := &governance.ProposalState{
		ProposalID: "proposal", Operation: governance.OpMemoryHashReanchor,
		TargetID: target, Payload: payload,
	}
	require.NoError(t, fixture.handler.attestMemoryHashReanchorProposal(
		context.Background(), proposal,
	))

	require.NoError(t, fixture.sql.DeleteMemory(context.Background(), "memory-a"))
	require.ErrorContains(t, fixture.handler.attestMemoryHashReanchorProposal(
		context.Background(), proposal,
	), "SQL envelope mismatches canonical state")
}
