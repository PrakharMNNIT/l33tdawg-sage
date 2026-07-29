package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/l33tdawg/sage/api/rest/middleware"
	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// v7.1 query expansion: POST /v1/memory/hybrid with optional Expansions[]
//
// When the request includes paraphrase/entity/temporal variants of the
// primary query, the handler runs SearchHybrid once per variant + once for
// the primary, then RRF-merges across variants. With no expansions the
// behaviour is identical to v7.0 (single SearchHybrid call).
// ---------------------------------------------------------------------------

func TestHybridSearchMemory_ExpansionsFanOut(t *testing.T) {
	srv, memStore, _ := newTestServer(t, "")

	// Seed three memories so the response has shape to inspect.
	for i, id := range []string{"a", "b", "c"} {
		memStore.memories[id] = &memory.MemoryRecord{
			MemoryID:        id,
			SubmittingAgent: "agent-x",
			Content:         "memory " + id,
			ContentHash:     []byte{byte(i + 1)},
			MemoryType:      memory.TypeObservation,
			DomainTag:       "general",
			ConfidenceScore: 0.9,
			Status:          memory.StatusCommitted,
			CreatedAt:       time.Now().Add(-time.Hour),
		}
	}

	// Build a request with primary + two expansions.
	body, _ := json.Marshal(HybridSearchMemoryRequest{
		Query:     "primary question",
		Embedding: []float32{0.1, 0.2, 0.3},
		Expansions: []HybridExpansion{
			{Query: "rephrasing one", Embedding: []float32{0.2, 0.2, 0.2}},
			{Query: "rephrasing two", Embedding: []float32{0.3, 0.1, 0.1}},
		},
		TopK: 5,
	})

	req, _ := signedRequest(t, http.MethodPost, "/v1/memory/hybrid", body)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())

	// We can't directly count SearchHybrid calls through the public surface
	// (the test server uses mockMemoryStore which forwards SearchHybrid to
	// QuerySimilar internally and tracks lastQueryTags). But we CAN verify
	// the response shape is still sane and includes the three seeded memories.
	var resp QueryMemoryResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.LessOrEqual(t, resp.TotalCount, 5, "TopK respected")
	assert.GreaterOrEqual(t, resp.TotalCount, 1, "at least one memory should land")
}

func TestHybridSearchMemory_EmptyExpansionsBehavesLikeV70(t *testing.T) {
	srv, memStore, _ := newTestServer(t, "")

	memStore.memories["only"] = &memory.MemoryRecord{
		MemoryID:        "only",
		SubmittingAgent: "agent-x",
		Content:         "single memory",
		ContentHash:     []byte{1},
		MemoryType:      memory.TypeObservation,
		DomainTag:       "general",
		ConfidenceScore: 0.85,
		Status:          memory.StatusCommitted,
		CreatedAt:       time.Now(),
	}

	body, _ := json.Marshal(HybridSearchMemoryRequest{
		Query:     "x",
		Embedding: []float32{0.1, 0.2, 0.3},
		// No expansions intentionally.
		TopK: 3,
	})

	req, _ := signedRequest(t, http.MethodPost, "/v1/memory/hybrid", body)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())
	var resp QueryMemoryResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.TotalCount, "single memory returned")
}

func TestHybridSearchMemory_BlankExpansionEntriesSkipped(t *testing.T) {
	srv, memStore, _ := newTestServer(t, "")

	memStore.memories["a"] = &memory.MemoryRecord{
		MemoryID:        "a",
		SubmittingAgent: "agent-x",
		Content:         "a",
		ContentHash:     []byte{1},
		MemoryType:      memory.TypeObservation,
		DomainTag:       "general",
		ConfidenceScore: 0.9,
		Status:          memory.StatusCommitted,
		CreatedAt:       time.Now(),
	}

	// One real expansion, one empty (should be skipped without error).
	body, _ := json.Marshal(HybridSearchMemoryRequest{
		Query:     "q",
		Embedding: []float32{0.1, 0.2, 0.3},
		Expansions: []HybridExpansion{
			{Query: "real variant", Embedding: []float32{0.2, 0.2, 0.2}},
			{Query: "", Embedding: nil}, // skip me
		},
		TopK: 3,
	})

	req, _ := signedRequest(t, http.MethodPost, "/v1/memory/hybrid", body)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())
	var resp QueryMemoryResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.GreaterOrEqual(t, resp.TotalCount, 1)
}

func TestHybridSearchMemory_RejectsUnboundedExpansionFanout(t *testing.T) {
	srv, _, _ := newTestServer(t, "")

	expansions := make([]HybridExpansion, maxHybridExpansions+1)
	for i := range expansions {
		expansions[i] = HybridExpansion{
			Query:     fmt.Sprintf("variant-%d", i),
			Embedding: []float32{0.1, 0.2, 0.3},
		}
	}
	body, err := json.Marshal(HybridSearchMemoryRequest{
		Query:      "primary",
		Embedding:  []float32{0.1, 0.2, 0.3},
		Expansions: expansions,
	})
	require.NoError(t, err)

	req, _ := signedRequest(t, http.MethodPost, "/v1/memory/hybrid", body)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	require.Equal(t, http.StatusUnprocessableEntity, rr.Code, "body=%s", rr.Body.String())
	require.Contains(t, rr.Body.String(), "at most 8 expansion variants")
}

type expansionBudgetStore struct {
	*mockMemoryStore
	calls       int
	perCall     int
	failOnCall  int
	failAll     bool
	failure     error
	filterCalls int
}

func (m *expansionBudgetStore) SearchHybrid(
	_ context.Context,
	_ string,
	_ []float32,
	opts store.QueryOptions,
) ([]*memory.MemoryRecord, error) {
	m.calls++
	if m.failAll || (m.failOnCall > 0 && m.calls == m.failOnCall) {
		return nil, m.failure
	}
	results := make([]*memory.MemoryRecord, 0, m.perCall)
	for i := 0; i < m.perCall; i++ {
		rec := &memory.MemoryRecord{MemoryID: fmt.Sprintf("%d-%d", m.calls, i)}
		if opts.CandidateFilter != nil {
			m.filterCalls++
			allowed, err := opts.CandidateFilter(rec)
			if err != nil {
				return nil, err
			}
			if !allowed {
				continue
			}
		}
		results = append(results, rec)
	}
	return results, nil
}

func TestRunHybridWithExpansions_UsesOneAggregateAuthorizationBudget(t *testing.T) {
	srv, _, _ := newTestServer(t, "")
	probe := &expansionBudgetStore{
		mockMemoryStore: newMockMemoryStore(),
		perCall:         3000,
	}
	srv.store = probe
	baseFilterCalls := 0
	opts := store.QueryOptions{
		TopK: 10,
		CandidateFilter: func(*memory.MemoryRecord) (bool, error) {
			baseFilterCalls++
			return true, nil
		},
	}

	_, err := srv.runHybridWithExpansions(context.Background(), HybridSearchMemoryRequest{
		Query:     "primary",
		Embedding: []float32{1},
		Expansions: []HybridExpansion{
			{Query: "one", Embedding: []float32{1}},
			{Query: "two", Embedding: []float32{1}},
			{Query: "three", Embedding: []float32{1}},
		},
	}, opts)

	require.ErrorIs(t, err, store.ErrCandidateFilterScanBudgetExceeded)
	require.Equal(t, store.CandidateFilterScanBudget, baseFilterCalls,
		"all variants must share one live authorization budget")
	require.Equal(t, 3, probe.calls,
		"processing must stop on the first variant that exhausts the shared budget")
}

func TestRunHybridWithExpansions_GovernedVariantErrorIsNeverPartialSuccess(t *testing.T) {
	srv, _, _ := newTestServer(t, "")
	probe := &expansionBudgetStore{
		mockMemoryStore: newMockMemoryStore(),
		perCall:         1,
		failOnCall:      2,
		failure:         store.ErrCandidateFilterScanBudgetExceeded,
	}
	srv.store = probe

	_, err := srv.runHybridWithExpansions(context.Background(), HybridSearchMemoryRequest{
		Query:     "primary",
		Embedding: []float32{1},
		Expansions: []HybridExpansion{
			{Query: "second", Embedding: []float32{1}},
		},
	}, store.QueryOptions{
		TopK: 10,
		CandidateFilter: func(*memory.MemoryRecord) (bool, error) {
			return true, nil
		},
	})

	require.True(t, errors.Is(err, store.ErrCandidateFilterScanBudgetExceeded))
	require.Equal(t, 2, probe.calls)
}

func TestRunHybridWithExpansions_UngovernedAllFailuresAreNotEmptySuccess(t *testing.T) {
	srv, _, _ := newTestServer(t, "")
	backendErr := errors.New("hybrid backend unavailable")
	probe := &expansionBudgetStore{
		mockMemoryStore: newMockMemoryStore(),
		failAll:         true,
		failure:         backendErr,
	}
	srv.store = probe

	records, err := srv.runHybridWithExpansions(context.Background(), HybridSearchMemoryRequest{
		Query:     "primary",
		Embedding: []float32{1},
		Expansions: []HybridExpansion{
			{Query: "one", Embedding: []float32{1}},
			{Query: "two", Embedding: []float32{1}},
		},
	}, store.QueryOptions{TopK: 10})

	require.Nil(t, records)
	require.ErrorIs(t, err, backendErr,
		"all failed variants must not masquerade as a successful empty corpus")
	require.Equal(t, 3, probe.calls)
}

func TestRunHybridWithExpansions_UngovernedPartialFailureStaysBestEffort(t *testing.T) {
	srv, _, _ := newTestServer(t, "")
	probe := &expansionBudgetStore{
		mockMemoryStore: newMockMemoryStore(),
		perCall:         1,
		failOnCall:      2,
		failure:         errors.New("one optional expansion failed"),
	}
	srv.store = probe

	records, err := srv.runHybridWithExpansions(context.Background(), HybridSearchMemoryRequest{
		Query:     "primary",
		Embedding: []float32{1},
		Expansions: []HybridExpansion{
			{Query: "one", Embedding: []float32{1}},
			{Query: "two", Embedding: []float32{1}},
		},
	}, store.QueryOptions{TopK: 10})

	require.NoError(t, err)
	require.Len(t, records, 2,
		"pre-v23 compatibility keeps successful primary/expansion results")
	require.Equal(t, 3, probe.calls)
}

func TestRunHybridWithExpansions_EmptyCorpusIsSuccessfulAndFanoutBounded(t *testing.T) {
	srv, _, _ := newTestServer(t, "")
	probe := &expansionBudgetStore{mockMemoryStore: newMockMemoryStore()}
	srv.store = probe
	expansions := make([]HybridExpansion, maxHybridExpansions)
	for i := range expansions {
		expansions[i] = HybridExpansion{
			Query:     fmt.Sprintf("empty-%d", i),
			Embedding: []float32{1},
		}
	}

	records, err := srv.runHybridWithExpansions(context.Background(), HybridSearchMemoryRequest{
		Query: "primary", Embedding: []float32{1}, Expansions: expansions,
	}, store.QueryOptions{TopK: 10})

	require.NoError(t, err)
	require.Empty(t, records)
	require.Equal(t, 1+maxHybridExpansions, probe.calls,
		"an empty corpus may issue only the primary plus the capped variants")
}

func TestHybridSearchMemory_AggregateBudgetExhaustionMapsTo422(t *testing.T) {
	srv, _, readerID, _, _ := setupAppV23RESTAccess(t)
	probe := &expansionBudgetStore{
		mockMemoryStore: newMockMemoryStore(),
		failAll:         true,
		failure:         store.ErrCandidateFilterScanBudgetExceeded,
	}
	srv.store = probe
	body, err := json.Marshal(HybridSearchMemoryRequest{
		Query:     "primary",
		Embedding: []float32{1},
		Expansions: []HybridExpansion{
			{Query: "one", Embedding: []float32{1}},
		},
	})
	require.NoError(t, err)
	req := httptest.NewRequest(
		http.MethodPost, "/v1/memory/hybrid", bytes.NewReader(body),
	)
	req = req.WithContext(middleware.WithAgentID(req.Context(), readerID))
	out := httptest.NewRecorder()

	srv.handleHybridSearchMemory(out, req)

	require.Equal(t, http.StatusUnprocessableEntity, out.Code, out.Body.String())
	require.Equal(t, "application/problem+json", out.Header().Get("Content-Type"))
	var problem struct {
		Status int    `json:"status"`
		Title  string `json:"title"`
	}
	require.NoError(t, json.Unmarshal(out.Body.Bytes(), &problem))
	require.Equal(t, http.StatusUnprocessableEntity, problem.Status)
	require.Equal(t, "Hybrid query too broad", problem.Title)
	require.Equal(t, 1, probe.calls,
		"the first governed exhaustion must abort every remaining expansion")
}
