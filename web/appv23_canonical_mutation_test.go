package web

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

func appV23CanonicalMutationRequest(
	t *testing.T,
	fixture appV23DashboardRouteFixture,
	method, path string,
	body []byte,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	markLocalCEREBRUM(fixture.handler, req)
	rec := httptest.NewRecorder()
	testRouter(fixture.handler).ServeHTTP(rec, req)
	return rec
}

func TestAppV23CerebrumForgetBroadcastsConsensusWithoutMutatingSQLite(t *testing.T) {
	fixture := newAppV23DashboardRouteFixture(t)
	insertTestMemory(t, fixture.sql, "forget-through-consensus", "member.home")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "forget-through-consensus",
		uint8(store.ClearanceInternal), true,
	)

	captured := make(chan *tx.ParsedTx, 1)
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := hex.DecodeString(strings.TrimPrefix(r.URL.Query().Get("tx"), "0x"))
		require.NoError(t, err)
		parsed, err := tx.DecodeTx(raw)
		require.NoError(t, err)
		captured <- parsed
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"check_tx":  map[string]any{"code": 0, "log": ""},
				"tx_result": map[string]any{"code": 0, "log": ""},
				"hash":      "FORGET",
				"height":    "9",
			},
		}))
	}))
	t.Cleanup(rpc.Close)
	fixture.handler.CometBFTRPC = rpc.URL

	rec := appV23CanonicalMutationRequest(
		t, fixture, http.MethodDelete,
		"/v1/dashboard/memory/forget-through-consensus", nil,
	)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "consensus_submitted")

	parsed := <-captured
	require.Equal(t, tx.TxTypeMemoryChallenge, parsed.Type)
	require.NotNil(t, parsed.MemoryChallenge)
	require.Equal(t, "forget-through-consensus", parsed.MemoryChallenge.MemoryID)

	record, err := fixture.sql.GetMemory(context.Background(), "forget-through-consensus")
	require.NoError(t, err)
	require.Equal(t, memory.StatusProposed, record.Status,
		"CEREBRUM must wait for canonical lifecycle projection instead of editing SQLite")
}

func TestAppV23CerebrumRejectsSQLOnlyDomainRewrites(t *testing.T) {
	fixture := newAppV23DashboardRouteFixture(t)
	insertTestMemory(t, fixture.sql, "immutable-domain", "member.home")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "immutable-domain",
		uint8(store.ClearanceInternal), true,
	)

	rec := appV23CanonicalMutationRequest(
		t, fixture, http.MethodPatch,
		"/v1/dashboard/memory/immutable-domain",
		[]byte(`{"domain":"rewritten.domain"}`),
	)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "canonical_domain_immutable")

	record, err := fixture.sql.GetMemory(context.Background(), "immutable-domain")
	require.NoError(t, err)
	require.Equal(t, "member.home", record.DomainTag)
	domain, err := fixture.badger.GetMemoryDomain("immutable-domain")
	require.NoError(t, err)
	require.Equal(t, "member.home", domain)
}

func TestAppV23CerebrumCleanupCannotDeprecateOnlySQLite(t *testing.T) {
	fixture := newAppV23DashboardRouteFixture(t)
	rec := appV23CanonicalMutationRequest(
		t, fixture, http.MethodPost, "/v1/dashboard/cleanup/run",
		[]byte(`{"dry_run":false}`),
	)
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "canonical_cleanup_required")
}

func TestAppV23UnreadableDeprecationBroadcastsConsensusWithoutMutatingSQLite(t *testing.T) {
	fixture := newAppV23DashboardRouteFixture(t)
	for _, id := range []string{"unreadable-a", "unreadable-b"} {
		insertTestMemory(t, fixture.sql, id, "member.home")
		require.NoError(t, fixture.sql.UpdateStatus(
			context.Background(), id, memory.StatusCommitted, time.Now().UTC(),
		))
		require.NoError(t, fixture.sql.MarkMemoryEmbeddingSkipped(
			context.Background(), id,
		))
		publishAppV23DashboardRecord(
			t, fixture.sql, fixture.badger, id,
			uint8(store.ClearanceInternal), true,
		)
	}

	captured := make(chan *tx.ParsedTx, 2)
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := hex.DecodeString(strings.TrimPrefix(r.URL.Query().Get("tx"), "0x"))
		require.NoError(t, err)
		parsed, err := tx.DecodeTx(raw)
		require.NoError(t, err)
		captured <- parsed
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"check_tx":  map[string]any{"code": 0, "log": ""},
				"tx_result": map[string]any{"code": 0, "log": ""},
				"hash":      "UNREADABLE",
				"height":    "10",
			},
		}))
	}))
	t.Cleanup(rpc.Close)
	fixture.handler.CometBFTRPC = rpc.URL

	rec := appV23CanonicalMutationRequest(
		t, fixture, http.MethodPost,
		"/v1/dashboard/embeddings/deprecate-unreadable", nil,
	)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"submitted":2`)
	require.Contains(t, rec.Body.String(), `"deprecated":0`)
	require.Contains(t, rec.Body.String(), `"remaining_unreadable":2`)

	for _, wantID := range []string{"unreadable-a", "unreadable-b"} {
		parsed := <-captured
		require.Equal(t, tx.TxTypeMemoryChallenge, parsed.Type)
		require.NotNil(t, parsed.MemoryChallenge)
		require.Equal(t, wantID, parsed.MemoryChallenge.MemoryID)

		record, err := fixture.sql.GetMemory(context.Background(), wantID)
		require.NoError(t, err)
		require.Equal(t, memory.StatusCommitted, record.Status,
			"CEREBRUM must wait for consensus projection instead of editing SQLite")
	}
}
