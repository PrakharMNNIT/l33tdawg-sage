package web

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
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
	"github.com/l33tdawg/sage/internal/vault"
)

type appV23ProjectionRouteFixture struct {
	handler *DashboardHandler
	sql     *store.SQLiteStore
	badger  *store.BadgerStore
	router  http.Handler
	dbPath  string
}

type headerMutationRecorder struct {
	*httptest.ResponseRecorder
	mutated bool
	mutate  func()
}

func (w *headerMutationRecorder) Header() http.Header {
	if !w.mutated {
		w.mutated = true
		w.mutate()
	}
	return w.ResponseRecorder.Header()
}

func newAppV23ProjectionRouteFixture(
	t *testing.T,
	encrypted bool,
) appV23ProjectionRouteFixture {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "sage.db")
	sqlStore, err := store.NewSQLiteStore(context.Background(), dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlStore.Close()) })
	if encrypted {
		keyPath := filepath.Join(t.TempDir(), "vault.key")
		require.NoError(t, vault.Init(keyPath, "projection-test-passphrase"))
		unlocked, openErr := vault.Open(keyPath, "projection-test-passphrase")
		require.NoError(t, openErr)
		sqlStore.SetVault(unlocked)
		sqlStore.SetVaultExpected(true)
	}
	badgerStore, err := store.NewBadgerStore(filepath.Join(t.TempDir(), "badger"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, badgerStore.CloseBadger()) })
	_, rootKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_, bootstrapAgentKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	rootID := agentIDForKey(rootKey)
	bootstrapAgentID := agentIDForKey(bootstrapAgentKey)
	require.NoError(t, badgerStore.BootstrapAppV23Genesis(
		store.AppV23GenesisBootstrap{
			RootID:          rootID,
			Scope:           "projection-route-fixture",
			AgentID:         bootstrapAgentID,
			Profile:         store.AppV23ProfileStandard,
			HomeDomain:      "bootstrap.home",
			Clearance:       uint8(store.ClearanceInternal),
			Capabilities:    0,
			Height:          1,
			BootstrapDigest: "projection-route-fixture",
		},
	))

	handler := NewDashboardHandler(sqlStore, "test")
	handler.BadgerStore = badgerStore
	handler.AdminSigningKey = rootKey
	handler.AppV23ActiveFn = func() bool { return true }
	handler.ResolveAgentKeyFn = func(agentID string) (ed25519.PrivateKey, bool) {
		if agentID == rootID {
			return rootKey, true
		}
		if agentID == bootstrapAgentID {
			return bootstrapAgentKey, true
		}
		return nil, false
	}
	return appV23ProjectionRouteFixture{
		handler: handler,
		sql:     sqlStore,
		badger:  badgerStore,
		router:  testRouter(handler),
		dbPath:  dbPath,
	}
}

func requestLocalProjectionRoute(
	t *testing.T,
	fixture appV23ProjectionRouteFixture,
	path string,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	markLocalCEREBRUM(fixture.handler, req)
	rec := httptest.NewRecorder()
	fixture.router.ServeHTTP(rec, req)
	return rec
}

func TestAppV23ProjectionHiddenCountIsLocalOperatorOnly(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	projection := appV23ProjectionResponseFromAudit(false, true, false, 7)

	local := httptest.NewRequest(http.MethodGet, "/v1/dashboard/stats", nil)
	markLocalCEREBRUM(fixture.handler, local)
	localProjection := fixture.handler.projectionResponseForRequest(local, projection)
	require.Equal(t, 7, localProjection.HiddenCount)
	require.Contains(t, localProjection.Message, "7 historical memories")

	remote := httptest.NewRequest(http.MethodGet, "/v1/dashboard/stats", nil)
	remote.RemoteAddr = "192.0.2.20:54321"
	remote.Host = "192.0.2.10:8080"
	remoteProjection := fixture.handler.projectionResponseForRequest(remote, projection)
	require.Zero(t, remoteProjection.HiddenCount)
	require.Equal(t, appV23PartialProjectionMessage, remoteProjection.Message)
}

func TestAppV23CerebrumBroadRoutesOmitLegacyUnanchoredProjection(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%t", encrypted), func(t *testing.T) {
			testAppV23CerebrumBroadRoutesOmitLegacyUnanchoredProjection(
				t, encrypted,
			)
		})
	}
}

func testAppV23CerebrumBroadRoutesOmitLegacyUnanchoredProjection(
	t *testing.T,
	encrypted bool,
) {
	fixture := newAppV23ProjectionRouteFixture(t, encrypted)
	insertTestMemory(t, fixture.sql, "sql-only-ghost", "ghost-domain")
	insertTestMemory(t, fixture.sql, "safe-anchor", "safe-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "safe-anchor",
		uint8(store.ClearanceInternal), true,
	)

	now := time.Now().UTC()
	routes := map[string]struct {
		path          string
		projectionKey string
	}{
		"list": {
			path:          "/v1/dashboard/memory/list?status=proposed",
			projectionKey: "projection",
		},
		"search": {
			path:          "/v1/dashboard/memory/list?q=content&status=proposed",
			projectionKey: "projection",
		},
		"graph": {
			path:          "/v1/dashboard/memory/graph?status=proposed",
			projectionKey: "projection",
		},
		"stats": {
			path:          "/v1/dashboard/stats",
			projectionKey: "projection",
		},
		"health": {
			path:          "/v1/dashboard/health",
			projectionKey: "memory_projection",
		},
		"timeline": {
			path: fmt.Sprintf(
				"/v1/dashboard/memory/timeline?from=%s&to=%s&bucket=hour",
				now.Add(-time.Hour).Format(time.RFC3339),
				now.Add(time.Hour).Format(time.RFC3339),
			),
			projectionKey: "projection",
		},
	}
	for name, route := range routes {
		t.Run(name, func(t *testing.T) {
			rec := requestLocalProjectionRoute(t, fixture, route.path)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.NotContains(t, rec.Body.String(), "content-sql-only-ghost")
			require.NotContains(t, rec.Body.String(), "sql-only-ghost")
			require.NotContains(t, rec.Body.String(), "ghost-domain")
			if name == "list" || name == "search" || name == "graph" {
				require.Contains(t, rec.Body.String(), "safe-anchor")
				require.Contains(t, rec.Body.String(), "safe-domain")
			}
			if name == "stats" || name == "health" {
				require.Contains(t, rec.Body.String(), `"total_memories":1`)
				require.Contains(t, rec.Body.String(), `"safe-domain":1`)
			}
			if name == "timeline" {
				require.Contains(t, rec.Body.String(), `"count":1`)
			}

			var payload map[string]any
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
			projection, ok := payload[route.projectionKey].(map[string]any)
			require.True(t, ok, rec.Body.String())
			require.Equal(t, false, projection["complete"])
			require.Equal(t, true, projection["partial"])
			require.Equal(t, true, projection["verified_only"])
			require.Equal(t, string(store.CanonicalMemoryProjectionQuarantined), projection["state"])
			if name == "health" {
				require.NotContains(t, projection, "hidden_count")
				require.Equal(t, appV23PartialProjectionMessage, projection["message"])
			} else {
				require.Equal(t, float64(1), projection["hidden_count"])
				require.Contains(t, projection["message"], "1 historical memory")
				require.Contains(t, projection["message"], "is hidden")
			}
		})
	}

	health := fixture.badger.CanonicalMemoryProjectionHealth()
	require.True(t, health.Checked)
	require.True(t, health.Required)
	require.False(t, health.OK)
	require.True(t, health.Quarantined)
	require.Equal(t, store.CanonicalMemoryProjectionQuarantined, health.State)
}

func TestAppV23CerebrumExactRoutesFailClosedForUnpublishedProjection(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "sql-only-ghost", "ghost-domain")

	for name, path := range map[string]string{
		"export":  "/v1/dashboard/export",
		"related": "/v1/dashboard/memory/sql-only-ghost/related",
	} {
		t.Run(name, func(t *testing.T) {
			rec := requestLocalProjectionRoute(t, fixture, path)
			require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
			require.NotContains(t, rec.Body.String(), "content-sql-only-ghost")
			require.NotContains(t, rec.Body.String(), "ghost-domain")
		})
	}
}

func TestAppV23CerebrumLegacyTerminalHashlessProjectionRemainsReadable(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "legacy-terminal", "legacy-domain")
	require.NoError(t, fixture.sql.UpdateStatus(
		context.Background(), "legacy-terminal", memory.StatusCommitted, time.Now().UTC(),
	))
	record, err := fixture.sql.GetMemory(context.Background(), "legacy-terminal")
	require.NoError(t, err)
	require.NoError(t, fixture.badger.SetMemoryHash(
		record.MemoryID, nil, string(record.Status),
	))
	require.NoError(t, fixture.badger.SetMemoryDomain(record.MemoryID, record.DomainTag))
	require.NoError(t, fixture.badger.SetMemoryAuthor(record.MemoryID, record.SubmittingAgent))
	require.NoError(t, fixture.badger.SetMemoryClassification(
		record.MemoryID, uint8(store.ClearanceInternal),
	))

	for name, path := range map[string]string{
		"list":   "/v1/dashboard/memory/list?status=committed",
		"export": "/v1/dashboard/export",
		"stats":  "/v1/dashboard/stats",
	} {
		t.Run(name, func(t *testing.T) {
			rec := requestLocalProjectionRoute(t, fixture, path)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.Contains(t, rec.Body.String(), "legacy-domain")
			if name != "stats" {
				require.Contains(t, rec.Body.String(), "legacy-terminal")
			}
		})
	}

	health := fixture.badger.CanonicalMemoryProjectionHealth()
	require.True(t, health.Checked)
	require.True(t, health.Required)
	require.True(t, health.OK)
	require.True(t, health.LegacyCompatible)
	require.False(t, health.Quarantined)
	require.Equal(t, store.CanonicalMemoryProjectionLegacyCompatible, health.State)
}

func TestAppV23CerebrumBroadRoutesOmitPrincipalHashlessProposedProjection(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "safe-anchor", "safe-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "safe-anchor",
		uint8(store.ClearanceInternal), true,
	)
	insertTestMemory(t, fixture.sql, "principal-hashless", "principal-domain")
	record, err := fixture.sql.GetMemory(context.Background(), "principal-hashless")
	require.NoError(t, err)
	require.NoError(t, fixture.badger.SetMemoryHash(
		record.MemoryID, nil, string(record.Status),
	))
	require.NoError(t, fixture.badger.SetMemoryDomain(record.MemoryID, record.DomainTag))
	require.NoError(t, fixture.badger.SetMemoryAuthor(record.MemoryID, record.SubmittingAgent))
	require.NoError(t, fixture.badger.SetMemoryAuthorPrincipal(
		record.MemoryID, record.SubmittingAgent,
	))
	require.NoError(t, fixture.badger.SetMemoryClassification(
		record.MemoryID, uint8(store.ClearanceInternal),
	))

	now := time.Now().UTC()
	routes := map[string]struct {
		path          string
		projectionKey string
	}{
		"list": {
			path:          "/v1/dashboard/memory/list?status=proposed",
			projectionKey: "projection",
		},
		"search": {
			path:          "/v1/dashboard/memory/list?q=content&status=proposed",
			projectionKey: "projection",
		},
		"graph": {
			path:          "/v1/dashboard/memory/graph?status=proposed",
			projectionKey: "projection",
		},
		"stats": {
			path:          "/v1/dashboard/stats",
			projectionKey: "projection",
		},
		"health": {
			path:          "/v1/dashboard/health",
			projectionKey: "memory_projection",
		},
		"timeline": {
			path: fmt.Sprintf(
				"/v1/dashboard/memory/timeline?from=%s&to=%s&bucket=hour",
				now.Add(-time.Hour).Format(time.RFC3339),
				now.Add(time.Hour).Format(time.RFC3339),
			),
			projectionKey: "projection",
		},
	}
	for name, route := range routes {
		t.Run(name, func(t *testing.T) {
			rec := requestLocalProjectionRoute(t, fixture, route.path)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.NotContains(t, rec.Body.String(), "principal-hashless")
			require.NotContains(t, rec.Body.String(), "principal-domain")
			if name == "list" || name == "search" || name == "graph" {
				require.Contains(t, rec.Body.String(), "safe-anchor")
				require.Contains(t, rec.Body.String(), "safe-domain")
			}
			if name == "stats" || name == "health" {
				require.Contains(t, rec.Body.String(), `"total_memories":1`)
				require.Contains(t, rec.Body.String(), `"safe-domain":1`)
			}
			if name == "timeline" {
				require.Contains(t, rec.Body.String(), `"count":1`)
			}
			var payload map[string]any
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
			projection, ok := payload[route.projectionKey].(map[string]any)
			require.True(t, ok, rec.Body.String())
			require.Equal(t, true, projection["partial"])
			if name == "health" {
				require.NotContains(t, projection, "hidden_count")
				require.Equal(t, appV23PartialProjectionMessage, projection["message"])
			} else {
				require.Equal(t, float64(1), projection["hidden_count"])
				require.Contains(t, projection["message"], "1 historical memory")
			}
		})
	}
	export := requestLocalProjectionRoute(t, fixture, "/v1/dashboard/export")
	require.Equal(t, http.StatusServiceUnavailable, export.Code, export.Body.String())
	require.NotContains(t, export.Body.String(), "principal-hashless")
}

func TestAppV23CerebrumBroadRoutesOmitCanonicalStatusMismatch(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "safe-anchor", "safe-domain")
	require.NoError(t, fixture.sql.UpdateStatus(
		context.Background(), "safe-anchor", memory.StatusCommitted, time.Now().UTC(),
	))
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "safe-anchor",
		uint8(store.ClearanceInternal), true,
	)
	insertTestMemory(t, fixture.sql, "status-mismatch", "mismatch-domain")
	require.NoError(t, fixture.sql.UpdateStatus(
		context.Background(), "status-mismatch", memory.StatusCommitted, time.Now().UTC(),
	))
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "status-mismatch",
		uint8(store.ClearanceInternal), true,
	)
	require.NoError(t, fixture.sql.UpdateStatus(
		context.Background(), "status-mismatch", memory.StatusDeprecated, time.Now().UTC(),
	))

	now := time.Now().UTC()
	routes := map[string]struct {
		path          string
		projectionKey string
	}{
		"list": {
			path:          "/v1/dashboard/memory/list",
			projectionKey: "projection",
		},
		"search": {
			path:          "/v1/dashboard/memory/list?q=content",
			projectionKey: "projection",
		},
		"graph": {
			path:          "/v1/dashboard/memory/graph",
			projectionKey: "projection",
		},
		"stats": {
			path:          "/v1/dashboard/stats",
			projectionKey: "projection",
		},
		"health": {
			path:          "/v1/dashboard/health",
			projectionKey: "memory_projection",
		},
		"timeline": {
			path: fmt.Sprintf(
				"/v1/dashboard/memory/timeline?from=%s&to=%s&bucket=hour",
				now.Add(-time.Hour).Format(time.RFC3339),
				now.Add(time.Hour).Format(time.RFC3339),
			),
			projectionKey: "projection",
		},
	}
	for name, route := range routes {
		t.Run(name, func(t *testing.T) {
			rec := requestLocalProjectionRoute(t, fixture, route.path)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.NotContains(t, rec.Body.String(), "status-mismatch")
			require.NotContains(t, rec.Body.String(), "mismatch-domain")
			if name == "list" || name == "search" || name == "graph" {
				require.Contains(t, rec.Body.String(), "safe-anchor")
				require.Contains(t, rec.Body.String(), "safe-domain")
			}
			if name == "stats" || name == "health" {
				require.Contains(t, rec.Body.String(), `"total_memories":1`)
				require.Contains(t, rec.Body.String(), `"safe-domain":1`)
			}
			if name == "timeline" {
				require.Contains(t, rec.Body.String(), `"count":1`)
			}
			var payload map[string]any
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
			projection, ok := payload[route.projectionKey].(map[string]any)
			require.True(t, ok, rec.Body.String())
			require.Equal(t, true, projection["partial"])
			if name == "health" {
				require.NotContains(t, projection, "hidden_count")
				require.Equal(t, appV23PartialProjectionMessage, projection["message"])
			} else {
				require.Equal(t, float64(1), projection["hidden_count"])
			}
		})
	}
	export := requestLocalProjectionRoute(t, fixture, "/v1/dashboard/export")
	require.Equal(t, http.StatusServiceUnavailable, export.Code, export.Body.String())
	require.NotContains(t, export.Body.String(), "status-mismatch")
}

func TestAppV23CanonicalProjectionAuditClearsStickyQuarantineAfterHashReanchor(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "reanchored-terminal", "reanchor-domain")
	require.NoError(t, fixture.sql.UpdateStatus(
		context.Background(), "reanchored-terminal", memory.StatusCommitted, time.Now().UTC(),
	))
	record, err := fixture.sql.GetMemory(context.Background(), "reanchored-terminal")
	require.NoError(t, err)
	require.NoError(t, fixture.badger.SetMemoryHash(
		record.MemoryID, nil, string(record.Status),
	))
	require.NoError(t, fixture.badger.SetMemoryDomain(record.MemoryID, record.DomainTag))
	require.NoError(t, fixture.badger.SetMemoryAuthor(record.MemoryID, record.SubmittingAgent))
	require.NoError(t, fixture.badger.SetMemoryAuthorPrincipal(
		record.MemoryID, record.SubmittingAgent,
	))
	require.NoError(t, fixture.badger.SetMemoryClassification(
		record.MemoryID, uint8(store.ClearanceInternal),
	))

	err = fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background())
	require.ErrorContains(t, err, "projection is unavailable")
	health := fixture.badger.CanonicalMemoryProjectionHealth()
	require.True(t, health.Quarantined)
	require.Equal(t, store.CanonicalMemoryProjectionQuarantined, health.State)

	// Model the consensus-approved app-v24 op 9 mutation. Health remains
	// fail-closed until the complete post-Commit SQL inventory rescan publishes
	// a fresh process-local result.
	require.NoError(t, fixture.badger.SetMemoryHash(
		record.MemoryID, record.ContentHash, string(record.Status),
	))
	require.True(t, fixture.badger.CanonicalMemoryProjectionHealth().Quarantined)
	canonicalIDs, err := store.CanonicalMemoryIDs(fixture.badger)
	require.NoError(t, err)
	require.Equal(t, []string{record.MemoryID}, canonicalIDs)

	require.NoError(t, fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background()))
	health = fixture.badger.CanonicalMemoryProjectionHealth()
	require.True(t, health.Checked)
	require.True(t, health.Required)
	require.True(t, health.OK)
	require.False(t, health.LegacyCompatible)
	require.False(t, health.Quarantined)
	require.Equal(t, store.CanonicalMemoryProjectionExact, health.State)
}

func TestAppV23CanonicalProjectionAuditQuarantinesMissingSQLRowsAcrossVaultModes(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%t", encrypted), func(t *testing.T) {
			fixture := newAppV23ProjectionRouteFixture(t, encrypted)
			const memoryID = "canonical-without-sql"
			contentHash := sha256.Sum256([]byte("content-" + memoryID))
			require.NoError(t, fixture.badger.SetMemoryHash(
				memoryID, contentHash[:], string(memory.StatusProposed),
			))
			require.NoError(t, fixture.badger.SetMemoryDomain(memoryID, "missing-domain"))
			require.NoError(t, fixture.badger.SetMemoryAuthor(memoryID, "agent1"))
			require.NoError(t, fixture.badger.SetMemoryAuthorPrincipal(memoryID, "agent1"))
			require.NoError(t, fixture.badger.SetMemoryClassification(
				memoryID, uint8(store.ClearanceInternal),
			))

			err := fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background())
			require.ErrorContains(t, err, "projection is unavailable")
			health := fixture.badger.CanonicalMemoryProjectionHealth()
			require.True(t, health.Checked)
			require.True(t, health.Required)
			require.False(t, health.OK)
			require.True(t, health.Quarantined)
			require.Equal(t, store.CanonicalMemoryProjectionQuarantined, health.State)

			stats := requestLocalProjectionRoute(t, fixture, "/v1/dashboard/stats")
			require.Equal(t, http.StatusOK, stats.Code, stats.Body.String())
			require.Contains(t, stats.Body.String(), `"total_memories":0`)
			require.Contains(t, stats.Body.String(), `"partial":true`)
			require.Contains(t, stats.Body.String(), `"hidden_count":1`)
			export := requestLocalProjectionRoute(t, fixture, "/v1/dashboard/export")
			require.Equal(t, http.StatusServiceUnavailable, export.Code, export.Body.String())
			require.NotContains(t, export.Header().Get("Content-Disposition"), "sage-backup-")

			// Rebuilding the exact SQL projection clears the sticky quarantine
			// on the next complete audit; no canonical history is rewritten.
			insertTestMemory(t, fixture.sql, memoryID, "missing-domain")
			require.NoError(t, fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background()))
			health = fixture.badger.CanonicalMemoryProjectionHealth()
			require.True(t, health.OK)
			require.False(t, health.Quarantined)
			require.Equal(t, store.CanonicalMemoryProjectionExact, health.State)
		})
	}
}

func TestAppV23CerebrumBroadRoutesOmitMissingSQLRowAndExactRoutesStayStrict(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "safe-anchor", "anchor-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "safe-anchor",
		uint8(store.ClearanceInternal), true,
	)

	const missingID = "canonical-without-sql-route-guard"
	contentHash := sha256.Sum256([]byte("content-" + missingID))
	require.NoError(t, fixture.badger.SetMemoryHash(
		missingID, contentHash[:], string(memory.StatusProposed),
	))
	require.NoError(t, fixture.badger.SetMemoryDomain(missingID, "missing-domain"))
	require.NoError(t, fixture.badger.SetMemoryAuthor(missingID, "agent1"))
	require.NoError(t, fixture.badger.SetMemoryAuthorPrincipal(missingID, "agent1"))
	require.NoError(t, fixture.badger.SetMemoryClassification(
		missingID, uint8(store.ClearanceInternal),
	))

	err := fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background())
	require.ErrorContains(t, err, "projection is unavailable")
	health := fixture.badger.CanonicalMemoryProjectionHealth()
	require.True(t, health.Checked)
	require.True(t, health.Required)
	require.False(t, health.OK)
	require.True(t, health.Quarantined)

	for name, route := range map[string]struct {
		path          string
		projectionKey string
	}{
		"list": {
			path:          "/v1/dashboard/memory/list?status=proposed",
			projectionKey: "projection",
		},
		"search": {
			path:          "/v1/dashboard/memory/list?q=safe-anchor&status=proposed",
			projectionKey: "projection",
		},
		"timeline": {
			path:          "/v1/dashboard/memory/timeline?domain=anchor-domain",
			projectionKey: "projection",
		},
		"graph": {
			path:          "/v1/dashboard/memory/graph?status=proposed",
			projectionKey: "projection",
		},
		"projection-stats": {
			path:          "/v1/dashboard/stats",
			projectionKey: "projection",
		},
		"health": {
			path:          "/v1/dashboard/health",
			projectionKey: "memory_projection",
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := requestLocalProjectionRoute(t, fixture, route.path)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			if name == "list" || name == "search" || name == "graph" {
				require.Contains(t, rec.Body.String(), "safe-anchor")
			}
			if name == "projection-stats" || name == "health" {
				require.Contains(t, rec.Body.String(), `"total_memories":1`)
				require.Contains(t, rec.Body.String(), `"anchor-domain":1`)
			}
			if name == "timeline" {
				require.Contains(t, rec.Body.String(), `"count":1`)
			}
			require.NotContains(t, rec.Body.String(), missingID)
			require.NotContains(t, rec.Body.String(), "missing-domain")
			var payload map[string]any
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
			projection, ok := payload[route.projectionKey].(map[string]any)
			require.True(t, ok, rec.Body.String())
			require.Equal(t, true, projection["partial"])
			if name == "health" {
				require.NotContains(t, projection, "hidden_count")
			} else {
				require.Equal(t, float64(1), projection["hidden_count"])
			}
		})
	}

	for name, path := range map[string]string{
		"related":       "/v1/dashboard/memory/safe-anchor/related",
		"tags":          "/v1/dashboard/tags",
		"memory-tags":   "/v1/dashboard/memory/safe-anchor/tags",
		"tasks":         "/v1/dashboard/tasks?all=true",
		"agent-tags":    "/v1/dashboard/network/agents/agent1/tags",
		"agent-domains": "/v1/dashboard/network/agents/agent1/domains",
		"agent-list":    "/v1/dashboard/network/agents",
		"agent-detail":  "/v1/dashboard/network/agents/agent1",
		"unregistered":  "/v1/dashboard/network/unregistered",
		"task-notices":  "/v1/dashboard/task-notifications",
	} {
		t.Run(name, func(t *testing.T) {
			rec := requestLocalProjectionRoute(t, fixture, path)
			require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
			require.NotContains(t, rec.Body.String(), missingID)
			require.NotContains(t, rec.Body.String(), "missing-domain")
		})
	}
}

func TestAppV23CerebrumBroadRoutesStillFailForUnavailableCanonicalStore(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	fixture.handler.BadgerStore = nil

	rec := requestLocalProjectionRoute(t, fixture, "/v1/dashboard/stats")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), `"total_memories":0`)
	require.NotContains(t, rec.Body.String(), `"partial":true`)
}

func TestAppV23CerebrumFilteredReadsIsolateDeterministicProjectionDrift(t *testing.T) {
	for _, tc := range []struct {
		name   string
		path   string
		tamper func(*testing.T, appV23ProjectionRouteFixture)
	}{
		{
			name: "domain-filter",
			path: "/v1/dashboard/memory/list?domain=canonical-domain&status=proposed",
			tamper: func(t *testing.T, fixture appV23ProjectionRouteFixture) {
				require.NoError(t, fixture.sql.UpdateDomainTag(
					context.Background(), "filtered-target", "hidden-domain",
				))
			},
		},
		{
			name: "status-filter",
			path: "/v1/dashboard/memory/list?status=proposed",
			tamper: func(t *testing.T, fixture appV23ProjectionRouteFixture) {
				require.NoError(t, fixture.sql.UpdateStatus(
					context.Background(), "filtered-target",
					memory.StatusCommitted, time.Now().UTC(),
				))
			},
		},
		{
			name: "agent-filter",
			path: "/v1/dashboard/memory/list?agent=agent1&status=proposed",
			tamper: func(t *testing.T, fixture appV23ProjectionRouteFixture) {
				tamperAppV23ProjectionRow(
					t, fixture.dbPath,
					"UPDATE memories SET submitting_agent = ? WHERE memory_id = ?",
					"forged-agent", "filtered-target",
				)
			},
		},
		{
			name: "content-search",
			path: "/v1/dashboard/memory/list?q=content-filtered-target&status=proposed",
			tamper: func(t *testing.T, fixture appV23ProjectionRouteFixture) {
				tamperAppV23ProjectionRow(
					t, fixture.dbPath,
					"UPDATE memories SET content = ? WHERE memory_id = ?",
					"replacement text", "filtered-target",
				)
			},
		},
		{
			name: "canonical-hash-mismatch",
			path: "/v1/dashboard/memory/list?status=proposed",
			tamper: func(t *testing.T, fixture appV23ProjectionRouteFixture) {
				forged := sha256.Sum256([]byte("forged canonical hash"))
				require.NoError(t, fixture.badger.SetMemoryHash(
					"filtered-target", forged[:], string(memory.StatusProposed),
				))
			},
		},
		{
			name: "malformed-classification",
			path: "/v1/dashboard/memory/list?status=proposed",
			tamper: func(t *testing.T, fixture appV23ProjectionRouteFixture) {
				require.NoError(t, fixture.badger.SetMemoryClassification(
					"filtered-target", 0xff,
				))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newAppV23ProjectionRouteFixture(t, false)
			insertTestMemory(t, fixture.sql, "filtered-target", "canonical-domain")
			publishAppV23DashboardRecord(
				t, fixture.sql, fixture.badger, "filtered-target",
				uint8(store.ClearanceInternal), true,
			)
			require.NoError(
				t,
				fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background()),
			)
			require.True(t, fixture.badger.CanonicalMemoryProjectionHealth().OK)

			tc.tamper(t, fixture)
			rec := requestLocalProjectionRoute(t, fixture, tc.path)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.Contains(t, rec.Body.String(), `"partial":true`)
			require.Contains(t, rec.Body.String(), `"hidden_count":1`)
			require.NotContains(t, rec.Body.String(), "filtered-target")
			require.True(t, fixture.badger.CanonicalMemoryProjectionHealth().Quarantined)
		})
	}
}

func TestAppV23CerebrumRelatedReauditsFilteredCandidateAfterHealthyProjection(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	for _, id := range []string{"related-anchor", "related-filtered-candidate"} {
		insertTestMemory(t, fixture.sql, id, "related-domain")
		publishAppV23DashboardRecord(
			t, fixture.sql, fixture.badger, id,
			uint8(store.ClearanceInternal), true,
		)
	}
	require.NoError(
		t,
		fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background()),
	)
	require.NoError(t, fixture.sql.UpdateDomainTag(
		context.Background(), "related-filtered-candidate", "hidden-domain",
	))

	rec := requestLocalProjectionRoute(
		t, fixture, "/v1/dashboard/memory/related-anchor/related",
	)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), "related-anchor")
	require.NotContains(t, rec.Body.String(), "related-filtered-candidate")
}

func TestAppV23CerebrumGraphReauditsAndOmitsTamperedCachedRow(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "cached-graph-memory", "graph-domain")
	require.NoError(t, fixture.sql.UpdateStatus(
		context.Background(), "cached-graph-memory",
		memory.StatusCommitted, time.Now().UTC(),
	))
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "cached-graph-memory",
		uint8(store.ClearanceInternal), true,
	)
	require.NoError(
		t,
		fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background()),
	)

	first := requestLocalProjectionRoute(
		t, fixture, "/v1/dashboard/memory/graph?status=committed",
	)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	require.Contains(t, first.Body.String(), "cached-graph-memory")
	require.NotEmpty(t, fixture.handler.graphCache)

	tamperAppV23ProjectionRow(
		t, fixture.dbPath,
		"UPDATE memories SET content = ? WHERE memory_id = ?",
		"tampered cached graph content", "cached-graph-memory",
	)
	second := requestLocalProjectionRoute(
		t, fixture, "/v1/dashboard/memory/graph?status=committed",
	)
	require.Equal(t, http.StatusOK, second.Code, second.Body.String())
	require.Contains(t, second.Body.String(), `"partial":true`)
	require.Contains(t, second.Body.String(), `"hidden_count":1`)
	require.NotContains(t, second.Body.String(), "cached-graph-memory")
	require.NotContains(t, second.Body.String(), "tampered cached graph content")
}

func TestAppV23CerebrumGraphDoesNotServeExactCacheAfterProjectionBecomesPartial(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "cached-safe-memory", "graph-domain")
	require.NoError(t, fixture.sql.UpdateStatus(
		context.Background(), "cached-safe-memory",
		memory.StatusCommitted, time.Now().UTC(),
	))
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "cached-safe-memory",
		uint8(store.ClearanceInternal), true,
	)

	first := requestLocalProjectionRoute(
		t, fixture, "/v1/dashboard/memory/graph?status=committed",
	)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	require.Contains(t, first.Body.String(), "cached-safe-memory")
	require.Contains(t, first.Body.String(), `"complete":true`)
	require.Contains(t, first.Body.String(), `"partial":false`)
	require.NotEmpty(t, fixture.handler.graphCache)

	insertTestMemory(t, fixture.sql, "post-cache-sql-only-ghost", "ghost-domain")
	second := requestLocalProjectionRoute(
		t, fixture, "/v1/dashboard/memory/graph?status=committed",
	)
	require.Equal(t, http.StatusOK, second.Code, second.Body.String())
	require.Contains(t, second.Body.String(), "cached-safe-memory")
	require.Contains(t, second.Body.String(), `"complete":false`)
	require.Contains(t, second.Body.String(), `"partial":true`)
	require.Contains(t, second.Body.String(), "1 historical memory")
	require.NotContains(t, second.Body.String(), "post-cache-sql-only-ghost")
	require.NotContains(t, second.Body.String(), "ghost-domain")
	require.NotEqual(t, first.Body.String(), second.Body.String())
}

func TestAppV23CerebrumBroadResponseCannotHidePostAuditQuarantine(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "post-audit-safe-memory", "safe-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "post-audit-safe-memory",
		uint8(store.ClearanceInternal), true,
	)

	stats, activity, projection, err :=
		fixture.handler.requireAppV23DashboardProjectionAudited(context.Background())
	require.NoError(t, err)
	require.NotNil(t, projection)
	require.True(t, projection.Complete)
	require.False(t, projection.Partial)

	// Model a Commit landing after the broad gate's complete audit but before
	// the route's own serving-row walk. The newly observed orphan must force the
	// final response marker to partial rather than reuse the exact snapshot.
	insertTestMemory(t, fixture.sql, "post-audit-sql-only-ghost", "ghost-domain")
	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/memory/list", nil)
	markLocalCEREBRUM(fixture.handler, req)
	req = req.WithContext(context.WithValue(
		req.Context(),
		appV23ProjectionAuditContextKey{},
		appV23ProjectionAuditSnapshot{
			stats: stats, activity: activity, projection: projection,
		},
	))
	rec := httptest.NewRecorder()
	fixture.handler.handleListMemories(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "post-audit-safe-memory")
	require.Contains(t, rec.Body.String(), `"complete":false`)
	require.Contains(t, rec.Body.String(), `"partial":true`)
	require.Contains(t, rec.Body.String(), appV23PartialProjectionMessage)
	require.NotContains(t, rec.Body.String(), "post-audit-sql-only-ghost")
	require.NotContains(t, rec.Body.String(), "ghost-domain")
}

func TestAppV23CerebrumTimelineOmitsFilteredDomainAfterHealthyProjection(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "timeline-filtered-memory", "timeline-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "timeline-filtered-memory",
		uint8(store.ClearanceInternal), true,
	)
	require.NoError(
		t,
		fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background()),
	)
	require.NoError(t, fixture.sql.UpdateDomainTag(
		context.Background(), "timeline-filtered-memory", "hidden-domain",
	))

	rec := requestLocalProjectionRoute(
		t, fixture, "/v1/dashboard/memory/timeline?domain=timeline-domain",
	)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"buckets":[]`)
	require.Contains(t, rec.Body.String(), `"partial":true`)
	require.Contains(t, rec.Body.String(), `"hidden_count":1`)
}

func TestAppV23CerebrumTagReadsRejectSQLOnlyGhostAndValidateExactTarget(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "tag-anchor", "tag-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "tag-anchor",
		uint8(store.ClearanceInternal), true,
	)
	require.NoError(
		t,
		fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background()),
	)

	missing := requestLocalProjectionRoute(
		t, fixture, "/v1/dashboard/memory/not-a-memory/tags",
	)
	require.Equal(t, http.StatusNotFound, missing.Code, missing.Body.String())

	insertTestMemory(t, fixture.sql, "sql-only-tag-ghost", "ghost-domain")
	require.NoError(t, fixture.sql.SetTags(
		context.Background(), "sql-only-tag-ghost", []string{"ghost-tag"},
	))
	for name, path := range map[string]string{
		"all-tags":   "/v1/dashboard/tags",
		"exact-tags": "/v1/dashboard/memory/sql-only-tag-ghost/tags",
		"agent-tags": "/v1/dashboard/network/agents/agent1/tags",
	} {
		t.Run(name, func(t *testing.T) {
			rec := requestLocalProjectionRoute(t, fixture, path)
			require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
			require.NotContains(t, rec.Body.String(), "ghost-tag")
			require.NotContains(t, rec.Body.String(), "ghost-domain")
		})
	}
}

func TestAppV23CerebrumTaskBoardRejectsPostAuditMissingCanonicalTask(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestTask(t, fixture.sql, "missing-board-task", "task-domain", "codex")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "missing-board-task",
		uint8(store.ClearanceInternal), true,
	)
	require.NoError(
		t,
		fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background()),
	)
	tamperAppV23ProjectionRow(
		t, fixture.dbPath,
		"DELETE FROM memories WHERE memory_id = ?",
		"missing-board-task",
	)

	rec := requestLocalProjectionRoute(t, fixture, "/v1/dashboard/tasks?all=true")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), `"tasks":[]`)
}

func TestAppV23CerebrumAgentMemoryCountsReauditAfterHealthyProjection(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	require.NoError(t, fixture.sql.CreateAgent(context.Background(), &store.AgentEntry{
		AgentID: "agent1",
		Name:    "Memory count agent",
		Role:    store.AppV23RoleMember,
		Status:  "active",
	}))
	insertTestMemory(t, fixture.sql, "agent-count-memory", "agent-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "agent-count-memory",
		uint8(store.ClearanceInternal), true,
	)
	require.NoError(
		t,
		fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background()),
	)
	tamperAppV23ProjectionRow(
		t, fixture.dbPath,
		"UPDATE memories SET submitting_agent = ? WHERE memory_id = ?",
		"forged-agent", "agent-count-memory",
	)

	for name, path := range map[string]string{
		"list":   "/v1/dashboard/network/agents",
		"detail": "/v1/dashboard/network/agents/agent1",
	} {
		t.Run(name, func(t *testing.T) {
			rec := requestLocalProjectionRoute(t, fixture, path)
			require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
			require.NotContains(t, rec.Body.String(), `"memory_count":0`)
			require.NotContains(t, rec.Body.String(), "forged-agent")
		})
	}
}

func TestAppV23CerebrumRoutesCompleteRequiredUncheckedAuditBeforeServing(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "legacy-before-full-audit", "legacy-domain")
	require.NoError(t, fixture.sql.UpdateStatus(
		context.Background(), "legacy-before-full-audit",
		memory.StatusCommitted, time.Now().UTC(),
	))
	record, err := fixture.sql.GetMemory(context.Background(), "legacy-before-full-audit")
	require.NoError(t, err)
	require.NoError(t, fixture.badger.SetMemoryHash(
		record.MemoryID, nil, string(record.Status),
	))
	require.NoError(t, fixture.badger.SetMemoryDomain(record.MemoryID, record.DomainTag))
	require.NoError(t, fixture.badger.SetMemoryAuthor(record.MemoryID, record.SubmittingAgent))
	require.NoError(t, fixture.badger.SetMemoryClassification(
		record.MemoryID, uint8(store.ClearanceInternal),
	))

	require.NoError(t, fixture.handler.validateAppV23DashboardRecord(record))
	health := fixture.badger.CanonicalMemoryProjectionHealth()
	require.False(t, health.Checked)
	require.True(t, health.Required)
	require.False(t, health.OK)
	require.False(t, health.Quarantined)

	rec := requestLocalProjectionRoute(
		t, fixture, "/v1/dashboard/memory/list?status=committed",
	)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "legacy-before-full-audit")
	health = fixture.badger.CanonicalMemoryProjectionHealth()
	require.True(t, health.Checked)
	require.True(t, health.Required)
	require.True(t, health.OK)
	require.False(t, health.Quarantined)
}

func TestAppV23StateSyncedProjectionAuditsCanonicalSubsetHonestly(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	fixture.handler.CanonicalProjectionMissingAllowedFn = func(memoryID string) bool {
		return memoryID == "canonical-remote-history"
	}
	contentHash := sha256.Sum256([]byte("content-canonical-remote-history"))
	require.NoError(t, fixture.badger.SetMemoryHash(
		"canonical-remote-history", contentHash[:], string(memory.StatusCommitted),
	))
	require.NoError(t, fixture.badger.SetMemoryDomain(
		"canonical-remote-history", "remote-history",
	))
	require.NoError(t, fixture.badger.SetMemoryAuthor(
		"canonical-remote-history", "remote-agent",
	))
	require.NoError(t, fixture.badger.SetMemoryAuthorPrincipal(
		"canonical-remote-history", "remote-agent",
	))
	require.NoError(t, fixture.badger.SetMemoryClassification(
		"canonical-remote-history", uint8(store.ClearanceInternal),
	))

	require.NoError(t, fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background()))
	health := fixture.badger.CanonicalMemoryProjectionHealth()
	require.True(t, health.Checked)
	require.True(t, health.Required)
	require.True(t, health.OK)
	require.False(t, health.Quarantined)
	require.Equal(t, store.CanonicalMemoryProjectionSubset, health.State)

	stats := requestLocalProjectionRoute(t, fixture, "/v1/dashboard/stats")
	require.Equal(t, http.StatusOK, stats.Code, stats.Body.String())
	require.Contains(t, stats.Body.String(), `"total_memories":0`)

	// A later canonical memory was not named by the sealed state-sync baseline,
	// so losing its local SQL projection must fail closed.
	postSyncHash := sha256.Sum256([]byte("content-post-sync-local"))
	require.NoError(t, fixture.badger.SetMemoryHash(
		"post-sync-local", postSyncHash[:], string(memory.StatusCommitted),
	))
	require.NoError(t, fixture.badger.SetMemoryDomain("post-sync-local", "local-after-sync"))
	require.NoError(t, fixture.badger.SetMemoryAuthor("post-sync-local", "local-agent"))
	require.NoError(t, fixture.badger.SetMemoryAuthorPrincipal("post-sync-local", "local-agent"))
	require.NoError(t, fixture.badger.SetMemoryClassification(
		"post-sync-local", uint8(store.ClearanceInternal),
	))
	err := fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background())
	require.ErrorContains(t, err, "projection is unavailable")
	health = fixture.badger.CanonicalMemoryProjectionHealth()
	require.False(t, health.OK)
	require.True(t, health.Quarantined)

	insertTestMemoryWithAgent(
		t, fixture.sql, "post-sync-local", "local-after-sync", "local-agent",
	)
	require.NoError(t, fixture.sql.UpdateStatus(
		context.Background(), "post-sync-local", memory.StatusCommitted, time.Now().UTC(),
	))
	require.NoError(t, fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background()))

	export := requestLocalProjectionRoute(t, fixture, "/v1/dashboard/export")
	require.Equal(t, http.StatusServiceUnavailable, export.Code, export.Body.String())
	require.NotContains(t, export.Header().Get("Content-Disposition"), "sage-backup-")

	// A DB rollback/wipe after the post-sync memory was projected cannot be
	// excused by the historical baseline.
	tamperAppV23ProjectionRow(
		t, fixture.dbPath,
		"DELETE FROM memories WHERE memory_id = ?",
		"post-sync-local",
	)
	err = fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background())
	require.ErrorContains(t, err, "projection is unavailable")
	health = fixture.badger.CanonicalMemoryProjectionHealth()
	require.False(t, health.OK)
	require.True(t, health.Quarantined)
	insertTestMemoryWithAgent(
		t, fixture.sql, "post-sync-local", "local-after-sync", "local-agent",
	)
	require.NoError(t, fixture.sql.UpdateStatus(
		context.Background(), "post-sync-local", memory.StatusCommitted, time.Now().UTC(),
	))
	require.NoError(t, fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background()))

	// A SQL row that does exist is still required to match canonical state; the
	// subset exception never turns SQL into an authority.
	insertTestMemory(t, fixture.sql, "subset-sql-ghost", "ghost-domain")
	err = fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background())
	require.ErrorContains(t, err, "projection is unavailable")
	health = fixture.badger.CanonicalMemoryProjectionHealth()
	require.False(t, health.OK)
	require.True(t, health.Quarantined)
	require.Equal(t, store.CanonicalMemoryProjectionQuarantined, health.State)
}

func TestAppV23EncryptedStateSyncSubsetRejectsPostBaselineRollback(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, true)
	fixture.handler.CanonicalProjectionMissingAllowedFn = func(memoryID string) bool {
		return memoryID == "encrypted-snapshot-history"
	}
	historyHash := sha256.Sum256([]byte("content-encrypted-snapshot-history"))
	require.NoError(t, fixture.badger.SetMemoryHash(
		"encrypted-snapshot-history", historyHash[:], string(memory.StatusCommitted),
	))
	require.NoError(t, fixture.badger.SetMemoryDomain(
		"encrypted-snapshot-history", "encrypted-history",
	))
	require.NoError(t, fixture.badger.SetMemoryAuthor(
		"encrypted-snapshot-history", "remote-agent",
	))
	require.NoError(t, fixture.badger.SetMemoryAuthorPrincipal(
		"encrypted-snapshot-history", "remote-agent",
	))
	require.NoError(t, fixture.badger.SetMemoryClassification(
		"encrypted-snapshot-history", uint8(store.ClearanceInternal),
	))

	insertTestMemory(t, fixture.sql, "encrypted-post-sync", "encrypted-local")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "encrypted-post-sync",
		uint8(store.ClearanceInternal), true,
	)
	require.NoError(t, fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background()))
	require.Equal(
		t,
		store.CanonicalMemoryProjectionSubset,
		fixture.badger.CanonicalMemoryProjectionHealth().State,
	)

	tamperAppV23ProjectionRow(
		t, fixture.dbPath,
		"DELETE FROM memories WHERE memory_id = ?",
		"encrypted-post-sync",
	)
	err := fixture.handler.AuditAppV23CanonicalMemoryProjection(context.Background())
	require.ErrorContains(t, err, "projection is unavailable")
	health := fixture.badger.CanonicalMemoryProjectionHealth()
	require.False(t, health.OK)
	require.True(t, health.Quarantined)
}

func TestAppV23CerebrumMemoryRoutesUseCanonicalProjectionWhenVaultUnlocked(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, true)
	insertTestMemory(t, fixture.sql, "encrypted-canonical", "encrypted-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "encrypted-canonical",
		uint8(store.ClearanceInternal), true,
	)

	now := time.Now().UTC()
	routes := map[string]string{
		"list":    "/v1/dashboard/memory/list?status=proposed",
		"search":  "/v1/dashboard/memory/list?q=content&status=proposed",
		"export":  "/v1/dashboard/export",
		"graph":   "/v1/dashboard/memory/graph?status=proposed",
		"related": "/v1/dashboard/memory/encrypted-canonical/related",
		"stats":   "/v1/dashboard/stats",
		"timeline": fmt.Sprintf(
			"/v1/dashboard/memory/timeline?from=%s&to=%s&bucket=hour",
			now.Add(-time.Hour).Format(time.RFC3339),
			now.Add(time.Hour).Format(time.RFC3339),
		),
	}
	for name, path := range routes {
		t.Run(name, func(t *testing.T) {
			rec := requestLocalProjectionRoute(t, fixture, path)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			switch name {
			case "list", "search", "export", "graph", "related":
				require.Contains(t, rec.Body.String(), "encrypted-canonical")
			case "stats":
				require.Contains(t, rec.Body.String(), "encrypted-domain")
			}
		})
	}
}

func TestAppV23CerebrumExportPreflightPreventsPartialBackup(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "canonical-before-ghost", "backup-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "canonical-before-ghost",
		uint8(store.ClearanceInternal), true,
	)
	insertTestMemory(t, fixture.sql, "later-sql-only-ghost", "backup-domain")

	rec := requestLocalProjectionRoute(t, fixture, "/v1/dashboard/export")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), "canonical-before-ghost")
	require.NotContains(t, rec.Body.String(), "later-sql-only-ghost")
	require.NotContains(t, rec.Header().Get("Content-Disposition"), "sage-backup-")
}

func TestAppV23CerebrumExportStreamsSealedSnapshotAcrossConcurrentProjectionMutation(
	t *testing.T,
) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "canonical-first", "backup-domain")
	tamperAppV23ProjectionRow(
		t, fixture.dbPath,
		"UPDATE memories SET created_at = ? WHERE memory_id = ?",
		"2026-07-29T22:11:01Z", "canonical-first",
	)
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "canonical-first",
		uint8(store.ClearanceInternal), true,
	)
	insertTestMemory(t, fixture.sql, "canonical-after-gap", "backup-domain")
	tamperAppV23ProjectionRow(
		t, fixture.dbPath,
		"UPDATE memories SET created_at = ? WHERE memory_id = ?",
		"2026-07-29T22:11:03Z", "canonical-after-gap",
	)
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "canonical-after-gap",
		uint8(store.ClearanceInternal), true,
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/export", nil)
	markLocalCEREBRUM(fixture.handler, req)
	rec := &headerMutationRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		mutate: func() {
			// The old two-pass implementation reached Header after canonical
			// preflight but before its second live SQL walk. Put an unpublished
			// row between the two canonical rows: that implementation emitted
			// only canonical-first under HTTP 200, a plausible truncated backup.
			insertTestMemory(t, fixture.sql, "inter-pass-sql-ghost", "backup-domain")
			tamperAppV23ProjectionRow(
				t, fixture.dbPath,
				"UPDATE memories SET created_at = ? WHERE memory_id = ?",
				"2026-07-29T22:11:02Z", "inter-pass-sql-ghost",
			)
		},
	}
	fixture.handler.handleExport(rec, req)

	require.True(t, rec.mutated)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, fmt.Sprint(rec.Body.Len()), rec.Header().Get("Content-Length"))
	require.NotContains(t, rec.Body.String(), "inter-pass-sql-ghost")

	lines := bytes.Split(bytes.TrimSpace(rec.Body.Bytes()), []byte("\n"))
	require.Len(t, lines, 2, "the sealed response must not lose the row after the mutation gap")
	var first, second memory.MemoryRecord
	require.NoError(t, json.Unmarshal(lines[0], &first))
	require.NoError(t, json.Unmarshal(lines[1], &second))
	require.Equal(t, "canonical-first", first.MemoryID)
	require.Equal(t, "canonical-after-gap", second.MemoryID)
}

func TestAppV23CerebrumBroadListOmitsTamperedProjectionFields(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tamper func(*testing.T, appV23ProjectionRouteFixture)
	}{
		{
			name: "domain",
			tamper: func(t *testing.T, fixture appV23ProjectionRouteFixture) {
				require.NoError(t, fixture.sql.UpdateDomainTag(
					context.Background(), "tampered-record", "other-domain",
				))
			},
		},
		{
			name: "status",
			tamper: func(t *testing.T, fixture appV23ProjectionRouteFixture) {
				require.NoError(t, fixture.sql.UpdateStatus(
					context.Background(), "tampered-record",
					memory.StatusCommitted, time.Now().UTC(),
				))
			},
		},
		{
			name: "content",
			tamper: func(t *testing.T, fixture appV23ProjectionRouteFixture) {
				tamperAppV23ProjectionRow(
					t, fixture.dbPath,
					"UPDATE memories SET content = ? WHERE memory_id = ?",
					"tampered plaintext", "tampered-record",
				)
			},
		},
		{
			name: "author",
			tamper: func(t *testing.T, fixture appV23ProjectionRouteFixture) {
				tamperAppV23ProjectionRow(
					t, fixture.dbPath,
					"UPDATE memories SET submitting_agent = ? WHERE memory_id = ?",
					"forged-agent", "tampered-record",
				)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newAppV23ProjectionRouteFixture(t, false)
			insertTestMemory(t, fixture.sql, "tampered-record", "canonical-domain")
			publishAppV23DashboardRecord(
				t, fixture.sql, fixture.badger, "tampered-record",
				uint8(store.ClearanceInternal), true,
			)
			tc.tamper(t, fixture)

			rec := requestLocalProjectionRoute(
				t, fixture, "/v1/dashboard/memory/list",
			)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.Contains(t, rec.Body.String(), `"partial":true`)
			require.Contains(t, rec.Body.String(), `"hidden_count":1`)
			require.NotContains(t, rec.Body.String(), "content-tampered-record")
			require.NotContains(t, rec.Body.String(), "other-domain")
		})
	}
}

func tamperAppV23ProjectionRow(
	t *testing.T,
	dbPath, query string,
	args ...any,
) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	_, err = db.ExecContext(context.Background(), query, args...)
	require.NoError(t, err)
}

func TestAppV23CerebrumRelatedFailsClosedForUnpublishedCandidate(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "canonical-anchor", "related-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "canonical-anchor",
		uint8(store.ClearanceInternal), true,
	)
	insertTestMemory(t, fixture.sql, "unpublished-candidate", "related-domain")
	require.NoError(t, fixture.sql.UpdateStatus(
		context.Background(), "unpublished-candidate", memory.StatusCommitted, time.Now().UTC(),
	))

	rec := requestLocalProjectionRoute(
		t, fixture,
		"/v1/dashboard/memory/canonical-anchor/related",
	)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), "content-unpublished-candidate")
}
