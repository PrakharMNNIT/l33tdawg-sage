package web

import (
	"bytes"
	"context"
	"crypto/ed25519"
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

func TestAppV23CerebrumBroadRoutesOmitUnpublishedProjection(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "sql-only-ghost", "ghost-domain")

	now := time.Now().UTC()
	routes := map[string]string{
		"list":   "/v1/dashboard/memory/list?status=proposed",
		"search": "/v1/dashboard/memory/list?q=content&status=proposed",
		"graph":  "/v1/dashboard/memory/graph?status=proposed",
		"stats":  "/v1/dashboard/stats",
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
			require.NotContains(t, rec.Body.String(), "content-sql-only-ghost")
			require.NotContains(t, rec.Body.String(), "ghost-domain")
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

func TestAppV23CerebrumPrincipalHashlessProjectionIsQuarantined(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "principal-hashless", "principal-domain")
	require.NoError(t, fixture.sql.UpdateStatus(
		context.Background(), "principal-hashless", memory.StatusCommitted, time.Now().UTC(),
	))
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

	for name, path := range map[string]string{
		"list":  "/v1/dashboard/memory/list?status=committed",
		"stats": "/v1/dashboard/stats",
	} {
		t.Run(name, func(t *testing.T) {
			rec := requestLocalProjectionRoute(t, fixture, path)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.NotContains(t, rec.Body.String(), "principal-hashless")
			require.NotContains(t, rec.Body.String(), "principal-domain")
		})
	}
	export := requestLocalProjectionRoute(t, fixture, "/v1/dashboard/export")
	require.Equal(t, http.StatusServiceUnavailable, export.Code, export.Body.String())
	require.NotContains(t, export.Body.String(), "principal-hashless")
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

func TestAppV23CerebrumRelatedOmitsUnpublishedCandidate(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "canonical-anchor", "related-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "canonical-anchor",
		uint8(store.ClearanceInternal), true,
	)
	insertTestMemory(t, fixture.sql, "unpublished-candidate", "related-domain")

	rec := requestLocalProjectionRoute(
		t, fixture,
		"/v1/dashboard/memory/canonical-anchor/related",
	)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "canonical-anchor")
	require.NotContains(t, rec.Body.String(), "content-unpublished-candidate")
}
