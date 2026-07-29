package web

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

func appV23ImportRecord(id, domain string) *memory.MemoryRecord {
	content := "imported " + id
	hash := sha256.Sum256([]byte(content))
	return &memory.MemoryRecord{
		MemoryID: id, Content: content, ContentHash: hash[:],
		MemoryType: memory.TypeObservation, DomainTag: domain,
		ConfidenceScore: 0.85, Status: memory.StatusProposed,
		CreatedAt: time.Now().UTC(),
	}
}

func appV23ImportSQLStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	sqlStore, err := store.NewSQLiteStore(
		context.Background(), filepath.Join(t.TempDir(), "sage.db"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlStore.Close()) })
	return sqlStore
}

func TestAppV23ImportRejectsMemberAndStaleAdminBeforeConsensus(t *testing.T) {
	t.Run("member", func(t *testing.T) {
		fixture := newAppV23AccessFixture(t)
		sqlStore := appV23ImportSQLStore(t)
		h := appV23AccessTestHandler(fixture, "http://unused.invalid", nil)
		h.store = sqlStore
		req := appV23AccessAs(
			httptest.NewRequest(http.MethodPost, "/v1/dashboard/import", nil),
			fixture.agentID,
		)
		rec := httptest.NewRecorder()

		h.processImportRecords(
			rec, req,
			[]*memory.MemoryRecord{appV23ImportRecord("member-import", "companion-home")},
			"sage-backup", nil,
		)

		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		_, err := sqlStore.GetMemory(context.Background(), "member-import")
		require.Error(t, err)
	})

	t.Run("stale admin", func(t *testing.T) {
		fixture := newAppV23AccessFixture(t)
		enrollment, err := fixture.badger.GetAppV23Enrollment(fixture.agentID)
		require.NoError(t, err)
		role, err := fixture.badger.GetAppV23Role(fixture.agentID)
		require.NoError(t, err)
		require.NoError(t, fixture.badger.SetAppV23Policy(
			fixture.rootID, fixture.agentID, store.AppV23RoleAdmin,
			enrollment.Profile, store.AppV23ProfileStandard, 4,
			store.AgentCapabilityReadAllDomains,
			role.Revision, enrollment.Revision, 2,
		))
		_, newRootKey, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		newRootID := agentIDForKey(newRootKey)
		require.NoError(t, fixture.badger.RotateAppV23RootCredential(1, newRootID, 3))

		sqlStore := appV23ImportSQLStore(t)
		h := appV23AccessTestHandler(
			fixture, "http://unused.invalid",
			map[string]ed25519.PrivateKey{newRootID: newRootKey},
		)
		h.store = sqlStore
		req := appV23AccessAs(
			httptest.NewRequest(http.MethodPost, "/v1/dashboard/import", nil),
			fixture.agentID,
		)
		rec := httptest.NewRecorder()

		h.processImportRecords(
			rec, req,
			[]*memory.MemoryRecord{appV23ImportRecord("stale-admin-import", "companion-home")},
			"sage-backup", nil,
		)

		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		_, err = sqlStore.GetMemory(context.Background(), "stale-admin-import")
		require.Error(t, err)
	})
}

func TestAppV23ImportRotatedRootConfirmsImmutablePrincipalProjection(t *testing.T) {
	fixture := newAppV23AccessFixture(t)
	_, newRootKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	newRootID := agentIDForKey(newRootKey)
	require.NoError(t, fixture.badger.RotateAppV23RootCredential(1, newRootID, 3))

	sqlStore := appV23ImportSQLStore(t)
	var calls atomic.Int32
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		raw, decodeErr := hex.DecodeString(strings.TrimPrefix(r.URL.Query().Get("tx"), "0x"))
		require.NoError(t, decodeErr)
		parsed, decodeErr := tx.DecodeTx(raw)
		require.NoError(t, decodeErr)
		require.Equal(t, tx.TxTypeMemorySubmit, parsed.Type)
		require.Equal(t, newRootID, hex.EncodeToString(parsed.AgentPubKey))
		require.NoError(t, sqlStore.InsertMemory(context.Background(), &memory.MemoryRecord{
			MemoryID:        parsed.MemorySubmit.MemoryID,
			SubmittingAgent: newRootID,
			Content:         parsed.MemorySubmit.Content, ContentHash: parsed.MemorySubmit.ContentHash,
			MemoryType: memory.TypeObservation, DomainTag: parsed.MemorySubmit.DomainTag,
			ConfidenceScore: parsed.MemorySubmit.ConfidenceScore,
			Status:          memory.StatusProposed, CreatedAt: time.Now().UTC(),
		}))
		_, _ = fmt.Fprint(w, `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"IMPORT","height":"4"}}`)
	}))
	defer rpc.Close()

	h := appV23AccessTestHandler(
		fixture, rpc.URL,
		map[string]ed25519.PrivateKey{newRootID: newRootKey},
	)
	h.AdminSigningKey = newRootKey
	h.store = sqlStore
	req := appV23AccessAs(
		httptest.NewRequest(http.MethodPost, "/v1/dashboard/import", nil),
		newRootID,
	)
	rec := httptest.NewRecorder()

	h.processImportRecords(
		rec, req,
		[]*memory.MemoryRecord{appV23ImportRecord("rotated-root-import", "companion-home")},
		"sage-backup", nil,
	)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"imported":1`)
	require.Equal(t, int32(1), calls.Load())
	committed, err := sqlStore.GetMemory(context.Background(), "rotated-root-import")
	require.NoError(t, err)
	require.Equal(t, newRootID, committed.SubmittingAgent)
}

func TestAppV23ImportConsensusRejectionNeverWritesOffChain(t *testing.T) {
	fixture := newAppV23AccessFixture(t)
	sqlStore := appV23ImportSQLStore(t)
	var calls atomic.Int32
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = fmt.Fprint(w, `{"result":{"check_tx":{"code":0},"tx_result":{"code":9,"log":"denied"},"hash":"REJECT","height":"2"}}`)
	}))
	defer rpc.Close()

	h := appV23AccessTestHandler(fixture, rpc.URL, nil)
	h.store = sqlStore
	req := appV23AccessAs(
		httptest.NewRequest(http.MethodPost, "/v1/dashboard/import", nil),
		fixture.rootID,
	)
	rec := httptest.NewRecorder()

	h.processImportRecords(
		rec, req,
		[]*memory.MemoryRecord{appV23ImportRecord("rejected-import", "companion-home")},
		"sage-backup", nil,
	)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"skipped":1`)
	require.Equal(t, int32(1), calls.Load())
	_, err := sqlStore.GetMemory(context.Background(), "rejected-import")
	require.Error(t, err)
}
