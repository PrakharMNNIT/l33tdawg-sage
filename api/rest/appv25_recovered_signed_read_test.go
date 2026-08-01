package rest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/auth"
	"github.com/l33tdawg/sage/internal/store"
)

// TestAppV25RecoveredV1SharedDomainSurvivesMalformedLegacyReadProjection is a
// production-shaped regression for the v11.16.2 read/write asymmetry. The old
// singleton continuity worker could commit a shared record with no owner row,
// then increment the same writer's enrollment revision while adopting a later
// private domain. That leaves the first revision-bound grant stale, but the
// exact recovered group remains the current read/write authority. An obsolete
// H-1 compatibility row must not turn that independently governed authority
// into a generic 403 (or a later per-record 503).
func TestAppV25RecoveredV1SharedDomainSurvivesMalformedLegacyReadProjection(t *testing.T) {
	srv, memories, badger, _ := newRBACTestServer(t)
	srv.SetPostV22ForNextTxAccessor(func() bool { return true })
	srv.SetPostV23ForNextTxAccessor(func() bool { return true })

	pub, priv, err := auth.GenerateKeypair()
	require.NoError(t, err)
	writerID := auth.PublicKeyToAgentID(pub)
	rootID := fmt.Sprintf("%064x", 99101)
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		rootID, "root", store.AppV23RoleAdmin, "", "test", "", 4, 0,
	))
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		writerID, "historical-writer", store.AppV23RoleMember,
		"", "test", "", 2, store.DefaultSelfRegisteredAgentCapabilities,
	))
	require.NoError(t, badger.SetAgentPermissionWithCapabilities(
		writerID, 2,
		`[{"domain":"different-historical-domain","read":true}]`,
		"", "", "", store.DefaultSelfRegisteredAgentCapabilities,
	))
	require.NoError(t, badger.EnsureAppV23Root("signed-recovered-read", 100))

	const recoveredDomain = "sage-federation-rbac"
	firstPlan := sha256.Sum256([]byte("old-v1-shared-continuity"))
	require.NoError(t, badger.ApplyAppV25DomainContinuity(
		recoveredDomain, []string{writerID}, firstPlan[:], 1, 110,
	))
	record, err := badger.GetAppV25DomainContinuity(recoveredDomain)
	require.NoError(t, err)
	require.NotNil(t, record)
	require.True(t, record.Shared)
	require.Empty(t, record.Owner)
	_, err = badger.GetDomainOwner(recoveredDomain)
	require.Error(t, err, "old shared continuity records had no owner row")

	// Reproduce the old singleton worker's later enrollment revision, which
	// makes the first grant stale without revoking its recovered-group policy.
	secondPlan := sha256.Sum256([]byte("later-private-continuity"))
	require.NoError(t, badger.ApplyAppV25DomainContinuity(
		"v11.9-state-sync", []string{writerID}, secondPlan[:], 1, 111,
	))
	stale, err := badger.AppV25AllowsHistoricalDomainWrite(writerID, recoveredDomain)
	require.NoError(t, err)
	require.False(t, stale)
	direct, err := badger.AuthorizeAppV25RecoveredDirectRead(writerID, recoveredDomain)
	require.NoError(t, err)
	require.True(t, direct)

	// The obsolete compatibility projection is intentionally unreadable. It
	// is still consensus state and remains visible to validation/repair, but it
	// cannot veto the exact app-v25 recovered-domain authority above.
	require.NoError(t, badger.SetRawForTest(
		[]byte("appv23:legacy_read:"+writerID), []byte("{"),
	))

	const memoryID = "recovered-signed-readback"
	seedMemory(t, memories, memoryID, writerID, recoveredDomain,
		"the historical writer can read its recovered domain")
	rec := memories.memories[memoryID]

	require.NoError(t, srv.checkDomainAccess(
		context.Background(), writerID, recoveredDomain, "read",
	))
	allowed, err := srv.hasMemoryReadAccess(
		recoveredDomain, writerID, 1, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.True(t, allowed)
	disclosure, err := srv.evaluateAppV23RecordDisclosure(
		writerID, rec, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.True(t, disclosure.Allowed)

	makeSigned := func(method, path string, body []byte) *http.Request {
		t.Helper()
		timestamp := time.Now().Unix()
		signature := auth.SignRequest(priv, method, path, body, timestamp)
		request := httptest.NewRequest(method, path, bytes.NewReader(body))
		request.Header.Set("X-Agent-ID", writerID)
		request.Header.Set("X-Signature", hex.EncodeToString(signature))
		request.Header.Set("X-Timestamp", strconv.FormatInt(timestamp, 10))
		return request
	}

	listPath := "/v1/memory/list?domain=" + recoveredDomain + "&limit=10"
	listOut := httptest.NewRecorder()
	srv.Router().ServeHTTP(listOut, makeSigned(http.MethodGet, listPath, nil))
	require.Equal(t, http.StatusOK, listOut.Code, listOut.Body.String())
	require.Contains(t, listOut.Body.String(), memoryID)

	queryBody, err := json.Marshal(QueryMemoryRequest{
		Embedding: []float32{0.1, 0.2, 0.3},
		DomainTag: recoveredDomain,
		TopK:      10,
	})
	require.NoError(t, err)
	queryOut := httptest.NewRecorder()
	srv.Router().ServeHTTP(queryOut, makeSigned(
		http.MethodPost, "/v1/memory/query", queryBody,
	))
	require.Equal(t, http.StatusOK, queryOut.Code, queryOut.Body.String())
	require.Contains(t, queryOut.Body.String(), memoryID)
}
