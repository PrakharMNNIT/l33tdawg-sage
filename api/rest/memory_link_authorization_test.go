package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/auth"
	"github.com/l33tdawg/sage/internal/store"
)

func TestLinkMemoriesRequiresSourceModifyAndTargetRead(t *testing.T) {
	srv, memStore, badger, agents := newRBACTestServer(t)
	body := []byte(`{"source_id":"source-memory","target_id":"target-memory","link_type":"supports"}`)
	callerPub, callerPriv, err := auth.GenerateKeypair()
	require.NoError(t, err)
	callerID := auth.PublicKeyToAgentID(callerPub)
	req := signedRequestAs(t, callerPriv, callerID, http.MethodPost, "/v1/memory/link", body)

	agents.agents[callerID] = &store.AgentEntry{
		AgentID: callerID,
		Name:    "linker",
		Role:    "member",
		Status:  "active",
	}
	require.NoError(t, badger.RegisterAgent(callerID, "linker", "member", "", "test", "", 1))
	require.NoError(t, badger.SetAgentPermission(callerID, 1, "", "*", "", ""))

	const ownerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	require.NoError(t, badger.RegisterAgent(ownerID, "owner", "member", "", "test", "", 1))
	require.NoError(t, badger.RegisterDomain("source.domain", ownerID, "", 1))
	require.NoError(t, badger.RegisterDomain("target.domain", ownerID, "", 1))
	require.NoError(t, badger.SetAccessGrant("source.domain", callerID, 1, 0, ownerID))
	require.NoError(t, badger.SetAccessGrant("target.domain", callerID, 1, 0, ownerID))
	require.NoError(t, badger.SetMemoryClassification("source-memory", 1))
	require.NoError(t, badger.SetMemoryClassification("target-memory", 1))
	seedMemory(t, memStore, "source-memory", ownerID, "source.domain", "source")
	seedMemory(t, memStore, "target-memory", ownerID, "target.domain", "target")

	denied := httptest.NewRecorder()
	srv.Router().ServeHTTP(denied, req)
	require.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())
	assert.Contains(t, denied.Body.String(), "Modify access")

	require.NoError(t, badger.SetAccessGrant("source.domain", callerID, 3, 0, ownerID))
	allowedBody := []byte(`{"source_id":"source-memory","target_id":"target-memory","link_type":"refines"}`)
	allowedReq := signedRequestAs(t, callerPriv, callerID, http.MethodPost, "/v1/memory/link", allowedBody)
	allowed := httptest.NewRecorder()
	srv.Router().ServeHTTP(allowed, allowedReq)
	require.Equal(t, http.StatusOK, allowed.Code, allowed.Body.String())
}

func TestLinkMemoriesReadAllCapabilityDoesNotGrantModify(t *testing.T) {
	srv, memStore, badger, agents := newRBACTestServer(t)
	srv.SetPostV22ForNextTxAccessor(func() bool { return true })
	body := []byte(`{"source_id":"source-memory","target_id":"target-memory"}`)
	req, callerID := signedRequest(t, http.MethodPost, "/v1/memory/link", body)

	agents.agents[callerID] = &store.AgentEntry{
		AgentID: callerID,
		Name:    "read-all companion",
		Role:    "member",
		Status:  "active",
	}
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		callerID, "read-all companion", "member", "", "test", "", 1,
		store.AgentCapabilityReadAllDomains,
	))
	require.NoError(t, badger.SetAgentPermissionWithCapabilities(
		callerID, 1, "", "*", "", "", store.AgentCapabilityReadAllDomains,
	))

	const ownerID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	require.NoError(t, badger.RegisterAgent(ownerID, "owner", "member", "", "test", "", 1))
	require.NoError(t, badger.RegisterDomain("source.domain", ownerID, "", 1))
	require.NoError(t, badger.RegisterDomain("target.domain", ownerID, "", 1))
	require.NoError(t, badger.SetMemoryClassification("source-memory", 1))
	require.NoError(t, badger.SetMemoryClassification("target-memory", 1))
	seedMemory(t, memStore, "source-memory", ownerID, "source.domain", "source")
	seedMemory(t, memStore, "target-memory", ownerID, "target.domain", "target")

	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "Modify access")
}

func TestLinkMemoriesRequiresActiveVisibleAgent(t *testing.T) {
	srv, memStore, badger, agents := newRBACTestServer(t)
	body := []byte(`{"source_id":"source-memory","target_id":"target-memory"}`)
	req, callerID := signedRequest(t, http.MethodPost, "/v1/memory/link", body)

	agents.agents[callerID] = &store.AgentEntry{
		AgentID: callerID,
		Name:    "inactive linker",
		Role:    "member",
		Status:  "inactive",
	}
	require.NoError(t, badger.RegisterAgent(callerID, "inactive linker", "member", "", "test", "", 1))
	seedMemory(t, memStore, "source-memory", callerID, "source.domain", "source")
	seedMemory(t, memStore, "target-memory", callerID, "target.domain", "target")

	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "Active agent")
}

func TestLinkMemoriesRejectsExpiredModifyGrant(t *testing.T) {
	srv, memStore, badger, agents := newRBACTestServer(t)
	body := []byte(`{"source_id":"source-memory","target_id":"target-memory"}`)
	req, callerID := signedRequest(t, http.MethodPost, "/v1/memory/link", body)

	agents.agents[callerID] = &store.AgentEntry{
		AgentID: callerID,
		Name:    "linker",
		Role:    "member",
		Status:  "active",
	}
	require.NoError(t, badger.RegisterAgent(callerID, "linker", "member", "", "test", "", 1))
	require.NoError(t, badger.SetAgentPermission(callerID, 1, "", "*", "", ""))

	const ownerID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	require.NoError(t, badger.RegisterAgent(ownerID, "owner", "member", "", "test", "", 1))
	require.NoError(t, badger.RegisterDomain("source.domain", ownerID, "", 1))
	require.NoError(t, badger.RegisterDomain("target.domain", ownerID, "", 1))
	require.NoError(t, badger.SetAccessGrant("source.domain", callerID, 3, time.Now().Add(-time.Minute).Unix(), ownerID))
	require.NoError(t, badger.SetAccessGrant("target.domain", callerID, 1, 0, ownerID))
	require.NoError(t, badger.SetMemoryClassification("source-memory", 1))
	require.NoError(t, badger.SetMemoryClassification("target-memory", 1))
	seedMemory(t, memStore, "source-memory", ownerID, "source.domain", "source")
	seedMemory(t, memStore, "target-memory", ownerID, "target.domain", "target")

	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "Modify access")
}
