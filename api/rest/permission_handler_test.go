package rest

// Regression tests for v6.6.9 — silent-failure on PUT /v1/agent/{id}/permission.
//
// Bug B (Level Up follow-up to v6.6.8): a non-admin caller setting
// `visible_agents="*"` on themselves got 200 + a real tx_hash but
// `network_agents.visible_agents` stayed empty. Two root causes:
//
//  1. REST used broadcast_tx_sync, which only checks CheckTx (signature/
//     nonce) — the FinalizeBlock rejection (code=67 "not an admin") was
//     never propagated to the client.
//  2. The ABCI handler hard-gated permission writes on the on-chain global
//     "admin" Role — meaning only the original deployment-admin identity
//     could ever set permissions, which is wrong for the common case of an
//     agent declaring its own RBAC surface.
//
// Fix:
//   - REST does a fail-fast pre-flight RBAC check using the Badger store,
//     returning 403 instead of broadcasting a doomed tx.
//   - REST switched to broadcast_tx_commit so any FinalizeBlock failure
//     surfaces as an error (defense-in-depth: 403 if access denied,
//     500 otherwise).
//   - ABCI auth model widened to: self-set OR global admin OR org admin
//     of any org the target also belongs to.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/auth"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

// permTestCometMock returns an httptest server impersonating CometBFT's
// broadcast_tx_commit endpoint with a configurable code/log so tests can
// simulate ABCI rejections without standing up the real chain.
func permTestCometMock(t *testing.T, txCode int, txLog string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"check_tx":  map[string]interface{}{"code": 0, "log": ""},
				"tx_result": map[string]interface{}{"code": txCode, "log": txLog},
				"hash":      "PERMTX0001",
				"height":    "1",
			},
		})
	}))
}

// signedRequestAs builds a signed PUT /v1/agent/<targetID>/permission
// request from a specific keypair — used so tests can assert that the
// caller's *agent identity* (not just any signed request) drives the
// pre-flight RBAC outcome.
func signedRequestAs(t *testing.T, priv ed25519.PrivateKey, callerID, method, path string, body []byte) *http.Request {
	t.Helper()
	ts := time.Now().Unix()
	sig := auth.SignRequest(priv, method, path, body, ts)

	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Header.Set("X-Agent-ID", callerID)
	req.Header.Set("X-Signature", hex.EncodeToString(sig))
	req.Header.Set("X-Timestamp", strconv.FormatInt(ts, 10))
	return req
}

// setPermBody is the JSON body used by every permission test.
var setPermBody = []byte(`{"clearance":3,"domain_access":"","visible_agents":"*"}`)

// TestSetPermission_SelfSet_Succeeds — agent X sets permission on itself.
// Auth model rule #1 (self-set): no admin role required, no org membership
// required. Returns 200 + tx_hash, and the chain accepts the tx.
func TestSetPermission_SelfSet_Succeeds(t *testing.T) {
	cometMock := permTestCometMock(t, 0, "agent permissions updated")
	defer cometMock.Close()

	srv, _, _ := newTestServer(t, cometMock.URL)
	bs, err := store.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	defer bs.CloseBadger()
	srv.badgerStore = bs

	pub, priv, err := auth.GenerateKeypair()
	require.NoError(t, err)
	agentID := auth.PublicKeyToAgentID(pub)
	require.NoError(t, bs.RegisterAgent(agentID, "self-agent", "member", "", "", "", 1))

	req := signedRequestAs(t, priv, agentID, http.MethodPut, "/v1/agent/"+agentID+"/permission", setPermBody)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "self-set must succeed; body: %s", rr.Body.String())

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "permissions_updated", resp["status"])
	assert.NotEmpty(t, resp["tx_hash"], "must return a tx_hash on success")
}

// TestSetPermission_OrgAdmin_Succeeds — an org admin sets permission on a
// member of that org. Auth model rule #3.
func TestSetPermission_OrgAdmin_Succeeds(t *testing.T) {
	cometMock := permTestCometMock(t, 0, "agent permissions updated")
	defer cometMock.Close()

	srv, _, _ := newTestServer(t, cometMock.URL)
	bs, err := store.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	defer bs.CloseBadger()
	srv.badgerStore = bs

	// Org admin (NOT a global admin — registers as plain "member") and a
	// regular org member; auth comes purely from org-membership role.
	adminPub, adminPriv, err := auth.GenerateKeypair()
	require.NoError(t, err)
	adminID := auth.PublicKeyToAgentID(adminPub)
	require.NoError(t, bs.RegisterAgent(adminID, "org-admin", "member", "", "", "", 1))

	memberPub, _, err := auth.GenerateKeypair()
	require.NoError(t, err)
	memberID := auth.PublicKeyToAgentID(memberPub)
	require.NoError(t, bs.RegisterAgent(memberID, "org-member", "member", "", "", "", 2))

	const orgID = "org-rest-perm-test"
	require.NoError(t, bs.RegisterOrg(orgID, "Perm Test Org", "", adminID, 1))
	require.NoError(t, bs.AddOrgMember(orgID, adminID, 4, "admin", 1))
	require.NoError(t, bs.AddOrgMember(orgID, memberID, 1, "member", 2))

	req := signedRequestAs(t, adminPriv, adminID, http.MethodPut, "/v1/agent/"+memberID+"/permission", setPermBody)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "org-admin set must succeed; body: %s", rr.Body.String())
}

// TestSetPermission_Unauthorized_Returns403 — a random agent tries to set
// permissions on someone they have no relationship with. The REST layer
// must reject with 403 BEFORE broadcasting (no tx_hash returned).
//
// This is the exact silent-failure scenario from the Level Up bug: prior
// to v6.6.9 this returned 200 + tx_hash with empty SQL.
func TestSetPermission_Unauthorized_Returns403(t *testing.T) {
	// The mock would happily return success — but a correctly-implemented
	// REST handler must short-circuit with 403 before even calling it.
	var cometCalled bool
	cometMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cometCalled = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"check_tx":  map[string]interface{}{"code": 0},
				"tx_result": map[string]interface{}{"code": 0},
				"hash":      "SHOULD_NEVER_BE_RETURNED",
				"height":    "1",
			},
		})
	}))
	defer cometMock.Close()

	srv, _, _ := newTestServer(t, cometMock.URL)
	bs, err := store.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	defer bs.CloseBadger()
	srv.badgerStore = bs

	callerPub, callerPriv, err := auth.GenerateKeypair()
	require.NoError(t, err)
	callerID := auth.PublicKeyToAgentID(callerPub)
	require.NoError(t, bs.RegisterAgent(callerID, "random-caller", "member", "", "", "", 1))

	targetPub, _, err := auth.GenerateKeypair()
	require.NoError(t, err)
	targetID := auth.PublicKeyToAgentID(targetPub)
	require.NoError(t, bs.RegisterAgent(targetID, "victim", "member", "", "", "", 2))

	req := signedRequestAs(t, callerPriv, callerID, http.MethodPut, "/v1/agent/"+targetID+"/permission", setPermBody)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code, "unauthorized cross-agent set must return 403; body: %s", rr.Body.String())
	assert.False(t, cometCalled, "REST must NOT broadcast when pre-flight RBAC denies the request")

	// The response must be RFC7807-style and must NOT include a tx_hash —
	// that's the exact misleading shape that caused the Level Up bug.
	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	_, hasTxHash := resp["tx_hash"]
	assert.False(t, hasTxHash, "403 response must NOT include a tx_hash")
}

// TestSetPermission_GlobalAdmin_Succeeds — backward-compat: an agent
// registered with on-chain Role="admin" can still set permissions on
// anyone. This preserves the legacy deployment-admin path so existing
// single-org installs keep working.
func TestSetPermission_GlobalAdmin_Succeeds(t *testing.T) {
	cometMock := permTestCometMock(t, 0, "ok")
	defer cometMock.Close()

	srv, _, _ := newTestServer(t, cometMock.URL)
	bs, err := store.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	defer bs.CloseBadger()
	srv.badgerStore = bs

	adminPub, adminPriv, err := auth.GenerateKeypair()
	require.NoError(t, err)
	adminID := auth.PublicKeyToAgentID(adminPub)
	require.NoError(t, bs.RegisterAgent(adminID, "deployment-admin", "admin", "", "", "", 1))

	targetPub, _, err := auth.GenerateKeypair()
	require.NoError(t, err)
	targetID := auth.PublicKeyToAgentID(targetPub)
	require.NoError(t, bs.RegisterAgent(targetID, "subject", "member", "", "", "", 2))

	req := signedRequestAs(t, adminPriv, adminID, http.MethodPut, "/v1/agent/"+targetID+"/permission", setPermBody)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "global-admin must keep working; body: %s", rr.Body.String())
}

// TestSetPermission_PartialUpdate_PreservesClearance is the v6.8.4 regression
// for Bug 2 in the network_agents-mirror-blanking bundle. Before the fix,
// calling PUT /v1/agent/{id}/permission with only `visible_agents` in the
// body silently demoted clearance to 1 (the Go zero-value default in the
// handler), which then propagated through ABCI -> BadgerDB -> SQL mirror and
// explained why levelup pipeline agents ended up with
// network_agents.clearance=1 even after admins had granted them clearance=4.
//
// PATCH semantics: missing fields must preserve the on-chain value, not
// reset it to a default. The wire format (tx.AgentSetPermission) is still
// full-replace, so the REST handler backfills missing fields from the
// existing BadgerDB record before signing the tx.
func TestSetPermission_PartialUpdate_PreservesClearance(t *testing.T) {
	var capturedTxHex string
	cometMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTxHex = r.URL.Query().Get("tx")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"check_tx":  map[string]interface{}{"code": 0},
				"tx_result": map[string]interface{}{"code": 0},
				"hash":      "PERMTX_PATCH",
				"height":    "1",
			},
		})
	}))
	defer cometMock.Close()

	srv, _, _ := newTestServer(t, cometMock.URL)
	bs, err := store.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	defer bs.CloseBadger()
	srv.badgerStore = bs

	pub, priv, err := auth.GenerateKeypair()
	require.NoError(t, err)
	agentID := auth.PublicKeyToAgentID(pub)

	// Pre-seed: the agent already has clearance=4, a domain access list,
	// and an existing org. The bridge's partial PATCH must not stomp any
	// of these.
	require.NoError(t, bs.RegisterAgent(agentID, "self-agent", "member", "", "", "", 1))
	require.NoError(t, bs.SetAgentPermission(agentID, 4, `["crypto","ot_ics"]`, "", "org-A", "dept-B"))

	// Body mirrors what the LevelUp bridge actually sends at startup —
	// only visible_agents, nothing else.
	body := []byte(`{"visible_agents":"*"}`)
	req := signedRequestAs(t, priv, agentID, http.MethodPut, "/v1/agent/"+agentID+"/permission", body)

	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "partial PUT must succeed; body: %s", rr.Body.String())

	require.NotEmpty(t, capturedTxHex, "broadcast should have been invoked")
	parsed, err := tx.DecodeTx(decodeHexTxParam(t, capturedTxHex))
	require.NoError(t, err)
	require.NotNil(t, parsed.AgentSetPermission)

	assert.Equal(t, "*", parsed.AgentSetPermission.VisibleAgents, "the field caller actually set must be carried verbatim")
	assert.Equal(t, uint8(4), parsed.AgentSetPermission.Clearance, "Bug 2: missing clearance in partial PATCH must NOT demote to default 1")
	assert.Equal(t, `["crypto","ot_ics"]`, parsed.AgentSetPermission.DomainAccess, "Bug 2: missing domain_access must NOT reset to empty string")
	assert.Equal(t, "org-A", parsed.AgentSetPermission.OrgID, "Bug 2: missing org_id must preserve existing org membership")
	assert.Equal(t, "dept-B", parsed.AgentSetPermission.DeptID, "Bug 2: missing dept_id must preserve existing dept membership")
}

func TestSetPermission_UnchangedExplicitZeroOmitsAppV22Extension(t *testing.T) {
	var capturedTxHex string
	cometMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTxHex = r.URL.Query().Get("tx")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"check_tx": map[string]interface{}{"code": 0},
				"tx_result": map[string]interface{}{
					"code": 0,
				},
				"hash":   "PERMTX_LEGACY_ZERO",
				"height": "1",
			},
		})
	}))
	defer cometMock.Close()

	srv, _, _ := newTestServer(t, cometMock.URL)
	bs, err := store.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	defer bs.CloseBadger()
	srv.badgerStore = bs

	pub, priv, err := auth.GenerateKeypair()
	require.NoError(t, err)
	agentID := auth.PublicKeyToAgentID(pub)
	require.NoError(t, bs.RegisterAgent(agentID, "legacy-agent", "member", "", "", "", 1))

	body := []byte(`{"visible_agents":"*","capabilities":0}`)
	req := signedRequestAs(t, priv, agentID, http.MethodPut, "/v1/agent/"+agentID+"/permission", body)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	parsed, err := tx.DecodeTx(decodeHexTxParam(t, capturedTxHex))
	require.NoError(t, err)
	require.NotNil(t, parsed.AgentSetPermission)
	assert.False(t, parsed.AgentSetPermission.CapabilitiesPresent,
		"unchanged zero must use the legacy wire form until app-v22 activates")
}

func TestSetPermission_OmittedCapabilityUsesAbsentWireAndPreservesCurrentInABCI(t *testing.T) {
	var capturedTxHex string
	cometMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTxHex = r.URL.Query().Get("tx")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"check_tx": map[string]interface{}{"code": 0},
				"tx_result": map[string]interface{}{
					"code": 0,
				},
				"hash":   "PERMTX_OMITTED_CAPABILITY",
				"height": "1",
			},
		})
	}))
	defer cometMock.Close()

	srv, _, _ := newTestServer(t, cometMock.URL)
	bs, err := store.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	defer bs.CloseBadger()
	srv.badgerStore = bs
	srv.SetPostV22ForNextTxAccessor(func() bool { return true })

	pub, _, err := auth.GenerateKeypair()
	require.NoError(t, err)
	agentID := auth.PublicKeyToAgentID(pub)
	require.NoError(t, bs.RegisterAgentWithCapabilities(
		agentID, "restricted-agent", "member", "", "", "", 1, 15,
	))
	adminPub, adminPriv, err := auth.GenerateKeypair()
	require.NoError(t, err)
	adminID := auth.PublicKeyToAgentID(adminPub)
	require.NoError(t, bs.RegisterAgent(adminID, "global-admin", "admin", "", "", "", 4))

	// Capabilities are intentionally omitted. REST must leave the extension
	// absent; consensus preserves the current mask when the decoded transaction
	// has CapabilitiesPresent=false.
	body := []byte(`{"visible_agents":"*"}`)
	req := signedRequestAs(t, adminPriv, adminID, http.MethodPut, "/v1/agent/"+agentID+"/permission", body)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	parsed, err := tx.DecodeTx(decodeHexTxParam(t, capturedTxHex))
	require.NoError(t, err)
	require.NotNil(t, parsed.AgentSetPermission)
	assert.Zero(t, parsed.AgentSetPermission.Capabilities)
	assert.False(t, parsed.AgentSetPermission.CapabilitiesPresent,
		"an omitted mask must stay absent even when the current consensus mask is nonzero")
}

func TestSetPermission_AppV22AnyChangedFieldRequiresGlobalAdmin(t *testing.T) {
	broadcasts := 0
	cometMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		broadcasts++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"check_tx": map[string]interface{}{"code": 0},
				"tx_result": map[string]interface{}{
					"code": 0,
				},
				"hash": "PERMTX_APPV22",
			},
		})
	}))
	defer cometMock.Close()

	srv, _, _ := newTestServer(t, cometMock.URL)
	bs, err := store.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	defer bs.CloseBadger()
	srv.badgerStore = bs
	srv.SetPostV22ForNextTxAccessor(func() bool { return true })

	orgAdminPub, orgAdminPriv, err := auth.GenerateKeypair()
	require.NoError(t, err)
	orgAdminID := auth.PublicKeyToAgentID(orgAdminPub)
	globalPub, globalPriv, err := auth.GenerateKeypair()
	require.NoError(t, err)
	globalID := auth.PublicKeyToAgentID(globalPub)
	targetPub, _, err := auth.GenerateKeypair()
	require.NoError(t, err)
	targetID := auth.PublicKeyToAgentID(targetPub)

	require.NoError(t, bs.RegisterAgent(orgAdminID, "org-admin", "member", "", "", "", 4))
	require.NoError(t, bs.RegisterAgent(globalID, "global-admin", "admin", "", "", "", 4))
	require.NoError(t, bs.RegisterAgentWithCapabilities(
		targetID, "target", "member", "", "", "", 1,
		store.AgentCapabilityReadAllDomains,
	))
	require.NoError(t, bs.RegisterOrg("shared-org", "Shared", "", orgAdminID, 1))
	require.NoError(t, bs.AddOrgMember("shared-org", orgAdminID, 4, "admin", 1))
	require.NoError(t, bs.AddOrgMember("shared-org", targetID, 1, "member", 1))

	// An unchanged PATCH remains a no-op that existing self/org authorization
	// may submit; app-v22 only reserves actual mutations for global admins.
	noOp := signedRequestAs(
		t, orgAdminPriv, orgAdminID, http.MethodPut,
		"/v1/agent/"+targetID+"/permission",
		[]byte(`{}`),
	)
	noOpRecorder := httptest.NewRecorder()
	srv.Router().ServeHTTP(noOpRecorder, noOp)
	require.Equal(t, http.StatusOK, noOpRecorder.Code, noOpRecorder.Body.String())
	require.Equal(t, 1, broadcasts)

	denied := signedRequestAs(
		t, orgAdminPriv, orgAdminID, http.MethodPut,
		"/v1/agent/"+targetID+"/permission",
		[]byte(`{"clearance":2}`),
	)
	deniedRecorder := httptest.NewRecorder()
	srv.Router().ServeHTTP(deniedRecorder, denied)
	require.Equal(t, http.StatusForbidden, deniedRecorder.Code, deniedRecorder.Body.String())
	require.Contains(t, deniedRecorder.Body.String(), "global administrator")
	require.Equal(t, 1, broadcasts, "denied mutation must not broadcast")

	allowed := signedRequestAs(
		t, globalPriv, globalID, http.MethodPut,
		"/v1/agent/"+targetID+"/permission",
		[]byte(`{"clearance":2}`),
	)
	allowedRecorder := httptest.NewRecorder()
	srv.Router().ServeHTTP(allowedRecorder, allowed)
	require.Equal(t, http.StatusOK, allowedRecorder.Code, allowedRecorder.Body.String())
	require.Equal(t, 2, broadcasts)
}

func TestSetPermission_CapabilityChangeWithoutConsensusStateFailsClosed(t *testing.T) {
	cometMock := permTestCometMock(t, 0, "must not be reached")
	defer cometMock.Close()

	srv, _, _ := newTestServer(t, cometMock.URL)
	srv.badgerStore = nil
	srv.SetPostV22ForNextTxAccessor(func() bool { return true })

	body := []byte(`{"capabilities":15}`)
	req, _ := signedRequest(t, http.MethodPut, "/v1/agent/target-agent/permission", body)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "consensus agent state is unavailable")
}

// TestSetPermission_BootstrapAdminFromSQL_BypassesPreflight is the v6.8.5
// regression for the dev-side 403. When BadgerDB doesn't have a record
// for the caller but the SQL agent store says they're an admin (the
// SQL-but-not-chain divergence found by LevelUp on prod), the REST
// pre-flight must NOT 403 — it has to defer to ABCI which will
// auto-register and process the tx (see ABCI's bootstrapAdminFromSQL
// for the full security invariants).
//
// Without this fix, dev's REST 403s before ABCI ever sees the tx and the
// chain stays broken even though ABCI has the recovery path wired up.
func TestSetPermission_BootstrapAdminFromSQL_BypassesPreflight(t *testing.T) {
	cometMock := permTestCometMock(t, 0, "agent permissions updated")
	defer cometMock.Close()

	srv, _, _ := newTestServer(t, cometMock.URL)
	bs, err := store.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	defer bs.CloseBadger()
	srv.badgerStore = bs

	// Wire a SQL agent store that knows about the caller as 'admin' but
	// the BadgerDB has NO record for them — exactly the dev-chain state.
	agentSt := newMockAgentStore()
	srv.agentStore = agentSt

	adminPub, adminPriv, err := auth.GenerateKeypair()
	require.NoError(t, err)
	adminID := auth.PublicKeyToAgentID(adminPub)
	agentSt.agents[adminID] = &store.AgentEntry{
		AgentID: adminID,
		Name:    "sql-admin",
		Role:    "admin",
		Status:  "active",
	}

	targetPub, _, err := auth.GenerateKeypair()
	require.NoError(t, err)
	targetID := auth.PublicKeyToAgentID(targetPub)
	require.NoError(t, bs.RegisterAgent(targetID, "subject", "member", "", "", "", 2))

	req := signedRequestAs(t, adminPriv, adminID, http.MethodPut, "/v1/agent/"+targetID+"/permission", setPermBody)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "SQL-trusted admin must bypass REST pre-flight 403; body: %s", rr.Body.String())
}

// TestSetPermission_SQLNonAdmin_StillReturns403 is the security boundary
// for v6.8.5: the SQL fallback must ONLY admit role='admin'. Any other
// SQL role (member, observer, blank) must keep returning 403 — the fix
// is for SQL-trusted admins recovering chain state, not a generic
// privilege-escalation primitive.
func TestSetPermission_SQLNonAdmin_StillReturns403(t *testing.T) {
	cometMock := permTestCometMock(t, 0, "should not be reached")
	defer cometMock.Close()

	srv, _, _ := newTestServer(t, cometMock.URL)
	bs, err := store.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	defer bs.CloseBadger()
	srv.badgerStore = bs

	agentSt := newMockAgentStore()
	srv.agentStore = agentSt

	callerPub, callerPriv, err := auth.GenerateKeypair()
	require.NoError(t, err)
	callerID := auth.PublicKeyToAgentID(callerPub)
	// SQL says this caller is a plain member — must NOT trigger the
	// admin-bootstrap fallback.
	agentSt.agents[callerID] = &store.AgentEntry{
		AgentID: callerID,
		Name:    "sql-member",
		Role:    "member",
		Status:  "active",
	}

	targetPub, _, err := auth.GenerateKeypair()
	require.NoError(t, err)
	targetID := auth.PublicKeyToAgentID(targetPub)
	require.NoError(t, bs.RegisterAgent(targetID, "victim", "member", "", "", "", 2))

	req := signedRequestAs(t, callerPriv, callerID, http.MethodPut, "/v1/agent/"+targetID+"/permission", setPermBody)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code, "SQL non-admin must still get 403; body: %s", rr.Body.String())
}

// decodeHexTxParam strips the leading "0x" CometBFT adds to broadcast tx
// query params and decodes the rest.
func decodeHexTxParam(t *testing.T, txHex string) []byte {
	t.Helper()
	if len(txHex) < 2 || txHex[:2] != "0x" {
		t.Fatalf("expected 0x-prefixed tx hex, got %q", txHex)
	}
	out, err := hex.DecodeString(txHex[2:])
	require.NoError(t, err)
	return out
}

// TestSetPermission_FinalizeBlockReject_Surfaces403 — defense-in-depth.
// Even if a caller somehow slips past the REST pre-flight (e.g. their
// auth state changed between REST and consensus, or a future REST bug),
// a non-zero ABCI tx_result code must still produce a non-2xx response.
// Pre-v6.6.9 broadcast_tx_sync would have returned 200 + tx_hash here —
// the silent failure we're closing.
func TestSetPermission_FinalizeBlockReject_Surfaces403(t *testing.T) {
	// Simulate the chain rejecting the tx with the "access denied" log
	// the new ABCI handler emits. broadcastErrorStatus maps that to 403.
	cometMock := permTestCometMock(t, 67, "access denied: caller cannot set permissions on target")
	defer cometMock.Close()

	srv, _, _ := newTestServer(t, cometMock.URL)
	// Run with badgerStore=nil so the REST pre-flight doesn't fire — we
	// need the request to actually reach the broadcast step to verify the
	// error-mapping path. (In production both gates run; this test
	// isolates the second gate.)
	srv.badgerStore = nil

	pub, priv, err := auth.GenerateKeypair()
	require.NoError(t, err)
	agentID := auth.PublicKeyToAgentID(pub)

	req := signedRequestAs(t, priv, agentID, http.MethodPut, "/v1/agent/"+agentID+"/permission", setPermBody)
	rr := httptest.NewRecorder()
	srv.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code, "FinalizeBlock 'access denied' must surface as 403; body: %s", rr.Body.String())

	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	_, hasTxHash := resp["tx_hash"]
	assert.False(t, hasTxHash, "rejected tx must NOT return a tx_hash to the client")
}
