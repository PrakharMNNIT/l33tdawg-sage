package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/stretchr/testify/require"
)

type agentExportContractDriver struct {
	FederationJoinDriver
	exports     map[string]store.FederatedAgentExport
	eligible    map[string]bool
	listErr     error
	setErr      error
	listCalls   int
	setCalls    int
	lastChain   string
	lastAgent   string
	lastState   string
	lastMax     uint8
	lastExclude []string
	lastExpect  int64
}

func (d *agentExportContractDriver) ListFederatedAgentExports(_ context.Context, chain string) ([]store.FederatedAgentExport, error) {
	d.listCalls++
	if d.listErr != nil {
		return nil, d.listErr
	}
	out := make([]store.FederatedAgentExport, 0, len(d.exports))
	for _, export := range d.exports {
		out = append(out, export)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LocalAgentID < out[j].LocalAgentID })
	return out, nil
}

func (d *agentExportContractDriver) SetFederatedAgentExport(
	_ context.Context,
	chain, agentID, state string,
	maxClassification uint8,
	exclusions []string,
	expectedRevision int64,
) (*store.FederatedAgentExport, error) {
	d.setCalls++
	d.lastChain, d.lastAgent, d.lastState = chain, agentID, state
	d.lastMax, d.lastExpect = maxClassification, expectedRevision
	d.lastExclude = append([]string(nil), exclusions...)
	if d.setErr != nil {
		return nil, d.setErr
	}
	if state == store.FederatedAgentExportStateActive && !d.eligible[agentID] {
		return nil, errors.New("only an active ordinary local agent may be exported")
	}
	current, exists := d.exports[agentID]
	if (!exists && expectedRevision != 0) || (exists && current.Revision != expectedRevision) {
		return nil, store.ErrFederatedAgentExportRevisionConflict
	}
	export := store.FederatedAgentExport{
		RemoteChainID:     chain,
		LocalAgentID:      agentID,
		PeerAgentID:       strings.Repeat("c", 64),
		PolicyEpoch:       "epoch-dashboard",
		RemoteCAPin:       strings.Repeat("44", 32),
		MaxClassification: maxClassification,
		DomainExclusions:  append([]string(nil), exclusions...),
		Revision:          expectedRevision + 1,
		State:             state,
	}
	d.exports[agentID] = export
	return &export, nil
}

type agentExportDashboardFixture struct {
	h       *DashboardHandler
	driver  *agentExportContractDriver
	ownerID string
}

func newAgentExportDashboardFixture(t *testing.T, activeAgreement bool) agentExportDashboardFixture {
	t.Helper()
	ctx := context.Background()
	ss, err := store.NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "dashboard-exports.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })
	bs, err := store.NewBadgerStore(filepath.Join(t.TempDir(), "badger"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = bs.CloseBadger() })

	operatorID := strings.Repeat("a", 64)
	ownerID := strings.Repeat("b", 64)
	require.NoError(t, bs.RegisterAgent(operatorID, "operator", "admin", "", "test", "", 1))
	require.NoError(t, bs.RegisterAgent(ownerID, "owner", "member", "", "test", "", 2))
	require.NoError(t, bs.RegisterDomain("owner.work", ownerID, "", 3))
	if activeAgreement {
		require.NoError(t, bs.SetCrossFed(
			"chain-peer", "https://peer:8444", bytes.Repeat([]byte{0x44}, 32),
			4, 0, nil, nil, "active",
		))
	}
	driver := &agentExportContractDriver{
		exports:  make(map[string]store.FederatedAgentExport),
		eligible: map[string]bool{ownerID: true},
	}
	h := NewDashboardHandler(ss, "test")
	h.BadgerStore = bs
	h.NodeOperatorAgentID = operatorID
	h.Federation = driver
	return agentExportDashboardFixture{h: h, driver: driver, ownerID: ownerID}
}

func agentExportDashboardRequest(
	t *testing.T,
	h *DashboardHandler,
	method, body string,
	operator bool,
) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == "" {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader([]byte(body))
	}
	req := withFederationChain(httptest.NewRequest(method,
		"http://localhost/v1/dashboard/federation/connections/chain-peer/agent-exports",
		reader), "chain-peer")
	if operator {
		markLocalCEREBRUM(h, req)
	}
	rr := httptest.NewRecorder()
	if method == http.MethodGet {
		h.handleFedAgentExportsGet(rr, req)
	} else {
		h.handleFedAgentExportsPut(rr, req)
	}
	return rr
}

func TestFederatedAgentExportDashboardIsOperatorOnlyAndAgreementBound(t *testing.T) {
	fixture := newAgentExportDashboardFixture(t, true)
	body := `{"agent_id":"` + fixture.ownerID + `","state":"active","expected_revision":0}`

	for _, method := range []string{http.MethodGet, http.MethodPut} {
		rr := agentExportDashboardRequest(t, fixture.h, method, body, false)
		require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	}
	require.Zero(t, fixture.driver.listCalls)
	require.Zero(t, fixture.driver.setCalls)

	missing := newAgentExportDashboardFixture(t, false)
	get := agentExportDashboardRequest(t, missing.h, http.MethodGet, "", true)
	require.Equal(t, http.StatusConflict, get.Code, get.Body.String())
	put := agentExportDashboardRequest(t, missing.h, http.MethodPut,
		`{"agent_id":"`+missing.ownerID+`","state":"active","expected_revision":0}`, true)
	require.Equal(t, http.StatusConflict, put.Code, put.Body.String())
	require.Zero(t, missing.driver.listCalls)
	require.Zero(t, missing.driver.setCalls)
}

func TestFederatedAgentExportDashboardLifecycleCASAndPolicyFields(t *testing.T) {
	fixture := newAgentExportDashboardFixture(t, true)
	active := `{"agent_id":"` + fixture.ownerID + `","state":"active",` +
		`"max_classification":2,"domain_exclusions":["owner.work.private","owner.work.secret"],` +
		`"expected_revision":0}`
	rr := agentExportDashboardRequest(t, fixture.h, http.MethodPut, active, true)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Equal(t, "chain-peer", fixture.driver.lastChain)
	require.Equal(t, fixture.ownerID, fixture.driver.lastAgent)
	require.Equal(t, store.FederatedAgentExportStateActive, fixture.driver.lastState)
	require.Equal(t, uint8(2), fixture.driver.lastMax)
	require.Equal(t, []string{"owner.work.private", "owner.work.secret"}, fixture.driver.lastExclude)
	require.Zero(t, fixture.driver.lastExpect)

	get := agentExportDashboardRequest(t, fixture.h, http.MethodGet, "", true)
	require.Equal(t, http.StatusOK, get.Code, get.Body.String())
	var listed struct {
		RemoteChainID string                       `json:"remote_chain_id"`
		Exports       []store.FederatedAgentExport `json:"exports"`
	}
	require.NoError(t, json.NewDecoder(get.Body).Decode(&listed))
	require.Equal(t, "chain-peer", listed.RemoteChainID)
	require.Len(t, listed.Exports, 1)
	require.Equal(t, uint8(2), listed.Exports[0].MaxClassification)
	require.Equal(t, []string{"owner.work.private", "owner.work.secret"}, listed.Exports[0].DomainExclusions)

	fixture.driver.eligible[fixture.ownerID] = false
	pause := `{"agent_id":"` + fixture.ownerID + `","state":"paused",` +
		`"max_classification":2,"domain_exclusions":["owner.work.private"],"expected_revision":1}`
	rr = agentExportDashboardRequest(t, fixture.h, http.MethodPut, pause, true)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String(),
		"an operator must be able to pause an export after the owner becomes ineligible")
	require.Equal(t, int64(2), fixture.driver.exports[fixture.ownerID].Revision)
	require.Equal(t, store.FederatedAgentExportStatePaused, fixture.driver.exports[fixture.ownerID].State)

	fixture.driver.eligible[fixture.ownerID] = true
	resume := `{"agent_id":"` + fixture.ownerID + `","state":"active",` +
		`"domain_exclusions":[],"expected_revision":2}`
	rr = agentExportDashboardRequest(t, fixture.h, http.MethodPut, resume, true)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Equal(t, uint8(store.ClearanceTopSecret), fixture.driver.lastMax,
		"omitting the ceiling must use the documented top-secret default")
	require.Equal(t, int64(3), fixture.driver.exports[fixture.ownerID].Revision)

	stale := `{"agent_id":"` + fixture.ownerID + `","state":"paused","expected_revision":1}`
	rr = agentExportDashboardRequest(t, fixture.h, http.MethodPut, stale, true)
	require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), "Refresh")
	require.Equal(t, int64(3), fixture.driver.exports[fixture.ownerID].Revision)
}

func TestFederatedAgentExportDashboardRequiresOwnedDomainAndActiveOrdinaryAgent(t *testing.T) {
	fixture := newAgentExportDashboardFixture(t, true)
	nonOwner := strings.Repeat("d", 64)
	rr := agentExportDashboardRequest(t, fixture.h, http.MethodPut,
		`{"agent_id":"`+nonOwner+`","state":"active","expected_revision":0}`, true)
	require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), "owns a shareable domain")
	require.Zero(t, fixture.driver.setCalls,
		"the dashboard must reject an ownerless selection before federation mutation")

	fixture.driver.eligible[fixture.ownerID] = false
	rr = agentExportDashboardRequest(t, fixture.h, http.MethodPut,
		`{"agent_id":"`+fixture.ownerID+`","state":"active","expected_revision":0}`, true)
	require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), "no longer authorized")
	require.Equal(t, 1, fixture.driver.setCalls,
		"the live federation authority must still reject inactive, Root, or otherwise nonordinary owners")
}

func TestFederatedAgentExportDashboardRejectsInvalidWireIntent(t *testing.T) {
	fixture := newAgentExportDashboardFixture(t, true)
	tests := []string{
		`{"agent_id":"` + fixture.ownerID + `","state":"revoked","expected_revision":0}`,
		`{"agent_id":"` + fixture.ownerID + `","state":"active","expected_revision":-1}`,
		`{"agent_id":"` + fixture.ownerID + `","state":"active","expected_revision":0,"unknown":true}`,
		`{"agent_id":"` + fixture.ownerID + `","state":"active","expected_revision":0`,
	}
	for _, body := range tests {
		rr := agentExportDashboardRequest(t, fixture.h, http.MethodPut, body, true)
		require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	}
	require.Zero(t, fixture.driver.setCalls)
}
