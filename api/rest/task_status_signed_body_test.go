package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// An omitted task_status on a new task must be rejected BEFORE any broadcast.
//
// This previously defaulted to "planned" by mutating the request AFTER the
// caller's signature covered the body. The transaction that then went to
// consensus no longer matched what was signed, so the app-v26 proof check —
// which rebuilds the expected transaction from the signed bytes — rejected it
// as "agent proof does not match the submitted action". A signed caller had no
// way to write a task at all, and the error's own remedy text ("update or
// reconnect the client") could not help, because nothing about the client was
// wrong.
//
// The zero-broadcast assertion is the load-bearing one: a 400 that still
// broadcast would have spent consensus work on a transaction guaranteed to be
// rejected.
func TestSignedTaskSubmitRejectsOmittedStatusBeforeBroadcast(t *testing.T) {
	fixture := newAppV23RESTRouteFixture(t)
	broadcasts := 0
	comet := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		broadcasts++
	}))
	t.Cleanup(comet.Close)
	fixture.server.cometbftRPC = comet.URL

	body := []byte(`{"content":"omitted status","memory_type":"task","domain_tag":"member.home","confidence_score":0.9}`)
	req := appV23SignedRESTRouteRequest(
		t, fixture, "member", http.MethodPost, "/v1/memory/submit", body, false,
	)
	rec := httptest.NewRecorder()
	fixture.server.Router().ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "task_status is required",
		"the rejection must say what is missing, not surface as a proof mismatch later")
	require.Zero(t, broadcasts,
		"an omitted task_status must never reach consensus; the proof cannot verify")
}

func TestAppV27SignedTaskSubmitCanonicalizesOmittedStatus(t *testing.T) {
	fixture := newAppV23RESTRouteFixture(t)
	fixture.server.SetPostV27ForNextTxAccessor(func() bool { return true })
	comet := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(comet.Close)
	fixture.server.cometbftRPC = comet.URL

	body := []byte(`{"content":"app-v27 omitted status","memory_type":"task","domain_tag":"member.home","confidence_score":0.9}`)
	req := appV23SignedRESTRouteRequest(
		t, fixture, "member", http.MethodPost, "/v1/memory/submit", body, false,
	)
	rec := httptest.NewRecorder()
	fixture.server.Router().ServeHTTP(rec, req)

	require.NotEqual(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.NotContains(t, rec.Body.String(), "task_status is required",
		"post-app-v27 omission must pass the edge guard as canonical planned")
}

func TestAppV27SignedTaskSubmitRejectsExplicitEmptyStatus(t *testing.T) {
	fixture := newAppV23RESTRouteFixture(t)
	fixture.server.SetPostV27ForNextTxAccessor(func() bool { return true })
	body := []byte(`{"content":"explicit empty","memory_type":"task","domain_tag":"member.home","confidence_score":0.9,"task_status":""}`)
	req := appV23SignedRESTRouteRequest(
		t, fixture, "member", http.MethodPost, "/v1/memory/submit", body, false,
	)
	rec := httptest.NewRecorder()
	fixture.server.Router().ServeHTTP(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "Invalid initial task status")
}

// An explicitly signed "planned" must be unaffected by the fail-fast — it is
// the only valid initial status and it must still get past this guard.
func TestSignedTaskSubmitAcceptsExplicitPlannedPastTheGuard(t *testing.T) {
	fixture := newAppV23RESTRouteFixture(t)
	comet := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(comet.Close)
	fixture.server.cometbftRPC = comet.URL

	body := []byte(`{"content":"explicit planned","memory_type":"task","domain_tag":"member.home","confidence_score":0.9,"task_status":"planned"}`)
	req := appV23SignedRESTRouteRequest(
		t, fixture, "member", http.MethodPost, "/v1/memory/submit", body, false,
	)
	rec := httptest.NewRecorder()
	fixture.server.Router().ServeHTTP(rec, req)

	require.NotEqual(t, http.StatusBadRequest, rec.Code,
		"an explicitly signed planned status must not be rejected by the omitted-status guard: %s",
		rec.Body.String())
	require.NotContains(t, rec.Body.String(), "task_status is required")
}

// Any other initial status must still be rejected. The fail-fast must not have
// widened what a new task may enter consensus as.
func TestSignedTaskSubmitStillRejectsNonPlannedInitialStatus(t *testing.T) {
	fixture := newAppV23RESTRouteFixture(t)
	comet := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(comet.Close)
	fixture.server.cometbftRPC = comet.URL

	body := []byte(`{"content":"already running","memory_type":"task","domain_tag":"member.home","confidence_score":0.9,"task_status":"in_progress"}`)
	req := appV23SignedRESTRouteRequest(
		t, fixture, "member", http.MethodPost, "/v1/memory/submit", body, false,
	)
	rec := httptest.NewRecorder()
	fixture.server.Router().ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "Invalid initial task status")
}

// A NON-task memory must be entirely unaffected: it neither requires nor
// accepts a task_status, and the new guard must not have leaked into its path.
func TestNonTaskSubmitUnaffectedByTaskStatusGuard(t *testing.T) {
	fixture := newAppV23RESTRouteFixture(t)
	comet := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(comet.Close)
	fixture.server.cometbftRPC = comet.URL

	body := []byte(`{"content":"an ordinary fact","memory_type":"fact","domain_tag":"member.home","confidence_score":0.9}`)
	req := appV23SignedRESTRouteRequest(
		t, fixture, "member", http.MethodPost, "/v1/memory/submit", body, false,
	)
	rec := httptest.NewRecorder()
	fixture.server.Router().ServeHTTP(rec, req)

	require.NotContains(t, rec.Body.String(), "task_status is required",
		"a non-task memory must never be asked for a task status")
}
