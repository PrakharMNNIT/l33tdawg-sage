package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/tx"
)

func requirePayloadFreeAccessInvalidation(t *testing.T, events <-chan []byte) {
	t.Helper()
	select {
	case frame := <-events:
		require.True(t, strings.HasPrefix(string(frame), "event: access\n"), string(frame))
		_, dataLine, ok := strings.Cut(string(frame), "data: ")
		require.True(t, ok)
		var payload map[string]any
		require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(dataLine)), &payload))
		require.Equal(t, map[string]any{
			"type": "access", "memory_id": "",
		}, payload, "the identity-free dashboard stream must carry no access-group data")
	case <-time.After(time.Second):
		t.Fatal("committed access-group mutation did not invalidate dashboard projections")
	}
}

func requireNoAccessInvalidation(t *testing.T, events <-chan []byte) {
	t.Helper()
	select {
	case frame := <-events:
		t.Fatalf("uncommitted access-group mutation emitted an event: %s", frame)
	default:
	}
}

func TestCommittedAppV23AccessGroupMutationEmitsPayloadFreeInvalidation(t *testing.T) {
	tests := []struct {
		name   string
		method string
		body   map[string]any
		invoke func(*DashboardHandler, http.ResponseWriter, *http.Request)
		check  func(*testing.T, *tx.ParsedTx)
	}{
		{
			name:   "put",
			method: http.MethodPut,
			body: map[string]any{
				"name": "Sentinel private group", "members": []string{}, "expected_revision": 0,
			},
			invoke: func(h *DashboardHandler, w http.ResponseWriter, r *http.Request) {
				h.handleAppV23AccessGroupPut().ServeHTTP(w, r)
			},
			check: func(t *testing.T, parsed *tx.ParsedTx) {
				require.False(t, parsed.AccessGroupMutate.Delete)
			},
		},
		{
			name:   "delete",
			method: http.MethodDelete,
			body:   map[string]any{"expected_revision": 1},
			invoke: func(h *DashboardHandler, w http.ResponseWriter, r *http.Request) {
				h.handleAppV23AccessGroupDelete().ServeHTTP(w, r)
			},
			check: func(t *testing.T, parsed *tx.ParsedTx) {
				require.True(t, parsed.AccessGroupMutate.Delete)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newAppV23AccessFixture(t)
			var captured *tx.ParsedTx
			var calls atomic.Int32
			rpc := newGrantRPC(t, &captured, &calls)
			defer rpc.Close()
			h := appV23AccessTestHandler(fixture, rpc.URL, nil)
			h.SSE = NewSSEBroadcaster()
			events := h.SSE.Subscribe()
			require.NotNil(t, events)
			defer h.SSE.Unsubscribe(events)

			req := appV23AccessRequest(t, tc.method, "/groups/sentinel-private-group",
				"groupID", "sentinel-private-group", tc.body)
			req = appV23AccessAs(req, fixture.rootID)
			rec := httptest.NewRecorder()
			tc.invoke(h, rec, req)

			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.Equal(t, int32(1), calls.Load())
			require.NotNil(t, captured)
			require.NotNil(t, captured.AccessGroupMutate)
			tc.check(t, captured)
			requirePayloadFreeAccessInvalidation(t, events)
		})
	}
}

func TestRejectedAppV23AccessGroupMutationEmitsNoInvalidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		body   map[string]any
		invoke func(*DashboardHandler, http.ResponseWriter, *http.Request)
	}{
		{
			name:   "put",
			method: http.MethodPut,
			body: map[string]any{
				"name": "Research", "members": []string{}, "expected_revision": 9,
			},
			invoke: func(h *DashboardHandler, w http.ResponseWriter, r *http.Request) {
				h.handleAppV23AccessGroupPut().ServeHTTP(w, r)
			},
		},
		{
			name:   "delete",
			method: http.MethodDelete,
			body:   map[string]any{"expected_revision": 9},
			invoke: func(h *DashboardHandler, w http.ResponseWriter, r *http.Request) {
				h.handleAppV23AccessGroupDelete().ServeHTTP(w, r)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newAppV23AccessFixture(t)
			rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeCommitCheckTxRejected(w, r, 19, "revision conflict")
			}))
			defer rpc.Close()
			h := appV23AccessTestHandler(fixture, rpc.URL, nil)
			h.SSE = NewSSEBroadcaster()
			events := h.SSE.Subscribe()
			require.NotNil(t, events)
			defer h.SSE.Unsubscribe(events)

			req := appV23AccessRequest(t, tc.method, "/groups/research",
				"groupID", "research", tc.body)
			req = appV23AccessAs(req, fixture.rootID)
			rec := httptest.NewRecorder()
			tc.invoke(h, rec, req)

			require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
			requireNoAccessInvalidation(t, events)
		})
	}
}
