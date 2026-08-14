package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	connectomeSnapshotPath = "/v1/dashboard/network/synapses"
	connectomeEventsPath   = "/v1/dashboard/events"
)

func signedConnectomeRouteRequest(
	t *testing.T,
	fixture appV23DashboardRouteFixture,
	path, actor, remoteAddr, host, origin string,
) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remoteAddr
	req.Host = host
	if origin != "" {
		req.Header.Set("Origin", origin)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
	}
	signAgentRequest(t, req, fixture.keys[actor], nil)
	return req
}

func serveConnectomeRoute(
	t *testing.T,
	fixture appV23DashboardRouteFixture,
	path, actor, remoteAddr, host, origin string,
) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	testRouter(fixture.handler).ServeHTTP(rec, signedConnectomeRouteRequest(
		t, fixture, path, actor, remoteAddr, host, origin,
	))
	return rec
}

// This matrix drives the real RegisterRoutes router. It therefore pins the
// complete production middleware composition for both the authorized snapshot
// and the global contentless invalidation stream, rather than merely testing a
// hand-assembled approximation of the gates.
func TestAppV23ConnectomeRoutesUseOperatorOnlyProductionGuards(t *testing.T) {
	for _, path := range []string{connectomeSnapshotPath, connectomeEventsPath} {
		for _, tc := range []struct {
			name       string
			actor      string
			remoteAddr string
			host       string
			origin     string
			want       int
		}{
			{name: "local Member", actor: "member", remoteAddr: "127.0.0.1:54321", host: "localhost:8080", want: http.StatusForbidden},
			{name: "local Manager", actor: "manager", remoteAddr: "127.0.0.1:54321", host: "localhost:8080", want: http.StatusForbidden},
			{name: "stale Admin", actor: "stale-admin", remoteAddr: "127.0.0.1:54321", host: "localhost:8080", want: http.StatusForbidden},
			{name: "LAN Root", actor: "current-root", remoteAddr: "192.168.1.20:54321", host: "192.168.1.10:8080", want: http.StatusNotFound},
			{name: "LAN Admin", actor: "current-admin", remoteAddr: "192.168.1.20:54321", host: "192.168.1.10:8080", want: http.StatusNotFound},
			{name: "cross-origin Root", actor: "current-root", remoteAddr: "127.0.0.1:54321", host: "localhost:8080", origin: "https://attacker.example", want: http.StatusForbidden},
			{name: "cross-origin Admin", actor: "current-admin", remoteAddr: "127.0.0.1:54321", host: "localhost:8080", origin: "https://attacker.example", want: http.StatusForbidden},
		} {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				fixture := newAppV23DashboardRouteFixture(t)
				rec := serveConnectomeRoute(
					t, fixture, path, tc.actor, tc.remoteAddr, tc.host, tc.origin,
				)
				require.Equal(t, tc.want, rec.Code, rec.Body.String())
				require.Zero(t, fixture.handler.SSE.ClientCount(),
					"a rejected events request must not reach the broadcaster")
			})
		}
	}
}

func TestAppV23CurrentLocalRootAndAdminCanUseConnectomeProductionRoutes(t *testing.T) {
	for _, actor := range []string{"current-root", "current-admin"} {
		t.Run(actor+" snapshot", func(t *testing.T) {
			fixture := newAppV23DashboardRouteFixture(t)
			rec := serveConnectomeRoute(
				t, fixture, connectomeSnapshotPath, actor,
				"127.0.0.1:54321", "localhost:8080", "",
			)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.Contains(t, rec.Body.String(), `"neurons"`)
			require.Contains(t, rec.Body.String(), `"synapses"`)
		})

		t.Run(actor+" events", func(t *testing.T) {
			fixture := newAppV23DashboardRouteFixture(t)
			router := testRouter(fixture.handler)
			ctx, cancel := context.WithCancel(context.Background())
			req := signedConnectomeRouteRequest(
				t, fixture, connectomeEventsPath, actor,
				"127.0.0.1:54321", "localhost:8080", "",
			).WithContext(ctx)
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				defer close(done)
				router.ServeHTTP(rec, req)
			}()

			require.Eventually(t, func() bool {
				return fixture.handler.SSE.ClientCount() == 1
			}, time.Second, 5*time.Millisecond,
				"authorized request must reach the real SSE broadcaster")
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("authorized SSE handler did not stop after context cancellation")
			}
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
			require.Contains(t, rec.Body.String(), ": connected")
			require.Zero(t, fixture.handler.SSE.ClientCount())
		})
	}
}
