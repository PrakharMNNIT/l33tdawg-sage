package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/web"
)

// connectomeWire connects the REAL production bridge — the same shape as
// cmd/sage-gui/node.go's restServer.OnEvent — to a REAL web.SSEBroadcaster and
// captures the exact bytes a dashboard would receive. The disclosure risk lives
// on the serialized frame, so that is what these tests inspect; a stubbed
// callback would only prove what this package passes to it.
type connectomeWire struct {
	client chan []byte
}

func newConnectomeWire(t *testing.T, srv *Server) *connectomeWire {
	t.Helper()
	b := web.NewSSEBroadcaster()
	ch := b.Subscribe()
	require.NotNil(t, ch)
	t.Cleanup(func() { b.CloseAll() })
	srv.OnEvent = func(eventType, memoryID, domain, content string, data any) {
		b.Broadcast(web.SSEEvent{
			Type: web.EventType(eventType), MemoryID: memoryID,
			Domain: domain, Content: content, Data: data,
		})
	}
	return &connectomeWire{client: ch}
}

// framesOfType drains the subscriber and returns only connectome ticks, so an
// unrelated event on the shared stream cannot make a count assertion flaky.
func (w *connectomeWire) framesOfType(t *testing.T, eventType string) []string {
	t.Helper()
	var out []string
	for {
		select {
		case msg := <-w.client:
			frame := string(msg)
			if strings.HasPrefix(frame, "event: "+eventType+"\n") {
				out = append(out, frame)
			}
		case <-time.After(150 * time.Millisecond):
			return out
		}
	}
}

func sendCanonical(t *testing.T, srv *Server, key string) *httptest.ResponseRecorder {
	t.Helper()
	return callMessageJSON(t, messageRouterAs(srv, "agent-sender", true),
		http.MethodPost, "/v1/messages", map[string]any{
			"to_agent": "agent-recipient", "intent": "secret-intent",
			"payload": "secret-payload", "idempotency_key": key,
		})
}

// TestConnectomeActivityEventNameMatchesRegistry links the three unconnected
// copies of this event name. api/rest spells it as a local constant because it
// does not import web; the dashboard spells it again in JavaScript. Nothing in
// the compiler connects them, so a rename in one place leaves the tick emitted
// by the server and subscribed by nobody — fully implemented, fully green, and
// silently dead. That is the failure mode this project has already shipped once.
func TestConnectomeActivityEventNameMatchesRegistry(t *testing.T) {
	require.Equal(t, string(web.EventConnectome), connectomeActivityEvent,
		"the emit-site name must equal web.EventConnectome")

	js, err := os.ReadFile(filepath.Join(moduleRootForConnectome(t), "web", "static", "js", "sse.js"))
	require.NoError(t, err)
	require.Contains(t, string(js), "'"+connectomeActivityEvent+"'",
		"the dashboard must subscribe to the event or the server emits to nobody")
}

// TestConnectomeActivityTickIsContentless drives a real canonical send and
// inspects the serialized frame. The tick invalidates an RBAC-filtered
// snapshot, so it must name neither endpoint, nor the provider, intent or
// payload: this stream fans out identically to every client, while the snapshot
// withholds edges per caller.
func TestConnectomeActivityTickIsContentless(t *testing.T) {
	srv, sqlite := newPipeServer(t)
	addMessageAgent(t, sqlite, "agent-sender")
	addMessageAgent(t, sqlite, "agent-recipient")
	wire := newConnectomeWire(t, srv)

	require.Equal(t, http.StatusCreated, sendCanonical(t, srv, "tick-1").Code)

	frames := wire.framesOfType(t, connectomeActivityEvent)
	require.Len(t, frames, 1, "exactly one connectome tick per non-replayed send")

	_, dataLine, ok := strings.Cut(frames[0], "data: ")
	require.True(t, ok)
	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(dataLine)), &payload))

	require.Equal(t, connectomeActivityEvent, payload["type"])
	require.Equal(t, "", payload["memory_id"], "the tick carries no identifier")
	for _, forbidden := range []string{"domain", "content", "data"} {
		require.NotContains(t, payload, forbidden,
			"the tick must be contentless; %q present in %s", forbidden, dataLine)
	}
	for k := range payload {
		require.Contains(t, []string{"type", "memory_id"}, k,
			"unexpected key %q in a contentless tick: %s", k, dataLine)
	}
	for _, secret := range []string{"agent-sender", "agent-recipient", "secret-intent", "secret-payload"} {
		require.NotContains(t, frames[0], secret,
			"no send material may reach the global stream; frame:\n%s", frames[0])
	}
}

// TestConnectomeActivityDoesNotTickOnReplay pins the non-replayed condition.
// An idempotent retry moved nothing, so pulsing for it would animate traffic
// that never happened — and a client retrying after a lost response would make
// the graph lie about its own history.
func TestConnectomeActivityDoesNotTickOnReplay(t *testing.T) {
	srv, sqlite := newPipeServer(t)
	addMessageAgent(t, sqlite, "agent-sender")
	addMessageAgent(t, sqlite, "agent-recipient")
	wire := newConnectomeWire(t, srv)

	require.Equal(t, http.StatusCreated, sendCanonical(t, srv, "replay-1").Code)
	require.Len(t, wire.framesOfType(t, connectomeActivityEvent), 1, "precondition: first send ticks")

	require.Equal(t, http.StatusOK, sendCanonical(t, srv, "replay-1").Code, "same key replays")
	require.Empty(t, wire.framesOfType(t, connectomeActivityEvent),
		"an idempotent replay must not tick")
}

// TestConnectomeActivityDoesNotTickOnFailedSend pins the failure direction: a
// send that never became durable must not announce a connectome change.
func TestConnectomeActivityDoesNotTickOnFailedSend(t *testing.T) {
	srv, sqlite := newPipeServer(t)
	addMessageAgent(t, sqlite, "agent-sender")
	wire := newConnectomeWire(t, srv)

	rr := callMessageJSON(t, messageRouterAs(srv, "agent-sender", true),
		http.MethodPost, "/v1/messages", map[string]any{
			"to_agent": "agent-nonexistent", "payload": "secret-payload",
			"idempotency_key": "bad-1",
		})
	require.NotEqual(t, http.StatusCreated, rr.Code, "precondition: the send is rejected")
	require.Empty(t, wire.framesOfType(t, connectomeActivityEvent),
		"a rejected send must not tick")
}

// moduleRootForConnectome walks up to the directory holding go.mod, so the
// dashboard script is found regardless of the package the test runs from.
func moduleRootForConnectome(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	require.NoError(t, err)
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "no go.mod found above the rest package")
		dir = parent
	}
}
