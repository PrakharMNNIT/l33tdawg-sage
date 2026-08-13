package rest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/web"
)

// sentinelPlaintext is deliberately distinctive so a leak cannot hide inside
// ordinary fixture words. If this string reaches a serialized SSE frame, memory
// content that was filtered for ONE caller has been republished to EVERY
// connected dashboard.
const sentinelPlaintext = "ZZQX-SENTINEL-PLAINTEXT-do-not-broadcast-7f3a"

// forbiddenValuesInFrame are VALUES that must never appear anywhere in a
// serialized frame. Deliberately values and not field names: SSEEvent.MemoryID
// is tagged json:"memory_id" WITHOUT omitempty, so the empty KEY is present in
// every frame by construction. Asserting on the key name would fail on a
// correct frame and would have to be loosened — which is exactly how a
// substring check stops meaning anything. The field is instead pinned by exact
// value in assertContentlessFrame below.
var forbiddenValuesInFrame = []string{
	sentinelPlaintext,
	"retrieved",
	"secret-domain",
}

// assertContentlessFrame parses one frame and pins the EXACT permitted shape:
// an event type, an empty memory id, and a count-only content string. Any
// domain, any data payload, or any populated memory id is a disclosure.
func assertContentlessFrame(t *testing.T, frame, wantType string) {
	t.Helper()
	_, dataLine, ok := strings.Cut(frame, "data: ")
	require.True(t, ok, "frame must carry a data line, got:\n%s", frame)
	dataLine = strings.TrimSpace(dataLine)

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(dataLine), &payload),
		"frame data must be valid JSON, got: %s", dataLine)

	require.Equal(t, wantType, payload["type"], "event type")
	require.Equal(t, "", payload["memory_id"],
		"memory_id must be empty: it is authorization-scoped")
	require.NotContains(t, payload, "domain",
		"the caller-derived domain must not cross the global stream")
	require.NotContains(t, payload, "data",
		"no structured result material may cross the global stream")

	content, _ := payload["content"].(string)
	require.Regexp(t, `^[0-9]+ memories$`, content,
		"content may carry a COUNT and nothing else, got %q", content)

	// Nothing beyond the three permitted keys may appear.
	for k := range payload {
		require.Contains(t, []string{"type", "memory_id", "content"}, k,
			"unexpected key %q in a contentless activity frame: %s", k, dataLine)
	}
}

// wireHarness connects the REAL production bridge — the same shape as
// cmd/sage-gui/node.go's restServer.OnEvent — to a REAL web.SSEBroadcaster, and
// captures the exact bytes a subscriber would receive. Asserting on a stubbed
// callback would only prove what this package passes; the disclosure happens at
// the serialized frame, so that is what is inspected.
type wireHarness struct {
	broadcaster *web.SSEBroadcaster
	client      chan []byte
}

func newWireHarness(t *testing.T, srv *Server) *wireHarness {
	t.Helper()
	b := web.NewSSEBroadcaster()
	ch := b.Subscribe()
	require.NotNil(t, ch, "subscriber channel")
	t.Cleanup(func() { b.CloseAll() })

	srv.OnEvent = func(eventType, memoryID, domain, content string, data any) {
		b.Broadcast(web.SSEEvent{
			Type:     web.EventType(eventType),
			MemoryID: memoryID,
			Domain:   domain,
			Content:  content,
			Data:     data,
		})
	}
	return &wireHarness{broadcaster: b, client: ch}
}

// frames drains everything currently queued for the subscriber.
func (h *wireHarness) frames(t *testing.T) []string {
	t.Helper()
	var out []string
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case msg := <-h.client:
			out = append(out, string(msg))
		case <-deadline:
			return out
		default:
			return out
		}
	}
}

func seedSentinelMemory(srv *Server, store *mockMemoryStore) {
	rec := committedFact("mem-sentinel", sentinelPlaintext, 0.95, time.Now())
	rec.DomainTag = "secret-domain"
	store.memories["mem-sentinel"] = rec
	_ = srv
}

// TestRetrievalActivityFramesCarryNoCallerAuthorizedContent is the release-gate
// regression for the plaintext disclosure: recall, text search and hybrid search
// each announced activity on the identity-free global stream while carrying the
// full content, id, domain, confidence and type of every result the CALLER was
// authorized to see. The stock dashboard rendered that content verbatim.
//
// All three paths are driven end to end and the SERIALIZED frames are searched.
func TestRetrievalActivityFramesCarryNoCallerAuthorizedContent(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		body any
	}{
		{"recall", "/v1/memory/query", QueryMemoryRequest{Embedding: []float32{0.1, 0.2, 0.3}, TopK: 10}},
		{"search", "/v1/memory/search", SearchMemoryRequest{Query: "sentinel", TopK: 10}},
		{"hybrid", "/v1/memory/hybrid", HybridSearchMemoryRequest{Query: "sentinel", Embedding: []float32{0.1, 0.2, 0.3}, TopK: 10}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, store, _ := newTestServer(t, "")
			seedSentinelMemory(srv, store)
			h := newWireHarness(t, srv)

			postJSON(t, srv, tc.path, tc.body)

			frames := h.frames(t)
			require.NotEmpty(t, frames,
				"precondition: a retrieval with results must still emit an activity frame — "+
					"otherwise this test proves nothing about what the frame contains")

			joined := strings.Join(frames, "\n")
			for _, forbidden := range forbiddenValuesInFrame {
				require.NotContains(t, joined, forbidden,
					"serialized SSE frame must not carry caller-authorized material (%q); frame was:\n%s",
					forbidden, joined)
			}
			require.Len(t, frames, 1, "exactly one activity frame per retrieval")
			assertContentlessFrame(t, frames[0], tc.name)
		})
	}
}

// TestRetrievalActivityEmitsNothingWithoutResults pins the zero-result path.
// An empty retrieval must not announce anything at all: a frame that fires on
// zero results would disclose that a caller searched and found nothing, and it
// would also mean the count is not the only variable crossing the boundary.
func TestRetrievalActivityEmitsNothingWithoutResults(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		body any
	}{
		{"recall", "/v1/memory/query", QueryMemoryRequest{Embedding: []float32{0.9, 0.9, 0.9}, TopK: 10, MinConfidence: 0.999}},
		{"search", "/v1/memory/search", SearchMemoryRequest{Query: "no-such-term-anywhere", TopK: 10, MinConfidence: 0.999}},
		{"hybrid", "/v1/memory/hybrid", HybridSearchMemoryRequest{Query: "no-such-term-anywhere", Embedding: []float32{0.9, 0.9, 0.9}, TopK: 10, MinConfidence: 0.999}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := newTestServer(t, "")
			h := newWireHarness(t, srv)

			postJSON(t, srv, tc.path, tc.body)

			require.Empty(t, h.frames(t), "a retrieval with no results must emit no activity frame")
		})
	}
}

// TestRetrievalActivityHasNoReplayForLateSubscriber pins the absence of replay.
// The stream has no history and drops on slow delivery, so a subscriber that
// connects AFTER a broadcast must receive nothing. This matters for the
// disclosure question: if frames were replayed, a client connecting later would
// inherit activity from a window it was not present for.
func TestRetrievalActivityHasNoReplayForLateSubscriber(t *testing.T) {
	srv, store, _ := newTestServer(t, "")
	seedSentinelMemory(srv, store)
	h := newWireHarness(t, srv)

	postJSON(t, srv, "/v1/memory/query", QueryMemoryRequest{Embedding: []float32{0.1, 0.2, 0.3}, TopK: 10})
	require.NotEmpty(t, h.frames(t), "precondition: the first subscriber received the frame")

	late := h.broadcaster.Subscribe()
	require.NotNil(t, late)
	select {
	case msg := <-late:
		t.Fatalf("a subscriber that connected after the broadcast must receive nothing, got: %s", msg)
	case <-time.After(200 * time.Millisecond):
	}
}
