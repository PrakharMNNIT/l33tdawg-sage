package mcp

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testWakeServer(t *testing.T, handler http.HandlerFunc) (*Server, *httptest.Server) {
	t.Helper()
	node := httptest.NewServer(handler)
	t.Cleanup(node.Close)
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return NewServer(node.URL, key), node
}

func flushWrite(t *testing.T, w http.ResponseWriter, format string, args ...any) {
	t.Helper()
	_, err := fmt.Fprintf(w, format, args...)
	require.NoError(t, err)
	w.(http.Flusher).Flush()
}

// The wake source must not reuse the server's request client. That client sets
// Timeout, which bounds the entire request including body reads, so a healthy
// SSE stream would be severed on a fixed timer and the break would masquerade
// as a reconnect. This pins the separation.
func TestClaudeWakeSourceStreamClientHasNoRequestTimeout(t *testing.T) {
	server, _ := testWakeServer(t, func(w http.ResponseWriter, r *http.Request) {})
	source, err := newRESTClaudeWakeSource(server)
	require.NoError(t, err)

	require.Zero(t, source.stream.Timeout, "SSE client must not carry a whole-request timeout")
	require.NotZero(t, server.httpClient.Timeout, "the ordinary request client should still be bounded")
	require.Same(t, server.httpClient.Transport, source.stream.Transport,
		"the stream client must share the server transport so TLS and CA resolution match")
}

// Two runtimes for the same agent must not both believe they own the wake. The
// node supersedes a reconnect from the same consumer and rejects a different
// one, so the consumer ID has to be unique per process.
func TestClaudeWakeSourceConsumerIDIsUniquePerSource(t *testing.T) {
	server, _ := testWakeServer(t, func(w http.ResponseWriter, r *http.Request) {})
	first, err := newRESTClaudeWakeSource(server)
	require.NoError(t, err)
	second, err := newRESTClaudeWakeSource(server)
	require.NoError(t, err)

	require.NotEqual(t, first.consumerID, second.consumerID)
	require.True(t, strings.HasPrefix(first.consumerID, claudeWakeConsumerPrefix))
}

func TestClaudeWakeSourceSignsAndPositionsSubscribe(t *testing.T) {
	type observed struct {
		agentID, signature, timestamp, nonce, accept, query string
	}
	seen := make(chan observed, 1)
	server, _ := testWakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		seen <- observed{
			agentID:   r.Header.Get("X-Agent-ID"),
			signature: r.Header.Get("X-Signature"),
			timestamp: r.Header.Get("X-Timestamp"),
			nonce:     r.Header.Get("X-Nonce"),
			accept:    r.Header.Get("Accept"),
			query:     r.URL.RawQuery,
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	source, err := newRESTClaudeWakeSource(server)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	subscription, err := source.Subscribe(ctx, 42)
	require.NoError(t, err)
	defer func() { require.NoError(t, subscription.Close()) }()

	got := <-seen
	require.NotEmpty(t, got.agentID)
	require.NotEmpty(t, got.signature)
	require.NotEmpty(t, got.timestamp)
	require.NotEmpty(t, got.nonce)
	require.Equal(t, "text/event-stream", got.accept)
	require.Contains(t, got.query, "after_seq=42")
	require.Contains(t, got.query, "consumer_id="+source.consumerID)
}

// A rejected subscribe must surface as an error so the adapter's bounded
// backoff owns retry. A 409 is the lease conflict and must not be swallowed.
func TestClaudeWakeSourceReportsRejectedSubscribe(t *testing.T) {
	for _, status := range []int{http.StatusConflict, http.StatusUnauthorized, http.StatusNotImplemented} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server, _ := testWakeServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"title":"nope"}`))
			})
			source, err := newRESTClaudeWakeSource(server)
			require.NoError(t, err)

			subscription, err := source.Subscribe(context.Background(), 0)
			require.Error(t, err)
			require.Nil(t, subscription)
		})
	}
}

func TestClaudeWakeSourceTranslatesEventsAndIgnoresHeartbeats(t *testing.T) {
	server, _ := testWakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		flushWrite(t, w, ": heartbeat\n\n")
		flushWrite(t, w, "id: 7\nevent: wake\ndata: {\"version\":1,\"seq\":7,\"pending\":true}\n\n")
		flushWrite(t, w, ": heartbeat\n\n")
		flushWrite(t, w, "id: 9\nevent: wake\ndata: {\"version\":1,\"seq\":9,\"pending\":false}\n\n")
		<-r.Context().Done()
	})
	source, err := newRESTClaudeWakeSource(server)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	subscription, err := source.Subscribe(ctx, 0)
	require.NoError(t, err)
	defer func() { require.NoError(t, subscription.Close()) }()

	first := requireWakeEvent(t, subscription)
	require.Equal(t, ClaudeWakeEvent{Version: 1, Seq: 7, Pending: true}, first)
	second := requireWakeEvent(t, subscription)
	require.Equal(t, ClaudeWakeEvent{Version: 1, Seq: 9, Pending: false}, second)
}

// The host is entitled to a cursor and nothing else. If the node ever grows
// extra fields, they must not reach the adapter — the event type is the whole
// contract and this fails if that stops being true.
func TestClaudeWakeSourceNeverSurfacesSenderOrContent(t *testing.T) {
	server, _ := testWakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		flushWrite(t, w, "event: wake\ndata: {\"version\":1,\"seq\":3,\"pending\":true,"+
			"\"from_agent\":\"mallory\",\"payload\":\"secret\",\"intent\":\"leak\"}\n\n")
		<-r.Context().Done()
	})
	source, err := newRESTClaudeWakeSource(server)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	subscription, err := source.Subscribe(ctx, 0)
	require.NoError(t, err)
	defer func() { require.NoError(t, subscription.Close()) }()

	event := requireWakeEvent(t, subscription)
	require.Equal(t, ClaudeWakeEvent{Version: 1, Seq: 3, Pending: true}, event)

	// The notification the host actually receives must not carry the extras
	// either, whatever the node sent.
	rendered := fmt.Sprintf("%v", claudeChannelNotification(event.Seq))
	require.NotContains(t, rendered, "mallory")
	require.NotContains(t, rendered, "secret")
	require.NotContains(t, rendered, "leak")
}

// A data line must never be attributed to a previous frame's event type.
func TestClaudeWakeSourceIgnoresDataOutsideAWakeFrame(t *testing.T) {
	server, _ := testWakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		flushWrite(t, w, "event: other\ndata: {\"version\":1,\"seq\":5,\"pending\":true}\n\n")
		flushWrite(t, w, "data: {\"version\":1,\"seq\":6,\"pending\":true}\n\n")
		flushWrite(t, w, "event: wake\ndata: {\"version\":1,\"seq\":8,\"pending\":true}\n\n")
		<-r.Context().Done()
	})
	source, err := newRESTClaudeWakeSource(server)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	subscription, err := source.Subscribe(ctx, 0)
	require.NoError(t, err)
	defer func() { require.NoError(t, subscription.Close()) }()

	// The first event delivered must be seq 8: the non-wake frame and the
	// orphaned data line are both dropped.
	require.Equal(t, uint64(8), requireWakeEvent(t, subscription).Seq)
}

func TestClaudeWakeSourceClosesEventsWhenStreamEndsAndCloseIsIdempotent(t *testing.T) {
	server, _ := testWakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		flushWrite(t, w, "event: wake\ndata: {\"version\":1,\"seq\":2,\"pending\":true}\n\n")
		// Handler returns: the stream ends.
	})
	source, err := newRESTClaudeWakeSource(server)
	require.NoError(t, err)

	subscription, err := source.Subscribe(context.Background(), 0)
	require.NoError(t, err)

	require.Equal(t, uint64(2), requireWakeEvent(t, subscription).Seq)

	require.Eventually(t, func() bool {
		select {
		case _, ok := <-subscription.Events():
			return !ok
		default:
			return false
		}
	}, 5*time.Second, 10*time.Millisecond, "Events must close when the stream ends")

	require.NoError(t, subscription.Close())
	require.NoError(t, subscription.Close())
}

func requireWakeEvent(t *testing.T, subscription ClaudeWakeSubscription) ClaudeWakeEvent {
	t.Helper()
	select {
	case event, ok := <-subscription.Events():
		require.True(t, ok, "stream closed before an event arrived")
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a wake event")
		return ClaudeWakeEvent{}
	}
}
