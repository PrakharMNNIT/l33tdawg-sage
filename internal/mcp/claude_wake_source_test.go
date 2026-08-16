package mcp

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// Default-on is safe only if a second runtime that loses the exact-agent wake
// lease remains alive and acquires it after the holder disconnects. This pins
// the complete REST-source + channel retry path rather than merely asserting
// that Subscribe returns an error for 409.
func TestClaudeChannelRetriesLeaseConflictAndAcquiresAfterRelease(t *testing.T) {
	var mu sync.Mutex
	var activeConsumer string
	var conflictCount int
	var firstID, secondID string
	firstAcquired := make(chan struct{})
	secondAcquired := make(chan struct{})
	var firstOnce, secondOnce sync.Once

	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		consumerID := r.URL.Query().Get("consumer_id")
		mu.Lock()
		if activeConsumer != "" && activeConsumer != consumerID {
			conflictCount++
			mu.Unlock()
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"title":"wake consumer already active"}`)
			return
		}
		activeConsumer = consumerID
		mu.Unlock()

		switch consumerID {
		case firstID:
			firstOnce.Do(func() { close(firstAcquired) })
		case secondID:
			secondOnce.Do(func() { close(secondAcquired) })
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		if consumerID == secondID {
			_, _ = fmt.Fprint(w, "event: wake\ndata: {\"version\":1,\"seq\":7,\"pending\":true}\n\n")
			w.(http.Flusher).Flush()
		}
		<-r.Context().Done()

		mu.Lock()
		if activeConsumer == consumerID {
			activeConsumer = ""
		}
		mu.Unlock()
	}))
	t.Cleanup(node.Close)
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	server := NewServer(node.URL, privateKey)
	first, err := newRESTClaudeWakeSource(server)
	require.NoError(t, err)
	second, err := newRESTClaudeWakeSource(server)
	require.NoError(t, err)
	firstID, secondID = first.consumerID, second.consumerID

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstOut := newStdioOutbound(firstCtx, io.Discard)
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		runClaudeChannel(firstCtx, firstOut, testClaudeConfig(first))
	}()
	select {
	case <-firstAcquired:
	case <-time.After(2 * time.Second):
		t.Fatal("first runtime did not acquire the wake lease")
	}

	secondCtx, cancelSecond := context.WithCancel(context.Background())
	var secondSink lockedBuffer
	secondOut := newStdioOutbound(secondCtx, &secondSink)
	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		runClaudeChannel(secondCtx, secondOut, testClaudeConfig(second))
	}()
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return conflictCount > 0
	}, 2*time.Second, time.Millisecond, "second runtime never observed the 409 lease conflict")

	cancelFirst()
	<-firstDone
	firstOut.Close()
	select {
	case <-secondAcquired:
	case <-time.After(2 * time.Second):
		t.Fatal("rejected runtime did not acquire the lease after release")
	}
	waitFor(t, func() bool { return len(secondSink.lines()) == 1 })
	require.Equal(t, []string{"7"}, wakeSeqs(t, secondSink.lines()))

	cancelSecond()
	<-secondDone
	secondOut.Close()
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

// Losslessness under saturation. An earlier revision dropped the event when the
// buffer was full, on the reasoning that only the highest sequence matters —
// but the dropped event IS the highest sequence, and the stream stays open so
// nothing forces a catch-up.
//
// The test must not begin draining until the buffer has actually saturated,
// otherwise the consumer keeps pace, the buffer never fills, and the assertion
// passes against the very drop it exists to forbid. Waiting on the handler to
// finish writing cannot be the synchronisation either: correct backpressure
// blocks the handler, so that would deadlock the fixed implementation. Waiting
// on the buffer to reach capacity is the condition that works for both.
func TestClaudeWakeSourceDeliversNewestEventUnderBufferSaturation(t *testing.T) {
	const total = claudeWakeEventBuffer * 4
	server, _ := testWakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		// A burst of non-pending frames first, exactly the shape that used to
		// fill the buffer and swallow the pending wake that follows.
		for seq := 1; seq < total; seq++ {
			flushWrite(t, w, "event: wake\ndata: {\"version\":1,\"seq\":%d,\"pending\":false}\n\n", seq)
		}
		flushWrite(t, w, "event: wake\ndata: {\"version\":1,\"seq\":%d,\"pending\":true}\n\n", total)
		<-r.Context().Done()
	})
	source, err := newRESTClaudeWakeSource(server)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	subscription, err := source.Subscribe(ctx, 0)
	require.NoError(t, err)
	defer func() { require.NoError(t, subscription.Close()) }()

	// Saturate first, draining nothing. Only now is a drop observable.
	require.Eventually(t, func() bool {
		return len(subscription.(*restClaudeWakeSubscription).events) == claudeWakeEventBuffer
	}, 10*time.Second, 10*time.Millisecond, "buffer should saturate while nothing drains")

	deadline := time.After(10 * time.Second)
	var highest uint64
	var sawPending bool
	for highest < total {
		select {
		case event, ok := <-subscription.Events():
			require.True(t, ok, "stream closed before the newest wake arrived")
			require.GreaterOrEqual(t, event.Seq, highest, "sequences must not go backwards")
			highest = event.Seq
			if event.Seq == total {
				sawPending = event.Pending
			}
		case <-deadline:
			t.Fatalf("newest wake was dropped; highest seen was %d of %d", highest, total)
		}
	}
	require.Equal(t, uint64(total), highest, "the newest cursor must survive a saturated buffer")
	require.True(t, sawPending, "the surviving newest event must retain pending=true")
}

// Close must release a reader parked on a full buffer rather than stranding the
// goroutine, and must stay idempotent while doing it.
func TestClaudeWakeSourceCloseReleasesReaderBlockedOnFullBuffer(t *testing.T) {
	server, _ := testWakeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for seq := 1; seq <= claudeWakeEventBuffer*4; seq++ {
			// Close intentionally tears down the response while this producer may
			// still be filling the socket. A post-close broken pipe is the expected
			// server-side observation, not a test failure.
			if _, writeErr := fmt.Fprintf(w, "event: wake\ndata: {\"version\":1,\"seq\":%d,\"pending\":true}\n\n", seq); writeErr != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
		<-r.Context().Done()
	})
	source, err := newRESTClaudeWakeSource(server)
	require.NoError(t, err)

	subscription, err := source.Subscribe(context.Background(), 0)
	require.NoError(t, err)

	// Let the reader fill the buffer and park on the send. Never drain.
	require.Eventually(t, func() bool {
		return len(subscription.(*restClaudeWakeSubscription).events) == claudeWakeEventBuffer
	}, 5*time.Second, 10*time.Millisecond, "buffer should saturate while nothing drains")

	closed := make(chan error, 1)
	go func() { closed <- subscription.Close() }()
	select {
	case closeErr := <-closed:
		require.NoError(t, closeErr)
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked behind a parked reader")
	}

	// Prove the reader exited before consuming from Events. Draining first would
	// release a bare blocking send even if Close stopped selecting on done,
	// making this shutdown regression test pass against the broken code.
	select {
	case <-subscription.(*restClaudeWakeSubscription).readerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("reader goroutine remained blocked until Events was drained")
	}

	// The reader must finish and close Events even though it was mid-send.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range subscription.Events() {
		}
	}()
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("reader goroutine was stranded; Events never closed")
	}

	require.NoError(t, subscription.Close())
}
