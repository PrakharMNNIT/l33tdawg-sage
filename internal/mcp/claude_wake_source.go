package mcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// The Claude channel adapter shipped in v11.18.9 with no production
// ClaudeWakeSource behind it: every implementation lived in a test file, so
// ConfigureClaudeChannel had no caller outside the package and the adapter was
// unreachable from any shipped binary. The node half — the signed
// /v1/messages/wake SSE route — shipped separately and is live. This file is
// the seam between them, and nothing here widens either contract.

const (
	// claudeWakeConsumerPrefix labels this runtime's lease so an operator
	// reading node logs can tell which host holds the wake.
	claudeWakeConsumerPrefix = "claude-code"
	// claudeWakeMaxFrameBytes bounds one SSE frame. The wake payload is three
	// small fields by design; anything larger is a malformed or hostile stream
	// rather than a wake this adapter should try to parse.
	claudeWakeMaxFrameBytes = 8 * 1024
	// claudeWakeEventBuffer keeps a slow adapter from blocking the reader
	// goroutine. Wakes coalesce by sequence downstream, so a dropped duplicate
	// costs nothing; only the highest sequence matters.
	claudeWakeEventBuffer = 8
)

// restClaudeWakeSource subscribes to this node's signed exact-recipient wake
// route on behalf of the server's own agent identity. It is deliberately the
// narrowest possible node dependency: it can observe a durable cursor and
// nothing else. It holds no ability to receive, claim, read, or acknowledge a
// message, and it never sees sender or content.
type restClaudeWakeSource struct {
	server     *Server
	consumerID string

	// stream is separate from server.httpClient on purpose. That client sets
	// Timeout (75s by default), which bounds the WHOLE request including body
	// reads — it would sever a healthy long-lived SSE stream on a fixed timer
	// and mask the break as a reconnect. The transport, and therefore the TLS
	// configuration and CA resolution, is shared exactly.
	stream *http.Client
}

// newRESTClaudeWakeSource binds a wake source to this server's exact identity.
//
// The consumer ID is random per process rather than derived from the project or
// provider, and that is a correctness requirement rather than a detail. The
// node supersedes an existing stream when the SAME consumer reconnects, and
// rejects a DIFFERENT consumer with 409 until the lease expires. A stable ID
// would therefore let a second Claude runtime silently steal the wake from a
// live one, which is exactly what the lease exists to prevent.
func newRESTClaudeWakeSource(server *Server) (*restClaudeWakeSource, error) {
	if server == nil {
		return nil, fmt.Errorf("claude wake source requires a server")
	}
	if server.httpClient == nil {
		return nil, fmt.Errorf("claude wake source requires an http client")
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return nil, fmt.Errorf("generate wake consumer id: %w", err)
	}
	return &restClaudeWakeSource{
		server:     server,
		consumerID: claudeWakeConsumerPrefix + "-" + hex.EncodeToString(suffix),
		stream:     &http.Client{Transport: server.httpClient.Transport},
	}, nil
}

// EnableRESTClaudeChannel binds the shipped Claude channel adapter to this
// node's signed wake route. It stays an explicit call rather than something
// NewServer does, because the adapter's own contract is that merely
// constructing a Server never advertises or emits the experimental protocol.
func (s *Server) EnableRESTClaudeChannel() error {
	source, err := newRESTClaudeWakeSource(s)
	if err != nil {
		return err
	}
	return s.ConfigureClaudeChannel(source)
}

// Subscribe opens one signed wake stream positioned after afterSeq. It returns
// promptly on ctx cancellation because the request carries ctx, and it reports
// a non-200 as an error so the adapter's bounded backoff — not this code — owns
// the retry policy.
func (w *restClaudeWakeSource) Subscribe(ctx context.Context, afterSeq uint64) (ClaudeWakeSubscription, error) {
	path := fmt.Sprintf("/v1/messages/wake?after_seq=%d&consumer_id=%s", afterSeq, w.consumerID)
	prepared, err := w.server.prepareSignedRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("sign wake subscribe: %w", err)
	}

	streamCtx, cancel := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(streamCtx, prepared.method, w.server.baseURL+prepared.path, nil)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create wake request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("X-Agent-ID", prepared.agentID)
	req.Header.Set("X-Signature", prepared.signature)
	req.Header.Set("X-Timestamp", prepared.timestamp)
	req.Header.Set("X-Nonce", prepared.nonce)

	resp, err := w.stream.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("open wake stream: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Drain a bounded prefix so the connection can be reused, then discard.
		// The body is a problem+json document; it is diagnostic only and must
		// not reach the host, which is entitled to a cursor and nothing else.
		_, _ = io.CopyN(io.Discard, resp.Body, claudeWakeMaxFrameBytes)
		_ = resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("wake stream rejected: %s", resp.Status)
	}

	subscription := &restClaudeWakeSubscription{
		events: make(chan ClaudeWakeEvent, claudeWakeEventBuffer),
		body:   resp.Body,
		cancel: cancel,
	}
	go subscription.read()
	return subscription, nil
}

// restClaudeWakeSubscription owns exactly one live stream. Close is idempotent
// and Events is closed exactly once when the stream ends, both of which the
// ClaudeWakeSubscription contract requires.
type restClaudeWakeSubscription struct {
	events chan ClaudeWakeEvent
	body   io.ReadCloser
	cancel context.CancelFunc

	closeOnce sync.Once
}

func (s *restClaudeWakeSubscription) Events() <-chan ClaudeWakeEvent { return s.events }

func (s *restClaudeWakeSubscription) Close() error {
	s.closeOnce.Do(func() {
		// Cancel first: it unblocks a read parked on a quiet stream so the
		// reader goroutine cannot outlive Close.
		s.cancel()
		_ = s.body.Close()
	})
	return nil
}

// read translates SSE frames into wake events until the stream ends. It closes
// events on exit so the adapter observes the break and schedules its own
// reconnect; it never reconnects on its own.
func (s *restClaudeWakeSubscription) read() {
	defer close(s.events)
	defer s.Close()

	scanner := bufio.NewScanner(s.body)
	scanner.Buffer(make([]byte, 0, 4096), claudeWakeMaxFrameBytes)

	var isWake bool
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			// Frame boundary. Reset so a data line can never be attributed to
			// a previous frame's event type.
			isWake = false
		case strings.HasPrefix(line, ":"):
			// Heartbeat comment. Proves liveness, carries nothing.
		case strings.HasPrefix(line, "event:"):
			isWake = strings.TrimSpace(strings.TrimPrefix(line, "event:")) == "wake"
		case strings.HasPrefix(line, "data:"):
			if !isWake {
				continue
			}
			var payload struct {
				Version int    `json:"version"`
				Seq     uint64 `json:"seq"`
				Pending bool   `json:"pending"`
			}
			raw := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if err := json.Unmarshal([]byte(raw), &payload); err != nil {
				// A frame we cannot parse is not a frame we may guess at.
				continue
			}
			event := ClaudeWakeEvent{
				Version: payload.Version,
				Seq:     payload.Seq,
				Pending: payload.Pending,
			}
			select {
			case s.events <- event:
			default:
				// Buffer full: the adapter is mid-write and already owes a
				// notification for a sequence at least this recent. Dropping is
				// safe precisely because wakes carry no content to lose.
			}
		}
	}
}
