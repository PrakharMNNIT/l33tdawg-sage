package tx

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// At-least-once delivery coverage for the submit path.
//
// The fault under test cannot be expressed with httptest: it needs a server
// that reads a request IN FULL — the point past which a real node may already
// have admitted the transaction — and then dies without writing a status line.
// So this is a raw HTTP/1.1 speaker over a TCP listener.
//
// What makes the transaction get sent twice is Go's transparent retry, and its
// first gate is pc.isReused(). Everything here exists to put a warm, reusable
// connection in front of the submission and then check that the submission did
// not travel down it twice.

// killableCometNode counts deliveries per transaction and can be told to accept
// a request fully and then vanish.
type killableCometNode struct {
	ln net.Listener

	mu         sync.Mutex
	deliveries map[string]int

	killTx atomic.Value // string: the tx hex whose delivery is answered with a dead socket
}

func newKillableCometNode(t *testing.T) *killableCometNode {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	n := &killableCometNode{ln: ln, deliveries: map[string]int{}}
	n.killTx.Store("")
	t.Cleanup(func() { _ = ln.Close() })
	go n.serve()
	return n
}

func (n *killableCometNode) url() string { return "http://" + n.ln.Addr().String() }

func (n *killableCometNode) delivered(txHex string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.deliveries[txHex]
}

func (n *killableCometNode) serve() {
	for {
		c, err := n.ln.Accept()
		if err != nil {
			return
		}
		go n.handleConn(c)
	}
}

func (n *killableCometNode) handleConn(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		requestLine, err := br.ReadString('\n')
		if err != nil {
			return
		}
		for { // drain headers; returning past this point means the request ARRIVED
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if strings.TrimSpace(line) == "" {
				break
			}
		}
		fields := strings.Fields(strings.TrimSpace(requestLine))
		if len(fields) < 2 {
			return
		}
		txHex := ""
		if i := strings.Index(fields[1], "tx=0x"); i >= 0 {
			txHex = fields[1][i+len("tx=0x"):]
			if j := strings.IndexByte(txHex, '&'); j >= 0 {
				txHex = txHex[:j]
			}
		}

		n.mu.Lock()
		n.deliveries[txHex]++
		n.mu.Unlock()

		if kill, _ := n.killTx.Load().(string); kill != "" && txHex == kill {
			// Fully received, deliberately unanswered. SetLinger(0) sends an RST
			// so the client cannot read this as an orderly half-close.
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0)
			}
			return
		}

		requestTarget := fields[1]
		raw, _ := hex.DecodeString(txHex)
		sum := sha256.Sum256(raw)
		bound := strings.ToUpper(hex.EncodeToString(sum[:]))
		body := fmt.Sprintf(`{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":%q,"height":"9"}}`, bound)
		if strings.Contains(requestTarget, "/broadcast_tx_sync") {
			body = fmt.Sprintf(`{"result":{"code":0,"hash":%q}}`, bound)
		}
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"+
			"Content-Length: %d\r\nConnection: keep-alive\r\n\r\n%s", len(body), body)
	}
}

// TestSubmissionPathsNeverDeliverOneRequestTwice is the regression test for the
// at-least-once hole across all three internal submission sites.
//
// The first broadcast succeeds and, on a keep-alive client, leaves a pooled
// connection behind. The second broadcast is then killed after the node has read
// it in full. If the submission travelled on a reused connection, Go re-sends it
// on a fresh one and the node receives the SAME transaction twice — while the
// caller may still see success.
//
// Reverting any one of commit, sync, or reconciler re-submit to
// http.DefaultClient makes its named subtest fail with deliveries=2.
func TestSubmissionPathsNeverDeliverOneRequestTwice(t *testing.T) {
	type submitFunc func(context.Context, string, []byte) error
	tests := []struct {
		name   string
		submit submitFunc
	}{
		{
			name: "commit",
			submit: func(ctx context.Context, endpoint string, encoded []byte) error {
				_, err := BroadcastCometCommit(ctx, endpoint, nil, encoded)
				return err
			},
		},
		{
			name: "sync",
			submit: func(ctx context.Context, endpoint string, encoded []byte) error {
				_, err := BroadcastCometSync(ctx, endpoint, nil, encoded)
				return err
			},
		},
		{
			name: "re-submit",
			submit: func(ctx context.Context, endpoint string, encoded []byte) error {
				var out cometBroadcastCommit
				_, err := cometBroadcastJSON(ctx, "test re-submit", endpoint, "broadcast_tx_commit", encoded, &out)
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			node := newKillableCometNode(t)
			t.Cleanup(func() { ClearSubmittedTx(nil) })

			// Submission 1 succeeds and warms any client pool. Submission 2 is
			// received in full, then the socket dies before response headers.
			warm := []byte("submit-delivery-" + tc.name + "-warmup")
			if err := tc.submit(context.Background(), node.url(), warm); err != nil {
				t.Fatalf("warmup submission failed, so the test never reached the case under test: %v", err)
			}
			victim := []byte("submit-delivery-" + tc.name + "-victim")
			victimHex := hex.EncodeToString(victim)
			node.killTx.Store(victimHex)

			if err := tc.submit(context.Background(), node.url(), victim); err == nil {
				t.Fatal("a submission whose response never arrived reported success; the outcome is unobserved")
			}
			if got := node.delivered(victimHex); got != 1 {
				t.Fatalf("the node received the transaction %d times, want exactly 1: the submission was "+
					"transparently re-sent, so a multi-responder endpoint could answer the second copy with a "+
					"hash-bound refusal and clear the fence for a transaction the first node still holds", got)
			}
		})
	}
}

// TestCometSubmitClientCannotReuseConnections pins the mechanism directly rather
// than through its symptom: the retry's first gate is pc.isReused(), so if the
// submit client ever pools a connection the guarantee above is gone even when
// this particular timing does not reproduce it.
func TestCometSubmitClientCannotReuseConnections(t *testing.T) {
	t.Cleanup(func() { ClearSubmittedTx(nil) })

	seen := map[string]bool{}
	var mu sync.Mutex
	recording := newRecordingCometNode(t, func(remote string) {
		mu.Lock()
		seen[remote] = true
		mu.Unlock()
	})

	for i := range 3 {
		encoded := fmt.Appendf(nil, "submit-client-reuse-%d", i)
		if _, err := BroadcastCometCommit(context.Background(), recording.url(), nil, encoded); err != nil {
			t.Fatalf("broadcast %d failed: %v", i, err)
		}
	}

	mu.Lock()
	distinct := len(seen)
	mu.Unlock()
	if distinct != 3 {
		t.Fatalf("3 submissions used %d distinct client connections, want 3: the submit client is pooling, "+
			"which re-arms Go's transparent retry (transport.go shouldRetryRequest gates on pc.isReused)",
			distinct)
	}
}

// recordingListener reports the remote address of every accepted connection.
type recordingListener struct {
	net.Listener
	onAccept func(remote string)
}

func (l *recordingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.onAccept(c.RemoteAddr().String())
	}
	return c, err
}

func newRecordingCometNode(t *testing.T, onAccept func(remote string)) *killableCometNode {
	t.Helper()
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	n := &killableCometNode{ln: &recordingListener{Listener: base, onAccept: onAccept}, deliveries: map[string]int{}}
	n.killTx.Store("")
	t.Cleanup(func() { _ = n.ln.Close() })
	go n.serve()
	return n
}
