package web

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

// The CEREBRUM commit broadcaster owns request-aware error classification in
// web/, so it cannot simply disappear behind internal/tx's strict decoder. It
// still has to share the exact same non-reusing submission transport. This raw
// HTTP/1.1 server makes the transport retry reachable: it accepts a complete
// request on a warm connection, then resets before writing response headers.
type killableWebCometNode struct {
	ln net.Listener

	mu         sync.Mutex
	deliveries map[string]int
	killTx     atomic.Value // string: tx hex to receive fully, then leave unanswered
}

func newKillableWebCometNode(t *testing.T) *killableWebCometNode {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	n := &killableWebCometNode{ln: ln, deliveries: map[string]int{}}
	n.killTx.Store("")
	t.Cleanup(func() { _ = ln.Close() })
	go n.serve()
	return n
}

func (n *killableWebCometNode) url() string { return "http://" + n.ln.Addr().String() }

func (n *killableWebCometNode) delivered(txHex string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.deliveries[txHex]
}

func (n *killableWebCometNode) serve() {
	for {
		conn, err := n.ln.Accept()
		if err != nil {
			return
		}
		go n.handleConn(conn)
	}
}

func (n *killableWebCometNode) handleConn(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		requestLine, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		for {
			line, err := reader.ReadString('\n')
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
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
			}
			return
		}

		raw, _ := hex.DecodeString(txHex)
		sum := sha256.Sum256(raw)
		body := fmt.Sprintf(`{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":%q,"height":"9"}}`,
			strings.ToUpper(hex.EncodeToString(sum[:])))
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"+
			"Content-Length: %d\r\nConnection: keep-alive\r\n\r\n%s", len(body), body)
	}
}

// TestWebCommitNeverDeliversOneSubmissionTwice is mutation-sensitive for the
// non-local CEREBRUM broadcaster. Replacing tx.DoCometSubmission with
// http.DefaultClient.Do makes this fail with deliveries=2.
func TestWebCommitNeverDeliversOneSubmissionTwice(t *testing.T) {
	node := newKillableWebCometNode(t)
	warm := []byte("web-submit-delivery-warmup")
	if _, _, _, err := broadcastTxCommitWebContext(context.Background(), node.url(), nil, warm); err != nil {
		t.Fatalf("warmup broadcast failed, so the test never reached the case under test: %v", err)
	}

	victim := []byte("web-submit-delivery-victim")
	victimHex := hex.EncodeToString(victim)
	node.killTx.Store(victimHex)
	if _, _, _, err := broadcastTxCommitWebContext(context.Background(), node.url(), nil, victim); err == nil {
		t.Fatal("a submission whose response never arrived reported success; the outcome is unobserved")
	}
	if got := node.delivered(victimHex); got != 1 {
		t.Fatalf("the web broadcaster delivered the transaction %d times, want exactly 1", got)
	}
}
