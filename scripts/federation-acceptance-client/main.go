// federation-acceptance-client is test-only local control-plane plumbing. It
// runs inside a SAGE acceptance container so dashboard mutations originate on
// loopback, matching the production CEREBRUM locality boundary.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/l33tdawg/sage/internal/auth"
)

func main() {
	if len(os.Args) < 3 || len(os.Args) > 4 {
		fmt.Fprintln(os.Stderr, "usage: federation-acceptance-client METHOD PATH [JSON_BODY]")
		os.Exit(2)
	}
	method, path := os.Args[1], os.Args[2]
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodPut && method != http.MethodDelete {
		fmt.Fprintln(os.Stderr, "method must be GET, POST, PUT, or DELETE")
		os.Exit(2)
	}
	if !strings.HasPrefix(path, "/v1/") || strings.ContainsAny(path, "\r\n") {
		fmt.Fprintln(os.Stderr, "path must be a local /v1/ request target")
		os.Exit(2)
	}
	body := []byte(nil)
	if len(os.Args) == 4 {
		body = []byte(os.Args[3])
	}
	seed, err := os.ReadFile("/root/.sage/agent.key")
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintf(os.Stderr, "read operator seed: %v (size %d)\n", err, len(seed))
		os.Exit(1)
	}
	key := ed25519.NewKeyFromSeed(seed)
	nonce := make([]byte, 8)
	if _, err = rand.Read(nonce); err != nil {
		panic(err)
	}
	ts := time.Now().Unix()
	sig := auth.SignRequestWithNonce(key, method, path, body, ts, nonce)
	// #nosec G704 -- the destination authority is a literal loopback address;
	// the only caller-supplied component is a validated /v1/ request target.
	req, err := http.NewRequest(method, "http://127.0.0.1:8080"+path, bytes.NewReader(body))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", hex.EncodeToString(key.Public().(ed25519.PublicKey)))
	req.Header.Set("X-Signature", hex.EncodeToString(sig))
	req.Header.Set("X-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Nonce", hex.EncodeToString(nonce))
	// #nosec G704 -- req cannot escape the fixed loopback authority above.
	resp, err := (&http.Client{Timeout: 90 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	_, _ = os.Stdout.Write(out)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		fmt.Fprintf(os.Stderr, "\nHTTP %d: %s\n", resp.StatusCode, out)
		os.Exit(1)
	}
}
