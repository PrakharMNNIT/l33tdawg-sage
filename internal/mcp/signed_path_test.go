package mcp

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The owner's backlog was unreadable for as long as the tool existed, and the
// model reported it as "your backlog is empty" rather than as an error.
//
// Callers build paths as `"/v1/memory/tasks?" + q.Encode()`, and
// url.Values{}.Encode() returns "" when every parameter is optional and none
// was set. So the client signed "/v1/memory/tasks?" while the verifier
// rebuilt "/v1/memory/tasks" from r.URL.Path plus an empty r.URL.RawQuery
// (web/handler.go:979). Different strings, invalid signature, 401.
//
// That is the default call — sage_backlog({}) with no domain filter — which is
// why every other signed tool worked and this one never did.
func TestEmptyQueryDoesNotLeaveATrailingQuestionMarkInTheSignedPath(t *testing.T) {
	q := url.Values{}
	built := "/v1/memory/tasks?" + q.Encode()
	if built != "/v1/memory/tasks?" {
		t.Fatalf("premise changed: call sites no longer produce a bare trailing ?, got %q", built)
	}

	signed := strings.TrimSuffix(built, "?")

	// What the server reconstructs, per validAgentSignature.
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080"+signed, nil)
	if err != nil {
		t.Fatal(err)
	}
	reconstructed := req.URL.Path
	if req.URL.RawQuery != "" {
		reconstructed = req.URL.Path + "?" + req.URL.RawQuery
	}

	if signed != reconstructed {
		t.Fatalf("signed %q but server verifies %q — this is the 401", signed, reconstructed)
	}
}

// A real query must survive untouched: trimming a trailing "?" must not become
// trimming query strings.
func TestARealQueryIsSignedExactlyAsSent(t *testing.T) {
	q := url.Values{}
	q.Set("domain", "hardware benchmarks")
	q.Set("provider", "ollama")
	built := "/v1/memory/tasks?" + q.Encode()

	signed := strings.TrimSuffix(built, "?")
	if signed != built {
		t.Fatalf("a populated query was altered: %q -> %q", built, signed)
	}

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080"+signed, nil)
	if err != nil {
		t.Fatal(err)
	}
	reconstructed := req.URL.Path + "?" + req.URL.RawQuery
	if signed != reconstructed {
		t.Fatalf("signed %q but server verifies %q", signed, reconstructed)
	}
}
