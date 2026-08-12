package tx

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A1: every outcome of the shared broadcasters that cannot prove the
// transaction's fate must be TYPED indeterminate, not merely non-nil.
//
// These tests exist because the pre-existing suite could not tell the
// difference. TestSharedCometBroadcastersFenceMalformedOnWireResponse proves
// end-to-end fencing for exactly ONE response shape and does it through the
// registration backstop, so deleting the typed wrapper entirely would leave it
// green. Asserting err != nil is not coverage of a classification.

// indeterminateCommitCases are the commit-side responses that leave the
// transaction's fate unknown. Each must fence.
func indeterminateCommitCases(bound, valid string) []struct {
	name   string
	status int
	body   string
} {
	return []struct {
		name   string
		status int
		body   string
	}{
		{"transport-level non-200", 500, valid},
		{"non-200 with empty body", 502, ``},
		{"malformed json", 200, `{"result":`},
		{"multiple json values", 200, valid + ` {}`},
		{"trailing garbage", 200, valid + ` garbage`},
		{"rpc error envelope with data", 200, `{"error":{"message":"boom","data":"detail"}}`},
		{"rpc error envelope without data", 200, `{"error":{"message":"boom"}}`},
		{"omitted result", 200, `{}`},
		{"null result", 200, `{"result":null}`},
		{"null check_tx", 200, `{"result":{"check_tx":null,"tx_result":{"code":0},"hash":"` + bound + `","height":"7"}}`},
		{"null tx_result", 200, `{"result":{"check_tx":{"code":0},"tx_result":null,"hash":"` + bound + `","height":"7"}}`},
		{"absent verdict code", 200, `{"result":{"check_tx":{},"tx_result":{"code":0},"hash":"` + bound + `","height":"7"}}`},
		{"hash names another tx", 200, `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"AB12","height":"7"}}`},
		{"empty hash", 200, `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"","height":"7"}}`},
		// Admitted to the mempool (CheckTx 0) but no block named. The single
		// most dangerous one to misread as a failure.
		{"admitted but heightless", 200, `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` + bound + `","height":"0"}}`},
	}
}

func indeterminateSyncCases(bound, valid string) []struct {
	name   string
	status int
	body   string
} {
	return []struct {
		name   string
		status int
		body   string
	}{
		{"transport-level non-200", 500, valid},
		{"non-200 with empty body", 502, ``},
		{"malformed json", 200, `{"result":`},
		{"multiple json values", 200, valid + ` {}`},
		{"trailing garbage", 200, valid + ` garbage`},
		{"rpc error envelope with data", 200, `{"error":{"message":"boom","data":"detail"}}`},
		{"rpc error envelope without data", 200, `{"error":{"message":"boom"}}`},
		{"omitted result", 200, `{}`},
		{"null result", 200, `{"result":null}`},
		{"absent verdict code", 200, `{"result":{"hash":"` + bound + `"}}`},
		{"hash names another tx", 200, `{"result":{"code":0,"hash":"AB12"}}`},
		{"empty hash", 200, `{"result":{"code":0,"hash":""}}`},
	}
}

func TestSharedCometCommitTypesEveryIndeterminateOutcome(t *testing.T) {
	encoded := []byte("a1-commit-indeterminate")
	sum := CometTxHash(encoded)
	bound := strings.ToUpper(hex.EncodeToString(sum[:]))
	valid := `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` + bound + `","height":"7"}}`

	for _, tc := range indeterminateCommitCases(bound, valid) {
		t.Run(tc.name, func(t *testing.T) {
			rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer rpc.Close()

			_, key, genErr := ed25519.GenerateKey(nil)
			if genErr != nil {
				t.Fatal(genErr)
			}
			got, err := BroadcastCometCommit(context.Background(), rpc.URL, key, encoded)
			if got != nil {
				t.Fatalf("indeterminate outcome returned a result: %+v", got)
			}
			if err == nil {
				t.Fatal("indeterminate outcome returned nil error")
			}
			if !errors.Is(err, ErrSubmitIndeterminate) {
				t.Fatalf("outcome is not TYPED indeterminate: %v\n"+
					"a bare error here fences only while the registration happens to be live", err)
			}
		})
	}
}

func TestSharedCometSyncTypesEveryIndeterminateOutcome(t *testing.T) {
	encoded := []byte("a1-sync-indeterminate")
	sum := CometTxHash(encoded)
	bound := strings.ToUpper(hex.EncodeToString(sum[:]))
	valid := `{"result":{"code":0,"hash":"` + bound + `"}}`

	for _, tc := range indeterminateSyncCases(bound, valid) {
		t.Run(tc.name, func(t *testing.T) {
			rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer rpc.Close()

			_, key, genErr := ed25519.GenerateKey(nil)
			if genErr != nil {
				t.Fatal(genErr)
			}
			got, err := BroadcastCometSync(context.Background(), rpc.URL, key, encoded)
			if got != nil {
				t.Fatalf("indeterminate outcome returned a result: %+v", got)
			}
			if err == nil {
				t.Fatal("indeterminate outcome returned nil error")
			}
			if !errors.Is(err, ErrSubmitIndeterminate) {
				t.Fatalf("outcome is not TYPED indeterminate: %v", err)
			}
		})
	}
}

// The transport failure is the canonical fence case and cannot be produced by a
// response body, so it gets its own test: point at a closed listener.
func TestSharedCometBroadcastersTypeTransportFailure(t *testing.T) {
	rpc := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dead := rpc.URL
	rpc.Close() // nothing is listening now

	encoded := []byte("a1-transport-failure")
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, cErr := BroadcastCometCommit(context.Background(), dead, key, encoded); !errors.Is(cErr, ErrSubmitIndeterminate) {
		t.Fatalf("commit transport failure not typed indeterminate: %v", cErr)
	}
	if _, sErr := BroadcastCometSync(context.Background(), dead, key, encoded); !errors.Is(sErr, ErrSubmitIndeterminate) {
		t.Fatalf("sync transport failure not typed indeterminate: %v", sErr)
	}
}

// Content-type validation was added after the typed-indeterminate branch was
// frozen. It runs after submission registration, so the merge must compose it
// with the typed fence rather than carrying forward the old bare error.
func TestSharedCometBroadcastersTypeNonJSONResponse(t *testing.T) {
	encoded := []byte("a1-non-json-response")
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, "<html>upstream failure</html>")
	}))
	defer rpc.Close()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, cErr := BroadcastCometCommit(context.Background(), rpc.URL, key, encoded); !errors.Is(cErr, ErrSubmitIndeterminate) {
		t.Fatalf("commit non-JSON response not typed indeterminate: %v", cErr)
	}
	if _, sErr := BroadcastCometSync(context.Background(), rpc.URL, key, encoded); !errors.Is(sErr, ErrSubmitIndeterminate) {
		t.Fatalf("sync non-JSON response not typed indeterminate: %v", sErr)
	}
}

// A pre-send failure must NOT be typed. Fencing a signing key because an
// endpoint string was malformed would take the key out of service over a
// transaction that never reached a socket.
func TestSharedCometBroadcastersDoNotTypePreSendFailures(t *testing.T) {
	encoded := []byte("a1-pre-send")
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// A control character makes http.NewRequestWithContext fail during URL
	// parsing, which is the only pre-registration error path in either function.
	badEndpoint := "http://cometbft\x7finvalid.local"

	_, cErr := BroadcastCometCommit(context.Background(), badEndpoint, key, encoded)
	if cErr == nil {
		t.Fatal("malformed endpoint returned nil error")
	}
	if errors.Is(cErr, ErrSubmitIndeterminate) {
		t.Fatalf("pre-send failure was typed indeterminate and would fence the key: %v", cErr)
	}

	_, sErr := BroadcastCometSync(context.Background(), badEndpoint, key, encoded)
	if sErr == nil {
		t.Fatal("malformed endpoint returned nil error")
	}
	if errors.Is(sErr, ErrSubmitIndeterminate) {
		t.Fatalf("pre-send failure was typed indeterminate and would fence the key: %v", sErr)
	}
}

// The typed wrapper must refuse EXACTLY the inputs RegisterSubmittedTx refuses
// (nonce.go:480), and this test pins both halves of that guard. It is the
// decision, not an implementation detail: getting either half wrong turns A1
// from an additive hardening into a new defect.
//
//   - empty encoded: typing it would raise a fence carrying no hash and no
//     nonce, which reconciliation can never prove, so the key would be held for
//     the life of the process. Today it is a harmless bare error.
//   - a key WithNonceLease would reject: such a key cannot hold its own lease,
//     so the enclosing lease belongs to a DIFFERENT signer, and the typed path
//     fences the LEASE's key. Typing here would fence signer B over signer A's
//     transaction.
//
// In both cases the correct behavior is the status quo: a bare error, no fence.
func TestIndeterminateWrapperRefusesExactlyWhatRegistrationRefuses(t *testing.T) {
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"result":`) // undecodable => indeterminate shape
	}))
	defer rpc.Close()

	_, goodKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		key     ed25519.PrivateKey
		encoded []byte
	}{
		{"nil signing key", nil, []byte("a1-gate")},
		{"short signing key", ed25519.PrivateKey([]byte{1, 2, 3}), []byte("a1-gate")},
		{"empty encoded with a valid key", goodKey, nil},
		{"zero-length encoded with a valid key", goodKey, []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, cErr := BroadcastCometCommit(context.Background(), rpc.URL, tc.key, tc.encoded)
			if cErr == nil {
				t.Fatal("commit: expected an error")
			}
			if errors.Is(cErr, ErrSubmitIndeterminate) {
				t.Fatalf("commit: wrapper typed an input RegisterSubmittedTx refuses to track, "+
					"which raises a fence nothing can ever prove: %v", cErr)
			}

			_, sErr := BroadcastCometSync(context.Background(), rpc.URL, tc.key, tc.encoded)
			if sErr == nil {
				t.Fatal("sync: expected an error")
			}
			if errors.Is(sErr, ErrSubmitIndeterminate) {
				t.Fatalf("sync: wrapper typed an input RegisterSubmittedTx refuses to track: %v", sErr)
			}
		})
	}
}

// The guard above must stay bug-for-bug identical to RegisterSubmittedTx's.
// If someone tightens or loosens one, this fails rather than letting the two
// fence mechanisms cover different input sets.
func TestIndeterminateWrapperGuardMatchesRegistrationGuard(t *testing.T) {
	_, goodKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("probe")

	for _, tc := range []struct {
		name      string
		key       ed25519.PrivateKey
		encoded   []byte
		wantTyped bool
	}{
		{"valid key and bytes", goodKey, []byte("x"), true},
		{"valid key, empty bytes", goodKey, nil, false},
		{"nil key, valid bytes", nil, []byte("x"), false},
		{"short key, valid bytes", ed25519.PrivateKey([]byte{9}), []byte("x"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// What the wrapper decides.
			wrapped := indeterminateBroadcast(tc.key, tc.encoded, "http://127.0.0.1:1")(sentinel)
			gotTyped := errors.Is(wrapped, ErrSubmitIndeterminate)

			// What the registration decides, observed through its own behavior.
			ClearSubmittedTx(tc.key)
			RegisterSubmittedTx(tc.key, tc.encoded, nil)
			gotRegistered := takeRegisteredSubmission(pubKeyOf(tc.key)) != nil

			if gotTyped != tc.wantTyped {
				t.Fatalf("wrapper typed=%v, want %v", gotTyped, tc.wantTyped)
			}
			if gotTyped != gotRegistered {
				t.Fatalf("guards diverged: wrapper typed=%v but registration tracked=%v; "+
					"the two fence mechanisms now cover different inputs", gotTyped, gotRegistered)
			}
		})
	}
}

// pubKeyOf mirrors the key derivation takeRegisteredSubmission is keyed by,
// without panicking on the short/nil keys this test deliberately feeds it.
func pubKeyOf(sk ed25519.PrivateKey) string {
	if len(sk) != ed25519.PrivateKeySize {
		return ""
	}
	pub, ok := sk.Public().(ed25519.PublicKey)
	if !ok {
		return ""
	}
	return string(pub)
}

// Definitive verdicts must stay definitive. If wrapping leaked onto these, every
// ordinary consensus rejection would fence the signer and turn a rejected
// transaction into an outage for that key.
func TestSharedCometBroadcastersDoNotTypeDefinitiveVerdicts(t *testing.T) {
	encoded := []byte("a1-definitive")
	sum := CometTxHash(encoded)
	bound := strings.ToUpper(hex.EncodeToString(sum[:]))

	for _, tc := range []struct {
		name string
		body string
	}{
		{"CheckTx refusal", `{"result":{"check_tx":{"code":9},"tx_result":{"code":0},"hash":"` + bound + `","height":"0"}}`},
		{"in-block FinalizeBlock refusal", `{"result":{"check_tx":{"code":0},"tx_result":{"code":9},"hash":"` + bound + `","height":"7"}}`},
		{"committed", `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` + bound + `","height":"7"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer rpc.Close()
			_, key, genErr := ed25519.GenerateKey(nil)
			if genErr != nil {
				t.Fatal(genErr)
			}
			got, err := BroadcastCometCommit(context.Background(), rpc.URL, key, encoded)
			if err != nil {
				t.Fatalf("definitive verdict returned an error: %v", err)
			}
			if got == nil {
				t.Fatal("definitive verdict returned no result")
			}
		})
	}
}

// The typed wrapper must be invisible in the message. Several web handlers
// surface submit's error text to operators verbatim, and WithNonceLease's
// contract is that submit's error comes back undecorated.
func TestIndeterminateWrapperPreservesOperatorVisibleText(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	inner := errors.New("broadcast tx commit: connection reset by peer")
	wrapped := indeterminateBroadcast(key, []byte("bytes"), "http://127.0.0.1:1")(inner)

	if wrapped.Error() != inner.Error() {
		t.Fatalf("wrapper changed operator-visible text:\n got: %q\nwant: %q", wrapped.Error(), inner.Error())
	}
	if !errors.Is(wrapped, ErrSubmitIndeterminate) {
		t.Fatal("wrapper did not carry the indeterminate sentinel")
	}
	if !errors.Is(wrapped, inner) {
		t.Fatal("wrapper broke the error chain: errors.Is no longer finds the wrapped cause")
	}
}
