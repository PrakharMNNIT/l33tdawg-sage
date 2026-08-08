package tx

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file tests CometTxResolver, the RE-SUBMISSION engine that makes "never
// lift without proof" survivable.
//
// The mapping it implements is the entire contract of the fence, so each case
// below is named for the outcome it must produce rather than for the RPC shape
// that produces it. Getting any of them wrong is not a cosmetic bug: mapping an
// unresolved answer to a verdict reopens a signing key while a transaction may
// still be in flight (silent Code 4 loss on some later request), and mapping a
// verdict to unresolved holds a key that could have been released.

// fakeCometRPC stands in for a CometBFT node. It records what was asked so a
// test can prove the resolver identified the transaction by its exact hash and
// re-submitted the exact bytes — anything else would be reconciling a different
// transaction, and re-submitting different bytes would not be idempotent.
type fakeCometRPC struct {
	t *testing.T

	mu            sync.Mutex
	lookupHashes  []string
	submittedHex  []string
	lookupHandler func(hash string) (int, string)
	submitHandler func(txHex string) (int, string)
}

func (f *fakeCometRPC) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tx":
			hash := strings.TrimPrefix(r.URL.Query().Get("hash"), "0x")
			f.mu.Lock()
			f.lookupHashes = append(f.lookupHashes, hash)
			handle := f.lookupHandler
			f.mu.Unlock()
			status, body := 200, `{"result":null}`
			if handle != nil {
				status, body = handle(hash)
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		case "/broadcast_tx_commit":
			txHex := strings.TrimPrefix(r.URL.Query().Get("tx"), "0x")
			f.mu.Lock()
			f.submittedHex = append(f.submittedHex, txHex)
			handle := f.submitHandler
			f.mu.Unlock()
			status, body := 200, `{"result":null}`
			if handle != nil {
				status, body = handle(txHex)
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		default:
			f.t.Errorf("unexpected CometBFT RPC path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// setHandlers installs the responses for one test. It goes through the mutex the
// serving goroutine reads under: assigning the fields directly would be a data
// race that only fails once a request happens to overlap the assignment.
func (f *fakeCometRPC) setHandlers(lookup, submit func(string) (int, string)) {
	f.mu.Lock()
	f.lookupHandler = lookup
	f.submitHandler = submit
	f.mu.Unlock()
}

func (f *fakeCometRPC) snapshot() (lookups, submits []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.lookupHashes...), append([]string(nil), f.submittedHex...)
}

// cometNotFound is the envelope CometBFT returns for a hash it has never
// indexed. It is deliberately indistinguishable, to this resolver, from the RPC
// being broken: both are the absence of proof.
const cometNotFound = `{"jsonrpc":"2.0","id":-1,"error":{"code":-32603,"message":"Internal error","data":"tx (ABC) not found"}}`

func newFakeComet(t *testing.T) (*fakeCometRPC, string) {
	t.Helper()
	fake := &fakeCometRPC{t: t}
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)
	return fake, server.URL
}

func resolveWithFake(t *testing.T, endpoint string, encoded []byte) (TxOutcome, error) {
	t.Helper()
	resolve := CometTxResolver(endpoint)
	if resolve == nil {
		t.Fatal("CometTxResolver returned nil for a non-empty endpoint")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return resolve(ctx, encoded)
}

// TestCometTxResolver_CommittedHashLiftsWithoutResubmitting covers the cheap
// path. If the exact hash is already in a block there is nothing to force, and
// re-broadcasting would be pointless traffic against a node that has already
// answered.
func TestCometTxResolver_CommittedHashLiftsWithoutResubmitting(t *testing.T) {
	fake, endpoint := newFakeComet(t)
	encoded := []byte("committed-transaction")
	wantHash := strings.ToUpper(hex.EncodeToString(func() []byte { h := CometTxHash(encoded); return h[:] }()))

	fake.setHandlers(func(hash string) (int, string) {
		if hash != wantHash {
			t.Errorf("looked up %q, want the hash of the exact bytes (%q)", hash, wantHash)
		}
		return 200, `{"result":{"hash":"` + wantHash + `","height":"42","tx_result":{"code":0,"log":"ok"}}}`
	}, nil)

	outcome, err := resolveWithFake(t, endpoint, encoded)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if outcome.Verdict != TxVerdictCommitted {
		t.Fatalf("got %v, want committed", outcome.Verdict)
	}
	if _, submits := fake.snapshot(); len(submits) != 0 {
		t.Fatalf("re-submitted %d times after the hash was already proven committed", len(submits))
	}
}

// TestCometTxResolver_CommittedButRejectedInFinalizeBlockIsAVerdict pins that a
// transaction which reached a block and was refused there still LIFTS. Consensus
// spoke about those exact bytes, so no nonce inversion is possible once the key
// reopens, and the loss is a visible rejection rather than the untraceable
// Code 4 the fence exists to prevent. That is the WHOLE claim: a failed
// transaction does not consume the nonce and a byte-identical copy can still be
// re-included from a peer mempool — see cometIndexedOutcome's caveat — so this
// is deliberately NOT "nothing is left in flight".
func TestCometTxResolver_CommittedButRejectedInFinalizeBlockIsAVerdict(t *testing.T) {
	fake, endpoint := newFakeComet(t)
	fake.setHandlers(func(hash string) (int, string) {
		return 200, `{"result":{"hash":"` + hash + `","height":"9","tx_result":{"code":4,"log":"nonce too low"}}}`
	}, nil)

	outcome, err := resolveWithFake(t, endpoint, []byte("rejected-in-block"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if outcome.Verdict != TxVerdictRejected {
		t.Fatalf("got %v, want rejected", outcome.Verdict)
	}
	if !strings.Contains(outcome.Detail, "FinalizeBlock code 4") {
		t.Fatalf("detail lost the rejection reason an operator needs: %q", outcome.Detail)
	}
}

// TestCometTxResolver_ResubmitsTheExactBytesToForceAnAnswer is the heart of the
// rework. A lookup that says "not found" proves nothing — CometBFT indexes a
// transaction only once it is in a block — so the resolver re-broadcasts the
// IDENTICAL bytes instead of waiting for an answer that may never come.
//
// The bytes must be byte-for-byte identical: same bytes mean the same hash and
// the same nonce, which is what makes re-submission idempotent instead of a way
// to put a second signed transaction on the chain.
func TestCometTxResolver_ResubmitsTheExactBytesToForceAnAnswer(t *testing.T) {
	fake, endpoint := newFakeComet(t)
	encoded := []byte{0x00, 0x01, 0xfe, 0xff, 0x7b, 0x7d}
	wantHex := hex.EncodeToString(encoded)

	fake.setHandlers(
		func(string) (int, string) { return 500, cometNotFound },
		func(txHex string) (int, string) {
			if !strings.EqualFold(txHex, wantHex) {
				t.Errorf("re-submitted %q, want the exact original bytes %q: different bytes are a different "+
					"transaction and re-submission would no longer be idempotent", txHex, wantHex)
			}
			return 200, `{"result":{"check_tx":{"code":0},"tx_result":{"code":0,"log":"ok"},"hash":"ABC","height":"43"}}`
		})

	outcome, err := resolveWithFake(t, endpoint, encoded)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if outcome.Verdict != TxVerdictCommitted {
		t.Fatalf("got %v, want committed via re-submission", outcome.Verdict)
	}
	lookups, submits := fake.snapshot()
	if len(lookups) != 1 || len(submits) != 1 {
		t.Fatalf("expected one lookup then one re-submission, got %d/%d", len(lookups), len(submits))
	}
}

// TestCometTxResolver_SupersededNonceIsADefinitiveRejection is the outcome the
// re-submission is most often going to produce in the failure this fence guards.
// Once the committed nonce for the key is at or above the abandoned one, app-v9's
// replay gate answers Code 4 "nonce too low" in CheckTx — which PROVES the
// abandoned bytes can never commit AGAIN, so the key is safe to reopen.
//
// What code 4 does NOT prove is WHICH fate happened: the gate is
// `nonce <= committed`, so a transaction that itself committed answers code 4
// exactly like one overtaken by a higher nonce. With the tx index unable to say
// (here: /tx keeps answering not-found, as it does with indexer="null" or a
// pruned index), the detail must state both readings rather than claim a
// rejection — an operator told "refused" redoes by hand work that may already
// have applied.
func TestCometTxResolver_SupersededNonceIsADefinitiveRejection(t *testing.T) {
	fake, endpoint := newFakeComet(t)
	fake.setHandlers(
		func(string) (int, string) { return 500, cometNotFound },
		func(string) (int, string) {
			return 200, `{"result":{"check_tx":{"code":4,"log":"nonce too low"},"tx_result":{"code":0},"hash":"ABC","height":"0"}}`
		})

	outcome, err := resolveWithFake(t, endpoint, []byte("superseded"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if outcome.Verdict != TxVerdictRejected {
		t.Fatalf("got %v, want rejected", outcome.Verdict)
	}
	if !strings.Contains(outcome.Detail, "committed-nonce gate (CheckTx code 4)") {
		t.Fatalf("detail lost the refusal reason: %q", outcome.Detail)
	}
	if !strings.Contains(outcome.Detail, "indistinguishable") {
		t.Fatalf("detail claims more than code 4 proves — it must say supersession and self-commit "+
			"cannot be told apart without the tx index: %q", outcome.Detail)
	}
	lookups, _ := fake.snapshot()
	if len(lookups) != 2 {
		t.Fatalf("expected the index to be re-checked once after the code-4 refusal, got %d lookup(s)", len(lookups))
	}
}

// TestCometTxResolver_NonceGateRefusalPrefersTheIndexedFate is the misreport
// regression. A code-4 refusal of the RE-SUBMIT can be caused by the fenced
// transaction's OWN commit landing in the gap after the first /tx lookup (or by
// the indexer catching up late). Labeling that fate_rejected tells the operator
// a committed change was refused — the "redo the work by hand, apply it twice"
// failure. So after the nonce gate answers, the resolver must ask the index once
// more and prefer its answer: an indexed commit is the true fate.
func TestCometTxResolver_NonceGateRefusalPrefersTheIndexedFate(t *testing.T) {
	fake, endpoint := newFakeComet(t)
	encoded := []byte("self-committed")
	wantHash := strings.ToUpper(hex.EncodeToString(func() []byte { h := CometTxHash(encoded); return h[:] }()))

	// First lookup: not indexed yet. After the re-submit hits the nonce gate,
	// the second lookup finds the exact hash committed — the self-commit case.
	var lookupCount int
	var mu sync.Mutex
	fake.setHandlers(
		func(hash string) (int, string) {
			mu.Lock()
			lookupCount++
			first := lookupCount == 1
			mu.Unlock()
			if first {
				return 500, cometNotFound
			}
			return 200, `{"result":{"hash":"` + wantHash + `","height":"77","tx_result":{"code":0,"log":"ok"}}}`
		},
		func(string) (int, string) {
			return 200, `{"result":{"check_tx":{"code":4,"log":"nonce too low: got 7, expected > 7"},"tx_result":{"code":0},"hash":"ABC","height":"0"}}`
		})

	outcome, err := resolveWithFake(t, endpoint, encoded)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if outcome.Verdict != TxVerdictCommitted {
		t.Fatalf("got %v (%q), want committed: the exact hash is indexed, so reporting the code-4 "+
			"refusal as the fate would misreport a committed transaction as rejected",
			outcome.Verdict, outcome.Detail)
	}
	if !strings.Contains(outcome.Detail, "committed at height 77") {
		t.Fatalf("detail lost the committed height: %q", outcome.Detail)
	}
}

// TestCometTxResolver_UnprovenAnswersStayUnresolved sweeps every RPC shape that
// is NOT proof. Each one of these was, in some form, a fail-open lift in the
// superseded implementation, so the assertion is uniform and blunt: no verdict.
func TestCometTxResolver_UnprovenAnswersStayUnresolved(t *testing.T) {
	for _, tc := range []struct {
		name   string
		lookup func(string) (int, string)
		submit func(string) (int, string)
		want   string
	}{
		{
			// The duplicate answer: the transaction is already pending, which
			// is the single strongest reason NOT to reopen the key.
			name:   "duplicate already pending in the mempool",
			lookup: func(string) (int, string) { return 500, cometNotFound },
			submit: func(string) (int, string) {
				return 500, `{"error":{"code":-32603,"message":"Internal error","data":"tx already exists in cache"}}`
			},
			want: "already exists in cache",
		},
		{
			// CometBFT gives up waiting for the block; the transaction is
			// still in the mempool.
			name:   "commit wait timed out",
			lookup: func(string) (int, string) { return 500, cometNotFound },
			submit: func(string) (int, string) {
				return 500, `{"error":{"code":-32603,"message":"Internal error","data":"timed out waiting for tx to be included in a block"}}`
			},
			want: "timed out waiting",
		},
		{
			name:   "mempool is full",
			lookup: func(string) (int, string) { return 500, cometNotFound },
			submit: func(string) (int, string) {
				return 500, `{"error":{"code":-32603,"message":"Internal error","data":"mempool is full"}}`
			},
			want: "mempool is full",
		},
		{
			// Both codes zero but nothing says it landed. Synthesizing
			// "committed" from silence is exactly the fail-open removed here.
			name:   "success envelope with no committed height",
			lookup: func(string) (int, string) { return 500, cometNotFound },
			submit: func(string) (int, string) {
				return 200, `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"","height":"0"}}`
			},
			want: "no committed height",
		},
		{
			name:   "undecodable response",
			lookup: func(string) (int, string) { return 500, cometNotFound },
			submit: func(string) (int, string) { return 200, `<html>proxy error</html>` },
			want:   "comet re-submit",
		},
		{
			name:   "rpc returns an unusable status",
			lookup: func(string) (int, string) { return http.StatusBadGateway, `` },
			submit: func(string) (int, string) { return http.StatusBadGateway, `` },
			want:   "502",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, endpoint := newFakeComet(t)
			fake.setHandlers(tc.lookup, tc.submit)

			outcome, err := resolveWithFake(t, endpoint, []byte("in-flight"))
			if err != nil {
				t.Fatalf("resolve returned an error rather than an unresolved outcome: %v", err)
			}
			if outcome.Verdict != TxVerdictUnresolved {
				t.Fatalf("got %v, want unresolved: this answer is not proof of the transaction's fate", outcome.Verdict)
			}
			if !strings.Contains(outcome.Detail, tc.want) {
				t.Fatalf("detail %q does not explain why the fence is still held (want it to mention %q)", outcome.Detail, tc.want)
			}
		})
	}
}

// TestCometTxResolver_UnreachableNodeStaysUnresolved covers the case that
// motivated the whole fence: the node this process was talking to is gone. An
// unreachable node is the least informative answer there is, and the superseded
// implementation eventually reopened the key on it.
func TestCometTxResolver_UnreachableNodeStaysUnresolved(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	endpoint := server.URL
	server.Close()

	outcome, err := resolveWithFake(t, endpoint, []byte("in-flight"))
	if err != nil {
		t.Fatalf("resolve returned an error rather than an unresolved outcome: %v", err)
	}
	if outcome.Verdict != TxVerdictUnresolved {
		t.Fatalf("got %v, want unresolved for an unreachable node", outcome.Verdict)
	}
	if outcome.Detail == "" {
		t.Fatal("an unresolved outcome with no detail makes a held fence undiagnosable")
	}
}

// TestCometTxResolver_EmptyEndpointHasNoResolver pins that a missing endpoint
// yields nil rather than a resolver that pretends to have checked. The fence is
// then held (errNoTxResolver), which is the correct fail-safe: not knowing how
// to ask is not evidence that the transaction is gone.
func TestCometTxResolver_EmptyEndpointHasNoResolver(t *testing.T) {
	for _, endpoint := range []string{"", "   ", "\t\n"} {
		if CometTxResolver(endpoint) != nil {
			t.Fatalf("CometTxResolver(%q) returned a resolver; it cannot resolve anything", endpoint)
		}
	}
}

// TestCometTxResolver_TrimsTrailingSlash keeps the URL join from producing
// "//tx", which some proxies answer with a redirect that this client does not
// follow — a self-inflicted permanent hold.
func TestCometTxResolver_TrimsTrailingSlash(t *testing.T) {
	fake, endpoint := newFakeComet(t)
	fake.setHandlers(func(hash string) (int, string) {
		return 200, fmt.Sprintf(`{"result":{"hash":%q,"height":"1","tx_result":{"code":0}}}`, hash)
	}, nil)

	outcome, err := resolveWithFake(t, endpoint+"/", []byte("tx"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if outcome.Verdict != TxVerdictCommitted {
		t.Fatalf("got %v, want committed", outcome.Verdict)
	}
}
