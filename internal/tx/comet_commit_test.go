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
	"sync/atomic"
	"testing"
	"time"
)

func TestBroadcastCometCommitRequiresCompleteBoundProof(t *testing.T) {
	encoded := []byte("strict-shared-commit-envelope")
	sum := CometTxHash(encoded)
	bound := strings.ToUpper(hex.EncodeToString(sum[:]))
	valid := `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` + bound + `","height":"7"}}`

	for _, tc := range []struct {
		name   string
		status int
		body   string
		ok     bool
	}{
		{"complete success", 200, valid, true},
		{"missing result", 200, `{}`, false},
		{"null result", 200, `{"result":null}`, false},
		{"missing nested verdicts", 200, `{"result":{"hash":"` + bound + `","height":"7"}}`, false},
		{"null checktx", 200, `{"result":{"check_tx":null,"tx_result":{"code":0},"hash":"` + bound + `","height":"7"}}`, false},
		{"null txresult", 200, `{"result":{"check_tx":{"code":0},"tx_result":null,"hash":"` + bound + `","height":"7"}}`, false},
		{"missing code", 200, `{"result":{"check_tx":{},"tx_result":{"code":0},"hash":"` + bound + `","height":"7"}}`, false},
		{"wrong hash", 200, `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"AB12","height":"7"}}`, false},
		{"zero height", 200, `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"` + bound + `","height":"0"}}`, false},
		{"heightless FinalizeBlock rejection", 200, `{"result":{"check_tx":{"code":0},"tx_result":{"code":47},"hash":"` + bound + `","height":"0"}}`, false},
		{"rpc error envelope", 200, `{"error":{"message":"request failed","data":"untrusted"}}`, false},
		{"malformed json", 200, `{"result":`, false},
		{"non-200 success-shaped body", 500, valid, false},
		{"second empty json value", 200, valid + ` {}`, false},
		{"invalid trailing data", 200, valid + ` garbage`, false},
		{"second valid Comet envelope", 200, valid + ` ` + valid, false},
		{"body over cap", 200, valid + strings.Repeat(" ", CometRPCMaxResponseBytes+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer rpc.Close()
			got, err := BroadcastCometCommit(context.Background(), rpc.URL, nil, encoded)
			if tc.ok {
				if err != nil || got == nil || got.Hash != bound || got.Height != 7 {
					t.Fatalf("got result=%+v err=%v, want bound success", got, err)
				}
				return
			}
			if err == nil || got != nil {
				t.Fatalf("malformed response produced result=%+v err=%v", got, err)
			}
		})
	}
}

func TestSharedCometBroadcastersFenceMalformedOnWireResponse(t *testing.T) {
	for _, tc := range []struct {
		name      string
		broadcast func(context.Context, string, ed25519.PrivateKey, []byte) error
	}{
		{"commit", func(ctx context.Context, endpoint string, key ed25519.PrivateKey, encoded []byte) error {
			_, err := BroadcastCometCommit(ctx, endpoint, key, encoded)
			return err
		}},
		{"sync", func(ctx context.Context, endpoint string, key ed25519.PrivateKey, encoded []byte) error {
			_, err := BroadcastCometSync(ctx, endpoint, key, encoded)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub, key, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			encoded := []byte("shared-" + tc.name + "-malformed-on-wire")
			hash := CometTxHash(encoded)
			bound := strings.ToUpper(hex.EncodeToString(hash[:]))
			var allowProof atomic.Bool
			rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if allowProof.Load() {
					_, _ = fmt.Fprintf(w, `{"result":{"hash":"%s","height":"1","tx_result":{"code":0}}}`, bound)
					return
				}
				_, _ = fmt.Fprint(w, `{"result":`)
			}))
			defer rpc.Close()

			err = WithNonceLease(context.Background(), key, func(uint64) error {
				return tc.broadcast(context.Background(), rpc.URL, key, encoded)
			})
			if err == nil {
				t.Fatal("malformed on-wire response returned nil")
			}
			signer := hex.EncodeToString(pub)
			var held *FencedSigner
			for _, candidate := range FencedSigners() {
				if candidate.SignerPubKeyHex == signer {
					copy := candidate
					held = &copy
					break
				}
			}
			if held == nil || held.TxHash != bound {
				t.Fatalf("exact signer/hash was not fenced: held=%+v want_hash=%s", held, bound)
			}

			entered := false
			blockedCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			blockedErr := WithNonceLease(blockedCtx, key, func(uint64) error {
				entered = true
				return nil
			})
			if entered || !errors.Is(blockedErr, ErrSignerFenced) {
				t.Fatalf("next same-key lease entered=%v err=%v, want held fence", entered, blockedErr)
			}

			allowProof.Store(true)
			deadline := time.Now().Add(2 * time.Second)
			for keyIsFenced(string(pub)) && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if keyIsFenced(string(pub)) {
				t.Fatal("fence did not lift after exact-hash indexed proof")
			}
		})
	}
}

func TestSharedCometCommitDefinitiveOutcomesDoNotFence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		checkCode  uint32
		txCode     uint32
		height     int64
		returnFail bool
	}{
		{"bound success", 0, 0, 7, false},
		{"bound CheckTx refusal", 4, 0, 0, true},
		{"bound FinalizeBlock refusal", 0, 47, 7, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub, key, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			encoded := []byte("shared-definitive-" + tc.name)
			hash := CometTxHash(encoded)
			bound := strings.ToUpper(hex.EncodeToString(hash[:]))
			rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintf(w,
					`{"result":{"check_tx":{"code":%d},"tx_result":{"code":%d},"hash":"%s","height":"%d"}}`,
					tc.checkCode, tc.txCode, bound, tc.height)
			}))
			defer rpc.Close()

			wantRefusal := errors.New("adopter surfaced definitive refusal")
			err = WithNonceLease(context.Background(), key, func(uint64) error {
				result, broadcastErr := BroadcastCometCommit(context.Background(), rpc.URL, key, encoded)
				if broadcastErr != nil {
					return broadcastErr
				}
				if tc.returnFail && (result.CheckTxCode != 0 || result.TxResultCode != 0) {
					return wantRefusal
				}
				return nil
			})
			if tc.returnFail {
				if !errors.Is(err, wantRefusal) {
					t.Fatalf("got %v, want definitive refusal", err)
				}
			} else if err != nil {
				t.Fatalf("success returned %v", err)
			}
			if keyIsFenced(string(pub)) {
				t.Fatal("hash-bound definitive outcome fenced the signer")
			}
			entered := false
			if err := WithNonceLease(context.Background(), key, func(uint64) error {
				entered = true
				return nil
			}); err != nil || !entered {
				t.Fatalf("next same-key lease entered=%v err=%v", entered, err)
			}
		})
	}
}

func TestBroadcastCometSyncRequiresCompleteBoundProof(t *testing.T) {
	encoded := []byte("strict-shared-sync-envelope")
	sum := CometTxHash(encoded)
	bound := strings.ToUpper(hex.EncodeToString(sum[:]))
	valid := `{"result":{"code":0,"hash":"` + bound + `","log":""}}`

	for _, tc := range []struct {
		name   string
		status int
		body   string
		ok     bool
	}{
		{"complete success", 200, valid, true},
		{"missing result", 200, `{}`, false},
		{"null result", 200, `{"result":null}`, false},
		{"missing code", 200, `{"result":{"hash":"` + bound + `"}}`, false},
		{"wrong hash", 200, `{"result":{"code":0,"hash":"AB12"}}`, false},
		{"rpc error envelope", 200, `{"error":{"message":"request failed"}}`, false},
		{"non-200 success-shaped body", 500, valid, false},
		{"second valid Comet envelope", 200, valid + ` ` + valid, false},
		{"invalid trailing data", 200, valid + ` garbage`, false},
		{"body over cap", 200, valid + strings.Repeat(" ", CometRPCMaxResponseBytes+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer rpc.Close()
			got, err := BroadcastCometSync(context.Background(), rpc.URL, nil, encoded)
			if tc.ok {
				if err != nil || got == nil || got.Hash != bound {
					t.Fatalf("got result=%+v err=%v, want bound success", got, err)
				}
				return
			}
			if err == nil || got != nil {
				t.Fatalf("malformed response produced result=%+v err=%v", got, err)
			}
		})
	}
}

func TestBroadcastCometCommitReturnsBoundRejectionVerdicts(t *testing.T) {
	encoded := []byte("strict-shared-rejection-envelope")
	sum := CometTxHash(encoded)
	bound := strings.ToUpper(hex.EncodeToString(sum[:]))
	for _, tc := range []struct {
		name string
		body string
		code uint32
	}{
		{"checktx", `{"result":{"check_tx":{"code":4,"log":"nonce too low"},"tx_result":{"code":0},"hash":"` + bound + `","height":"0"}}`, 4},
		{"finalizeblock", `{"result":{"check_tx":{"code":0},"tx_result":{"code":47,"log":"already pending"},"hash":"` + bound + `","height":"9"}}`, 47},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, key, keyErr := ed25519.GenerateKey(nil)
			if keyErr != nil {
				t.Fatal(keyErr)
			}
			rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer rpc.Close()
			got, err := BroadcastCometCommit(context.Background(), rpc.URL, key, encoded)
			if err != nil || got == nil {
				t.Fatalf("got result=%+v err=%v", got, err)
			}
			if got.CheckTxCode != tc.code && got.TxResultCode != tc.code {
				t.Fatalf("verdict codes check=%d finalize=%d, want %d", got.CheckTxCode, got.TxResultCode, tc.code)
			}
			pub := key.Public().(ed25519.PublicKey)
			registeredMu.Lock()
			_, stillRegistered := registeredSubmissions[string(pub)]
			registeredMu.Unlock()
			if stillRegistered {
				t.Fatal("hash-bound rejection left the submission registration live")
			}
		})
	}
}
