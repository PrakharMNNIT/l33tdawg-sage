package tx

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
		{"rpc error envelope", 200, `{"error":{"message":"request failed","data":"untrusted"}}`, false},
		{"malformed json", 200, `{"result":`, false},
		{"non-200 success-shaped body", 500, valid, false},
		{"second empty json value", 200, valid + ` {}`, false},
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
			rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprint(w, tc.body)
			}))
			defer rpc.Close()
			got, err := BroadcastCometCommit(context.Background(), rpc.URL, nil, encoded)
			if err != nil || got == nil {
				t.Fatalf("got result=%+v err=%v", got, err)
			}
			if got.CheckTxCode != tc.code && got.TxResultCode != tc.code {
				t.Fatalf("verdict codes check=%d finalize=%d, want %d", got.CheckTxCode, got.TxResultCode, tc.code)
			}
		})
	}
}
