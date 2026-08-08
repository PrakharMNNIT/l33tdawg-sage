package voter

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/tx"
)

func TestVoteBroadcastMalformedCometResponseFencesExactSigner(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	encoded := []byte("voter-ambiguous-on-wire-bytes")
	wantHash := tx.CometTxHash(encoded)
	var allowProof atomic.Bool
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if allowProof.Load() {
			_, _ = w.Write([]byte(`{"result":{"hash":"` + strings.ToUpper(hex.EncodeToString(wantHash[:])) + `","height":"1","tx_result":{"code":0}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"result":`))
	}))
	defer rpc.Close()

	err = tx.WithNonceLease(context.Background(), key, func(uint64) error {
		_, broadcastErr := broadcastVoteTx(context.Background(), rpc.URL, key, encoded, zerolog.Nop())
		return broadcastErr
	})
	require.Error(t, err)

	wantSigner := hex.EncodeToString(pub)
	for _, held := range tx.FencedSigners() {
		if held.SignerPubKeyHex == wantSigner {
			require.Equal(t, strings.ToUpper(hex.EncodeToString(wantHash[:])), held.TxHash)
			allowProof.Store(true)
			require.Eventually(t, func() bool {
				for _, current := range tx.FencedSigners() {
					if current.SignerPubKeyHex == wantSigner {
						return false
					}
				}
				return true
			}, 2*time.Second, 10*time.Millisecond)
			return
		}
	}
	t.Fatalf("malformed on-wire vote response released signer %s instead of fencing it", wantSigner)
}
