package federation

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/tlsca"
	"github.com/stretchr/testify/require"
)

func TestPeerAuthRejectsLegacyShortAgentIDWithoutPanic(t *testing.T) {
	a := newTestChain(t, "short-id-a")
	b := newTestChain(t, "short-id-b")
	federate(t, b, a, "https://unused.invalid", []string{"*"}, 4, 0)

	pair, err := tls.LoadX509KeyPair(
		filepath.Join(a.certsDir, tlsca.NodeCertFile),
		filepath.Join(a.certsDir, tlsca.NodeKeyFile),
	)
	require.NoError(t, err)
	peerCert, err := x509.ParseCertificate(pair.Certificate[0])
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/fed/v1/status", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peerCert}}
	req.Header.Set(HeaderSigVersion, SigVersion2)
	req.Header.Set(HeaderChainID, a.chainID)
	req.Header.Set(HeaderAgentID, "x")
	req.Header.Set(HeaderSignature, "00")
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set(HeaderNonce, hex.EncodeToString([]byte("short-id-test")))
	rr := httptest.NewRecorder()

	b.mgr.peerAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("malformed short agent id reached the authenticated handler")
	})).ServeHTTP(rr, req)

	require.Equal(t, http.StatusUnauthorized, rr.Code)
	require.Contains(t, rr.Body.String(), "invalid agent id")
}
