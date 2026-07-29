package rest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/auth"
	"github.com/l33tdawg/sage/internal/store"
)

type countingEmbedder struct {
	calls atomic.Int64
}

func (e *countingEmbedder) Embed(context.Context, string) ([]float32, error) {
	e.calls.Add(1)
	return []float32{0.25, 0.75}, nil
}

func (*countingEmbedder) Dimension() int { return 2 }
func (*countingEmbedder) Ready() bool    { return true }
func (*countingEmbedder) Semantic() bool { return false }

func appV23EmbedTestKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("app-v23-embed:" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func appV23EmbedTestID(key ed25519.PrivateKey) string {
	return hex.EncodeToString(key.Public().(ed25519.PublicKey))
}

func appV23EmbedSignedRequest(
	t *testing.T,
	key ed25519.PrivateKey,
	path, remoteAddr, host string,
) *http.Request {
	t.Helper()
	body := []byte(`{"text":"security boundary"}`)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.RemoteAddr = remoteAddr
	req.Host = host
	timestamp := time.Now().Unix()
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	require.NoError(t, err)
	signature := auth.SignRequestWithNonce(
		key, http.MethodPost, path, body, timestamp, nonce,
	)
	req.Header.Set("X-Agent-ID", appV23EmbedTestID(key))
	req.Header.Set("X-Signature", hex.EncodeToString(signature))
	req.Header.Set("X-Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set("X-Nonce", hex.EncodeToString(nonce))
	return req
}

func appV23EmbedInfoSignedRequest(
	t *testing.T,
	key ed25519.PrivateKey,
	remoteAddr, host string,
) *http.Request {
	t.Helper()
	const path = "/v1/embed/info"
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remoteAddr
	req.Host = host
	timestamp := time.Now().Unix()
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	require.NoError(t, err)
	signature := auth.SignRequestWithNonce(
		key, http.MethodGet, path, nil, timestamp, nonce,
	)
	req.Header.Set("X-Agent-ID", appV23EmbedTestID(key))
	req.Header.Set("X-Signature", hex.EncodeToString(signature))
	req.Header.Set("X-Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set("X-Nonce", hex.EncodeToString(nonce))
	return req
}

func appV23ApproveEmbedAgent(
	t *testing.T,
	badger *store.BadgerStore,
	rootID string,
	key ed25519.PrivateKey,
	role string,
	height int64,
	active bool,
) {
	t.Helper()
	agentID := appV23EmbedTestID(key)
	capabilities := store.AgentCapabilities(0)
	clearance := uint8(2)
	if role == store.AppV23RoleAdmin {
		capabilities = store.AgentCapabilityReadAllDomains
		clearance = uint8(4)
	}
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		agentID, role+"-embed-agent", store.AppV23RoleMember,
		"", "test", "", height, 0,
	))
	require.NoError(t, badger.ApproveAppV23LocalAgent(
		store.AppV23LocalEnrollment{
			AgentID: agentID, ApprovedBy: rootID, RootGeneration: 1,
			Profile: store.AppV23ProfileStandard, HomeDomain: agentID[:12] + ".home",
			Clearance: clearance, Capabilities: capabilities, Active: active,
			UpdatedHeight: height,
		},
		role, 0, 0,
	))
}

func setupAppV23EmbedServer(
	t *testing.T,
) (*Server, *store.BadgerStore, *countingEmbedder, map[string]ed25519.PrivateKey) {
	t.Helper()
	srv, _, badger, _ := newRBACTestServer(t)
	embedder := &countingEmbedder{}
	srv.embedder = embedder

	keys := map[string]ed25519.PrivateKey{
		"root":     appV23EmbedTestKey("root"),
		"member":   appV23EmbedTestKey("member"),
		"manager":  appV23EmbedTestKey("manager"),
		"admin":    appV23EmbedTestKey("admin"),
		"pending":  appV23EmbedTestKey("pending"),
		"inactive": appV23EmbedTestKey("inactive"),
		"unknown":  appV23EmbedTestKey("unknown"),
	}
	rootID := appV23EmbedTestID(keys["root"])
	memberID := appV23EmbedTestID(keys["member"])
	require.NoError(t, badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: rootID, Scope: "app-v23-embed-boundary", AgentID: memberID,
		Profile: store.AppV23ProfileStandard, HomeDomain: "member.embed.home",
		Clearance: 2, Capabilities: 0, Height: 1, BootstrapDigest: "embed-bootstrap",
	}))
	appV23ApproveEmbedAgent(t, badger, rootID, keys["manager"], store.AppV23RoleManager, 2, true)
	appV23ApproveEmbedAgent(t, badger, rootID, keys["admin"], store.AppV23RoleAdmin, 3, true)
	appV23ApproveEmbedAgent(t, badger, rootID, keys["inactive"], store.AppV23RoleMember, 4, false)
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		appV23EmbedTestID(keys["pending"]), "pending-embed-agent",
		store.AppV23RoleMember, "", "test", "", 5,
		store.DefaultSelfRegisteredAgentCapabilities,
	))

	srv.SetPostV23ForNextTxAccessor(func() bool { return true })
	return srv, badger, embedder, keys
}

func TestAppV23EmbedRoutesRequireActiveApprovedAgent(t *testing.T) {
	srv, _, embedder, keys := setupAppV23EmbedServer(t)
	remoteAddr := "198.51.100.23:44000"
	remoteHost := "sage.example.test:8080"

	for _, path := range []string{"/v1/embed", "/v1/embed/personal"} {
		for _, identity := range []string{"unknown", "pending", "inactive"} {
			before := embedder.calls.Load()
			rec := httptest.NewRecorder()
			srv.Router().ServeHTTP(rec, appV23EmbedSignedRequest(
				t, keys[identity], path, remoteAddr, remoteHost,
			))
			require.Equal(t, http.StatusForbidden, rec.Code, "%s %s: %s", path, identity, rec.Body.String())
			require.Equal(t, before, embedder.calls.Load(), "denied caller must not consume embedding work")
		}
		for _, identity := range []string{"member", "manager"} {
			before := embedder.calls.Load()
			rec := httptest.NewRecorder()
			srv.Router().ServeHTTP(rec, appV23EmbedSignedRequest(
				t, keys[identity], path, remoteAddr, remoteHost,
			))
			require.Equal(t, http.StatusOK, rec.Code, "%s %s: %s", path, identity, rec.Body.String())
			require.Equal(t, before+1, embedder.calls.Load())
		}
	}
}

func TestAppV23EmbedInfoRequiresActiveApprovedAgent(t *testing.T) {
	srv, _, embedder, keys := setupAppV23EmbedServer(t)
	remoteAddr := "198.51.100.23:44000"
	remoteHost := "sage.example.test:8080"

	unknown := httptest.NewRecorder()
	srv.Router().ServeHTTP(unknown, appV23EmbedInfoSignedRequest(
		t, keys["unknown"], remoteAddr, remoteHost,
	))
	require.Equal(t, http.StatusForbidden, unknown.Code, unknown.Body.String())
	require.Zero(t, embedder.calls.Load())

	member := httptest.NewRecorder()
	srv.Router().ServeHTTP(member, appV23EmbedInfoSignedRequest(
		t, keys["member"], remoteAddr, remoteHost,
	))
	require.Equal(t, http.StatusOK, member.Code, member.Body.String())
	require.Zero(t, embedder.calls.Load(), "provider-info must not generate an embedding")

	remoteAdmin := httptest.NewRecorder()
	srv.Router().ServeHTTP(remoteAdmin, appV23EmbedInfoSignedRequest(
		t, keys["admin"], remoteAddr, "localhost:8080",
	))
	require.Equal(t, http.StatusForbidden, remoteAdmin.Code, remoteAdmin.Body.String())

	localAdmin := httptest.NewRecorder()
	srv.Router().ServeHTTP(localAdmin, appV23EmbedInfoSignedRequest(
		t, keys["admin"], "127.0.0.1:44000", "localhost:8080",
	))
	require.Equal(t, http.StatusOK, localAdmin.Code, localAdmin.Body.String())
}

func TestAppV23EmbedRoutesPreserveAdminLocalityAndRejectRootHistory(t *testing.T) {
	srv, badger, embedder, keys := setupAppV23EmbedServer(t)
	localAddr := "127.0.0.1:44000"
	localHost := "localhost:8080"

	for _, path := range []string{"/v1/embed", "/v1/embed/personal"} {
		before := embedder.calls.Load()
		remoteAdmin := httptest.NewRecorder()
		srv.Router().ServeHTTP(remoteAdmin, appV23EmbedSignedRequest(
			t, keys["admin"], path, "198.51.100.23:44000", localHost,
		))
		require.Equal(t, http.StatusForbidden, remoteAdmin.Code, remoteAdmin.Body.String())
		require.Equal(t, before, embedder.calls.Load())

		localAdmin := httptest.NewRecorder()
		srv.Router().ServeHTTP(localAdmin, appV23EmbedSignedRequest(
			t, keys["admin"], path, localAddr, localHost,
		))
		require.Equal(t, http.StatusOK, localAdmin.Code, localAdmin.Body.String())
		require.Equal(t, before+1, embedder.calls.Load())

		currentRoot := httptest.NewRecorder()
		srv.Router().ServeHTTP(currentRoot, appV23EmbedSignedRequest(
			t, keys["root"], path, localAddr, localHost,
		))
		require.Equal(t, http.StatusForbidden, currentRoot.Code, currentRoot.Body.String())
		require.Equal(t, before+1, embedder.calls.Load())
	}

	retiredRootKey := keys["root"]
	newRootKey := appV23EmbedTestKey("replacement-root")
	require.NoError(t, badger.RotateAppV23RootCredential(
		1, appV23EmbedTestID(newRootKey), 6,
	))
	for _, key := range []ed25519.PrivateKey{retiredRootKey, newRootKey} {
		before := embedder.calls.Load()
		rec := httptest.NewRecorder()
		srv.Router().ServeHTTP(rec, appV23EmbedSignedRequest(
			t, key, "/v1/embed", localAddr, localHost,
		))
		require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		require.Equal(t, before, embedder.calls.Load())
	}
}

func TestPreAppV23EmbedRoutesKeepHistoricalSignedKeyCompatibility(t *testing.T) {
	srv, _, embedder, keys := setupAppV23EmbedServer(t)
	srv.SetPostV23ForNextTxAccessor(func() bool { return false })

	for _, path := range []string{"/v1/embed", "/v1/embed/personal"} {
		before := embedder.calls.Load()
		rec := httptest.NewRecorder()
		srv.Router().ServeHTTP(rec, appV23EmbedSignedRequest(
			t, keys["unknown"], path, "198.51.100.23:44000", "sage.example.test:8080",
		))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Equal(t, before+1, embedder.calls.Load())
	}

	info := httptest.NewRecorder()
	srv.Router().ServeHTTP(info, appV23EmbedInfoSignedRequest(
		t, keys["unknown"], "198.51.100.23:44000", "sage.example.test:8080",
	))
	require.Equal(t, http.StatusOK, info.Code, info.Body.String())
}

func TestEmbedPersonalAliasIsNeverUnsignedPublicCompute(t *testing.T) {
	srv, _, embedder, _ := setupAppV23EmbedServer(t)
	req := httptest.NewRequest(
		http.MethodPost, "/v1/embed/personal",
		bytes.NewBufferString(`{"text":"unsigned"}`),
	)
	req.RemoteAddr = "198.51.100.23:44000"
	req.Host = "sage.example.test:8080"
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	require.Zero(t, embedder.calls.Load())
}
