package rest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/api/rest/middleware"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

func appV23ElevationTestKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func appV23ElevationTestID(key ed25519.PrivateKey) string {
	return hex.EncodeToString(key.Public().(ed25519.PublicKey))
}

func promoteAppV23ElevationTestAdmin(
	t *testing.T,
	badgerStore *store.BadgerStore,
	rootID, adminID string,
	height int64,
) {
	t.Helper()
	enrollment, err := badgerStore.GetAppV23Enrollment(adminID)
	require.NoError(t, err)
	require.NotNil(t, enrollment)
	role, err := badgerStore.GetAppV23Role(adminID)
	require.NoError(t, err)
	require.NotNil(t, role)
	require.NoError(t, badgerStore.SetAppV23Policy(
		rootID, adminID, store.AppV23RoleAdmin,
		enrollment.Profile, store.AppV23ProfileStandard,
		4, store.AgentCapabilityReadAllDomains,
		role.Revision, enrollment.Revision, height,
	))
}

func TestRESTAppV23SigningBrokerCountersignsPromotedAdminOnly(t *testing.T) {
	badgerStore, err := store.NewBadgerStore(filepath.Join(t.TempDir(), "badger"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, badgerStore.CloseBadger()) })

	rootKey := appV23ElevationTestKey("rest-elevation-root")
	rootID := appV23ElevationTestID(rootKey)
	adminKey := appV23ElevationTestKey("rest-elevation-admin")
	adminID := appV23ElevationTestID(adminKey)
	memberKey := appV23ElevationTestKey("rest-elevation-member")
	memberID := appV23ElevationTestID(memberKey)
	require.NoError(t, badgerStore.RegisterAgentWithCapabilities(rootID, "root", "admin", "", "", "", 1, 0))
	require.NoError(t, badgerStore.RegisterAgentWithCapabilities(adminID, "admin", "admin", "", "", "", 2, 0))
	require.NoError(t, badgerStore.RegisterAgentWithCapabilities(memberID, "member", "member", "", "", "", 3, 0))
	require.NoError(t, badgerStore.EnsureAppV23Root("scope-rest-elevation", 10))
	promoteAppV23ElevationTestAdmin(t, badgerStore, rootID, adminID, 11)
	var heightBytes [8]byte
	binary.BigEndian.PutUint64(heightBytes[:], 12)
	require.NoError(t, badgerStore.SetState("height", heightBytes[:]))

	server := NewServer("", nil, nil, badgerStore, nil, zerolog.Nop(), nil)
	server.SetPostV23ForNextTxAccessor(func() bool { return true })
	server.SetAppV23RootKeyResolver(func(agentID string) (ed25519.PrivateKey, bool) {
		return rootKey, agentID == rootID
	})
	adminAction := &tx.ParsedTx{
		Type:          tx.TxTypeAccessGrant,
		Timestamp:     time.Now(),
		AgentPubKey:   adminKey.Public().(ed25519.PublicKey),
		AccessGrant:   &tx.AccessGrant{GranterID: adminID, GranteeID: memberID, Domain: "member-home", Level: 2},
		AgentBodyHash: make([]byte, sha256.Size),
	}
	actionBytes, err := tx.PayloadBytes(adminAction)
	require.NoError(t, err)
	require.NoError(t, server.signTx(adminAction))
	require.NotNil(t, adminAction.LocalElevation)
	require.Equal(t, uint64(1), adminAction.LocalElevation.RootGeneration)
	require.Equal(t, int64(13), adminAction.LocalElevation.ValidFromHeight)
	require.Equal(t, int64(13)+store.AppV23MaxElevationWindow, adminAction.LocalElevation.ValidUntilHeight)
	require.Len(t, adminAction.LocalElevation.Nonce, 32)
	require.True(t, ed25519.Verify(
		rootKey.Public().(ed25519.PublicKey),
		tx.AppV23ElevationSignBytes(
			"scope-rest-elevation", adminID, adminAction.Type, actionBytes, adminAction.LocalElevation,
		),
		adminAction.LocalElevation.Signature,
	))
	valid, err := tx.VerifyTx(adminAction)
	require.NoError(t, err)
	require.True(t, valid)

	rootAction := &tx.ParsedTx{
		Type:        tx.TxTypeAccessGrant,
		Timestamp:   time.Now(),
		AgentPubKey: rootKey.Public().(ed25519.PublicKey),
		AccessGrant: &tx.AccessGrant{GranterID: rootID, GranteeID: memberID, Domain: "root-home", Level: 2},
	}
	require.NoError(t, server.signTx(rootAction))
	require.Nil(t, rootAction.LocalElevation)

	memberAction := &tx.ParsedTx{
		Type:        tx.TxTypeAccessGrant,
		Timestamp:   time.Now(),
		AgentPubKey: memberKey.Public().(ed25519.PublicKey),
		AccessGrant: &tx.AccessGrant{GranterID: memberID, GranteeID: adminID, Domain: "member-home", Level: 1},
	}
	require.NoError(t, server.signTx(memberAction))
	require.Nil(t, memberAction.LocalElevation)
}

func TestRESTAppV23SigningBrokerFailsClosedWithoutCurrentRootKey(t *testing.T) {
	badgerStore, err := store.NewBadgerStore(filepath.Join(t.TempDir(), "badger"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, badgerStore.CloseBadger()) })

	rootKey := appV23ElevationTestKey("rest-missing-root")
	rootID := appV23ElevationTestID(rootKey)
	adminKey := appV23ElevationTestKey("rest-missing-admin")
	adminID := appV23ElevationTestID(adminKey)
	require.NoError(t, badgerStore.RegisterAgentWithCapabilities(rootID, "root", "admin", "", "", "", 1, 0))
	require.NoError(t, badgerStore.RegisterAgentWithCapabilities(adminID, "admin", "admin", "", "", "", 2, 0))
	require.NoError(t, badgerStore.EnsureAppV23Root("scope-rest-missing", 10))
	promoteAppV23ElevationTestAdmin(t, badgerStore, rootID, adminID, 11)
	var heightBytes [8]byte
	binary.BigEndian.PutUint64(heightBytes[:], 12)
	require.NoError(t, badgerStore.SetState("height", heightBytes[:]))

	server := NewServer("", nil, nil, badgerStore, nil, zerolog.Nop(), nil)
	server.SetPostV23ForNextTxAccessor(func() bool { return true })
	action := &tx.ParsedTx{
		Type:        tx.TxTypeAccessGrant,
		Timestamp:   time.Now(),
		AgentPubKey: adminKey.Public().(ed25519.PublicKey),
		AccessGrant: &tx.AccessGrant{GranterID: adminID, GranteeID: rootID, Domain: "admin-home", Level: 1},
	}
	require.ErrorContains(t, server.signTx(action), "local CEREBRUM broker is unavailable")
	require.Nil(t, action.LocalElevation)
}

func TestRESTAppV23RootAndAdminBoundaryRequiresLoopbackControlPlane(t *testing.T) {
	badgerStore, err := store.NewBadgerStore(filepath.Join(t.TempDir(), "badger"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, badgerStore.CloseBadger()) })

	rootKey := appV23ElevationTestKey("rest-locality-root")
	rootID := appV23ElevationTestID(rootKey)
	adminKey := appV23ElevationTestKey("rest-locality-admin")
	adminID := appV23ElevationTestID(adminKey)
	memberKey := appV23ElevationTestKey("rest-locality-member")
	memberID := appV23ElevationTestID(memberKey)
	managerKey := appV23ElevationTestKey("rest-locality-manager")
	managerID := appV23ElevationTestID(managerKey)
	require.NoError(t, badgerStore.RegisterAgentWithCapabilities(rootID, "root", "admin", "", "", "", 1, 0))
	require.NoError(t, badgerStore.RegisterAgentWithCapabilities(adminID, "admin", "admin", "", "", "", 2, 0))
	require.NoError(t, badgerStore.RegisterAgentWithCapabilities(memberID, "member", "member", "", "", "", 3, 0))
	require.NoError(t, badgerStore.RegisterAgentWithCapabilities(managerID, "manager", "manager", "", "", "", 4, 0))
	require.NoError(t, badgerStore.EnsureAppV23Root("scope-rest-locality", 10))
	promoteAppV23ElevationTestAdmin(t, badgerStore, rootID, adminID, 11)

	server := NewServer("", nil, nil, badgerStore, nil, zerolog.Nop(), nil)
	server.SetPostV23ForNextTxAccessor(func() bool { return true })
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	boundary := server.appV23LocalAdminBoundary(next)
	request := func(agentID, remoteAddr, host string, headers map[string]string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/v1/memory/list", nil)
		req.RemoteAddr = remoteAddr
		req.Host = host
		for name, value := range headers {
			req.Header.Set(name, value)
		}
		return req.WithContext(middleware.WithAgentID(req.Context(), agentID))
	}

	for _, actorID := range []string{rootID, adminID} {
		for _, testCase := range []struct {
			name       string
			remoteAddr string
			host       string
			headers    map[string]string
		}{
			{
				name:       "remote socket cannot forge localhost host",
				remoteAddr: "198.51.100.8:4242", host: "localhost:8080",
			},
			{
				name:       "loopback reverse proxy cannot carry a public host",
				remoteAddr: "127.0.0.1:4242", host: "sage.example.com",
			},
			{
				name:       "remote x-forwarded-for is deny-only evidence",
				remoteAddr: "127.0.0.1:4242", host: "localhost:8080",
				headers: map[string]string{"X-Forwarded-For": "198.51.100.8"},
			},
			{
				name:       "remote x-real-ip is deny-only evidence",
				remoteAddr: "127.0.0.1:4242", host: "localhost:8080",
				headers: map[string]string{"X-Real-IP": "198.51.100.8"},
			},
			{
				name:       "remote forwarded host is deny-only evidence",
				remoteAddr: "127.0.0.1:4242", host: "localhost:8080",
				headers: map[string]string{"X-Forwarded-Host": "sage.example.com"},
			},
			{
				name:       "rfc forwarded remote peer is deny-only evidence",
				remoteAddr: "127.0.0.1:4242", host: "localhost:8080",
				headers: map[string]string{"Forwarded": `for=198.51.100.8;host="localhost:8080"`},
			},
		} {
			t.Run(actorID[:8]+"/"+testCase.name, func(t *testing.T) {
				recorder := httptest.NewRecorder()
				boundary.ServeHTTP(recorder, request(
					actorID, testCase.remoteAddr, testCase.host, testCase.headers,
				))
				require.Equal(t, http.StatusForbidden, recorder.Code, recorder.Body.String())
			})
		}
	}

	for _, actorID := range []string{rootID, adminID} {
		for _, address := range []string{"127.0.0.1:4242", "[::1]:4242"} {
			recorder := httptest.NewRecorder()
			boundary.ServeHTTP(recorder, request(
				actorID, address, "localhost:8080",
				map[string]string{
					"X-Forwarded-For":  "127.0.0.1",
					"X-Forwarded-Host": "localhost:8080",
				},
			))
			require.Equal(t, http.StatusNoContent, recorder.Code, recorder.Body.String())
		}
	}

	for _, actorID := range []string{memberID, managerID} {
		recorder := httptest.NewRecorder()
		boundary.ServeHTTP(recorder, request(
			actorID, "198.51.100.8:4242", "sage.example.com",
			map[string]string{"X-Forwarded-For": "198.51.100.8"},
		))
		require.Equal(t, http.StatusNoContent, recorder.Code, recorder.Body.String())
	}
}
