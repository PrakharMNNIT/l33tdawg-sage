package rest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/api/rest/middleware"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/vault"
	"github.com/l33tdawg/sage/web"
)

func TestOAuthAppV23ConsentUsesAuthenticatedControlActorAsIssuer(t *testing.T) {
	retiredTransportRoot := appV23RESTAgentID("11")
	for _, actorID := range []string{
		appV23RESTAgentID("22"), // current Root
		appV23RESTAgentID("33"), // current local Admin
	} {
		t.Run(actorID[:8], func(t *testing.T) {
			h, router, tokenStore := newOAuthRouter(t, true, "")
			h.NodeOperatorAgentID = retiredTransportRoot
			h.IsAuthed = func(r *http.Request) (bool, string) {
				return middleware.ContextAgentID(r.Context()) == actorID, ""
			}
			asCurrentControlActor := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.RemoteAddr = "127.0.0.1:43210"
				r.Host = "localhost:8080"
				router.ServeHTTP(w, r.WithContext(middleware.WithAgentID(r.Context(), actorID)))
			})

			redirect := "https://chat.openai.com/cb"
			clientID := registerOAuthClient(t, router, redirect)
			_ = mintAuthCode(
				t, asCurrentControlActor, clientID, redirect,
				pkceChallenge("current-control-actor-verifier-aaaaaaaa"),
				"current-control-actor", "",
			)

			rows, err := tokenStore.ListMCPTokens(context.Background())
			require.NoError(t, err)
			require.Len(t, rows, 1)
			require.Equal(t, actorID, rows[0].IssuerID,
				"OAuth issuance must follow the authenticated current Root/Admin, not the JOIN-frozen transport Root")
			require.NotEqual(t, retiredTransportRoot, rows[0].IssuerID)
		})
	}
}

func TestOAuthAppV23RetiredRootSignatureCannotAuthorizeConsent(t *testing.T) {
	retiredPub, retiredKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	retiredRootID := hex.EncodeToString(retiredPub)
	currentPub, currentRootKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	currentRootID := hex.EncodeToString(currentPub)
	memberID := appV23RESTAgentID("44")

	badger, err := store.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, badger.CloseBadger()) })
	require.NoError(t, badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: retiredRootID, Scope: "oauth-handover", AgentID: memberID,
		Profile: store.AppV23ProfileStandard, HomeDomain: "member-home",
		Clearance: 2, Height: 1, BootstrapDigest: "oauth-adversary",
	}))
	require.NoError(t, badger.RotateAppV23RootCredential(1, currentRootID, 2))

	h, router, tokenStore := newOAuthRouter(t, true, "")
	dashboard := web.NewDashboardHandler(tokenStore, "test")
	dashboard.NodeOperatorAgentID = retiredRootID
	dashboard.BadgerStore = badger
	dashboard.AppV23ActiveFn = func() bool { return true }
	dashboard.AdminSigningKey = retiredKey
	dashboard.ResolveAgentKeyFn = func(agentID string) (ed25519.PrivateKey, bool) {
		switch agentID {
		case retiredRootID:
			return retiredKey, true
		case currentRootID:
			return currentRootKey, true
		default:
			return nil, false
		}
	}
	h.NodeOperatorAgentID = retiredRootID
	h.IsAuthed = dashboard.IsRequestAuthenticated
	h.IsLocalApproval = dashboard.IsLocalCEREBRUMRequest
	h.ResolveControlActor = dashboard.ResolveOAuthControlActor

	redirect := "https://chat.openai.com/cb"
	clientID := registerOAuthClient(t, router, redirect)
	authURL := "/oauth/authorize?client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape(redirect) +
		"&code_challenge=" + pkceChallenge("retired-root-verifier-aaaaaaaa-bbbbbbbb") +
		"&code_challenge_method=S256&response_type=code&state=retired"
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	req.RemoteAddr = "127.0.0.1:43210"
	req.Host = "localhost:8080"
	rec := httptest.NewRecorder()
	signOAuthRequestsAs(t, router, retiredKey).ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code,
		"a retired CEREBRUM Root must be sent back through local approval, never shown consent")
	require.NotContains(t, rec.Body.String(), `name="csrf_nonce"`)
	rows, err := tokenStore.ListMCPTokens(context.Background())
	require.NoError(t, err)
	require.Empty(t, rows)
}

func TestOAuthAppV23CurrentRootAndAdminResolveAfterHandover(t *testing.T) {
	retiredPub, retiredKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	retiredID := hex.EncodeToString(retiredPub)
	currentPub, currentKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	currentID := hex.EncodeToString(currentPub)
	adminPub, adminKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	adminID := hex.EncodeToString(adminPub)

	badger, err := store.NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, badger.CloseBadger()) })
	require.NoError(t, badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: retiredID, Scope: "oauth-current-authority", AgentID: adminID,
		Profile: store.AppV23ProfileCompanion, HomeDomain: "admin-home",
		Clearance: 4, Capabilities: store.AgentCapabilityReadAllDomains,
		Height: 1, BootstrapDigest: "oauth-current-authority",
	}))
	require.NoError(t, badger.RotateAppV23RootCredential(1, currentID, 2))
	require.NoError(t, badger.SetAppV23Policy(
		currentID, adminID,
		store.AppV23RoleAdmin,
		store.AppV23ProfileCompanion,
		store.AppV23ProfileStandard,
		4,
		store.AgentCapabilityReadAllDomains,
		1,
		1,
		3,
	))

	h, router, tokenStore := newOAuthRouter(t, true, "")
	dashboard := web.NewDashboardHandler(tokenStore, "test")
	dashboard.NodeOperatorAgentID = retiredID
	dashboard.BadgerStore = badger
	dashboard.AppV23ActiveFn = func() bool { return true }
	dashboard.AdminSigningKey = retiredKey
	dashboard.ResolveAgentKeyFn = func(agentID string) (ed25519.PrivateKey, bool) {
		switch agentID {
		case retiredID:
			return retiredKey, true
		case currentID:
			return currentKey, true
		case adminID:
			return adminKey, true
		default:
			return nil, false
		}
	}
	h.NodeOperatorAgentID = retiredID
	h.IsAuthed = dashboard.IsRequestAuthenticated
	h.IsLocalApproval = dashboard.IsLocalCEREBRUMRequest
	h.ResolveControlActor = dashboard.ResolveOAuthControlActor

	redirect := "https://chat.openai.com/cb"
	clientID := registerOAuthClient(t, router, redirect)
	authURL := "/oauth/authorize?client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape(redirect) +
		"&code_challenge=" + pkceChallenge("current-authority-verifier-aaaaaaaa") +
		"&code_challenge_method=S256&response_type=code&state=current"
	for name, key := range map[string]ed25519.PrivateKey{
		"current Root":  currentKey,
		"current Admin": adminKey,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, authURL, nil)
			req.RemoteAddr = "127.0.0.1:43210"
			req.Host = "localhost:8080"
			rec := httptest.NewRecorder()
			signOAuthRequestsAs(t, router, key).ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.Contains(t, rec.Body.String(), "distinct pending-review MCP agent")
		})
	}
}

func TestOAuthPublicAuthorizeRedirectsToAbsoluteLoopbackApprovalBridge(t *testing.T) {
	h, router, _ := newOAuthRouter(t, false, "")
	h.IsAuthed = func(*http.Request) (bool, string) { return false, "" }
	redirect := "https://chat.openai.com/cb"
	clientID := registerOAuthClient(t, router, redirect)
	authURL := "/oauth/authorize?client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape(redirect) +
		"&code_challenge=" + pkceChallenge("public-bridge-verifier-aaaaaaaa-bbbbbbbb") +
		"&code_challenge_method=S256&response_type=code&state=bridge"

	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	req.RemoteAddr = "203.0.113.42:43210"
	req.Host = "sage.example.com"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)

	location, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.True(t, location.IsAbs(),
		"relative /ui redirects bounce back to the public tunnel where CEREBRUM is intentionally 404")
	host := location.Hostname()
	ip := net.ParseIP(host)
	require.True(t,
		host == "localhost" || (ip != nil && ip.IsLoopback()),
		"OAuth consent must cross an opaque ceremony into the localhost-only approval surface; got %q",
		rec.Header().Get("Location"),
	)
}

func oauthHiddenInput(t *testing.T, body, name string) string {
	t.Helper()
	marker := `name="` + name + `" value="`
	start := strings.Index(body, marker)
	require.GreaterOrEqual(t, start, 0, "missing hidden input %q", name)
	value := body[start+len(marker):]
	end := strings.Index(value, `"`)
	require.GreaterOrEqual(t, end, 0)
	return value[:end]
}

func TestOAuthLocalApprovalBridgeBindsExistingManagedAgentEncryptionOnAndOff(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "unencrypted", true: "vault-encrypted"}[encrypted], func(t *testing.T) {
			h, router, tokenStore := newOAuthRouter(t, false, "")
			if encrypted {
				keyPath := filepath.Join(t.TempDir(), "vault.key")
				require.NoError(t, vault.Init(keyPath, "bridge-passphrase"))
				v, err := vault.Open(keyPath, "bridge-passphrase")
				require.NoError(t, err)
				tokenStore.SetVault(v)
				tokenStore.SetVaultExpected(true)
			}
			tokenStore.SetMCPTokenKeyedIdentityRequirement(func() bool { return true })
			t.Cleanup(func() { tokenStore.SetMCPTokenKeyedIdentityRequirement(nil) })
			targetPub, targetPriv, keyErr := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, keyErr)
			targetID := hex.EncodeToString(targetPub)
			tokenStore.SetMCPTokenIdentityResolver(func(id string) (ed25519.PrivateKey, bool) {
				if id != targetID {
					return nil, false
				}
				return targetPriv, true
			})
			t.Cleanup(func() { tokenStore.SetMCPTokenIdentityResolver(nil) })
			h.ManagedTokenTargetsRequired = func() bool { return true }
			h.ValidateTokenTarget = func(_ context.Context, id string) error {
				if id != targetID {
					return errors.New("not an approved target")
				}
				return nil
			}

			approverID := strings.Repeat("7", 64)
			h.ResolveControlActor = func(r *http.Request) (string, bool) {
				if !isOAuthLoopbackRequest(r) {
					return "", false
				}
				if encrypted {
					cookie, err := r.Cookie("test-cerebrum-session")
					return approverID, err == nil && cookie.Value == "unlocked"
				}
				return approverID,
					r.Header.Get("Sec-Fetch-Site") == "same-origin" &&
						r.Header.Get("Origin") == "http://localhost:8080"
			}

			redirect := "https://chat.openai.com/cb"
			clientID := registerOAuthClient(t, router, redirect)
			verifier := "bridge-verifier-aaaaaaaa-bbbbbbbb-cccccccc"
			authURL := "/oauth/authorize?client_id=" + url.QueryEscape(clientID) +
				"&redirect_uri=" + url.QueryEscape(redirect) +
				"&code_challenge=" + pkceChallenge(verifier) +
				"&code_challenge_method=S256&response_type=code&state=bridge-state"

			publicReq := httptest.NewRequest(http.MethodGet, authURL, nil)
			publicReq.RemoteAddr = "203.0.113.9:44321"
			publicReq.Host = "sage.example.com"
			publicRec := httptest.NewRecorder()
			router.ServeHTTP(publicRec, publicReq)
			require.Equal(t, http.StatusFound, publicRec.Code)
			approvalURL, err := url.Parse(publicRec.Header().Get("Location"))
			require.NoError(t, err)
			require.Equal(t, "/oauth/approve", approvalURL.Path)
			handoff := approvalURL.Query().Get("handoff")
			require.NotEmpty(t, handoff)
			require.NotContains(t, handoff, clientID)
			require.NotContains(t, handoff, verifier)

			localApprovalGET := func() *http.Response {
				t.Helper()
				req := httptest.NewRequest(http.MethodGet, approvalURL.RequestURI(), nil)
				req.RemoteAddr = "127.0.0.1:43210"
				req.Host = "localhost:8080"
				req.Header.Set("Origin", "http://localhost:8080")
				req.Header.Set("Sec-Fetch-Site", "same-origin")
				if encrypted {
					req.AddCookie(&http.Cookie{Name: "test-cerebrum-session", Value: "unlocked"})
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				return rec.Result()
			}
			getResp := localApprovalGET()
			require.Equal(t, http.StatusOK, getResp.StatusCode)
			getBody, err := io.ReadAll(getResp.Body)
			require.NoError(t, err)
			require.NoError(t, getResp.Body.Close())
			csrf := oauthHiddenInput(t, string(getBody), "csrf_nonce")
			require.Contains(t, string(getBody), "selected existing active agent")

			form := url.Values{
				"handoff":    {handoff},
				"csrf_nonce": {csrf},
				"token_name": {"bridge-client"},
				"agent_id":   {targetID},
			}
			postReq := httptest.NewRequest(
				http.MethodPost, approvalURL.RequestURI(), strings.NewReader(form.Encode()),
			)
			postReq.RemoteAddr = "127.0.0.1:43210"
			postReq.Host = "localhost:8080"
			postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			postReq.Header.Set("Origin", "http://localhost:8080")
			postReq.Header.Set("Sec-Fetch-Site", "same-origin")
			if encrypted {
				postReq.AddCookie(&http.Cookie{Name: "test-cerebrum-session", Value: "unlocked"})
			}
			postRec := httptest.NewRecorder()
			router.ServeHTTP(postRec, postReq)
			require.Equal(t, http.StatusFound, postRec.Code, postRec.Body.String())
			clientRedirect, err := url.Parse(postRec.Header().Get("Location"))
			require.NoError(t, err)
			code := clientRedirect.Query().Get("code")
			require.NotEmpty(t, code)

			rows, err := tokenStore.ListMCPTokens(context.Background())
			require.NoError(t, err)
			require.Len(t, rows, 1)
			require.Equal(t, approverID, rows[0].IssuerID)
			require.Equal(t, targetID, rows[0].AgentID)
			require.NotEqual(t, approverID, rows[0].AgentID)

			tokenForm := url.Values{
				"grant_type": {"authorization_code"}, "code": {code},
				"code_verifier": {verifier}, "redirect_uri": {redirect},
				"client_id": {clientID},
			}
			tokenReq := httptest.NewRequest(
				http.MethodPost, "/oauth/token", strings.NewReader(tokenForm.Encode()),
			)
			tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			tokenReq.RemoteAddr = "203.0.113.9:44321"
			tokenReq.Host = "sage.example.com"
			tokenRec := httptest.NewRecorder()
			router.ServeHTTP(tokenRec, tokenReq)
			require.Equal(t, http.StatusOK, tokenRec.Code, tokenRec.Body.String())
			var tokenResponse struct {
				AccessToken string `json:"access_token"`
			}
			require.NoError(t, json.NewDecoder(tokenRec.Body).Decode(&tokenResponse))
			require.NotEmpty(t, tokenResponse.AccessToken)
			tokenDigest := sha256.Sum256([]byte(tokenResponse.AccessToken))
			agentID, signer, err := tokenStore.LookupMCPTokenSignerWithBearer(
				context.Background(),
				tokenResponse.AccessToken,
				hex.EncodeToString(tokenDigest[:]),
			)
			require.NoError(t, err)
			require.Equal(t, targetID, agentID)
			require.Equal(t, targetID, hex.EncodeToString(signer.Public().(ed25519.PublicKey)))

			// The same approval handle cannot mint a second token.
			replayReq := httptest.NewRequest(
				http.MethodPost, approvalURL.RequestURI(), strings.NewReader(form.Encode()),
			)
			replayReq.RemoteAddr = "127.0.0.1:43210"
			replayReq.Host = "localhost:8080"
			replayReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			replayReq.Header.Set("Origin", "http://localhost:8080")
			replayReq.Header.Set("Sec-Fetch-Site", "same-origin")
			if encrypted {
				replayReq.AddCookie(&http.Cookie{Name: "test-cerebrum-session", Value: "unlocked"})
			}
			replayRec := httptest.NewRecorder()
			router.ServeHTTP(replayRec, replayReq)
			require.Equal(t, http.StatusBadRequest, replayRec.Code)
			rows, err = tokenStore.ListMCPTokens(context.Background())
			require.NoError(t, err)
			require.Len(t, rows, 1)
		})
	}
}

func TestOAuthLocalApprovalHandoffExpiryTamperAndProxyLocality(t *testing.T) {
	h, router, _ := newOAuthRouter(t, false, "")
	h.ResolveControlActor = func(r *http.Request) (string, bool) {
		return strings.Repeat("8", 64), isOAuthLoopbackRequest(r)
	}
	now := time.Date(2026, 7, 29, 9, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	redirect := "https://chat.openai.com/cb"
	clientID := registerOAuthClient(t, router, redirect)
	authURL := "/oauth/authorize?client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape(redirect) +
		"&code_challenge=" + pkceChallenge("expiry-verifier-aaaaaaaa-bbbbbbbb") +
		"&code_challenge_method=S256&response_type=code&state=expiry"

	publicReq := httptest.NewRequest(http.MethodGet, authURL, nil)
	publicReq.RemoteAddr = "203.0.113.10:43210"
	publicReq.Host = "sage.example.com"
	publicRec := httptest.NewRecorder()
	router.ServeHTTP(publicRec, publicReq)
	require.Equal(t, http.StatusFound, publicRec.Code)
	approvalURL, err := url.Parse(publicRec.Header().Get("Location"))
	require.NoError(t, err)

	proxyReq := httptest.NewRequest(http.MethodGet, approvalURL.RequestURI(), nil)
	proxyReq.RemoteAddr = "127.0.0.1:43210"
	proxyReq.Host = "localhost:8080"
	proxyReq.Header.Set("X-Forwarded-For", "203.0.113.10")
	proxyRec := httptest.NewRecorder()
	router.ServeHTTP(proxyRec, proxyReq)
	require.Equal(t, http.StatusNotFound, proxyRec.Code)

	tampered := *approvalURL
	q := tampered.Query()
	q.Set("handoff", q.Get("handoff")+"x")
	tampered.RawQuery = q.Encode()
	tamperedReq := httptest.NewRequest(http.MethodGet, tampered.RequestURI(), nil)
	tamperedReq.RemoteAddr = "127.0.0.1:43210"
	tamperedReq.Host = "localhost:8080"
	tamperedRec := httptest.NewRecorder()
	router.ServeHTTP(tamperedRec, tamperedReq)
	require.Equal(t, http.StatusBadRequest, tamperedRec.Code)

	now = now.Add(OAuthApprovalHandoffTTL + time.Second)
	expiredReq := httptest.NewRequest(http.MethodGet, approvalURL.RequestURI(), nil)
	expiredReq.RemoteAddr = "127.0.0.1:43210"
	expiredReq.Host = "localhost:8080"
	expiredRec := httptest.NewRecorder()
	router.ServeHTTP(expiredRec, expiredReq)
	require.Equal(t, http.StatusBadRequest, expiredRec.Code)
	require.Contains(t, expiredRec.Body.String(), "expired")
}

func TestOAuthLocalApprovalConcurrentPOSTIsSingleUse(t *testing.T) {
	h, router, tokenStore := newOAuthRouter(t, false, "")
	h.ResolveControlActor = func(r *http.Request) (string, bool) {
		return strings.Repeat("9", 64), isOAuthLoopbackRequest(r)
	}
	redirect := "https://chat.openai.com/cb"
	clientID := registerOAuthClient(t, router, redirect)
	authURL := "/oauth/authorize?client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape(redirect) +
		"&code_challenge=" + pkceChallenge("concurrent-verifier-aaaaaaaa-bbbbbbbb") +
		"&code_challenge_method=S256&response_type=code&state=concurrent"
	publicReq := httptest.NewRequest(http.MethodGet, authURL, nil)
	publicReq.RemoteAddr = "203.0.113.12:43210"
	publicReq.Host = "sage.example.com"
	publicRec := httptest.NewRecorder()
	router.ServeHTTP(publicRec, publicReq)
	require.Equal(t, http.StatusFound, publicRec.Code)
	approvalURL, err := url.Parse(publicRec.Header().Get("Location"))
	require.NoError(t, err)
	handoff := approvalURL.Query().Get("handoff")

	getReq := httptest.NewRequest(http.MethodGet, approvalURL.RequestURI(), nil)
	getReq.RemoteAddr = "127.0.0.1:43210"
	getReq.Host = "localhost:8080"
	getRec := httptest.NewRecorder()
	router.ServeHTTP(getRec, getReq)
	require.Equal(t, http.StatusOK, getRec.Code)
	csrf := oauthHiddenInput(t, getRec.Body.String(), "csrf_nonce")
	form := url.Values{
		"handoff": {handoff}, "csrf_nonce": {csrf}, "token_name": {"concurrent"},
	}.Encode()

	start := make(chan struct{})
	results := make(chan int, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(
				http.MethodPost, approvalURL.RequestURI(), strings.NewReader(form),
			)
			req.RemoteAddr = "127.0.0.1:43210"
			req.Host = "localhost:8080"
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			results <- rec.Code
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	counts := map[int]int{}
	for status := range results {
		counts[status]++
	}
	require.Equal(t, 1, counts[http.StatusFound])
	require.Equal(t, 1, counts[http.StatusBadRequest])
	rows, err := tokenStore.ListMCPTokens(context.Background())
	require.NoError(t, err)
	require.Len(t, rows, 1)
}

func TestOAuthLocalApprovalBaseURLIsStrictLoopbackOriginAndMapIsBounded(t *testing.T) {
	h, _, _ := newOAuthRouter(t, false, "")
	valid := []string{
		"http://127.0.0.1:8080",
		"http://localhost:8080/",
		"https://[::1]:8443",
	}
	for _, base := range valid {
		h.LocalApprovalBaseURL = base
		got, err := h.localApprovalURL("opaque")
		require.NoError(t, err, base)
		parsed, err := url.Parse(got)
		require.NoError(t, err)
		require.Equal(t, "/oauth/approve", parsed.Path)
	}
	invalid := []string{
		"https://sage.example.com",
		"http://127.0.0.1:8080/ui",
		"http://user@127.0.0.1:8080",
		"http://127.0.0.1:8080?next=evil",
		"http://127.0.0.1:8080/#fragment",
		"mailto:root@localhost",
		"//127.0.0.1:8080",
	}
	for _, base := range invalid {
		h.LocalApprovalBaseURL = base
		_, err := h.localApprovalURL("opaque")
		require.Error(t, err, base)
	}

	h.approvalMu.Lock()
	for i := 0; i < oauthApprovalHandoffMax; i++ {
		h.approvals[fmt.Sprintf("pending-%d", i)] = &oauthApprovalHandoff{
			ExpiresAt: h.nowTime().Add(time.Minute),
		}
	}
	h.approvalMu.Unlock()
	_, err := h.issueApprovalHandoff(authorizeFormParams{ClientID: "bounded"})
	require.ErrorContains(t, err, "too many pending")
	h.approvalMu.Lock()
	require.Len(t, h.approvals, oauthApprovalHandoffMax)
	h.approvalMu.Unlock()
}
