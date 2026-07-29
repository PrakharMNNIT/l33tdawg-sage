package rest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/store"
)

// newOAuthRouter spins up a real SQLite-backed OAuth handler on a chi router.
// `authed` controls whether IsRequestAuthenticated returns true. Use
// `redirectURL` to assert the unauthenticated-redirect path.
func newOAuthRouter(t *testing.T, authed bool, redirectURL string) (*OAuthHandler, http.Handler, *store.SQLiteStore) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "oauth.db")
	memStore, err := store.NewSQLiteStore(context.Background(), dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = memStore.Close() })

	checker := func(_ *http.Request) (bool, string) { return authed, redirectURL }
	h := NewOAuthHandler(memStore, checker, func(_ *http.Request) string { return "https://sage.test" })
	// Tests assume the node operator's identity is configured — production
	// reads this from cfg.AgentKey at startup.
	h.NodeOperatorAgentID = strings.Repeat("a", 64)
	r := chi.NewRouter()
	MountOAuthRoutes(r, h)
	// httptest.NewRequest defaults to example.com / 192.0.2.1. Most historical
	// OAuth unit tests exercise the local consent path; preserve that intent
	// while tests that explicitly set a remote peer/Host continue to exercise
	// the public opaque-handoff bridge.
	localDefaults := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.RemoteAddr == "192.0.2.1:1234" && req.Host == "example.com" {
			req.RemoteAddr = "127.0.0.1:43210"
			req.Host = "localhost:8080"
		}
		r.ServeHTTP(w, req)
	})
	return h, localDefaults, memStore
}

// pkceChallenge returns the S256 base64url-no-pad challenge for the verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// registerOAuthClient drives /oauth/register and returns the issued client_id.
// Helper for tests that exercise downstream /authorize + /token flows.
func registerOAuthClient(t *testing.T, r http.Handler, redirectURIs ...string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"redirect_uris": redirectURIs,
		"client_name":   "test-client",
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	require.Equal(t, http.StatusCreated, rr.Code, "register failed: %s", rr.Body.String())
	var resp map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	id, _ := resp["client_id"].(string)
	require.NotEmpty(t, id)
	return id
}

// fetchCSRFNonce GETs /oauth/authorize with the given query string and yanks
// the csrf_nonce hidden input out of the rendered form. Tests need the nonce
// to round-trip via the POST submission.
func fetchCSRFNonce(t *testing.T, r http.Handler, authURL string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, "consent render failed: %s", rr.Body.String())
	body := rr.Body.String()
	const marker = `name="csrf_nonce" value="`
	i := strings.Index(body, marker)
	require.GreaterOrEqual(t, i, 0, "csrf_nonce hidden input not present in consent body")
	rest := body[i+len(marker):]
	end := strings.Index(rest, `"`)
	require.GreaterOrEqual(t, end, 0)
	return rest[:end]
}

// mintAuthCode runs the full GET→POST consent flow against r and returns
// the freshly-minted authorization code. The agentHex argument is retained
// for source-compat with older tests but is ignored — the bearer is bound
// to the OAuthHandler's NodeOperatorAgentID.
func mintAuthCode(t *testing.T, r http.Handler, clientID, redirect, challenge, state, _ string) string {
	t.Helper()
	authURL := "/oauth/authorize?client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape(redirect) +
		"&code_challenge=" + challenge +
		"&code_challenge_method=S256&response_type=code&state=" + url.QueryEscape(state)
	nonce := fetchCSRFNonce(t, r, authURL)
	form := url.Values{}
	form.Set("token_name", "test-token")
	form.Set("csrf_nonce", nonce)
	req := httptest.NewRequest(http.MethodPost, authURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	require.Equal(t, http.StatusFound, rr.Code, "consent post failed: %s", rr.Body.String())
	parsed, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	code := parsed.Query().Get("code")
	require.NotEmpty(t, code)
	return code
}

func TestOAuth_DiscoveryDocShape(t *testing.T) {
	_, r, _ := newOAuthRouter(t, true, "")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var doc map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&doc))

	assert.Equal(t, "https://sage.test", doc["issuer"])
	assert.Equal(t, "https://sage.test/oauth/authorize", doc["authorization_endpoint"])
	assert.Equal(t, "https://sage.test/oauth/token", doc["token_endpoint"])
	assert.ElementsMatch(t, []any{"code"}, doc["response_types_supported"])
	assert.ElementsMatch(t, []any{"S256"}, doc["code_challenge_methods_supported"])
	assert.ElementsMatch(t, []any{"authorization_code"}, doc["grant_types_supported"])
	// DCR added in v6.7.5 for ChatGPT's MCP connector — must advertise the
	// registration_endpoint and the DCR-specific auth method.
	assert.Equal(t, "https://sage.test/oauth/register", doc["registration_endpoint"])
}

func TestOAuth_Authorize_MissingParams_400(t *testing.T) {
	_, r, _ := newOAuthRouter(t, true, "")
	cases := []string{
		"",                   // no params at all
		"?client_id=chatgpt", // missing redirect_uri
		"?client_id=chatgpt&redirect_uri=https://x/cb",                                                // missing challenge
		"?client_id=chatgpt&redirect_uri=https://x/cb&code_challenge=abc&code_challenge_method=plain", // bad method
	}
	for _, q := range cases {
		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize"+q, nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code, "query=%s", q)
	}
}

func TestOAuth_Authorize_Unauthed_RedirectsToLogin(t *testing.T) {
	_, r, _ := newOAuthRouter(t, false, "/ui/?next=/oauth/authorize?stub")
	clientID := registerOAuthClient(t, r, "https://x/cb")

	req := httptest.NewRequest(http.MethodGet,
		"/oauth/authorize?client_id="+url.QueryEscape(clientID)+
			"&redirect_uri=https://x/cb&code_challenge=abc&code_challenge_method=S256&response_type=code&state=xyz",
		nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "/ui/?next=")
}

func TestOAuth_Authorize_GET_RendersConsent(t *testing.T) {
	_, r, _ := newOAuthRouter(t, true, "")
	clientID := registerOAuthClient(t, r, "https://x/cb")

	req := httptest.NewRequest(http.MethodGet,
		"/oauth/authorize?client_id="+url.QueryEscape(clientID)+
			"&redirect_uri=https://x/cb&code_challenge=abc&code_challenge_method=S256&response_type=code&state=xyz",
		nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "Authorize MCP Client")
	assert.Contains(t, body, clientID)
	assert.Contains(t, body, "https://x/cb")
	assert.Contains(t, body, `name="csrf_nonce"`)
	assert.Contains(t, rr.Header().Get("Content-Type"), "text/html")
}

func TestOAuth_Authorize_POST_RedirectsWithCode(t *testing.T) {
	_, r, memStore := newOAuthRouter(t, true, "")
	redirect := "https://chat.openai.com/cb"
	clientID := registerOAuthClient(t, r, redirect)

	verifier := "verifier-with-enough-length-aaaaaa-bbbbbb"
	challenge := pkceChallenge(verifier)
	code := mintAuthCode(t, r, clientID, redirect, challenge, "opaque-state", strings.Repeat("a", 64))
	require.NotEmpty(t, code)

	// Confirm a mcp_tokens row was minted.
	tokens, err := memStore.ListMCPTokens(context.Background())
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "test-token", tokens[0].Name)
	// The OAuth flow binds the bearer to the node operator's agent_id, not
	// to whatever the consent form might have submitted.
	assert.Equal(t, strings.Repeat("a", 64), tokens[0].AgentID)
}

func TestOAuth_Token_Happy(t *testing.T) {
	_, r, _ := newOAuthRouter(t, true, "")
	redirect := "https://chat.openai.com/cb"
	clientID := registerOAuthClient(t, r, redirect)

	verifier := "verifier-token-happy-path-aaaaaa-bbbbbb"
	challenge := pkceChallenge(verifier)
	code := mintAuthCode(t, r, clientID, redirect, challenge, "happy", strings.Repeat("b", 64))

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", code)
	tokenForm.Set("code_verifier", verifier)
	tokenForm.Set("redirect_uri", redirect)
	tokenForm.Set("client_id", clientID)

	tokReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenForm.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRR := httptest.NewRecorder()
	r.ServeHTTP(tokRR, tokReq)

	require.Equal(t, http.StatusOK, tokRR.Code, "body=%s", tokRR.Body.String())
	var resp map[string]any
	require.NoError(t, json.NewDecoder(tokRR.Body).Decode(&resp))
	assert.NotEmpty(t, resp["access_token"])
	assert.Equal(t, "Bearer", resp["token_type"])
}

func TestOAuth_Token_ReusedCode_400(t *testing.T) {
	_, r, _ := newOAuthRouter(t, true, "")
	redirect := "https://chat.openai.com/cb"
	clientID := registerOAuthClient(t, r, redirect)

	verifier := "verifier-for-reuse-test-aaaaaa-bbbbbb"
	challenge := pkceChallenge(verifier)
	code := mintAuthCode(t, r, clientID, redirect, challenge, "reuse-state", strings.Repeat("c", 64))

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", code)
	tokenForm.Set("code_verifier", verifier)
	tokenForm.Set("redirect_uri", redirect)
	tokenForm.Set("client_id", clientID)

	// First redeem succeeds.
	tokReq1 := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenForm.Encode()))
	tokReq1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRR1 := httptest.NewRecorder()
	r.ServeHTTP(tokRR1, tokReq1)
	require.Equal(t, http.StatusOK, tokRR1.Code, "first redeem should succeed: %s", tokRR1.Body.String())

	// Second redeem fails 400.
	tokReq2 := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenForm.Encode()))
	tokReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRR2 := httptest.NewRecorder()
	r.ServeHTTP(tokRR2, tokReq2)

	assert.Equal(t, http.StatusBadRequest, tokRR2.Code)
	assert.Contains(t, tokRR2.Body.String(), "invalid_grant")
}

func TestOAuth_Token_BadVerifier_400(t *testing.T) {
	_, r, _ := newOAuthRouter(t, true, "")
	redirect := "https://chat.openai.com/cb"
	clientID := registerOAuthClient(t, r, redirect)

	correctVerifier := "correct-verifier-correct-verifier-aaaaaa"
	challenge := pkceChallenge(correctVerifier)
	code := mintAuthCode(t, r, clientID, redirect, challenge, "bad-verifier", strings.Repeat("d", 64))

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", code)
	tokenForm.Set("code_verifier", "totally-different-verifier-aaaaaa-bbbb")
	tokenForm.Set("redirect_uri", redirect)
	tokenForm.Set("client_id", clientID)

	tokReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenForm.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRR := httptest.NewRecorder()
	r.ServeHTTP(tokRR, tokReq)

	assert.Equal(t, http.StatusBadRequest, tokRR.Code)
	assert.Contains(t, tokRR.Body.String(), "invalid_grant")
	assert.Contains(t, tokRR.Body.String(), "PKCE")
}

func TestOAuth_Token_RedirectMismatch_400(t *testing.T) {
	_, r, _ := newOAuthRouter(t, true, "")
	originalRedirect := "https://chat.openai.com/cb"
	clientID := registerOAuthClient(t, r, originalRedirect, "https://attacker.example.com/cb")

	verifier := "verifier-redirect-mismatch-aaaaaa-bbbbbb"
	challenge := pkceChallenge(verifier)
	code := mintAuthCode(t, r, clientID, originalRedirect, challenge, "rm-state", strings.Repeat("e", 64))

	// /token uses a redirect that's a registered URI for the client (so the
	// resolveClient check passes) but DOES NOT match the URI bound to the
	// auth code at /authorize. The auth-code store enforces the per-code
	// redirect match independently.
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", code)
	tokenForm.Set("code_verifier", verifier)
	tokenForm.Set("redirect_uri", "https://attacker.example.com/cb")
	tokenForm.Set("client_id", clientID)

	tokReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenForm.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRR := httptest.NewRecorder()
	r.ServeHTTP(tokRR, tokReq)

	assert.Equal(t, http.StatusBadRequest, tokRR.Code)
	assert.Contains(t, tokRR.Body.String(), "invalid_grant")
}

func TestOAuth_Token_BadGrantType_400(t *testing.T) {
	_, r, _ := newOAuthRouter(t, true, "")

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "client_credentials")
	tokenForm.Set("code", "anything")

	tokReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenForm.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRR := httptest.NewRecorder()
	r.ServeHTTP(tokRR, tokReq)

	assert.Equal(t, http.StatusBadRequest, tokRR.Code)
	assert.Contains(t, tokRR.Body.String(), "unsupported_grant_type")
}

func TestOAuth_Token_MissingFields_400(t *testing.T) {
	_, r, _ := newOAuthRouter(t, true, "")

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	// No code, no verifier, no redirect_uri.

	tokReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenForm.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRR := httptest.NewRecorder()
	r.ServeHTTP(tokRR, tokReq)

	assert.Equal(t, http.StatusBadRequest, tokRR.Code)
	assert.Contains(t, tokRR.Body.String(), "invalid_request")
}

func TestOAuth_Token_GET_405(t *testing.T) {
	_, r, _ := newOAuthRouter(t, true, "")
	// chi will route POST-only registrations to method-not-allowed for other verbs.
	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// TestOAuth_Authorize_RendersDistinctPendingAgent asserts consent never
// presents Root/Admin as the bearer identity or offers an arbitrary picker.
func TestOAuth_Authorize_RendersDistinctPendingAgent(t *testing.T) {
	_, r, _ := newOAuthRouter(t, true, "")
	clientID := registerOAuthClient(t, r, "https://x/cb")

	req := httptest.NewRequest(http.MethodGet,
		"/oauth/authorize?client_id="+url.QueryEscape(clientID)+
			"&redirect_uri=https://x/cb&code_challenge=abc&code_challenge_method=S256&response_type=code&state=op-label",
		nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "distinct pending-review MCP agent")
	assert.Contains(t, body, "never inherits Root or Admin")
	assert.NotContains(t, body, `name="agent_id"`)
	assert.NotContains(t, body, "<select")
}
