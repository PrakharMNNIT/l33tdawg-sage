package rest

// OAuth 2.0 + PKCE wrapper around SAGE's bearer-token MCP transport.
//
// Why this exists (v6.7.2):
//   ChatGPT's MCP connector form requires Authorization URL + Token URL —
//   the form's red banner explicitly rejects "static bearer in Client ID"
//   as an auth method. SAGE's HTTP MCP transport (v6.7.0/v6.7.1) only
//   accepts a long-lived bearer in the Authorization header. To close the
//   gap without disturbing v6.7.1, this layer presents a standards-track
//   OAuth flow whose `access_token` IS the existing bearer.
//
// Endpoints (mounted at the host root, not under /v1/mcp):
//   GET  /.well-known/oauth-authorization-server  RFC 8414 discovery doc
//   GET  /oauth/authorize                          consent screen + code mint
//   POST /oauth/authorize                          consent submission
//   POST /oauth/token                              code → bearer redemption
//
// Discovery URL placement: ChatGPT auto-discovers from the MCP server URL's
// host. The discovery doc MUST live at the root (`/.well-known/...`), not
// under `/v1/mcp/...` — the host is the OAuth issuer.
//
// Dynamic Client Registration (RFC 7591): NOT implemented in v6.7.2. The
// ChatGPT form's "User-Defined OAuth Client" path doesn't need DCR; the
// metadata simply omits `registration_endpoint`. Future work.
//
// Bearer reuse: at /authorize approval time we mint a fresh bearer via the
// existing IssueMCPToken path (so the operator gets a normal mcp_tokens row
// they can revoke from the dashboard). The auth-code row stores only
// SHA-256(code) plus an AES-GCM bearer-delivery envelope whose key is derived
// from the unpersisted raw code. /token uses that code to redeem the bearer.
// Sessions to /v1/mcp/sse continue to use the same Authorization: Bearer
// scheme as before. Zero changes to the bearer-auth middleware.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/l33tdawg/sage/api/rest/middleware"
	"github.com/l33tdawg/sage/internal/store"
)

// AuthCodeTTL is the lifetime of an issued OAuth authorization code. RFC
// 6749 §4.1.2 recommends ≤10 minutes; SAGE uses 5.
const AuthCodeTTL = 5 * time.Minute

// csrfTTL bounds how long a rendered consent form can be submitted. Mirrors
// AuthCodeTTL — anything older is treated as a stale tab.
const csrfTTL = 5 * time.Minute

// csrfClockSkew permits a small wall-clock correction between render and
// submit without allowing a materially future-issued signed form to become
// valid for longer than csrfTTL after a local clock rollback.
const csrfClockSkew = time.Minute

// OAuthApprovalHandoffTTL bounds the public-authorize → localhost-approval
// bridge. The token contains no OAuth parameters or CEREBRUM state; it is an
// opaque, HMAC-authenticated handle to process-local state and is single-use
// at consent submission.
const OAuthApprovalHandoffTTL = 5 * time.Minute

// oauthApprovalHandoffMax is a hard process-memory bound. Expiry pruning keeps
// normal usage far below it; reaching the cap fails new authorization attempts
// closed instead of evicting a still-valid consent ceremony.
const oauthApprovalHandoffMax = 2048

// oauthCleanupTimeout bounds revocation/authorization-code cleanup after an
// issuance failure. It must not inherit a canceled browser request.
const oauthCleanupTimeout = 8 * time.Second

// dcrRegisterPerIPLimit is the maximum number of /oauth/register calls
// accepted from a single remote address per dcrRegisterWindow. Legitimate
// clients register once per connector setup; bursty traffic is a sign of
// abuse.
const (
	dcrRegisterPerIPLimit   = 10
	dcrRegisterWindow       = 1 * time.Hour
	oauthApprovalPerIPLimit = 60
	oauthApprovalRateWindow = 5 * time.Minute
)

// OAuthStore is the storage surface OAuthHandler needs. The full
// SQLiteStore satisfies it.
type OAuthStore interface {
	// Token table — to mint a bearer at /authorize approval and to list the
	// operator's existing tokens for the consent screen dropdown.
	IssuePendingMCPToken(ctx context.Context, name, issuerID, legacyAgentID, provider string) (*store.MCPTokenIssue, error)
	ActivatePendingMCPToken(ctx context.Context, id string) error
	MarkMCPTokenCleanupPending(ctx context.Context, id string) error
	RevokeMCPToken(ctx context.Context, id string) error
	DeleteAuthCode(ctx context.Context, code string) error
	ListMCPTokens(ctx context.Context) ([]*store.MCPToken, error)
	// Auth-code table.
	IssueAuthCode(ctx context.Context,
		code, tokenID, codeChallenge, codeChallengeMethod, redirectURI, clientID, state, bearerPlaintext string,
		ttl time.Duration) error
	RedeemAuthCode(ctx context.Context, code, codeVerifier, redirectURI, clientID string) (string, error)
	// OAuth client (DCR) table — persisted at /oauth/register, looked up at
	// /oauth/authorize and /oauth/token to validate redirect_uri.
	InsertOAuthClient(ctx context.Context, clientID string, redirectURIs []string, clientName string) error
	GetOAuthClient(ctx context.Context, clientID string) (*store.OAuthClient, error)
	// Agent listing — for the consent screen's pre-filled dropdown so the
	// operator doesn't have to copy/paste a 64-char hex pubkey.
	ListAgents(ctx context.Context) ([]*store.AgentEntry, error)
}

// OAuthSessionChecker reports whether the inbound request is authenticated
// for the SAGE dashboard. Used by /oauth/authorize to gate the consent
// screen. If `false`, the second return is the location header to redirect
// the user to (typically `/ui/?next=<encoded /oauth/authorize URL>`).
//
// On nodes without encryption enabled, the dashboard considers all requests
// authenticated, so this returns (true, "") and /authorize serves directly.
type OAuthSessionChecker func(r *http.Request) (authenticated bool, loginRedirect string)

// OAuthDashboardSession reports whether the inbound request carries a real
// dashboard session cookie — independent of encryption state. We use this to
// decide whether the consent screen should render the agent roster
// (privileged information) versus a raw text input. Returns false when
// encryption is off and the dashboard's catch-all "everyone is authed"
// branch is in play, so an unauthenticated tunnel-exposed visitor never
// sees the agent list.
type OAuthDashboardSession func(r *http.Request) bool

// OAuthControlActorResolver resolves the exact current local CEREBRUM
// authority for this request. Production wires the dashboard's app-v23-aware
// resolver, which accepts only the current committed Root or an active
// current-generation same-machine Admin. The returned identity owns the token;
// app-v23 selects a separate existing managed ordinary agent as its actor.
type OAuthControlActorResolver func(r *http.Request) (agentID string, ok bool)

// OAuthLocalityChecker is the localhost control-plane boundary used by the
// approval route. It must reject remote peers, non-loopback Host values, and
// reverse-proxy forwarding metadata that names a non-loopback client.
type OAuthLocalityChecker func(r *http.Request) bool

type oauthApprovalHandoff struct {
	Params    authorizeFormParams
	ExpiresAt time.Time
	Used      bool
}

// OAuthHandler bundles the OAuth 2.0 endpoints. Built once at server start,
// mounted on the chi router at the host root.
//
// NodeOperatorAgentID is the on-chain identity that OAuth-issued bearers
// operate as. The MCP HTTP transport currently signs every outbound REST
// call with the node's signing key (cfg.AgentKey), so bearer-authenticated
// MCP traffic is attributed to that single identity regardless of which
// agent label the operator selects. We expose this honestly to the consent
// screen rather than letting the user pick an agent that the bearer will
// not actually act as.
type OAuthHandler struct {
	Store                       OAuthStore
	IsAuthed                    OAuthSessionChecker
	HasDashboardCookie          OAuthDashboardSession
	ResolveControlActor         OAuthControlActorResolver
	IsLocalApproval             OAuthLocalityChecker
	IssuerBaseURL               func(r *http.Request) string // e.g. "https://host:8443" — derived per request
	LocalApprovalBaseURL        string                       // e.g. "http://127.0.0.1:8080"
	NodeOperatorAgentID         string
	ManagedTokenTargetsRequired func() bool
	ValidateTokenTarget         func(context.Context, string) error

	csrfKey        []byte // process-lifetime random for HMAC-signing consent + approval handles
	dcrLimits      *ipRateLimiter
	approvalLimits *ipRateLimiter
	approvalMu     sync.Mutex
	approvals      map[string]*oauthApprovalHandoff
	now            func() time.Time
	random         io.Reader
}

// NewOAuthHandler constructs a handler with sensible defaults.
//
// `issuer` may be nil; if so the handler infers the issuer from the inbound
// request (`scheme://host`).
func NewOAuthHandler(s OAuthStore, isAuthed OAuthSessionChecker, issuer func(r *http.Request) string) *OAuthHandler {
	if isAuthed == nil {
		// Default: open. (Test convenience — production mounts the dashboard checker.)
		isAuthed = func(_ *http.Request) (bool, string) { return true, "" }
	}
	if issuer == nil {
		issuer = inferIssuer
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// OAuth approval and CSRF integrity cannot function with a predictable
		// HMAC key. crypto/rand failure is a startup-fatal platform condition.
		panic(fmt.Sprintf("oauth: seed approval HMAC key: %v", err))
	}
	return &OAuthHandler{
		Store:                s,
		IsAuthed:             isAuthed,
		IsLocalApproval:      isOAuthLoopbackRequest,
		IssuerBaseURL:        issuer,
		LocalApprovalBaseURL: "http://127.0.0.1:8080",
		csrfKey:              key,
		dcrLimits:            newIPRateLimiter(dcrRegisterPerIPLimit, dcrRegisterWindow),
		approvalLimits:       newIPRateLimiter(oauthApprovalPerIPLimit, oauthApprovalRateWindow),
		approvals:            make(map[string]*oauthApprovalHandoff),
		now:                  time.Now,
		random:               rand.Reader,
	}
}

func (h *OAuthHandler) nowTime() time.Time {
	if h != nil && h.now != nil {
		return h.now()
	}
	return time.Now()
}

func (h *OAuthHandler) randomReader() io.Reader {
	if h != nil && h.random != nil {
		return h.random
	}
	return rand.Reader
}

// inferIssuer reconstructs `scheme://host` from the request. Honors
// X-Forwarded-Proto / X-Forwarded-Host for reverse-proxy setups.
func inferIssuer(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		scheme = xfp
	}
	host := r.Host
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		host = xfh
	}
	return scheme + "://" + host
}

// HandleDiscovery serves the RFC 8414 OAuth Authorization Server Metadata
// document. ChatGPT's MCP connector reads this to auto-populate
// authorization_endpoint and token_endpoint.
func (h *OAuthHandler) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	issuer := h.IssuerBaseURL(r)
	doc := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth/authorize",
		"token_endpoint":                        issuer + "/oauth/token",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"mcp"},
		"registration_endpoint":                 issuer + "/oauth/register",
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(doc)
}

// HandleClientRegister implements RFC 7591 Dynamic Client Registration.
// ChatGPT's MCP connector REQUIRES this endpoint — without it the connector
// silently fails before making any user-visible request. Registrations
// persist to the oauth_clients table so /oauth/authorize and /oauth/token
// can validate that an inbound redirect_uri belongs to the registered set.
//
// Per RFC 7591 §2 we issue public clients (no client_secret) — PKCE is the
// proof-of-possession mechanism. Per-IP rate limiting prevents anonymous
// abuse of the open endpoint.
func (h *OAuthHandler) HandleClientRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.dcrLimits != nil && !h.dcrLimits.allow(remoteIP(r)) {
		w.Header().Set("Retry-After", "3600")
		writeOAuthError(w, http.StatusTooManyRequests, "rate_limited",
			"too many client registrations from this address — try again in an hour")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req struct {
		RedirectURIs            []string `json:"redirect_uris,omitempty"`
		ClientName              string   `json:"client_name,omitempty"`
		GrantTypes              []string `json:"grant_types,omitempty"`
		ResponseTypes           []string `json:"response_types,omitempty"`
		Scope                   string   `json:"scope,omitempty"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
		ApplicationType         string   `json:"application_type,omitempty"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	cleanRedirects, vErr := validateRedirectURIs(req.RedirectURIs)
	if vErr != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", vErr.Error())
		return
	}
	// Generate a public-client identifier. 16 random bytes base64url-encoded
	// (~22 chars) is well over the OAuth-spec minimum and unguessable.
	rawID := make([]byte, 16)
	if _, err := rand.Read(rawID); err != nil {
		http.Error(w, "client_id generation failed", http.StatusInternalServerError)
		return
	}
	clientID := base64.RawURLEncoding.EncodeToString(rawID)

	if err := h.Store.InsertOAuthClient(r.Context(), clientID, cleanRedirects, req.ClientName); err != nil {
		log.Printf("oauth: persist DCR client failed: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to persist client registration")
		return
	}

	// Default to authorization_code + S256 if the client didn't specify.
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "none"
	}

	resp := map[string]any{
		"client_id":                  clientID,
		"client_id_issued_at":        time.Now().Unix(),
		"redirect_uris":              cleanRedirects,
		"grant_types":                req.GrantTypes,
		"response_types":             req.ResponseTypes,
		"token_endpoint_auth_method": req.TokenEndpointAuthMethod,
		"client_name":                req.ClientName,
		"scope":                      req.Scope,
		// No client_secret — PKCE is the proof-of-possession mechanism.
		// No expiration — public clients in RFC 7591 §2 may be perpetual.
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// validateRedirectURIs enforces the constraints we care about for OAuth
// redirect targets:
//   - at least one URI required
//   - HTTPS only (no http:// — clear-text redirects leak codes; localhost
//     development paths can use the bearer-token CLI flow instead)
//   - no userinfo (user:pass@host) — never a legitimate OAuth target
//   - no fragment — RFC 6749 §3.1.2 forbids fragments
//   - parseable as an absolute URL
//
// Returns the cleaned (TrimSpace, lowercased scheme/host) URIs.
func validateRedirectURIs(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, errors.New("redirect_uris must list at least one URL")
	}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid redirect_uri %q: %w", raw, err)
		}
		if !u.IsAbs() {
			return nil, fmt.Errorf("redirect_uri %q must be an absolute URL", raw)
		}
		if strings.ToLower(u.Scheme) != "https" {
			return nil, fmt.Errorf("redirect_uri %q must use https", raw)
		}
		if u.User != nil {
			return nil, fmt.Errorf("redirect_uri %q must not contain userinfo", raw)
		}
		if u.Fragment != "" {
			return nil, fmt.Errorf("redirect_uri %q must not contain a fragment", raw)
		}
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		out = append(out, u.String())
	}
	if len(out) == 0 {
		return nil, errors.New("redirect_uris must contain at least one non-empty URL")
	}
	return out, nil
}

// remoteIP extracts the caller IP (best-effort) for rate limiting. Not used
// for any auth decision — only as a soft DOS bucket key.
func remoteIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return xff
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		return host[:i]
	}
	return host
}

// ipRateLimiter is a small fixed-window per-IP counter. Not perfectly
// accurate, but cheap and adequate for the DCR endpoint where legitimate
// usage is sparse.
type ipRateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string]*ipRateBucket
}

type ipRateBucket struct {
	count    int
	resetsAt time.Time
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{limit: limit, window: window, hits: map[string]*ipRateBucket{}}
}

func (l *ipRateLimiter) allow(ip string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.hits[ip]
	if !ok || now.After(b.resetsAt) {
		l.hits[ip] = &ipRateBucket{count: 1, resetsAt: now.Add(l.window)}
		return true
	}
	if b.count >= l.limit {
		return false
	}
	b.count++
	return true
}

// HandleProtectedResource serves the RFC 9728 Protected Resource Metadata
// document. The MCP authorization spec (June 2025 revision) requires MCP
// servers to expose this so clients can discover the authorization server
// associated with the MCP resource. ChatGPT's MCP connector follows the
// WWW-Authenticate header from a 401 to this URL, parses it, then bootstraps
// the OAuth flow against the authorization_servers entry — without it the
// connector hangs at "Continue" with no way to learn how to auth.
func (h *OAuthHandler) HandleProtectedResource(w http.ResponseWriter, r *http.Request) {
	issuer := h.IssuerBaseURL(r)
	doc := map[string]any{
		// The resource being protected is the MCP transport endpoint. Per
		// RFC 9728 §3, this is the canonical URL clients use to identify
		// the resource server.
		"resource":              issuer + "/v1/mcp/sse",
		"authorization_servers": []string{issuer},
		// Clients use bearer tokens issued via the authorization-code flow
		// against /oauth/token. No DPoP for v6.7.x.
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"mcp"},
		// Resource metadata is otherwise free-form; we keep it minimal so the
		// surface area we maintain matches what we actually implement.
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(doc)
}

// authorizeFormParams captures the validated /authorize query parameters.
type authorizeFormParams struct {
	ClientID            string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	ResponseType        string
	Scope               string
	ApprovalHandoff     string
}

// parseAuthorizeParams reads + validates the /authorize parameters from
// either the URL query (GET render of the consent screen) or the form body
// (POST submission of the consent form). r.FormValue checks form first then
// URL — perfect since the consent form's hidden inputs carry the original
// query params verbatim, but the GET path only has them in the query.
//
// Returns a problem-detail string for the caller to surface as a 400 if
// invalid.
func parseAuthorizeParams(r *http.Request) (authorizeFormParams, string) {
	// Parse form body for POST; FormValue auto-handles GET via r.URL.Query.
	if err := r.ParseForm(); err != nil {
		return authorizeFormParams{}, "invalid form body"
	}
	p := authorizeFormParams{
		ClientID:            strings.TrimSpace(r.FormValue("client_id")),
		RedirectURI:         strings.TrimSpace(r.FormValue("redirect_uri")),
		State:               strings.TrimSpace(r.FormValue("state")),
		CodeChallenge:       strings.TrimSpace(r.FormValue("code_challenge")),
		CodeChallengeMethod: strings.ToUpper(strings.TrimSpace(r.FormValue("code_challenge_method"))),
		ResponseType:        strings.ToLower(strings.TrimSpace(r.FormValue("response_type"))),
		Scope:               strings.TrimSpace(r.FormValue("scope")),
	}
	if p.ClientID == "" {
		return p, "client_id is required"
	}
	if p.RedirectURI == "" {
		return p, "redirect_uri is required"
	}
	u, err := url.Parse(p.RedirectURI)
	if err != nil || !u.IsAbs() {
		return p, "redirect_uri must be a valid absolute URL"
	}
	if u.User != nil {
		return p, "redirect_uri must not contain userinfo"
	}
	if u.Fragment != "" {
		return p, "redirect_uri must not contain a fragment"
	}
	if p.State == "" {
		// RFC 6749 §10.12 strongly recommends state for CSRF protection on
		// the OAuth client side; we make it mandatory so a vulnerable client
		// cannot omit it.
		return p, "state is required"
	}
	if p.ResponseType == "" {
		p.ResponseType = "code"
	}
	if p.ResponseType != "code" {
		return p, "response_type must be 'code'"
	}
	if p.CodeChallenge == "" {
		return p, "code_challenge is required (PKCE)"
	}
	if p.CodeChallengeMethod == "" {
		p.CodeChallengeMethod = "S256"
	}
	if p.CodeChallengeMethod != "S256" {
		return p, "code_challenge_method must be S256"
	}
	return p, ""
}

// resolveClient looks up the DCR-registered client for clientID and confirms
// redirectURI belongs to its registered set. Returns the matched URI on
// success (which may differ in casing from the input — we use the stored
// value at the redirect step so the response always points at a known URI)
// or a problem-detail string for the caller to surface as a 400.
func (h *OAuthHandler) resolveClient(ctx context.Context, clientID, redirectURI string) (*store.OAuthClient, string, string) {
	client, err := h.Store.GetOAuthClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, store.ErrOAuthClientNotFound) {
			return nil, "", "client_id is not registered — call /oauth/register first"
		}
		log.Printf("oauth: client lookup failed: %v", err)
		return nil, "", "internal client lookup error"
	}
	wanted := strings.TrimSpace(redirectURI)
	for _, registered := range client.RedirectURIs {
		if registered == wanted {
			return client, registered, ""
		}
	}
	return nil, "", "redirect_uri does not match a registered URI for this client_id"
}

func oauthLoopbackHost(raw string) bool {
	host := strings.TrimSpace(raw)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// isOAuthLoopbackRequest is the standalone fail-closed default. sage-gui
// replaces it with the dashboard's canonical CEREBRUM locality predicate.
func isOAuthLoopbackRequest(r *http.Request) bool {
	if r == nil || !oauthLoopbackHost(r.RemoteAddr) || !oauthLoopbackHost(r.Host) {
		return false
	}
	for _, name := range []string{"X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host", "Forwarded"} {
		for _, value := range r.Header.Values(name) {
			if strings.TrimSpace(value) != "" {
				// The default has no trusted-proxy configuration. Production's
				// dashboard checker understands the exact forwarding grammar;
				// this generic fallback therefore rejects all forwarded hops.
				return false
			}
		}
	}
	return true
}

func (h *OAuthHandler) requestIsLocalApproval(r *http.Request) bool {
	return h != nil && h.IsLocalApproval != nil && h.IsLocalApproval(r)
}

func (h *OAuthHandler) resolveControlActor(r *http.Request) (string, bool) {
	if h.ResolveControlActor != nil {
		id, ok := h.ResolveControlActor(r)
		id = strings.TrimSpace(id)
		return id, ok && len(id) == 64
	}
	// Compatibility for embedded/pre-v23 callers. Production sage-gui always
	// wires ResolveControlActor, so app-v23 never reaches the static operator
	// fallback after a Root handover.
	if h.IsAuthed == nil {
		return "", false
	}
	ok, _ := h.IsAuthed(r)
	if !ok {
		return "", false
	}
	if actorID := strings.TrimSpace(middleware.ContextAgentID(r.Context())); len(actorID) == 64 {
		return actorID, true
	}
	id := strings.TrimSpace(h.NodeOperatorAgentID)
	return id, len(id) == 64
}

func (h *OAuthHandler) redirectToLocalLogin(w http.ResponseWriter, r *http.Request) {
	loginURL := ""
	if h.IsAuthed != nil {
		_, loginURL = h.IsAuthed(r)
	}
	if loginURL == "" {
		loginURL = "/ui/?next=" + url.QueryEscape(r.URL.RequestURI())
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (h *OAuthHandler) approvalMAC(value, issuedAt string) []byte {
	mac := hmac.New(sha256.New, h.csrfKey)
	mac.Write([]byte("sage:oauth-local-approval:v1|"))
	mac.Write([]byte(value))
	mac.Write([]byte("|"))
	mac.Write([]byte(issuedAt))
	return mac.Sum(nil)
}

func (h *OAuthHandler) issueApprovalHandoff(p authorizeFormParams) (string, error) {
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(h.randomReader(), nonce); err != nil {
		return "", fmt.Errorf("generate approval handoff: %w", err)
	}
	value := base64.RawURLEncoding.EncodeToString(nonce)
	issuedAt := fmt.Sprintf("%d", h.nowTime().Unix())
	token := value + "." + issuedAt + "." +
		base64.RawURLEncoding.EncodeToString(h.approvalMAC(value, issuedAt))
	h.approvalMu.Lock()
	h.pruneApprovalHandoffsLocked()
	if len(h.approvals) >= oauthApprovalHandoffMax {
		h.approvalMu.Unlock()
		return "", errors.New("too many pending OAuth approval handoffs")
	}
	h.approvals[token] = &oauthApprovalHandoff{
		Params:    p,
		ExpiresAt: h.nowTime().Add(OAuthApprovalHandoffTTL),
	}
	h.approvalMu.Unlock()
	return token, nil
}

func (h *OAuthHandler) verifyApprovalHandoffToken(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("malformed approval handoff")
	}
	received, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || subtle.ConstantTimeCompare(received, h.approvalMAC(parts[0], parts[1])) != 1 {
		return errors.New("invalid approval handoff signature")
	}
	var issuedAt int64
	if _, err := fmt.Sscanf(parts[1], "%d", &issuedAt); err != nil {
		return errors.New("invalid approval handoff timestamp")
	}
	now := h.nowTime()
	issued := time.Unix(issuedAt, 0)
	if issued.After(now.Add(time.Minute)) || now.Sub(issued) > OAuthApprovalHandoffTTL {
		return errors.New("approval handoff expired")
	}
	return nil
}

func (h *OAuthHandler) approvalHandoff(token string, consume bool) (authorizeFormParams, error) {
	if err := h.verifyApprovalHandoffToken(token); err != nil {
		return authorizeFormParams{}, err
	}
	h.approvalMu.Lock()
	defer h.approvalMu.Unlock()
	h.pruneApprovalHandoffsLocked()
	entry := h.approvals[token]
	if entry == nil || h.nowTime().After(entry.ExpiresAt) {
		return authorizeFormParams{}, errors.New("approval handoff expired or unknown")
	}
	if entry.Used {
		return authorizeFormParams{}, errors.New("approval handoff already used")
	}
	if consume {
		entry.Used = true
	}
	return entry.Params, nil
}

func (h *OAuthHandler) pruneApprovalHandoffsLocked() {
	now := h.nowTime()
	for token, entry := range h.approvals {
		if entry == nil || now.After(entry.ExpiresAt.Add(time.Minute)) {
			delete(h.approvals, token)
		}
	}
}

func (h *OAuthHandler) localApprovalURL(token string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(h.LocalApprovalBaseURL), "/")
	parsed, err := url.Parse(base)
	if err != nil || !parsed.IsAbs() || parsed.Opaque != "" ||
		parsed.User != nil || parsed.Fragment != "" || parsed.RawFragment != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" ||
		!oauthLoopbackHost(parsed.Host) ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", errors.New("local OAuth approval URL is not configured as a loopback HTTP(S) origin")
	}
	parsed.Path = "/oauth/approve"
	q := parsed.Query()
	q.Set("handoff", token)
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

// HandleAuthorize is the public OAuth authorization endpoint. Remote requests
// never see CEREBRUM, a consent form, or a dashboard cookie: they receive only
// an absolute loopback redirect carrying a short-lived opaque handoff. A
// local, already-authorized caller retains the direct path for pre-v23 CLI
// compatibility; sage-gui's normal Cloudflare flow always uses HandleApprove.
func (h *OAuthHandler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	}
	localApproval := h.requestIsLocalApproval(r)
	var localActorID string
	if localApproval {
		// Resolve signed Admin/Root authority before ParseForm consumes the
		// exact body covered by the Ed25519 request signature.
		var ok bool
		localActorID, ok = h.resolveControlActor(r)
		if !ok {
			h.redirectToLocalLogin(w, r)
			return
		}
	}

	params, problem := parseAuthorizeParams(r)
	if problem != "" {
		http.Error(w, problem, http.StatusBadRequest)
		return
	}
	// Only authenticated callers may learn whether a client_id is registered,
	// and the final redirect sink performs this allowlist check again.
	if _, _, clientErr := h.resolveClient(r.Context(), params.ClientID, params.RedirectURI); clientErr != "" {
		http.Error(w, clientErr, http.StatusBadRequest)
		return
	}

	if !localApproval {
		if h.approvalLimits != nil && !h.approvalLimits.allow(remoteIP(r)) {
			w.Header().Set("Retry-After", "300")
			writeOAuthError(
				w, http.StatusTooManyRequests, "rate_limited",
				"too many pending authorization attempts from this address",
			)
			return
		}
		handoff, err := h.issueApprovalHandoff(params)
		if err != nil {
			http.Error(w, "failed to create local approval handoff", http.StatusInternalServerError)
			return
		}
		approvalURL, err := h.localApprovalURL(handoff)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		http.Redirect(w, r, approvalURL, http.StatusFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.renderConsent(w, r, params, localActorID, "", "/oauth/authorize")
	case http.MethodPost:
		h.processConsent(w, r, params, localActorID, "")
	}
}

// HandleApprove is the localhost-only side of the public authorization
// bridge. It never appears in discovery or Cloudflare's ingress allowlist.
func (h *OAuthHandler) HandleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.requestIsLocalApproval(r) {
		http.NotFound(w, r)
		return
	}
	// Authenticate while a signed POST body is still intact. Browser session
	// checks are unaffected, and an unencrypted app-v23 same-origin CEREBRUM
	// request resolves current Root through the same callback.
	actorID, ok := h.resolveControlActor(r)
	if !ok {
		h.redirectToLocalLogin(w, r)
		return
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid approval form", http.StatusBadRequest)
			return
		}
	}
	handoff := strings.TrimSpace(r.FormValue("handoff"))
	params, err := h.approvalHandoff(handoff, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, _, clientErr := h.resolveClient(r.Context(), params.ClientID, params.RedirectURI); clientErr != "" {
		http.Error(w, clientErr, http.StatusBadRequest)
		return
	}
	params.ApprovalHandoff = handoff
	switch r.Method {
	case http.MethodGet:
		h.renderConsent(w, r, params, actorID, "", "/oauth/approve")
	case http.MethodPost:
		h.processConsent(w, r, params, actorID, handoff)
	}
}

// signCSRFNonce returns "value.iat.mac" — a self-contained signed token
// that processConsent can verify on POST without server-side state.
func (h *OAuthHandler) signCSRFNonce(p authorizeFormParams) (string, error) {
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(h.randomReader(), nonce); err != nil {
		return "", fmt.Errorf("generate csrf nonce: %w", err)
	}
	value := base64.RawURLEncoding.EncodeToString(nonce)
	iat := h.nowTime().Unix()
	iatStr := fmt.Sprintf("%d", iat)
	mac := hmac.New(sha256.New, h.csrfKey)
	mac.Write([]byte(p.ClientID))
	mac.Write([]byte("|"))
	mac.Write([]byte(p.RedirectURI))
	mac.Write([]byte("|"))
	mac.Write([]byte(p.State))
	mac.Write([]byte("|"))
	mac.Write([]byte(p.CodeChallenge))
	mac.Write([]byte("|"))
	mac.Write([]byte(p.ApprovalHandoff))
	mac.Write([]byte("|"))
	mac.Write([]byte(value))
	mac.Write([]byte("|"))
	mac.Write([]byte(iatStr))
	return value + "." + iatStr + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// verifyCSRFNonce confirms the POSTed nonce was signed by THIS handler with
// the same authorize params it was rendered for, within csrfTTL.
func (h *OAuthHandler) verifyCSRFNonce(p authorizeFormParams, token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("malformed csrf nonce")
	}
	value, iatStr, macB64 := parts[0], parts[1], parts[2]
	gotMAC, err := base64.RawURLEncoding.DecodeString(macB64)
	if err != nil {
		return errors.New("malformed csrf nonce mac")
	}
	mac := hmac.New(sha256.New, h.csrfKey)
	mac.Write([]byte(p.ClientID))
	mac.Write([]byte("|"))
	mac.Write([]byte(p.RedirectURI))
	mac.Write([]byte("|"))
	mac.Write([]byte(p.State))
	mac.Write([]byte("|"))
	mac.Write([]byte(p.CodeChallenge))
	mac.Write([]byte("|"))
	mac.Write([]byte(p.ApprovalHandoff))
	mac.Write([]byte("|"))
	mac.Write([]byte(value))
	mac.Write([]byte("|"))
	mac.Write([]byte(iatStr))
	if subtle.ConstantTimeCompare(mac.Sum(nil), gotMAC) != 1 {
		return errors.New("csrf nonce signature mismatch")
	}
	var iat int64
	if _, perr := fmt.Sscanf(iatStr, "%d", &iat); perr != nil {
		return errors.New("csrf nonce iat parse")
	}
	now := h.nowTime()
	issued := time.Unix(iat, 0)
	if issued.After(now.Add(csrfClockSkew)) {
		return errors.New("csrf nonce issued in the future — refresh the consent page and resubmit")
	}
	if now.Sub(issued) > csrfTTL {
		return errors.New("csrf nonce expired — refresh the consent page and resubmit")
	}
	return nil
}

// consentTemplate is the minimal HTML form. Lists existing active tokens as
// radio choices; offers a "mint a new token" path that takes a name + agent.
//
// We keep the markup deliberately spartan — this page is operator-facing,
// rarely seen, and ChatGPT's redirect destination so it doesn't need to be
// branded.
var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Authorize MCP client — SAGE</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; max-width: 640px; margin: 4em auto; padding: 0 1em; color: #222; }
  h1 { font-size: 1.4em; margin-bottom: 0.2em; }
  .sub { color: #666; font-size: 0.95em; margin-top: 0; }
  .card { border: 1px solid #ddd; border-radius: 8px; padding: 1em 1.2em; margin: 1em 0; background: #fafafa; }
  label { display: block; padding: 0.4em 0; cursor: pointer; }
  label:hover { background: #f0f0f0; }
  input[type=text], input[type=submit], button { padding: 0.5em 0.8em; font-size: 1em; }
  input[type=submit], button { background: #2b7cd1; color: white; border: 0; border-radius: 4px; cursor: pointer; }
  input[type=submit]:hover, button:hover { background: #1f5fa3; }
  .err { color: #b00020; padding: 0.5em; background: #fde7ea; border-radius: 4px; }
  code { background: #eee; padding: 0.1em 0.3em; border-radius: 3px; font-size: 0.9em; }
  .meta { color: #888; font-size: 0.85em; }
</style>
</head>
<body>
  <h1>Authorize MCP Client</h1>
  <p class="sub">A client wants to connect to your SAGE node as an MCP agent.</p>

  <div class="card">
    <p><strong>Client:</strong> <code>{{.ClientID}}</code></p>
    <p><strong>Redirect URI:</strong> <code>{{.RedirectURI}}</code></p>
    {{if .Scope}}<p><strong>Scope:</strong> <code>{{.Scope}}</code></p>{{end}}
  </div>

  {{if .Error}}<p class="err">{{.Error}}</p>{{end}}

  <form method="POST" action="{{.Action}}">
    <!-- OAuth params travel as hidden inputs, NOT as a query-string suffix on
         the action URL. html/template treats the action attribute as URL
         context and would double-encode an interpolated raw query string, so
         we use hidden inputs instead. Submission posts them as
         application/x-www-form-urlencoded which the POST handler reads via
         r.FormValue. (Note: keep template actions out of HTML comments —
         html/template parses through comments and a stale field reference in
         a comment will fail Execute even though the comment never reaches
         the browser.) -->
    <input type="hidden" name="client_id" value="{{.ClientID}}">
    <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
    <input type="hidden" name="response_type" value="{{.ResponseType}}">
    <input type="hidden" name="scope" value="{{.Scope}}">
    <input type="hidden" name="state" value="{{.State}}">
    <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
    <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
    {{if .ApprovalHandoff}}<input type="hidden" name="handoff" value="{{.ApprovalHandoff}}">{{end}}
    <input type="hidden" name="csrf_nonce" value="{{.CSRFNonce}}">
    <h2 style="font-size: 1.1em;">Mint a new bearer for this client</h2>
    <p class="meta">A new <code>mcp_tokens</code> row is created for this connection — you can revoke it at any time from <code>sage-gui mcp-token revoke &lt;id&gt;</code> or the dashboard.</p>
    <p>
      {{if .BindExisting}}<label>Existing managed agent ID<br>
        <input type="text" name="agent_id" value="" required style="width: 100%; box-sizing: border-box;" placeholder="64-char Ed25519 public key">
      </label>{{end}}
      <label>Token name (optional, e.g. "chatgpt-laptop")<br>
        <input type="text" name="token_name" value="" style="width: 100%; box-sizing: border-box;">
      </label>
    </p>
    {{if .BindExisting}}<div class="card" style="background:#fff;border-color:#cfd8dc;">
      <p style="margin:0;"><strong>Identity:</strong> the selected existing active agent</p>
      <p class="meta" style="margin:0.5em 0 0;">The node must already hold this agent's managed key. The bearer receives exactly that agent's existing permissions; token creation never creates a pending identity.</p>
    </div>{{else}}<div class="card" style="background:#fff;border-color:#cfd8dc;">
      <p style="margin:0;"><strong>Identity:</strong> a distinct pending-review MCP agent</p>
      <p class="meta" style="margin:0.5em 0 0;">It never inherits Root or Admin authority from the person approving it.</p>
    </div>{{end}}
    <p style="margin-top:1em;"><button type="submit">Authorize</button></p>
  </form>

  <p class="meta">After authorization, you'll be redirected to {{.RedirectURI}}.<br>
  This consent screen is a thin OAuth wrapper around SAGE's existing bearer-token MCP transport.</p>
</body>
</html>`))

// renderConsent writes the GET-side HTML form.
//
// The screen shows the operator the canonical "operates as" identity (the
// node operator's agent_id) so they understand what privileges the bearer
// will inherit. Earlier revisions allowed the operator to pick an arbitrary
// agent_id from a dropdown, but the underlying MCP transport always signs
// outgoing REST calls with the node's signing key — so the picked agent_id
// only ever functioned as a label. Removing the picker is the honest
// representation of what the bearer actually does.
func (h *OAuthHandler) renderConsent(
	w http.ResponseWriter,
	r *http.Request,
	p authorizeFormParams,
	actorID, errMsg, action string,
) {
	csrfNonce, err := h.signCSRFNonce(p)
	if err != nil {
		log.Printf("oauth: cannot generate consent CSRF nonce: %v", err)
		http.Error(w, "failed to create secure consent page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	data := struct {
		ClientID            string
		RedirectURI         string
		Scope               string
		State               string
		ResponseType        string
		CodeChallenge       string
		CodeChallengeMethod string
		Error               string
		CSRFNonce           string
		ApprovalHandoff     string
		Action              string
		BindExisting        bool
	}{
		ClientID:            p.ClientID,
		RedirectURI:         p.RedirectURI,
		Scope:               p.Scope,
		State:               p.State,
		ResponseType:        p.ResponseType,
		CodeChallenge:       p.CodeChallenge,
		CodeChallengeMethod: p.CodeChallengeMethod,
		Error:               errMsg,
		CSRFNonce:           csrfNonce,
		ApprovalHandoff:     p.ApprovalHandoff,
		Action:              action,
		BindExisting:        h.ManagedTokenTargetsRequired != nil && h.ManagedTokenTargetsRequired(),
	}
	_ = actorID // authority is deliberately not rendered into the consent page
	if err := consentTemplate.Execute(w, data); err != nil {
		log.Printf("oauth: consentTemplate.Execute failed: %v (data=%+v)", err, data)
		http.Error(w, "failed to render consent page", http.StatusInternalServerError)
	}
}

// processConsent handles the POST: mint a bearer for the chosen agent, bind
// it to a fresh authorization code, and 302-redirect the user back to the
// client's redirect_uri carrying the code (and original state).
func (h *OAuthHandler) processConsent(
	w http.ResponseWriter,
	r *http.Request,
	p authorizeFormParams,
	actorID, approvalHandoff string,
) {
	// HandleAuthorize already bounded and parsed the form, after authenticating
	// against the original bytes.
	if err := h.verifyCSRFNonce(p, r.FormValue("csrf_nonce")); err != nil {
		h.renderConsent(
			w, r, p, actorID,
			"Consent request could not be verified — please try again. ("+err.Error()+")",
			r.URL.Path,
		)
		return
	}
	if approvalHandoff != "" {
		handedParams, err := h.approvalHandoff(approvalHandoff, true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		handedParams.ApprovalHandoff = approvalHandoff
		if handedParams != p {
			http.Error(w, "approval handoff does not match consent request", http.StatusBadRequest)
			return
		}
	}
	tokenName := strings.TrimSpace(r.FormValue("token_name"))
	if tokenName == "" {
		tokenName = "oauth-" + p.ClientID
	}

	// actorID is the authorizing Root/Admin and remains the token owner. The
	// bearer acts only as the separately selected existing managed identity.
	issuerID := strings.TrimSpace(actorID)
	if len(issuerID) != 64 {
		h.renderConsent(w, r, p, actorID, "current CEREBRUM authority unavailable — bearers cannot be issued", r.URL.Path)
		return
	}
	if _, decErr := hex.DecodeString(issuerID); decErr != nil {
		h.renderConsent(w, r, p, actorID, "current CEREBRUM authority is invalid — server misconfiguration", r.URL.Path)
		return
	}
	targetID := issuerID
	if h.ManagedTokenTargetsRequired != nil && h.ManagedTokenTargetsRequired() {
		targetID = strings.TrimSpace(r.FormValue("agent_id"))
		if len(targetID) != 64 {
			h.renderConsent(w, r, p, actorID, "select an existing managed agent identity", r.URL.Path)
			return
		}
		if _, decErr := hex.DecodeString(targetID); decErr != nil {
			h.renderConsent(w, r, p, actorID, "selected agent identity is invalid", r.URL.Path)
			return
		}
		if h.ValidateTokenTarget == nil {
			h.renderConsent(w, r, p, actorID, "agent enrollment validation is unavailable", r.URL.Path)
			return
		}
		if targetErr := h.ValidateTokenTarget(r.Context(), targetID); targetErr != nil {
			h.renderConsent(w, r, p, actorID, "selected agent is not an active approved local identity", r.URL.Path)
			return
		}
	}
	// Validate the redirect sink before creating either secret. The normal
	// HandleAuthorize validation is intentionally repeated here because this is
	// the issuance boundary, not merely a UI-render boundary.
	_, registered, clientErr := h.resolveClient(r.Context(), p.ClientID, p.RedirectURI)
	if clientErr != "" {
		http.Error(w, clientErr, http.StatusBadRequest)
		return
	}
	if _, err := url.Parse(registered); err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	// 1. Mint via the exact shared issuer used by /v1/mcp/tokens and the
	// wizard. App-v23 binds the bearer to targetID while recording the live
	// Root/Admin as its issuer/owner.
	issued, err := h.Store.IssuePendingMCPToken(r.Context(), tokenName, issuerID, targetID, "oauth-mcp-token")
	if err != nil {
		http.Error(w, "failed to persist token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 2. Mint the auth code and bind it to an encrypted bearer-delivery
	// envelope. Neither raw secret is persisted by the store.
	codeRaw := make([]byte, 32)
	if _, err = rand.Read(codeRaw); err != nil {
		h.cleanupOAuthIssue(issued.ID, "")
		http.Error(w, "failed to generate auth code", http.StatusInternalServerError)
		return
	}
	code := base64.RawURLEncoding.EncodeToString(codeRaw)
	if err = h.Store.IssueAuthCode(r.Context(),
		code, issued.ID, p.CodeChallenge, p.CodeChallengeMethod,
		p.RedirectURI, p.ClientID, p.State, issued.Token, AuthCodeTTL); err != nil {
		h.cleanupOAuthIssue(issued.ID, code)
		http.Error(w, "failed to issue auth code: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// The code row is durable. Now (and only now) permit its bearer to
	// authenticate. If this state flip cannot commit, cleanup remains pending
	// and the code/token are never delivered as an active credential.
	if err = h.activateOAuthIssue(issued.ID); err != nil {
		h.cleanupOAuthIssue(issued.ID, code)
		http.Error(w, "failed to activate token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 3. Redirect back to the client's redirect_uri with the code + state.
	//
	// Defence-in-depth: even though HandleAuthorize already called
	// resolveClient() for this (client_id, redirect_uri) pair AND the
	// CSRF nonce above HMACs the RedirectURI so it can't be tampered
	// with between GET and POST, we re-resolve at the redirect sink so
	// the allowlist check is co-located with the http.Redirect call.
	// This closes go/unvalidated-url-redirection and makes the
	// invariant obvious to future readers.
	_, registered, clientErr = h.resolveClient(r.Context(), p.ClientID, p.RedirectURI)
	if clientErr != "" {
		h.cleanupOAuthIssue(issued.ID, code)
		http.Error(w, clientErr, http.StatusBadRequest)
		return
	}
	redirectURL, err := url.Parse(registered)
	if err != nil {
		h.cleanupOAuthIssue(issued.ID, code)
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := redirectURL.Query()
	q.Set("code", code)
	if p.State != "" {
		q.Set("state", p.State)
	}
	redirectURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// cleanupOAuthIssue revokes a just-issued bearer and erases any bound code
// using a short independent context. The original browser request may be
// canceled exactly when IssueAuthCode or sink validation fails; using that
// context would strand a live bearer or its plaintext-bearing code row.
func (h *OAuthHandler) cleanupOAuthIssue(tokenID, code string) {
	ctx, cancel := context.WithTimeout(context.Background(), oauthCleanupTimeout)
	defer cancel()
	if err := h.Store.MarkMCPTokenCleanupPending(ctx, tokenID); err != nil {
		log.Printf("oauth: durable cleanup marker failed: %v", err)
	}
	if err := h.Store.DeleteAuthCode(ctx, code); err != nil {
		log.Printf("oauth: cleanup delete auth code failed: %v", err)
	}
	if err := h.Store.RevokeMCPToken(ctx, tokenID); err != nil {
		log.Printf("oauth: cleanup revoke token failed: %v", err)
	}
}

func (h *OAuthHandler) activateOAuthIssue(tokenID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), oauthCleanupTimeout)
	defer cancel()
	return h.Store.ActivatePendingMCPToken(ctx, tokenID)
}

// HandleToken implements POST /oauth/token. Form-encoded body per OAuth 2.0
// §4.1.3:
//
//	grant_type=authorization_code&code=...&redirect_uri=...&code_verifier=...&client_id=...
//
// On success returns:
//
//	{"access_token": "<bearer>", "token_type": "Bearer", "expires_in": 0}
//
// expires_in=0 = does not expire — the underlying mcp_tokens revocation
// status is the real lifetime gate, and the OAuth spec does NOT require a
// non-zero value.
func (h *OAuthHandler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64KB cap on /token form bodies
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type",
			"only authorization_code is supported")
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	codeVerifier := strings.TrimSpace(r.FormValue("code_verifier"))
	redirectURI := strings.TrimSpace(r.FormValue("redirect_uri"))
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	if code == "" || codeVerifier == "" || redirectURI == "" || clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"code, code_verifier, redirect_uri, client_id are required")
		return
	}
	if _, _, clientErr := h.resolveClient(r.Context(), clientID, redirectURI); clientErr != "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", clientErr)
		return
	}

	bearer, err := h.Store.RedeemAuthCode(r.Context(), code, codeVerifier, redirectURI, clientID)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrAuthCodeNotFound),
			errors.Is(err, store.ErrAuthCodeUsed),
			errors.Is(err, store.ErrAuthCodeExpired):
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid, used, or expired")
		case errors.Is(err, store.ErrAuthCodeRedirectMismatch):
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
				"redirect_uri does not match the authorization request")
		case errors.Is(err, store.ErrAuthCodeClientMismatch):
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
				"client_id does not match the authorization request")
		case errors.Is(err, store.ErrAuthCodePKCEMismatch):
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
				"PKCE code_verifier does not match code_challenge")
		default:
			log.Printf("oauth: /oauth/token unexpected redeem error: %v", err)
			writeOAuthError(w, http.StatusInternalServerError, "server_error",
				"failed to redeem authorization code")
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": bearer,
		"token_type":   "Bearer",
		"expires_in":   0,
		"scope":        "mcp",
	})
}

// writeOAuthError emits an RFC 6749 §5.2 error response. The body is JSON
// with `error` + `error_description` fields.
func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// MountOAuthRoutes wires the OAuth endpoints onto a chi-compatible router.
// Caller is responsible for mounting at the host root (NOT under /v1/mcp/).
//
// All endpoints get a CORS shim — ChatGPT's MCP connector does an OPTIONS
// preflight on /oauth/token (and sometimes /oauth/authorize) before
// initiating the user-visible auth flow. Without `Access-Control-Allow-Origin`
// in the preflight response the browser silently rejects the response and
// the connector hangs at "Continue" with a never-resolving spinner. These
// endpoints don't read cookies (token: bearer in body; authorize: query+
// form params + a dashboard cookie that's only checked AFTER the form is
// rendered), so wildcard Origin doesn't open any CSRF vector.
func MountOAuthRoutes(r interface {
	Get(pattern string, h http.HandlerFunc)
	Post(pattern string, h http.HandlerFunc)
	Options(pattern string, h http.HandlerFunc)
}, h *OAuthHandler) {
	wrap := oauthCORSMiddleware
	r.Get("/.well-known/oauth-authorization-server", wrap(h.HandleDiscovery))
	r.Options("/.well-known/oauth-authorization-server", wrap(oauthPreflightHandler))
	r.Get("/.well-known/oauth-protected-resource", wrap(h.HandleProtectedResource))
	r.Options("/.well-known/oauth-protected-resource", wrap(oauthPreflightHandler))
	r.Post("/oauth/register", wrap(h.HandleClientRegister))
	r.Options("/oauth/register", wrap(oauthPreflightHandler))
	r.Get("/oauth/authorize", wrap(h.HandleAuthorize))
	r.Post("/oauth/authorize", wrap(h.HandleAuthorize))
	r.Options("/oauth/authorize", wrap(oauthPreflightHandler))
	// Local approval bridge. Intentionally absent from discovery and from the
	// Cloudflare ingress allowlist generated by the CEREBRUM wizard.
	r.Get("/oauth/approve", h.HandleApprove)
	r.Post("/oauth/approve", h.HandleApprove)
	r.Post("/oauth/token", wrap(h.HandleToken))
	r.Options("/oauth/token", wrap(oauthPreflightHandler))
}

// oauthCORSMiddleware is a passthrough — CORS is handled by the parent
// chi/cors middleware (see node.go), which echoes the origin back when it
// matches the allowlist. We deliberately do NOT set Access-Control-Allow-
// Origin here: writing `*` would override the parent's per-origin echo and
// produce a preflight/actual-response ACAO mismatch (preflight was
// origin-specific, actual was wildcard) that some browsers and OAuth
// clients reject — which is exactly the bug v6.7.5 hit, where ChatGPT
// completed consent but never POSTed /oauth/token.
func oauthCORSMiddleware(h http.HandlerFunc) http.HandlerFunc {
	return h
}

// oauthPreflightHandler is the no-op OPTIONS responder — the middleware
// above has already written the CORS headers.
func oauthPreflightHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
