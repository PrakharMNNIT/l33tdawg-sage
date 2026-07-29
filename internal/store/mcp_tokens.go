package store

// Bearer-token storage for the HTTP MCP transport.
//
// External MCP clients (ChatGPT, Cursor, Cline, custom HTTP clients) cannot
// easily ed25519-sign every request the way the SAGE REST API expects, so
// we expose a long-lived bearer-token path for them.
//
// Storage model:
//   - Tokens are 32 random bytes, base64-url-encoded — they're shown to the
//     operator exactly once at create-time and never readable again.
//   - We store the SHA-256 digest of the token, never the token itself, so
//     a database compromise cannot leak working credentials.
//   - On every MCP request, the bearer token is hashed and looked up by
//     digest.
//
// This file lives alongside the other SQLiteStore methods so it inherits
// the same writeMu / encryption / vault patterns.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

// MCPToken describes one issued bearer token. The actual token value is
// only ever returned once — see IssueMCPToken.
type MCPToken struct {
	ID         string    // stable identifier (UUID)
	Name       string    // human label set at create-time (e.g. "chatgpt-laptop")
	AgentID    string    // the on-chain agent identity this token authenticates as
	IssuerID   string    // agent that created/owns the token (distinct from AgentID for keyed tokens)
	CreatedAt  time.Time // issuance time
	LastUsedAt time.Time // updated on every successful auth (zero if never used)
	RevokedAt  time.Time // zero unless revoked
}

// ErrTokenRevoked is returned by LookupMCPToken when a token exists but has
// been explicitly revoked. Distinct from "no row" so callers can log it.
var ErrTokenRevoked = errors.New("mcp token revoked")

// ErrTokenIdentityPending is returned while a keyed token's freshly-generated
// signing identity has not yet been confirmed on-chain. Bearer auth must fail
// closed during this window: possession of a private key is not registration.
var ErrTokenIdentityPending = errors.New("mcp token identity registration is pending")

// ErrTokenIssuancePending means the bearer was created for an OAuth exchange
// but its authorization code has not been durably persisted/activated yet.
// It is deliberately fail-closed even for legacy keyless rows.
var ErrTokenIssuancePending = errors.New("mcp token issuance is pending")

// ErrTokenLegacyDisabled is returned once app-v23 requires every MCP bearer to
// carry its own registered signing identity. A keyless bearer otherwise falls
// back to the node's agent.key; after app-v23 activation that key is CEREBRUM
// Root, which would turn the bearer into an impermissible delegated Root
// credential.
var ErrTokenLegacyDisabled = errors.New("legacy keyless mcp token is disabled by app-v23")

// MCPTokenIssue is the one-shot result of the shared REST/OAuth/wizard issuer.
// Token is plaintext and must never be persisted or logged.
type MCPTokenIssue struct {
	ID        string
	Name      string
	AgentID   string
	IssuerID  string
	Token     string
	CreatedAt time.Time
}

// MCPTokenIdentityRegistrar commits a freshly-generated token identity using
// the normal AgentRegister transaction. Implementations MUST honor ctx: token
// issuance does not return a bearer until this call confirms the registration.
// A cancellation or transport error is an AMBIGUOUS chain outcome: callers
// must leave the sealed token pending and reconcile it later, never delete it
// on the assumption that the broadcast did not commit.
type MCPTokenIdentityRegistrar func(ctx context.Context, pub ed25519.PublicKey, priv ed25519.PrivateKey, name, provider string) error

var mcpTokenRegistrars sync.Map // map[*SQLiteStore]MCPTokenIdentityRegistrar

// mcpTokenKeyedRequirements is process-local policy wiring. The callback is
// evaluated for every issuance and lookup so the activation edge fails closed
// immediately, before the durable revocation reconciler has to observe it.
// A nil/missing callback preserves the historical pre-v23 behavior.
var mcpTokenKeyedRequirements sync.Map // map[*SQLiteStore]func() bool

var mcpTokenRegistrationWait = 8 * time.Second

// mcpTokenFinalizeWait bounds local state finalization and cleanup after a
// known registration result. It deliberately does not inherit a disconnected
// HTTP request's context: the chain result is already known at that point.
var mcpTokenFinalizeWait = 8 * time.Second

const (
	mcpTokenPrivateKeySealVaultV1  = "vault-v1"
	mcpTokenPrivateKeySealBearerV1 = "bearer-hkdf-aes256gcm-v1" // #nosec G101 -- encryption format label, not a credential
	mcpTokenBearerSealSaltSize     = 32
)

// SetMCPTokenIdentityRegistrar wires the off-consensus issuer to the REST
// registration broadcaster. It is process-local and intentionally not copied
// into SQLite transactions.
func (s *SQLiteStore) SetMCPTokenIdentityRegistrar(reg MCPTokenIdentityRegistrar) {
	if reg == nil {
		mcpTokenRegistrars.Delete(s)
		return
	}
	mcpTokenRegistrars.Store(s, reg)
}

// SetMCPTokenKeyedIdentityRequirement wires the app-version gate used by all
// direct, OAuth, and wizard MCP-token paths. Once required, new keyless tokens
// are refused and existing keyless tokens cannot authenticate.
func (s *SQLiteStore) SetMCPTokenKeyedIdentityRequirement(required func() bool) {
	if required == nil {
		mcpTokenKeyedRequirements.Delete(s)
		return
	}
	mcpTokenKeyedRequirements.Store(s, required)
}

func (s *SQLiteStore) mcpTokenKeyedIdentityRequired() bool {
	requiredAny, ok := mcpTokenKeyedRequirements.Load(s)
	if !ok {
		return false
	}
	required, ok := requiredAny.(func() bool)
	return ok && required != nil && required()
}

// migrateMCPTokens creates the mcp_tokens table on first boot. Idempotent.
// We store SHA-256(token), never the token itself. This schema is part of the
// authentication boundary, so startup must fail if any statement other than a
// verified concurrent duplicate-column addition fails.
func (s *SQLiteStore) migrateMCPTokens(ctx context.Context) error {
	if _, err := s.writeExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS mcp_tokens (
		id            TEXT PRIMARY KEY,
		name          TEXT NOT NULL DEFAULT '',
		agent_id      TEXT NOT NULL,
		token_sha256  TEXT NOT NULL UNIQUE,
		created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
		last_used_at  TEXT,
		revoked_at    TEXT
	)`); err != nil {
		return fmt.Errorf("create mcp token table: %w", err)
	}
	if _, err := s.writeExecContext(ctx,
		`CREATE INDEX IF NOT EXISTS idx_mcp_tokens_agent ON mcp_tokens(agent_id)`); err != nil {
		return fmt.Errorf("create mcp token agent index: %w", err)
	}
	if _, err := s.writeExecContext(ctx,
		`CREATE INDEX IF NOT EXISTS idx_mcp_tokens_active ON mcp_tokens(token_sha256) WHERE revoked_at IS NULL`); err != nil {
		return fmt.Errorf("create mcp token active index: %w", err)
	}

	// Per-token signing identity (v11.8): a token may carry its OWN ed25519
	// keypair so MCP calls sign as the token's on-chain identity instead of
	// collapsing every bearer to the node operator. token_pubkey is the hex
	// public key; token_privkey_sealed is the vault-sealed private key. Both stay
	// NULL for legacy keyless tokens, which keep signing as the operator. SQLite
	// ALTER is non-idempotent, so guard each ADD COLUMN behind a
	// pragma_table_info existence check — the mcp_auth_codes migration sibling.
	if err := s.migrateMCPTokenAddColumn(
		ctx, "token_pubkey", `ALTER TABLE mcp_tokens ADD COLUMN token_pubkey TEXT`,
	); err != nil {
		return err
	}
	if err := s.migrateMCPTokenAddColumn(
		ctx, "token_privkey_sealed", `ALTER TABLE mcp_tokens ADD COLUMN token_privkey_sealed BLOB`,
	); err != nil {
		return err
	}
	if err := s.migrateMCPTokenAddColumn(
		ctx, "issuer_id", `ALTER TABLE mcp_tokens ADD COLUMN issuer_id TEXT`,
	); err != nil {
		return err
	}
	// Fail closed for pre-migration keyed rows: the previous implementation
	// could return a bearer while registration was still retrying, so their
	// on-chain confirmation is not knowable from SQLite alone. Legacy keyless
	// rows remain compatible because they need no minted identity registration.
	if err := s.migrateMCPTokenAddColumn(
		ctx, "registration_state",
		`ALTER TABLE mcp_tokens ADD COLUMN registration_state TEXT NOT NULL DEFAULT 'pending'`,
	); err != nil {
		return err
	}
	// Repeat this idempotent normalization on every startup. That closes the
	// crash/race window between a winning ADD COLUMN and its data backfill.
	if _, err := s.writeExecContext(ctx, `UPDATE mcp_tokens
		SET registration_state = 'confirmed'
		WHERE (token_pubkey IS NULL OR token_pubkey = '')
		  AND (token_privkey_sealed IS NULL OR length(token_privkey_sealed) = 0)`); err != nil {
		return fmt.Errorf("initialize mcp token registration state: %w", err)
	}
	// Provider is part of the idempotent AgentRegister payload. Persist it so
	// a pending identity can be retried after a process restart with the same
	// on-chain metadata rather than guessing from its issuance route.
	if err := s.migrateMCPTokenAddColumn(
		ctx, "identity_provider",
		`ALTER TABLE mcp_tokens ADD COLUMN identity_provider TEXT NOT NULL DEFAULT 'mcp-token'`,
	); err != nil {
		return err
	}
	// OAuth creates its bearer before the authorization code can be inserted.
	// A durable pending bit closes that two-step crash window: lookup refuses
	// the bearer until the code exists and activation commits.
	if err := s.migrateMCPTokenAddColumn(
		ctx, "cleanup_pending",
		`ALTER TABLE mcp_tokens ADD COLUMN cleanup_pending INTEGER NOT NULL DEFAULT 0`,
	); err != nil {
		return err
	}
	// Existing keyed rows were sealed by the node vault. Keep that format
	// explicit so unencrypted app-v23 rows can use a bearer-derived envelope
	// without making old ciphertext ambiguous.
	if err := s.migrateMCPTokenAddColumn(
		ctx, "token_privkey_seal",
		`ALTER TABLE mcp_tokens ADD COLUMN token_privkey_seal TEXT NOT NULL DEFAULT ''`,
	); err != nil {
		return err
	}
	if err := s.migrateMCPTokenAddColumn(
		ctx, "token_privkey_salt", `ALTER TABLE mcp_tokens ADD COLUMN token_privkey_salt BLOB`,
	); err != nil {
		return err
	}
	// Normalize rows from the short-lived keyed-token schema that predated an
	// explicit seal discriminator. They were all vault ciphertext.
	if _, err := s.writeExecContext(ctx, `UPDATE mcp_tokens
		SET token_privkey_seal = '`+mcpTokenPrivateKeySealVaultV1+`'
		WHERE COALESCE(token_privkey_seal, '') = ''
		  AND token_pubkey IS NOT NULL AND token_pubkey != ''
		  AND token_privkey_sealed IS NOT NULL AND length(token_privkey_sealed) > 0`); err != nil {
		return fmt.Errorf("normalize mcp token private-key seal: %w", err)
	}
	return nil
}

// mcpTokensHasColumn reports whether the mcp_tokens table already has the named
// column, so the idempotent ADD COLUMN migrations above don't fail on a
// re-migrated database.
func (s *SQLiteStore) mcpTokensHasColumn(ctx context.Context, column string) (bool, error) {
	row := s.conn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pragma_table_info('mcp_tokens') WHERE name = ?`, column)
	var count int
	if err := row.Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *SQLiteStore) migrateMCPTokenAddColumn(ctx context.Context, column, statement string) error {
	exists, err := s.mcpTokensHasColumn(ctx, column)
	if err != nil {
		return fmt.Errorf("inspect mcp token column %s: %w", column, err)
	}
	if exists {
		return nil
	}
	if _, err := s.writeExecContext(ctx, statement); err != nil {
		// Two node processes can inspect the same old database before either
		// ALTER commits. SQLite has no ADD COLUMN IF NOT EXISTS, so tolerate only
		// the exact duplicate-column race and verify the winning schema before
		// continuing. Every other DDL error is startup-fatal.
		duplicate := strings.Contains(
			strings.ToLower(err.Error()),
			"duplicate column name: "+strings.ToLower(column),
		)
		if !duplicate {
			return fmt.Errorf("add mcp token column %s: %w", column, err)
		}
		exists, inspectErr := s.mcpTokensHasColumn(ctx, column)
		if inspectErr != nil {
			return fmt.Errorf("verify concurrently added mcp token column %s: %w", column, inspectErr)
		}
		if !exists {
			return fmt.Errorf("add mcp token column %s: %w", column, err)
		}
	}
	return nil
}

// InsertMCPToken records a newly-issued token by its SHA-256 digest. The
// token's plaintext value is never persisted. Caller hands the plaintext
// back to the user once and never touches it again.
func (s *SQLiteStore) InsertMCPToken(ctx context.Context, id, name, agentID, tokenSHA256 string) error {
	return s.insertLegacyMCPToken(ctx, id, name, agentID, agentID, tokenSHA256, false)
}

func (s *SQLiteStore) insertLegacyMCPToken(ctx context.Context, id, name, agentID, issuerID, tokenSHA256 string, cleanupPending bool) error {
	if id == "" || agentID == "" || tokenSHA256 == "" {
		return fmt.Errorf("id, agent_id, and tokenSHA256 are required")
	}
	if issuerID == "" {
		return fmt.Errorf("issuer_id is required")
	}
	_, err := s.writeExecContext(ctx,
		`INSERT INTO mcp_tokens (id, name, agent_id, issuer_id, token_sha256, registration_state, cleanup_pending) VALUES (?, ?, ?, ?, ?, 'confirmed', ?)`,
		id, name, agentID, issuerID, tokenSHA256, boolToInt(cleanupPending))
	if err != nil {
		return fmt.Errorf("insert mcp token: %w", err)
	}
	return nil
}

// InsertMCPTokenWithIdentity records a newly-issued token that carries its OWN
// ed25519 signing identity. The raw private key is sealed with the store vault
// (AES-256-GCM) before it ever touches disk — the plaintext key never persists.
// A vault MUST be attached: a node without encryption cannot safely store a
// signing key, so it issues a legacy keyless token via InsertMCPToken instead
// (sign-as-operator fallback). tokenPubHex is the hex-encoded public half, which
// is also the token's on-chain agent identity.
func (s *SQLiteStore) InsertMCPTokenWithIdentity(ctx context.Context, id, name, agentID, tokenSHA256, tokenPubHex string, tokenPriv ed25519.PrivateKey) error {
	return s.insertMCPTokenWithIdentity(ctx, id, name, agentID, agentID, tokenSHA256, tokenPubHex, tokenPriv, "mcp-token", false)
}

func (s *SQLiteStore) insertMCPTokenWithIdentity(ctx context.Context, id, name, agentID, issuerID, tokenSHA256, tokenPubHex string, tokenPriv ed25519.PrivateKey, provider string, cleanupPending bool) error {
	if id == "" || agentID == "" || tokenSHA256 == "" || tokenPubHex == "" {
		return fmt.Errorf("id, agent_id, tokenSHA256, and tokenPubHex are required")
	}
	if len(tokenPriv) != ed25519.PrivateKeySize {
		return fmt.Errorf("token private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(tokenPriv))
	}
	pub, ok := tokenPriv.Public().(ed25519.PublicKey)
	if !ok || hex.EncodeToString(pub) != tokenPubHex || agentID != tokenPubHex {
		return fmt.Errorf("token private key, public key, and acting agent_id do not match")
	}
	if issuerID == "" {
		return fmt.Errorf("issuer_id is required")
	}
	if provider == "" {
		provider = "mcp-token"
	}
	activeVault := s.vault.Load()
	if activeVault == nil {
		// Fail CLOSED: never persist a signing key in the clear. Callers detect
		// this via VaultActive() and fall back to a legacy keyless token.
		return fmt.Errorf("cannot seal token signing key: vault is not active")
	}
	sealed, err := activeVault.Encrypt(tokenPriv)
	if err != nil {
		return fmt.Errorf("seal token private key: %w", err)
	}
	_, err = s.writeExecContext(ctx,
		`INSERT INTO mcp_tokens (
			id, name, agent_id, issuer_id, token_sha256, token_pubkey,
			token_privkey_sealed, token_privkey_seal, registration_state,
			identity_provider, cleanup_pending
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
		id, name, agentID, issuerID, tokenSHA256, tokenPubHex, sealed,
		mcpTokenPrivateKeySealVaultV1, provider, boolToInt(cleanupPending))
	if err != nil {
		return fmt.Errorf("insert mcp token with identity: %w", err)
	}
	return nil
}

// insertMCPTokenWithBearerIdentity stores a distinct Ed25519 identity on a
// node whose memory vault is intentionally disabled. The bearer plaintext is
// the only secret capable of deriving the AES-256-GCM key. SQLite retains its
// SHA-256 digest for indexed lookup, but that digest is deliberately not KDF
// input and cannot decrypt the envelope after a database-only compromise.
func (s *SQLiteStore) insertMCPTokenWithBearerIdentity(
	ctx context.Context,
	id, name, agentID, issuerID, tokenSHA256, tokenPubHex string,
	tokenPriv ed25519.PrivateKey,
	bearerPlaintext, provider string,
	cleanupPending bool,
) error {
	if id == "" || agentID == "" || issuerID == "" || tokenSHA256 == "" ||
		tokenPubHex == "" || bearerPlaintext == "" {
		return fmt.Errorf("id, agent_id, issuer_id, tokenSHA256, tokenPubHex, and bearer are required")
	}
	if len(tokenPriv) != ed25519.PrivateKeySize {
		return fmt.Errorf("token private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(tokenPriv))
	}
	pub, ok := tokenPriv.Public().(ed25519.PublicKey)
	if !ok || hex.EncodeToString(pub) != tokenPubHex || agentID != tokenPubHex {
		return fmt.Errorf("token private key, public key, and acting agent_id do not match")
	}
	if provider == "" {
		provider = "mcp-token"
	}
	salt := make([]byte, mcpTokenBearerSealSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate bearer envelope salt: %w", err)
	}
	sealed, err := sealMCPTokenPrivateKeyWithBearer(
		bearerPlaintext, salt, mcpTokenPrivateKeyAAD(id, tokenPubHex, tokenSHA256), tokenPriv,
	)
	if err != nil {
		return err
	}
	_, err = s.writeExecContext(ctx,
		`INSERT INTO mcp_tokens (
			id, name, agent_id, issuer_id, token_sha256, token_pubkey,
			token_privkey_sealed, token_privkey_seal, token_privkey_salt,
			registration_state, identity_provider, cleanup_pending
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
		id, name, agentID, issuerID, tokenSHA256, tokenPubHex, sealed,
		mcpTokenPrivateKeySealBearerV1, salt, provider, boolToInt(cleanupPending))
	if err != nil {
		return fmt.Errorf("insert bearer-sealed mcp token identity: %w", err)
	}
	return nil
}

func mcpTokenPrivateKeyAAD(id, pubHex, tokenSHA256 string) []byte {
	return []byte("sage:mcp-token-private-key:v1|" + id + "|" + pubHex + "|" + tokenSHA256)
}

func mcpTokenBearerEnvelopeKey(bearer string, salt []byte) ([]byte, error) {
	if bearer == "" || len(salt) != mcpTokenBearerSealSaltSize {
		return nil, errors.New("invalid bearer envelope inputs")
	}
	key := make([]byte, 32)
	reader := hkdf.New(
		sha256.New,
		[]byte(bearer),
		salt,
		[]byte("sage:mcp-token:bearer-private-key-envelope:v1"),
	)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("derive bearer envelope key: %w", err)
	}
	return key, nil
}

func sealMCPTokenPrivateKeyWithBearer(
	bearer string,
	salt, aad []byte,
	privateKey ed25519.PrivateKey,
) ([]byte, error) {
	key, err := mcpTokenBearerEnvelopeKey(bearer, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create bearer envelope cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create bearer envelope AEAD: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate bearer envelope nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, privateKey, aad), nil
}

func openMCPTokenPrivateKeyWithBearer(
	bearer string,
	salt, aad, sealed []byte,
) ([]byte, error) {
	if bearer == "" {
		return nil, errors.New("bearer does not unlock this token identity")
	}
	key, err := mcpTokenBearerEnvelopeKey(bearer, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create bearer envelope cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create bearer envelope AEAD: %w", err)
	}
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("bearer envelope is truncated")
	}
	nonce := sealed[:gcm.NonceSize()]
	plaintext, err := gcm.Open(nil, nonce, sealed[gcm.NonceSize():], aad)
	if err != nil {
		return nil, errors.New("bearer does not unlock this token identity")
	}
	return plaintext, nil
}

// IssueMCPToken is the single issuance primitive shared by direct REST, OAuth,
// and the setup wizard. Vault-active nodes seal a distinct signing identity
// with the vault. App-v23 nodes without a vault seal that identity under the
// bearer itself, so an unencrypted personal node never falls back to Root.
// Legacy keyless issuance remains only for unencrypted pre-v23 nodes.
func (s *SQLiteStore) IssueMCPToken(ctx context.Context, name, issuerID, legacyAgentID, provider string) (*MCPTokenIssue, error) {
	return s.issueMCPToken(ctx, name, issuerID, legacyAgentID, provider, false)
}

// IssuePendingMCPToken creates an OAuth-bound bearer in a durable fail-closed
// state. Call ActivatePendingMCPToken only after its authorization-code row is
// committed; otherwise cleanup/reconciliation can safely revoke it later.
func (s *SQLiteStore) IssuePendingMCPToken(ctx context.Context, name, issuerID, legacyAgentID, provider string) (*MCPTokenIssue, error) {
	return s.issueMCPToken(ctx, name, issuerID, legacyAgentID, provider, true)
}

func (s *SQLiteStore) issueMCPToken(ctx context.Context, name, issuerID, legacyAgentID, provider string, cleanupPending bool) (*MCPTokenIssue, error) {
	if issuerID == "" || legacyAgentID == "" {
		return nil, fmt.Errorf("issuer_id and legacy agent_id are required")
	}
	requireKeyed := s.mcpTokenKeyedIdentityRequired()
	if s.VaultLocked() {
		return nil, fmt.Errorf("keyed MCP token issuance unavailable: vault is locked")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate bearer: %w", err)
	}
	plain := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(plain))
	digestHex := hex.EncodeToString(digest[:])
	issued := &MCPTokenIssue{ID: uuid.NewString(), Name: name, IssuerID: issuerID, Token: plain, CreatedAt: time.Now().UTC()}

	if !s.VaultActive() && !requireKeyed {
		issued.AgentID = legacyAgentID
		if err := s.insertLegacyMCPToken(ctx, issued.ID, name, legacyAgentID, issuerID, digestHex, cleanupPending); err != nil {
			return nil, err
		}
		return issued, nil
	}

	regAny, ok := mcpTokenRegistrars.Load(s)
	if !ok {
		return nil, fmt.Errorf("keyed MCP token issuance unavailable: identity registrar is not configured")
	}
	reg := regAny.(MCPTokenIdentityRegistrar)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate token identity: %w", err)
	}
	issued.AgentID = hex.EncodeToString(pub)
	if requireKeyed {
		// App-v23 uses the bearer envelope regardless of memory-vault state.
		// This keeps the credential stable across optional ledger
		// enable/disable, lock/unlock, and passphrase-change transitions.
		if err := s.insertMCPTokenWithBearerIdentity(
			ctx, issued.ID, name, issued.AgentID, issuerID, digestHex,
			issued.AgentID, priv, plain, provider, cleanupPending,
		); err != nil {
			return nil, err
		}
	} else if s.VaultActive() {
		if err := s.insertMCPTokenWithIdentity(ctx, issued.ID, name, issued.AgentID, issuerID, digestHex, issued.AgentID, priv, provider, cleanupPending); err != nil {
			return nil, err
		}
	} else {
		if err := s.insertMCPTokenWithBearerIdentity(
			ctx, issued.ID, name, issued.AgentID, issuerID, digestHex,
			issued.AgentID, priv, plain, provider, cleanupPending,
		); err != nil {
			return nil, err
		}
	}

	// Register synchronously under a child deadline. A timeout, cancellation, or
	// transport error is deliberately NOT a negative chain result: CometBFT may
	// have committed just before its response was lost. Keep the sealed row
	// pending (and therefore unusable) so reconciliation can retry the
	// idempotent AgentRegister without losing a potentially real identity.
	regCtx, cancel := context.WithTimeout(ctx, mcpTokenRegistrationWait)
	defer cancel()
	if regErr := reg(regCtx, pub, priv, name, provider); regErr != nil {
		if errors.Is(regErr, context.DeadlineExceeded) || errors.Is(regCtx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("register token identity outcome unknown; token remains pending and cannot authenticate: %w", regErr)
		}
		return nil, fmt.Errorf("register token identity outcome unknown; token remains pending and cannot authenticate: %w", regErr)
	}
	if err := s.confirmMCPTokenIdentity(issued.ID); err != nil {
		// Registration returned a definitive success. Do not let a canceled
		// request or a transient SQLite write turn that into a destructive delete.
		// The pending row remains fail-closed and the reconciler will finalize it.
		return nil, fmt.Errorf("register token identity succeeded but local confirmation is pending: %w", err)
	}
	return issued, nil
}

// confirmMCPTokenIdentity records a known successful AgentRegister result. It
// always uses its own bounded background context: callers commonly discover
// success while their original HTTP request has already been canceled.
func (s *SQLiteStore) confirmMCPTokenIdentity(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), mcpTokenFinalizeWait)
	defer cancel()
	res, err := s.writeExecContext(ctx, `UPDATE mcp_tokens SET registration_state = 'confirmed' WHERE id = ? AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("confirm token identity registration: %w", err)
	}
	if n, rowsErr := res.RowsAffected(); rowsErr != nil || n != 1 {
		if rowsErr != nil {
			return fmt.Errorf("confirm token identity registration: %w", rowsErr)
		}
		return fmt.Errorf("confirm token identity registration: pending token is revoked or missing")
	}
	return nil
}

// ActivatePendingMCPToken makes an OAuth-issued bearer usable only after its
// authorization code has been durably written. The state bit is an auth gate,
// not merely cleanup metadata.
func (s *SQLiteStore) ActivatePendingMCPToken(ctx context.Context, id string) error {
	res, err := s.writeExecContext(ctx, `UPDATE mcp_tokens SET cleanup_pending = 0 WHERE id = ? AND revoked_at IS NULL AND cleanup_pending = 1`, id)
	if err != nil {
		return fmt.Errorf("activate pending mcp token: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("activate pending mcp token: token is revoked, missing, or already active")
	}
	return nil
}

// MarkMCPTokenCleanupPending fail-closes a token before an OAuth rollback.
// It is idempotent and durable, so a process crash cannot leave the bearer
// usable while a best-effort immediate revoke is retried later.
func (s *SQLiteStore) MarkMCPTokenCleanupPending(ctx context.Context, id string) error {
	_, err := s.writeExecContext(ctx, `UPDATE mcp_tokens SET cleanup_pending = 1 WHERE id = ? AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("mark mcp token cleanup pending: %w", err)
	}
	return nil
}

// PurgeMCPTokenCleanup atomically revokes all fail-closed OAuth issuance rows
// and removes their authorization codes. It is the durable retry path when an
// immediate request-time cleanup was interrupted.
func (s *SQLiteStore) PurgeMCPTokenCleanup(ctx context.Context) (int64, error) {
	tx, unlock, err := s.beginTxLocked(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin mcp token cleanup: %w", err)
	}
	defer unlock()
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE mcp_tokens
		SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
		WHERE cleanup_pending = 1 AND revoked_at IS NULL`)
	if err != nil {
		return 0, fmt.Errorf("revoke cleanup-pending mcp tokens: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mcp_auth_codes WHERE token_id IN (SELECT id FROM mcp_tokens WHERE cleanup_pending = 1)`); err != nil {
		return 0, fmt.Errorf("delete cleanup-pending auth codes: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit mcp token cleanup: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// RevokeAppV23LegacyMCPBearers durably retires every bearer without its own
// signing key and removes any still-redeemable OAuth authorization code bound
// to one. Historically all keyless rows fall back to this process's node
// agent.key regardless of their stored agent_id, so once that key is app-v23
// Root every keyless bearer is Root-capable and must be invalidated.
//
// The operation is idempotent and safe to run at boot and at the activation
// edge. Keyed rows, including pending distinct token identities, are untouched.
func (s *SQLiteStore) RevokeAppV23LegacyMCPBearers(ctx context.Context) (int64, error) {
	tx, unlock, err := s.beginTxLocked(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin app-v23 legacy mcp bearer revocation: %w", err)
	}
	defer unlock()
	defer func() { _ = tx.Rollback() }()

	keyless := `(COALESCE(token_pubkey, '') = '' AND
		(token_privkey_sealed IS NULL OR length(token_privkey_sealed) = 0))`
	if _, deleteErr := tx.ExecContext(ctx, `DELETE FROM mcp_auth_codes
		WHERE token_id IN (
			SELECT id FROM mcp_tokens WHERE `+keyless+`
		)`); deleteErr != nil {
		return 0, fmt.Errorf("delete app-v23 legacy mcp auth codes: %w", deleteErr)
	}
	res, err := tx.ExecContext(ctx, `UPDATE mcp_tokens
		SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
		    cleanup_pending = 0
		WHERE revoked_at IS NULL AND `+keyless)
	if err != nil {
		return 0, fmt.Errorf("revoke app-v23 legacy mcp bearers: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit app-v23 legacy mcp bearer revocation: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ReconcilePendingMCPTokenIdentities retries the idempotent standard
// AgentRegister transaction for sealed pending rows, then marks only known
// successes confirmed. It is safe after an ambiguous RPC response because
// processAgentRegister accepts an already-registered identity. Failed retries
// remain pending and therefore fail closed; callers can schedule this at node
// startup or periodically without ever exposing the bearer secret.
func (s *SQLiteStore) ReconcilePendingMCPTokenIdentities(ctx context.Context) (int, error) {
	regAny, ok := mcpTokenRegistrars.Load(s)
	if !ok {
		return 0, fmt.Errorf("keyed MCP token reconciliation unavailable: identity registrar is not configured")
	}
	reg := regAny.(MCPTokenIdentityRegistrar)
	rows, err := s.conn.QueryContext(ctx, `
		SELECT id, name, agent_id, token_pubkey, token_privkey_sealed,
		       COALESCE(token_privkey_seal, ''), COALESCE(token_privkey_salt, x''),
		       COALESCE(identity_provider, 'mcp-token')
		  FROM mcp_tokens
		 WHERE registration_state = 'pending' AND revoked_at IS NULL
		   AND token_pubkey IS NOT NULL AND token_pubkey != ''
		   AND token_privkey_sealed IS NOT NULL AND length(token_privkey_sealed) > 0`)
	if err != nil {
		return 0, fmt.Errorf("list pending mcp token identities: %w", err)
	}
	defer func() { _ = rows.Close() }()
	type pendingIdentity struct {
		id, name, agentID, pubHex, sealKind, provider string
		sealed, salt                                  []byte
	}
	var pending []pendingIdentity
	for rows.Next() {
		var p pendingIdentity
		if scanErr := rows.Scan(
			&p.id, &p.name, &p.agentID, &p.pubHex, &p.sealed,
			&p.sealKind, &p.salt, &p.provider,
		); scanErr != nil {
			return 0, fmt.Errorf("scan pending mcp token identity: %w", scanErr)
		}
		pending = append(pending, p)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate pending mcp token identities: %w", err)
	}

	confirmed := 0
	for _, p := range pending {
		if err := ctx.Err(); err != nil {
			return confirmed, err
		}
		if p.sealKind == mcpTokenPrivateKeySealBearerV1 {
			// The plaintext bearer was intentionally never persisted and was
			// never returned after an ambiguous issuance. There is no recovery
			// secret available at startup, so this row remains fail-closed. A
			// committed registration, if any, is only an ordinary pending-review
			// agent and carries no Root/Admin authority.
			continue
		}
		if p.sealKind != "" && p.sealKind != mcpTokenPrivateKeySealVaultV1 {
			return confirmed, fmt.Errorf("pending mcp token %s has unknown private-key seal %q", p.id, p.sealKind)
		}
		activeVault := s.vault.Load()
		if activeVault == nil {
			return confirmed, fmt.Errorf("cannot reconcile keyed MCP token %s: vault is locked", p.id)
		}
		priv, decErr := activeVault.Decrypt(p.sealed)
		if decErr != nil || len(priv) != ed25519.PrivateKeySize {
			// Corrupt/unavailable local key cannot safely become legacy. Keep the
			// row pending; surface the problem for operator repair.
			if decErr != nil {
				return confirmed, fmt.Errorf("unseal pending mcp token %s: %w", p.id, decErr)
			}
			return confirmed, fmt.Errorf("unseal pending mcp token %s: wrong private key length", p.id)
		}
		pub, decErr := hex.DecodeString(p.pubHex)
		if decErr != nil || len(pub) != ed25519.PublicKeySize || p.agentID != p.pubHex {
			return confirmed, fmt.Errorf("pending mcp token %s has invalid identity binding", p.id)
		}
		child, cancel := context.WithTimeout(ctx, mcpTokenRegistrationWait)
		regErr := reg(child, ed25519.PublicKey(pub), ed25519.PrivateKey(priv), p.name, p.provider)
		cancel()
		if regErr != nil {
			// Ambiguous and deterministic rejections both remain fail-closed. A
			// later retry may observe the idempotent already-registered success.
			continue
		}
		if confirmErr := s.confirmMCPTokenIdentity(p.id); confirmErr != nil {
			return confirmed, confirmErr
		}
		confirmed++
	}
	return confirmed, nil
}

// LookupMCPTokenSigner resolves an active (non-revoked) token to its signing
// identity. For a KEYED token it unseals the per-token ed25519 private key with
// the store vault and returns (agentID, priv, nil). For a LEGACY keyless token
// (token_pubkey NULL — issued before per-token identity landed) it returns
// (agentID, nil, nil) so the caller falls back to operator signing.
//
// FAIL-CLOSED: when a row HAS key material but the vault is unavailable (nil or
// locked), it returns an error rather than silently degrading a keyed token to
// the operator identity. Side-effect: bumps last_used_at like LookupMCPToken.
//
// Returns sql.ErrNoRows if no token matches and ErrTokenRevoked if the token
// exists but was revoked.
func (s *SQLiteStore) LookupMCPTokenSigner(ctx context.Context, tokenSHA256 string) (string, ed25519.PrivateKey, error) {
	return s.lookupMCPTokenSigner(ctx, "", tokenSHA256)
}

// LookupMCPTokenSignerWithBearer resolves a token while the authentication
// boundary still holds its plaintext. The plaintext is used only to unlock a
// bearer-derived private-key envelope; it is never persisted or placed in a
// request context. Vault-sealed and legacy rows remain backward compatible.
func (s *SQLiteStore) LookupMCPTokenSignerWithBearer(
	ctx context.Context,
	bearerPlaintext, tokenSHA256 string,
) (string, ed25519.PrivateKey, error) {
	return s.lookupMCPTokenSigner(ctx, bearerPlaintext, tokenSHA256)
}

func (s *SQLiteStore) lookupMCPTokenSigner(
	ctx context.Context,
	bearerPlaintext, tokenSHA256 string,
) (string, ed25519.PrivateKey, error) {
	row := s.conn.QueryRowContext(ctx, `
		SELECT id, agent_id, COALESCE(revoked_at, ''), token_pubkey,
		       token_privkey_sealed, COALESCE(token_privkey_seal, ''),
		       COALESCE(token_privkey_salt, x''), registration_state,
		       cleanup_pending
		  FROM mcp_tokens
		 WHERE token_sha256 = ?`, tokenSHA256)

	var id, agentID, revokedAt, sealKind, registrationState string
	var cleanupPending int
	var pubHex sql.NullString
	var sealed, salt []byte
	if err := row.Scan(
		&id, &agentID, &revokedAt, &pubHex, &sealed, &sealKind, &salt,
		&registrationState, &cleanupPending,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil, sql.ErrNoRows
		}
		return "", nil, fmt.Errorf("lookup mcp token signer: %w", err)
	}
	if revokedAt != "" {
		return "", nil, ErrTokenRevoked
	}
	if cleanupPending != 0 {
		return "", nil, ErrTokenIssuancePending
	}

	pubAbsent := !pubHex.Valid || pubHex.String == ""
	sealedAbsent := len(sealed) == 0
	// Legacy means BOTH key columns are absent. Partial key state is corruption,
	// never permission to inherit the operator identity.
	if pubAbsent != sealedAbsent {
		return "", nil, fmt.Errorf("mcp token %s has incomplete signing key state", id)
	}
	if pubAbsent && sealedAbsent {
		if s.mcpTokenKeyedIdentityRequired() {
			return "", nil, ErrTokenLegacyDisabled
		}
		s.touchMCPTokenLastUsed(ctx, id)
		return agentID, nil, nil
	}
	if registrationState != "confirmed" {
		return "", nil, ErrTokenIdentityPending
	}

	// Keyed token: the private key MUST be unsealable using its exact declared
	// format. No failure may silently degrade to the node operator/Root key.
	var priv []byte
	var err error
	switch sealKind {
	case "", mcpTokenPrivateKeySealVaultV1:
		activeVault := s.vault.Load()
		if activeVault == nil {
			return "", nil, fmt.Errorf("mcp token %s carries a vault-sealed signing key but the vault is locked", id)
		}
		priv, err = activeVault.Decrypt(sealed)
		if err != nil {
			return "", nil, fmt.Errorf("unseal token signing key for %s: %w", id, err)
		}
		if s.mcpTokenKeyedIdentityRequired() && bearerPlaintext != "" {
			if rewrapErr := s.rewrapMCPTokenPrivateKeyForBearer(
				ctx, id, pubHex.String, tokenSHA256, bearerPlaintext, ed25519.PrivateKey(priv),
			); rewrapErr != nil {
				return "", nil, fmt.Errorf("migrate token signing key %s to transition-stable bearer envelope: %w", id, rewrapErr)
			}
		}
	case mcpTokenPrivateKeySealBearerV1:
		priv, err = openMCPTokenPrivateKeyWithBearer(
			bearerPlaintext,
			salt,
			mcpTokenPrivateKeyAAD(id, pubHex.String, tokenSHA256),
			sealed,
		)
		if err != nil {
			return "", nil, fmt.Errorf("unseal token signing key for %s: %w", id, err)
		}
	default:
		return "", nil, fmt.Errorf("mcp token %s has unknown private-key seal %q", id, sealKind)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return "", nil, fmt.Errorf("unsealed token signing key for %s has wrong length %d", id, len(priv))
	}
	privKey := ed25519.PrivateKey(priv)
	derivedPub, ok := privKey.Public().(ed25519.PublicKey)
	if !ok || hex.EncodeToString(derivedPub) != pubHex.String || agentID != pubHex.String {
		return "", nil, fmt.Errorf("mcp token %s signing key does not match public key and agent_id", id)
	}
	s.touchMCPTokenLastUsed(ctx, id)
	return agentID, privKey, nil
}

// rewrapMCPTokenPrivateKeyForBearer upgrades a legacy vault-v1 keyed row after
// the user presents its bearer and the vault successfully decrypts it. Before
// that moment SAGE intentionally does not possess the bearer plaintext, so no
// safe pre-emptive conversion exists. The conditional update prevents a
// concurrent authentication from replacing an already migrated envelope.
func (s *SQLiteStore) rewrapMCPTokenPrivateKeyForBearer(
	ctx context.Context,
	id, pubHex, tokenSHA256, bearerPlaintext string,
	privateKey ed25519.PrivateKey,
) error {
	salt := make([]byte, mcpTokenBearerSealSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate bearer envelope salt: %w", err)
	}
	sealed, err := sealMCPTokenPrivateKeyWithBearer(
		bearerPlaintext,
		salt,
		mcpTokenPrivateKeyAAD(id, pubHex, tokenSHA256),
		privateKey,
	)
	if err != nil {
		return err
	}
	_, err = s.writeExecContext(ctx, `
		UPDATE mcp_tokens
		   SET token_privkey_sealed = ?,
		       token_privkey_seal = ?,
		       token_privkey_salt = ?
		 WHERE id = ? AND token_sha256 = ?
		   AND COALESCE(token_privkey_seal, '') IN ('', ?)`,
		sealed, mcpTokenPrivateKeySealBearerV1, salt,
		id, tokenSHA256, mcpTokenPrivateKeySealVaultV1,
	)
	if err != nil {
		return fmt.Errorf("persist bearer envelope: %w", err)
	}
	return nil
}

// touchMCPTokenLastUsed best-effort bumps last_used_at; a write error never
// fails auth (mirrors LookupMCPToken).
func (s *SQLiteStore) touchMCPTokenLastUsed(ctx context.Context, id string) {
	_, _ = s.writeExecContext(ctx,
		`UPDATE mcp_tokens SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`, id)
}

// DeleteMCPToken hard-deletes a token row by public ID. Used to roll back any
// issuance whose on-chain identity registration was not confirmed, so a
// half-provisioned keyed token never lingers. Idempotent (missing row is a no-op).
func (s *SQLiteStore) DeleteMCPToken(ctx context.Context, id string) error {
	if _, err := s.writeExecContext(ctx, `DELETE FROM mcp_tokens WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete mcp token: %w", err)
	}
	return nil
}

// LookupMCPToken finds an active (non-revoked) token by its SHA-256 digest
// and returns the associated agent ID. Side-effect: bumps last_used_at to
// now() so the operator can see when each token was last hit.
//
// Returns sql.ErrNoRows if no token matches and ErrTokenRevoked if the
// token exists but was revoked.
func (s *SQLiteStore) LookupMCPToken(ctx context.Context, tokenSHA256 string) (*MCPToken, error) {
	row := s.conn.QueryRowContext(ctx, `
		SELECT id, name, agent_id, COALESCE(issuer_id, agent_id), created_at,
		       COALESCE(last_used_at, ''), COALESCE(revoked_at, ''),
		       cleanup_pending, token_pubkey, token_privkey_sealed
		  FROM mcp_tokens
		 WHERE token_sha256 = ?`, tokenSHA256)

	var tok MCPToken
	var createdAt, lastUsedAt, revokedAt string
	var cleanupPending int
	var pubHex sql.NullString
	var sealed []byte
	if err := row.Scan(
		&tok.ID, &tok.Name, &tok.AgentID, &tok.IssuerID, &createdAt,
		&lastUsedAt, &revokedAt, &cleanupPending, &pubHex, &sealed,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("lookup mcp token: %w", err)
	}

	tok.CreatedAt = parseTime(createdAt)
	if lastUsedAt != "" {
		tok.LastUsedAt = parseTime(lastUsedAt)
	}
	if revokedAt != "" {
		tok.RevokedAt = parseTime(revokedAt)
		return &tok, ErrTokenRevoked
	}
	if cleanupPending != 0 {
		return &tok, ErrTokenIssuancePending
	}
	pubAbsent := !pubHex.Valid || pubHex.String == ""
	sealedAbsent := len(sealed) == 0
	if pubAbsent != sealedAbsent {
		return &tok, fmt.Errorf("mcp token %s has incomplete signing key state", tok.ID)
	}
	if pubAbsent && sealedAbsent && s.mcpTokenKeyedIdentityRequired() {
		return &tok, ErrTokenLegacyDisabled
	}

	// Best-effort last_used_at update — never fail auth on a write error.
	_, _ = s.writeExecContext(ctx,
		`UPDATE mcp_tokens SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`,
		tok.ID)

	return &tok, nil
}

// ListMCPTokens returns all issued tokens (active + revoked) so the
// dashboard / CLI can show issuance history. Token values are NEVER
// returned (we don't have them — only digests).
func (s *SQLiteStore) ListMCPTokens(ctx context.Context) ([]*MCPToken, error) {
	rows, err := s.conn.QueryContext(ctx, `
		SELECT id, name, agent_id, COALESCE(issuer_id, agent_id), created_at, COALESCE(last_used_at, ''), COALESCE(revoked_at, '')
		  FROM mcp_tokens
		 ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list mcp tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*MCPToken
	for rows.Next() {
		var tok MCPToken
		var createdAt, lastUsedAt, revokedAt string
		if scanErr := rows.Scan(&tok.ID, &tok.Name, &tok.AgentID, &tok.IssuerID, &createdAt, &lastUsedAt, &revokedAt); scanErr != nil {
			return nil, fmt.Errorf("scan mcp token: %w", scanErr)
		}
		tok.CreatedAt = parseTime(createdAt)
		if lastUsedAt != "" {
			tok.LastUsedAt = parseTime(lastUsedAt)
		}
		if revokedAt != "" {
			tok.RevokedAt = parseTime(revokedAt)
		}
		out = append(out, &tok)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("iterate mcp tokens: %w", rowsErr)
	}
	return out, nil
}

// RevokeMCPToken marks a token as revoked by its public ID (NOT the token
// digest — operators don't have access to digests). Idempotent: revoking
// an already-revoked token is a no-op.
func (s *SQLiteStore) RevokeMCPToken(ctx context.Context, id string) error {
	res, err := s.writeExecContext(ctx,
		`UPDATE mcp_tokens
		    SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
		  WHERE id = ? AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("revoke mcp token: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Either no such token, or already revoked. Distinguish for the caller.
		row := s.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM mcp_tokens WHERE id = ?`, id)
		var count int
		_ = row.Scan(&count)
		if count == 0 {
			return sql.ErrNoRows
		}
	}
	return nil
}
