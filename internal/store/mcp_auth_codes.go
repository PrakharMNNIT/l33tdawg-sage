package store

// OAuth 2.0 + PKCE authorization-code storage for the HTTP MCP transport.
//
// Why this exists:
//   ChatGPT's MCP connector form requires an `Authorization URL` + `Token URL`
//   pair and refuses to accept a static bearer in the Client ID field. SAGE's
//   HTTP MCP transport is bearer-only (v6.7.0/v6.7.1), so we layer a thin
//   OAuth 2.0 authorization-code-with-PKCE wrapper on top: the operator
//   approves a known mcp_tokens row at /oauth/authorize, the auth code is
//   redeemed once at /oauth/token, and the bearer token plaintext is handed
//   back to ChatGPT via the standard `access_token` field.
//
// Storage model:
//   - Codes are 32 random bytes, base64-url-encoded — opaque to the client.
//     Only SHA-256(code) is persisted. The raw code is also the key material
//     for a short-lived AES-GCM delivery envelope containing the bearer, so a
//     database snapshot has neither credential needed to authenticate.
//   - PKCE: SHA-256(code_verifier) base64url-no-pad is sent up-front as
//     `code_challenge` (S256 only). On redeem, the client presents the
//     verifier; we recompute the hash and compare in constant time.
//   - Single-use is enforced via the partial-WHERE update at redeem time:
//     UPDATE mcp_auth_codes SET used_at=now WHERE code_sha256=? AND used_at IS NULL
//     (RowsAffected==0 ⇒ already-used or vanished — treat as used).
//   - TTL is enforced at redeem with `expires_at > now`; expired rows are
//     revoked and removed by the periodic purge.
//   - The bearer plaintext exists only in memory. Its encrypted delivery
//     envelope and salt are wiped on successful redemption.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	oauthCodeDeliverySealV1   = "code-hkdf-aes256gcm-v1"
	oauthCodeDeliverySaltSize = 32
)

// MCPAuthCode is the persisted auth-code row. Code is the SHA-256 digest of
// the one-shot authorization code; neither the raw code nor bearer is stored.
type MCPAuthCode struct {
	Code                string
	TokenID             string
	CodeChallenge       string
	CodeChallengeMethod string
	RedirectURI         string
	ClientID            string
	State               string
	ExpiresAt           time.Time
	UsedAt              time.Time
	CreatedAt           time.Time
}

// Sentinels distinguish auth-code redemption failures so the OAuth handler
// can surface the right `error` field per RFC 6749 §5.2.
var (
	// ErrAuthCodeNotFound — code does not exist.
	ErrAuthCodeNotFound = errors.New("oauth auth code not found")
	// ErrAuthCodeUsed — the single-use redemption already happened.
	ErrAuthCodeUsed = errors.New("oauth auth code already used")
	// ErrAuthCodeExpired — past expires_at.
	ErrAuthCodeExpired = errors.New("oauth auth code expired")
	// ErrAuthCodeClientMismatch — client_id at /token differs from the one
	// bound at /authorize. Same-redirect sibling public clients cannot redeem.
	ErrAuthCodeClientMismatch = errors.New("oauth client_id mismatch")
	// ErrAuthCodeRedirectMismatch — redirect_uri at /token differs from
	// what was bound at /authorize. Required by RFC 6749 §4.1.3.
	ErrAuthCodeRedirectMismatch = errors.New("oauth redirect_uri mismatch")
	// ErrAuthCodePKCEMismatch — SHA-256(code_verifier) != stored challenge.
	ErrAuthCodePKCEMismatch = errors.New("oauth pkce verifier mismatch")
	// ErrAuthCodeUnsupportedMethod — code_challenge_method != S256.
	ErrAuthCodeUnsupportedMethod = errors.New("oauth code_challenge_method unsupported")
)

// migrateMCPAuthCodes creates the mcp_auth_codes table on first boot. It is
// idempotent and security-critical: callers must fail startup if a migration
// cannot establish the no-plaintext schema or revoke legacy plaintext rows.
func (s *SQLiteStore) migrateMCPAuthCodes(ctx context.Context) error {
	if _, err := s.writeExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS mcp_auth_codes (
		code                  TEXT PRIMARY KEY,
		code_sha256           TEXT,
		token_id              TEXT NOT NULL,
		code_challenge        TEXT NOT NULL,
		code_challenge_method TEXT NOT NULL DEFAULT 'S256',
		redirect_uri          TEXT NOT NULL,
		client_id             TEXT NOT NULL,
		state                 TEXT NOT NULL DEFAULT '',
		expires_at            TEXT NOT NULL,
		used_at               TEXT,
		bearer_plaintext      TEXT,
		delivery_sealed       BLOB,
		delivery_salt         BLOB,
		delivery_seal         TEXT NOT NULL DEFAULT '',
		created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
	)`); err != nil {
		return fmt.Errorf("create oauth auth-code table: %w", err)
	}
	if _, err := s.writeExecContext(ctx,
		`CREATE INDEX IF NOT EXISTS idx_mcp_auth_codes_token ON mcp_auth_codes(token_id)`); err != nil {
		return fmt.Errorf("create oauth auth-code token index: %w", err)
	}
	if _, err := s.writeExecContext(ctx,
		`CREATE INDEX IF NOT EXISTS idx_mcp_auth_codes_expires ON mcp_auth_codes(expires_at)`); err != nil {
		return fmt.Errorf("create oauth auth-code expiry index: %w", err)
	}

	for _, column := range []struct {
		name string
		sql  string
	}{
		{"bearer_plaintext", `ALTER TABLE mcp_auth_codes ADD COLUMN bearer_plaintext TEXT`},
		{"code_sha256", `ALTER TABLE mcp_auth_codes ADD COLUMN code_sha256 TEXT`},
		{"delivery_sealed", `ALTER TABLE mcp_auth_codes ADD COLUMN delivery_sealed BLOB`},
		{"delivery_salt", `ALTER TABLE mcp_auth_codes ADD COLUMN delivery_salt BLOB`},
		{"delivery_seal", `ALTER TABLE mcp_auth_codes ADD COLUMN delivery_seal TEXT NOT NULL DEFAULT ''`},
	} {
		row := s.conn.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM pragma_table_info('mcp_auth_codes') WHERE name = ?`, column.name)
		var count int
		if err := row.Scan(&count); err != nil {
			return fmt.Errorf("inspect oauth auth-code column %s: %w", column.name, err)
		}
		if count == 0 {
			if _, err := s.writeExecContext(ctx, column.sql); err != nil {
				return fmt.Errorf("add oauth auth-code column %s: %w", column.name, err)
			}
		}
	}
	if _, err := s.writeExecContext(ctx,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_auth_codes_digest ON mcp_auth_codes(code_sha256) WHERE code_sha256 IS NOT NULL`); err != nil {
		return fmt.Errorf("create oauth auth-code digest index: %w", err)
	}

	// A legacy in-flight row contains both the raw authorization code and raw
	// bearer. It cannot be made safe in place: a copied pre-upgrade database
	// already contains both credentials. Revoke its token and force the client
	// to restart authorization, then erase the plaintext row. Used legacy rows
	// are erased as well. New rows always carry code_sha256.
	tx, unlock, err := s.beginTxLocked(ctx)
	if err != nil {
		return fmt.Errorf("begin oauth auth-code legacy revocation: %w", err)
	}
	defer unlock()
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `UPDATE mcp_tokens
		SET revoked_at = COALESCE(revoked_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
		WHERE id IN (
			SELECT token_id FROM mcp_auth_codes
			WHERE code_sha256 IS NULL OR code_sha256 = ''
		)`); err != nil {
		return fmt.Errorf("revoke legacy plaintext oauth bearer: %w", err)
	}
	if _, err = tx.ExecContext(ctx,
		`DELETE FROM mcp_auth_codes WHERE code_sha256 IS NULL OR code_sha256 = ''`); err != nil {
		return fmt.Errorf("erase legacy plaintext oauth auth code: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit oauth auth-code legacy revocation: %w", err)
	}
	return nil
}

// IssueAuthCode persists a freshly-minted authorization code bound to the
// given mcp_tokens row plus an encrypted bearer delivery envelope. The caller is responsible
// for generating the random code value (32 bytes base64url is the
// convention). The raw code is never stored.
//
// `ttl` is the lifetime from now() until the code is unredeemable. RFC 6749
// §4.1.2 recommends ~10 minutes maximum; SAGE uses 5 minutes.
//
// `bearerPlaintext` is the just-minted bearer that /token will return. It is
// sealed with a key derived from the raw code and a per-row random salt.
//
// Returns an error if the code already exists (PRIMARY KEY collision —
// astronomically unlikely with 32 random bytes).
func (s *SQLiteStore) IssueAuthCode(
	ctx context.Context,
	code, tokenID, codeChallenge, codeChallengeMethod, redirectURI, clientID, state, bearerPlaintext string,
	ttl time.Duration,
) error {
	if code == "" || tokenID == "" || codeChallenge == "" || redirectURI == "" || bearerPlaintext == "" {
		return fmt.Errorf("code, token_id, code_challenge, redirect_uri, bearer are required")
	}
	method := strings.ToUpper(strings.TrimSpace(codeChallengeMethod))
	if method == "" {
		method = "S256"
	}
	if method != "S256" {
		return ErrAuthCodeUnsupportedMethod
	}
	codeDigest := oauthCodeDigest(code)
	salt := make([]byte, oauthCodeDeliverySaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate oauth delivery salt: %w", err)
	}
	aad := oauthCodeDeliveryAAD(
		tokenID, codeDigest, codeChallenge, method, redirectURI, clientID,
	)
	sealed, err := sealOAuthBearerForCode(code, salt, aad, bearerPlaintext)
	if err != nil {
		return err
	}
	expiresAt := time.Now().UTC().Add(ttl).Format("2006-01-02T15:04:05.999999999Z07:00")
	_, err = s.writeExecContext(ctx,
		`INSERT INTO mcp_auth_codes
		   (code, code_sha256, token_id, code_challenge, code_challenge_method,
		    redirect_uri, client_id, state, expires_at, bearer_plaintext,
		    delivery_sealed, delivery_salt, delivery_seal)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)`,
		codeDigest, codeDigest, tokenID, codeChallenge, method, redirectURI,
		clientID, state, expiresAt, sealed, salt, oauthCodeDeliverySealV1)
	if err != nil {
		return fmt.Errorf("insert auth code: %w", err)
	}
	return nil
}

func oauthCodeDigest(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func oauthCodeDeliveryAAD(tokenID, codeDigest, challenge, method, redirectURI, clientID string) []byte {
	return []byte(strings.Join([]string{
		"sage:oauth-code-bearer-delivery:v1",
		tokenID,
		codeDigest,
		challenge,
		method,
		redirectURI,
		clientID,
	}, "|"))
}

func oauthCodeDeliveryKey(code string, salt []byte) ([]byte, error) {
	if code == "" || len(salt) != oauthCodeDeliverySaltSize {
		return nil, errors.New("invalid oauth delivery envelope inputs")
	}
	key := make([]byte, 32)
	reader := hkdf.New(
		sha256.New,
		[]byte(code),
		salt,
		[]byte("sage:oauth-code:bearer-delivery-envelope:v1"),
	)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("derive oauth delivery key: %w", err)
	}
	return key, nil
}

func sealOAuthBearerForCode(code string, salt, aad []byte, bearer string) ([]byte, error) {
	key, err := oauthCodeDeliveryKey(code, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create oauth delivery cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create oauth delivery AEAD: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate oauth delivery nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, []byte(bearer), aad), nil
}

func openOAuthBearerForCode(code string, salt, aad, sealed []byte) (string, error) {
	key, err := oauthCodeDeliveryKey(code, salt)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create oauth delivery cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create oauth delivery AEAD: %w", err)
	}
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return "", errors.New("oauth bearer delivery envelope is truncated")
	}
	plaintext, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], aad)
	if err != nil {
		return "", errors.New("authorization code does not unlock bearer delivery")
	}
	return string(plaintext), nil
}

// DeleteAuthCode removes an unredeemed authorization code during an issuance
// rollback. It lets the OAuth handler erase the bearer-delivery ciphertext
// when a later redirect-sink validation cannot complete. Missing rows are a
// harmless no-op.
func (s *SQLiteStore) DeleteAuthCode(ctx context.Context, code string) error {
	if code == "" {
		return nil
	}
	if _, err := s.writeExecContext(ctx,
		`DELETE FROM mcp_auth_codes WHERE code_sha256 = ?`, oauthCodeDigest(code)); err != nil {
		return fmt.Errorf("delete auth code: %w", err)
	}
	return nil
}

// RedeemAuthCode performs the OAuth /token half of the flow:
//  1. Look up the code (must exist, not used, not expired).
//  2. Confirm the redirect_uri provided at /token matches the one bound at /authorize.
//  3. Confirm SHA-256(code_verifier) base64url-no-pad equals the stored code_challenge.
//  4. Derive the delivery key from the raw code, decrypt the bearer, then
//     atomically mark the code used and wipe the delivery material.
//
// Returns the bearer plaintext on success.
func (s *SQLiteStore) RedeemAuthCode(
	ctx context.Context,
	code, codeVerifier, redirectURI, clientID string,
) (string, error) {
	if code == "" || codeVerifier == "" || redirectURI == "" || clientID == "" {
		return "", fmt.Errorf("code, code_verifier, redirect_uri, client_id are required")
	}

	// 1. Load the row by the digest of the raw code.
	codeDigest := oauthCodeDigest(code)
	row := s.conn.QueryRowContext(ctx, `
		SELECT token_id, code_challenge, code_challenge_method, redirect_uri, client_id,
		       expires_at, COALESCE(used_at, ''), COALESCE(delivery_sealed, X''),
		       COALESCE(delivery_salt, X''), COALESCE(delivery_seal, '')
		  FROM mcp_auth_codes
		 WHERE code_sha256 = ?`, codeDigest)

	var tokenID, codeChallenge, method, storedRedirect, storedClientID, expiresAtStr, usedAtStr, sealFormat string
	var sealed, salt []byte
	if scanErr := row.Scan(
		&tokenID, &codeChallenge, &method, &storedRedirect, &storedClientID,
		&expiresAtStr, &usedAtStr, &sealed, &salt, &sealFormat,
	); scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return "", ErrAuthCodeNotFound
		}
		return "", fmt.Errorf("load auth code: %w", scanErr)
	}

	if usedAtStr != "" {
		return "", ErrAuthCodeUsed
	}
	if expiresAt := parseTime(expiresAtStr); expiresAt.IsZero() || time.Now().UTC().After(expiresAt) {
		return "", ErrAuthCodeExpired
	}
	if storedRedirect != redirectURI {
		return "", ErrAuthCodeRedirectMismatch
	}
	if storedClientID != clientID {
		return "", ErrAuthCodeClientMismatch
	}

	// 2. PKCE verify: SHA-256(code_verifier) base64url-no-pad must equal stored.
	if strings.ToUpper(method) != "S256" {
		return "", ErrAuthCodeUnsupportedMethod
	}
	sum := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) != 1 {
		return "", ErrAuthCodePKCEMismatch
	}
	if sealFormat != oauthCodeDeliverySealV1 {
		return "", fmt.Errorf("unsupported oauth bearer delivery envelope %q", sealFormat)
	}
	bearer, err := openOAuthBearerForCode(
		code,
		salt,
		oauthCodeDeliveryAAD(
			tokenID, codeDigest, codeChallenge, method, storedRedirect, storedClientID,
		),
		sealed,
	)
	if err != nil {
		return "", err
	}

	// 3. Single-use mark — atomic. Also wipe all delivery material so the row
	// is harmless once redeemed.
	res, execErr := s.writeExecContext(ctx, `
		UPDATE mcp_auth_codes
		   SET used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
		       bearer_plaintext = NULL,
		       delivery_sealed = NULL,
		       delivery_salt = NULL
		 WHERE code_sha256 = ? AND client_id = ? AND redirect_uri = ?
		   AND used_at IS NULL
		   AND julianday(expires_at) > julianday('now')`, codeDigest, clientID, redirectURI)
	if execErr != nil {
		return "", fmt.Errorf("mark auth code used: %w", execErr)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// The UPDATE is the authority. This follow-up only distinguishes an
		// expiry-boundary loss from a concurrent successful claimant.
		var usedAt, expiresAt string
		checkErr := s.conn.QueryRowContext(ctx,
			`SELECT COALESCE(used_at, ''), expires_at FROM mcp_auth_codes WHERE code_sha256 = ?`,
			codeDigest,
		).Scan(&usedAt, &expiresAt)
		if errors.Is(checkErr, sql.ErrNoRows) {
			return "", ErrAuthCodeNotFound
		}
		if checkErr != nil {
			return "", fmt.Errorf("classify auth code claim: %w", checkErr)
		}
		if usedAt != "" {
			return "", ErrAuthCodeUsed
		}
		if expiry := parseTime(expiresAt); expiry.IsZero() || !expiry.After(time.Now().UTC()) {
			return "", ErrAuthCodeExpired
		}
		return "", ErrAuthCodeUsed
	}

	return bearer, nil
}

// PurgeExpiredAuthCodes atomically revokes the active bearer bound to every
// unredeemed expired code, then deletes expired code rows. The authorization
// code is the only delivery path for a freshly minted OAuth bearer, so expiry
// retires both sides rather than merely erasing the code.
func (s *SQLiteStore) PurgeExpiredAuthCodes(ctx context.Context) (int64, error) {
	tx, unlock, err := s.beginTxLocked(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin purge auth codes: %w", err)
	}
	defer unlock()
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `UPDATE mcp_tokens
		SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
		WHERE id IN (
			SELECT token_id FROM mcp_auth_codes
			WHERE used_at IS NULL AND julianday(expires_at) <= julianday('now')
		) AND revoked_at IS NULL`); err != nil {
		return 0, fmt.Errorf("revoke expired auth-code tokens: %w", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM mcp_auth_codes WHERE julianday(expires_at) <= julianday('now')`)
	if err != nil {
		return 0, fmt.Errorf("delete expired auth codes: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit purge auth codes: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
