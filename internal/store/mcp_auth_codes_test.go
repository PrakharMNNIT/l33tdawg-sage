package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newAuthCodeStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "auth_codes.db")
	s, err := NewSQLiteStore(context.Background(), dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// pkceChallenge produces the S256 code_challenge for the given verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestAuthCode_IssueRedeem_Happy(t *testing.T) {
	s := newAuthCodeStore(t)
	ctx := context.Background()

	verifier := "the-quick-brown-fox-jumps-over-the-lazy-dog-12345"
	challenge := pkceChallenge(verifier)
	require.NoError(t, s.IssueAuthCode(ctx,
		"code-1", "tok-1", challenge, "S256",
		"https://chat.openai.com/cb", "chatgpt", "state-abc",
		"BEARER-PLAINTEXT-1", 5*time.Minute))

	bearer, err := s.RedeemAuthCode(ctx, "code-1", verifier, "https://chat.openai.com/cb", "chatgpt")
	require.NoError(t, err)
	assert.Equal(t, "BEARER-PLAINTEXT-1", bearer)
}

func TestAuthCode_Redeem_SingleUse(t *testing.T) {
	s := newAuthCodeStore(t)
	ctx := context.Background()
	verifier := "another-verifier-of-sufficient-length-67890"
	challenge := pkceChallenge(verifier)
	require.NoError(t, s.IssueAuthCode(ctx,
		"code-2", "tok-2", challenge, "S256",
		"https://chat.openai.com/cb", "chatgpt", "", "BEARER-2", time.Minute))

	// First redeem succeeds.
	_, err := s.RedeemAuthCode(ctx, "code-2", verifier, "https://chat.openai.com/cb", "chatgpt")
	require.NoError(t, err)

	// Second redeem fails with ErrAuthCodeUsed.
	_, err = s.RedeemAuthCode(ctx, "code-2", verifier, "https://chat.openai.com/cb", "chatgpt")
	assert.True(t, errors.Is(err, ErrAuthCodeUsed), "expected ErrAuthCodeUsed, got %v", err)
}

func TestAuthCode_Redeem_PKCEMismatch(t *testing.T) {
	s := newAuthCodeStore(t)
	ctx := context.Background()
	correct := "correct-verifier-correct-verifier-12345"
	challenge := pkceChallenge(correct)
	require.NoError(t, s.IssueAuthCode(ctx,
		"code-3", "tok-3", challenge, "S256",
		"https://chat.openai.com/cb", "chatgpt", "", "BEARER-3", time.Minute))

	_, err := s.RedeemAuthCode(ctx, "code-3", "wrong-verifier-wrong-verifier-12345", "https://chat.openai.com/cb", "chatgpt")
	assert.True(t, errors.Is(err, ErrAuthCodePKCEMismatch), "expected PKCE mismatch, got %v", err)
}

func TestAuthCode_Redeem_RedirectMismatch(t *testing.T) {
	s := newAuthCodeStore(t)
	ctx := context.Background()
	verifier := "verifier-for-redirect-mismatch-test"
	challenge := pkceChallenge(verifier)
	require.NoError(t, s.IssueAuthCode(ctx,
		"code-4", "tok-4", challenge, "S256",
		"https://chat.openai.com/cb", "chatgpt", "", "BEARER-4", time.Minute))

	_, err := s.RedeemAuthCode(ctx, "code-4", verifier, "https://evil.example.com/cb", "chatgpt")
	assert.True(t, errors.Is(err, ErrAuthCodeRedirectMismatch), "expected redirect mismatch, got %v", err)
}

func TestAuthCode_Redeem_ClientMismatchPreservesCodeForBoundClient(t *testing.T) {
	s := newAuthCodeStore(t)
	ctx := context.Background()
	verifier := "verifier-for-client-binding-regression-12345"
	require.NoError(t, s.IssueAuthCode(ctx,
		"code-client", "tok-client", pkceChallenge(verifier), "S256",
		"https://chat.openai.com/cb", "client-a", "", "BEARER-CLIENT", time.Minute))

	_, err := s.RedeemAuthCode(ctx, "code-client", verifier, "https://chat.openai.com/cb", "client-b")
	require.ErrorIs(t, err, ErrAuthCodeClientMismatch)
	// A mismatch is not a claim: the client the code was issued to can still
	// redeem it, proving same-redirect public clients cannot steal each other.
	bearer, err := s.RedeemAuthCode(ctx, "code-client", verifier, "https://chat.openai.com/cb", "client-a")
	require.NoError(t, err)
	require.Equal(t, "BEARER-CLIENT", bearer)
}

func TestAuthCode_Redeem_Expired(t *testing.T) {
	s := newAuthCodeStore(t)
	ctx := context.Background()
	verifier := "verifier-for-expiry-test-expiry-test"
	challenge := pkceChallenge(verifier)

	// Issue with a 1ns TTL → already expired by the time redeem runs.
	require.NoError(t, s.IssueAuthCode(ctx,
		"code-5", "tok-5", challenge, "S256",
		"https://chat.openai.com/cb", "chatgpt", "", "BEARER-5", time.Nanosecond))

	time.Sleep(2 * time.Millisecond)

	_, err := s.RedeemAuthCode(ctx, "code-5", verifier, "https://chat.openai.com/cb", "chatgpt")
	assert.True(t, errors.Is(err, ErrAuthCodeExpired), "expected expired, got %v", err)
}

func TestAuthCode_Redeem_NotFound(t *testing.T) {
	s := newAuthCodeStore(t)
	_, err := s.RedeemAuthCode(context.Background(), "ghost", "v", "https://x/cb", "chatgpt")
	assert.True(t, errors.Is(err, ErrAuthCodeNotFound), "expected not-found, got %v", err)
}

func TestAuthCode_Issue_RejectsUnsupportedMethod(t *testing.T) {
	s := newAuthCodeStore(t)
	err := s.IssueAuthCode(context.Background(),
		"code-6", "tok-6", "challenge", "plain", // <-- not S256
		"https://chat.openai.com/cb", "chatgpt", "", "BEARER-6", time.Minute)
	assert.True(t, errors.Is(err, ErrAuthCodeUnsupportedMethod), "expected unsupported method, got %v", err)
}

func TestAuthCode_Issue_RequiredFields(t *testing.T) {
	s := newAuthCodeStore(t)
	ctx := context.Background()
	cases := []struct {
		name                                       string
		code, tokenID, challenge, redirect, bearer string
	}{
		{"empty code", "", "tok", "ch", "https://x/cb", "b"},
		{"empty token_id", "c", "", "ch", "https://x/cb", "b"},
		{"empty challenge", "c", "tok", "", "https://x/cb", "b"},
		{"empty redirect", "c", "tok", "ch", "", "b"},
		{"empty bearer", "c", "tok", "ch", "https://x/cb", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.IssueAuthCode(ctx,
				tc.code, tc.tokenID, tc.challenge, "S256",
				tc.redirect, "chatgpt", "", tc.bearer, time.Minute)
			assert.Error(t, err)
		})
	}
}

func TestAuthCode_Purge(t *testing.T) {
	s := newAuthCodeStore(t)
	ctx := context.Background()

	// The OAuth issuer's token is active before the code expires; purge must
	// retire it atomically with the abandoned authorization code.
	require.NoError(t, s.InsertMCPToken(ctx, "tok-p", "purge", "operator", mkDigest("BEARER-P")))
	require.NoError(t, s.IssueAuthCode(ctx,
		"code-purge", "tok-p", pkceChallenge("v"), "S256",
		"https://x/cb", "chatgpt", "", "BEARER-P", time.Nanosecond))
	time.Sleep(2 * time.Millisecond)

	n, err := s.PurgeExpiredAuthCodes(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	// Purged → not found.
	_, err = s.RedeemAuthCode(ctx, "code-purge", "v", "https://x/cb", "chatgpt")
	assert.True(t, errors.Is(err, ErrAuthCodeNotFound))
	_, err = s.LookupMCPToken(ctx, mkDigest("BEARER-P"))
	assert.True(t, errors.Is(err, ErrTokenRevoked), "expired unredeemed code must revoke its bearer")
}

func TestAuthCode_BearerWipedAfterRedeem(t *testing.T) {
	s := newAuthCodeStore(t)
	ctx := context.Background()
	verifier := "verifier-for-bearer-wipe-test-zzzzzz"
	challenge := pkceChallenge(verifier)
	require.NoError(t, s.IssueAuthCode(ctx,
		"code-w", "tok-w", challenge, "S256",
		"https://chat.openai.com/cb", "chatgpt", "", "BEARER-W", time.Minute))

	_, err := s.RedeemAuthCode(ctx, "code-w", verifier, "https://chat.openai.com/cb", "chatgpt")
	require.NoError(t, err)

	// Inspect the row directly — both the obsolete plaintext column and the
	// encrypted delivery material should be wiped after redeem.
	row := s.conn.QueryRowContext(ctx,
		`SELECT COALESCE(bearer_plaintext, '<NULL>'), COALESCE(used_at, ''),
		        length(COALESCE(delivery_sealed, X'')), length(COALESCE(delivery_salt, X''))
		   FROM mcp_auth_codes WHERE code_sha256 = ?`,
		oauthCodeDigest("code-w"))
	var bearer, usedAt string
	var sealedLen, saltLen int
	require.NoError(t, row.Scan(&bearer, &usedAt, &sealedLen, &saltLen))
	assert.Equal(t, "<NULL>", bearer, "bearer plaintext should be wiped after redeem")
	assert.NotEmpty(t, usedAt, "used_at should be set after redeem")
	assert.Zero(t, sealedLen, "delivery ciphertext should be wiped after redeem")
	assert.Zero(t, saltLen, "delivery salt should be wiped after redeem")
}

func TestAuthCode_DatabaseHoldsNeitherRawCodeNorBearer(t *testing.T) {
	s := newAuthCodeStore(t)
	ctx := context.Background()
	code := "RAW-AUTHORIZATION-CODE-NEVER-PERSIST"
	bearer := "RAW-BEARER-NEVER-PERSIST"
	verifier := "database-compromise-verifier-aaaaaaaaaaaa"
	challenge := pkceChallenge(verifier)
	require.NoError(t, s.IssueAuthCode(
		ctx, code, "tok-sealed", challenge, "S256",
		"https://chat.openai.com/cb", "chatgpt", "", bearer, time.Minute,
	))

	var storedCode, storedDigest, storedBearer, sealFormat string
	var sealed, salt []byte
	require.NoError(t, s.conn.QueryRowContext(ctx, `
		SELECT code, code_sha256, COALESCE(bearer_plaintext, ''),
		       delivery_sealed, delivery_salt, delivery_seal
		  FROM mcp_auth_codes WHERE code_sha256 = ?`,
		oauthCodeDigest(code),
	).Scan(&storedCode, &storedDigest, &storedBearer, &sealed, &salt, &sealFormat))
	require.Equal(t, oauthCodeDigest(code), storedCode)
	require.Equal(t, oauthCodeDigest(code), storedDigest)
	require.Empty(t, storedBearer)
	require.Equal(t, oauthCodeDeliverySealV1, sealFormat)
	require.NotEmpty(t, sealed)
	require.Len(t, salt, oauthCodeDeliverySaltSize)
	require.NotContains(t, string(sealed), bearer)

	// A database attacker has the digest, salt, AAD fields, and ciphertext,
	// but substituting the stored digest for the absent raw code cannot derive
	// the delivery key.
	_, err := openOAuthBearerForCode(
		storedDigest,
		salt,
		oauthCodeDeliveryAAD(
			"tok-sealed", storedDigest, challenge, "S256",
			"https://chat.openai.com/cb", "chatgpt",
		),
		sealed,
	)
	require.Error(t, err)
}

func TestAuthCode_RestartRedemptionUsesRawCode(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "restart.db")
	s, err := NewSQLiteStore(ctx, dbPath)
	require.NoError(t, err)
	code := "restart-code-secret"
	verifier := "restart-verifier-aaaaaaaaaaaaaaaaaaaa"
	require.NoError(t, s.IssueAuthCode(
		ctx, code, "tok-restart", pkceChallenge(verifier), "S256",
		"https://chat.openai.com/cb", "chatgpt", "", "BEARER-RESTART", time.Minute,
	))
	require.NoError(t, s.Close())

	reopened, err := NewSQLiteStore(ctx, dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	bearer, err := reopened.RedeemAuthCode(
		ctx, code, verifier, "https://chat.openai.com/cb", "chatgpt",
	)
	require.NoError(t, err)
	require.Equal(t, "BEARER-RESTART", bearer)

	_, err = reopened.RedeemAuthCode(
		ctx, oauthCodeDigest(code), verifier, "https://chat.openai.com/cb", "chatgpt",
	)
	require.ErrorIs(t, err, ErrAuthCodeNotFound,
		"the stored digest must not substitute for the raw authorization code")
}

func TestAuthCode_ConcurrentRedeemHasOneWinner(t *testing.T) {
	s := newAuthCodeStore(t)
	ctx := context.Background()
	code := "concurrent-code"
	verifier := "concurrent-verifier-aaaaaaaaaaaaaaaaa"
	require.NoError(t, s.IssueAuthCode(
		ctx, code, "tok-concurrent", pkceChallenge(verifier), "S256",
		"https://chat.openai.com/cb", "chatgpt", "", "BEARER-CONCURRENT", time.Minute,
	))

	type result struct {
		bearer string
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			bearer, err := s.RedeemAuthCode(
				ctx, code, verifier, "https://chat.openai.com/cb", "chatgpt",
			)
			results <- result{bearer: bearer, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var successes, used int
	for got := range results {
		switch {
		case got.err == nil:
			successes++
			require.Equal(t, "BEARER-CONCURRENT", got.bearer)
		case errors.Is(got.err, ErrAuthCodeUsed):
			used++
		default:
			require.NoError(t, got.err)
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, used)
}

func TestAuthCode_MigrationRevokesAndErasesLegacyPlaintextRows(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	s, err := NewSQLiteStore(ctx, dbPath)
	require.NoError(t, err)
	require.NoError(t, s.InsertMCPToken(ctx, "tok-legacy-code", "legacy", "operator", mkDigest("LEGACY-BEARER")))
	_, err = s.writeExecContext(ctx, `
		INSERT INTO mcp_auth_codes (
			code, code_sha256, token_id, code_challenge, code_challenge_method,
			redirect_uri, client_id, expires_at, bearer_plaintext
		) VALUES (?, NULL, ?, ?, 'S256', ?, ?, ?, ?)`,
		"RAW-LEGACY-CODE", "tok-legacy-code", pkceChallenge("legacy-verifier"),
		"https://chat.openai.com/cb", "chatgpt",
		time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), "LEGACY-BEARER",
	)
	require.NoError(t, err)
	require.NoError(t, s.Close())

	reopened, err := NewSQLiteStore(ctx, dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	var count int
	require.NoError(t, reopened.conn.QueryRowContext(
		ctx, `SELECT COUNT(*) FROM mcp_auth_codes WHERE token_id = ?`, "tok-legacy-code",
	).Scan(&count))
	require.Zero(t, count)
	_, err = reopened.LookupMCPToken(ctx, mkDigest("LEGACY-BEARER"))
	require.ErrorIs(t, err, ErrTokenRevoked)
}
