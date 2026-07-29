package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"database/sql"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/vault"
)

func newTokenStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "tokens.db")
	s, err := NewSQLiteStore(context.Background(), dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestMCPTokenMigrationFailsStartupOnSchemaDDLFailure(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "malformed-token-schema.db")
	raw, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	_, err = raw.ExecContext(ctx, `CREATE TABLE mcp_tokens (id TEXT PRIMARY KEY)`)
	require.NoError(t, err)
	require.NoError(t, raw.Close())

	reopened, err := NewSQLiteStore(ctx, dbPath)
	require.Nil(t, reopened)
	require.ErrorContains(t, err, "migrate MCP tokens")
	require.ErrorContains(t, err, "no such column: agent_id")
}

func attachTokenVault(t *testing.T, s *SQLiteStore) {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "vault.key")
	require.NoError(t, vault.Init(keyPath, "test-passphrase"))
	v, err := vault.Open(keyPath, "test-passphrase")
	require.NoError(t, err)
	s.SetVault(v)
}

func mkDigest(token string) string {
	d := sha256.Sum256([]byte(token))
	return hex.EncodeToString(d[:])
}

func TestMCPTokens_InsertAndLookup(t *testing.T) {
	s := newTokenStore(t)
	ctx := context.Background()

	digest := mkDigest("plaintext-token-1")
	require.NoError(t, s.InsertMCPToken(ctx, "tok-1", "chatgpt", "agent-aaa", digest))

	tok, err := s.LookupMCPToken(ctx, digest)
	require.NoError(t, err)
	assert.Equal(t, "tok-1", tok.ID)
	assert.Equal(t, "chatgpt", tok.Name)
	assert.Equal(t, "agent-aaa", tok.AgentID)
	assert.False(t, tok.CreatedAt.IsZero())
}

func TestMCPTokens_Lookup_NoRows(t *testing.T) {
	s := newTokenStore(t)
	_, err := s.LookupMCPToken(context.Background(), mkDigest("missing"))
	assert.True(t, errors.Is(err, sql.ErrNoRows))
}

func TestMCPTokens_Revoke(t *testing.T) {
	s := newTokenStore(t)
	ctx := context.Background()

	digest := mkDigest("plaintext-token-2")
	require.NoError(t, s.InsertMCPToken(ctx, "tok-2", "cursor", "agent-bbb", digest))
	require.NoError(t, s.RevokeMCPToken(ctx, "tok-2"))

	// Lookup should now report ErrTokenRevoked.
	tok, err := s.LookupMCPToken(ctx, digest)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTokenRevoked))
	require.NotNil(t, tok)
	assert.False(t, tok.RevokedAt.IsZero())
}

func TestMCPTokens_Revoke_Idempotent(t *testing.T) {
	s := newTokenStore(t)
	ctx := context.Background()

	digest := mkDigest("plaintext-token-3")
	require.NoError(t, s.InsertMCPToken(ctx, "tok-3", "", "agent-ccc", digest))
	require.NoError(t, s.RevokeMCPToken(ctx, "tok-3"))
	// Second revoke should not error (idempotent — token still exists, just stays revoked).
	require.NoError(t, s.RevokeMCPToken(ctx, "tok-3"))
}

func TestMCPTokens_Revoke_Missing(t *testing.T) {
	s := newTokenStore(t)
	err := s.RevokeMCPToken(context.Background(), "does-not-exist")
	assert.True(t, errors.Is(err, sql.ErrNoRows))
}

func TestMCPTokens_List(t *testing.T) {
	s := newTokenStore(t)
	ctx := context.Background()

	require.NoError(t, s.InsertMCPToken(ctx, "id-a", "a", "agent-1", mkDigest("ta")))
	require.NoError(t, s.InsertMCPToken(ctx, "id-b", "b", "agent-2", mkDigest("tb")))
	require.NoError(t, s.InsertMCPToken(ctx, "id-c", "c", "agent-1", mkDigest("tc")))
	require.NoError(t, s.RevokeMCPToken(ctx, "id-b"))

	rows, err := s.ListMCPTokens(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 3)

	revoked := 0
	for _, r := range rows {
		if !r.RevokedAt.IsZero() {
			revoked++
			assert.Equal(t, "id-b", r.ID)
		}
	}
	assert.Equal(t, 1, revoked)
}

func TestMCPTokens_DigestUnique(t *testing.T) {
	s := newTokenStore(t)
	ctx := context.Background()

	digest := mkDigest("dupe-token")
	require.NoError(t, s.InsertMCPToken(ctx, "id-1", "n1", "agent-1", digest))
	err := s.InsertMCPToken(ctx, "id-2", "n2", "agent-2", digest)
	require.Error(t, err) // UNIQUE constraint on token_sha256
}

func TestMCPTokens_LookupBumpsLastUsed(t *testing.T) {
	s := newTokenStore(t)
	ctx := context.Background()

	digest := mkDigest("track-me")
	require.NoError(t, s.InsertMCPToken(ctx, "id-track", "tracked", "agent-x", digest))

	first, err := s.LookupMCPToken(ctx, digest)
	require.NoError(t, err)
	// First lookup may or may not have last_used set yet (write happens after read);
	// list view shows it next time.
	_ = first

	rows, err := s.ListMCPTokens(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.False(t, rows[0].LastUsedAt.IsZero(), "last_used_at should be set after lookup")
}

func TestMCPTokenIssue_KeyedConfirmedAndOwnedByIssuer(t *testing.T) {
	s := newTokenStore(t)
	attachTokenVault(t, s)
	issuer := strings.Repeat("a", 64)
	s.SetMCPTokenIdentityRegistrar(func(_ context.Context, pub ed25519.PublicKey, priv ed25519.PrivateKey, _, _ string) error {
		require.True(t, ed25519.PrivateKey(priv).Public().(ed25519.PublicKey).Equal(pub))
		return nil
	})
	t.Cleanup(func() { s.SetMCPTokenIdentityRegistrar(nil) })

	issued, err := s.IssueMCPToken(context.Background(), "oauth", issuer, issuer, "test")
	require.NoError(t, err)
	require.NotEqual(t, issuer, issued.AgentID, "keyed token must act as its own identity")

	rows, err := s.ListMCPTokens(context.Background())
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, issuer, rows[0].IssuerID)
	require.Equal(t, issued.AgentID, rows[0].AgentID)

	digest := mkDigest(issued.Token)
	gotID, signer, err := s.LookupMCPTokenSigner(context.Background(), digest)
	require.NoError(t, err)
	require.Equal(t, issued.AgentID, gotID)
	require.Equal(t, issued.AgentID, hex.EncodeToString(signer.Public().(ed25519.PublicKey)))
}

func TestMCPTokenIssue_LockedExpectedVaultNeverFallsBackToOperator(t *testing.T) {
	s := newTokenStore(t)
	s.SetVaultExpected(true)
	issued, err := s.IssueMCPToken(context.Background(), "locked", "issuer", "operator", "test")
	require.Nil(t, issued)
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault is locked")
	rows, listErr := s.ListMCPTokens(context.Background())
	require.NoError(t, listErr)
	require.Empty(t, rows)
}

func TestMCPTokenIssue_LegacyTokenPreservesDistinctIssuer(t *testing.T) {
	s := newTokenStore(t)
	issued, err := s.IssueMCPToken(context.Background(), "legacy", "operator-owner", "operator-actor", "test")
	require.NoError(t, err)
	require.Equal(t, "operator-actor", issued.AgentID)
	require.Equal(t, "operator-owner", issued.IssuerID)
	rows, err := s.ListMCPTokens(context.Background())
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "operator-owner", rows[0].IssuerID)
}

func TestAppV23MCPTokenPolicyMintsBearerSealedIdentityWithoutVault(t *testing.T) {
	s := newTokenStore(t)
	s.SetMCPTokenKeyedIdentityRequirement(func() bool { return true })
	t.Cleanup(func() { s.SetMCPTokenKeyedIdentityRequirement(nil) })
	var registeredID string
	s.SetMCPTokenIdentityRegistrar(func(
		_ context.Context,
		pub ed25519.PublicKey,
		_ ed25519.PrivateKey,
		_, _ string,
	) error {
		registeredID = hex.EncodeToString(pub)
		return nil
	})
	t.Cleanup(func() { s.SetMCPTokenIdentityRegistrar(nil) })

	issued, err := s.IssueMCPToken(
		context.Background(), "must-be-keyed", "root-principal", "root-credential", "test",
	)
	require.NoError(t, err)
	require.NotNil(t, issued)
	require.Equal(t, issued.AgentID, registeredID)
	require.NotEqual(t, "root-principal", issued.AgentID)
	require.NotEqual(t, "root-credential", issued.AgentID)

	rows, listErr := s.ListMCPTokens(context.Background())
	require.NoError(t, listErr)
	require.Len(t, rows, 1)

	agentID, signer, lookupErr := s.LookupMCPTokenSignerWithBearer(
		context.Background(), issued.Token, mkDigest(issued.Token),
	)
	require.NoError(t, lookupErr)
	require.Equal(t, issued.AgentID, agentID)
	require.Equal(t, issued.AgentID, hex.EncodeToString(signer.Public().(ed25519.PublicKey)))

	_, _, lookupErr = s.LookupMCPTokenSigner(context.Background(), mkDigest(issued.Token))
	require.ErrorContains(t, lookupErr, "bearer does not unlock",
		"the database digest alone must not decrypt an unencrypted-node token identity")
}

func TestAppV23BearerSealedIdentitySurvivesRestartAndDBDigestCannotDecrypt(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "bearer-envelope-restart.db")
	s, err := NewSQLiteStore(ctx, dbPath)
	require.NoError(t, err)
	s.SetMCPTokenKeyedIdentityRequirement(func() bool { return true })
	s.SetMCPTokenIdentityRegistrar(func(
		context.Context,
		ed25519.PublicKey,
		ed25519.PrivateKey,
		string,
		string,
	) error {
		return nil
	})
	issued, err := s.IssueMCPToken(ctx, "restart", "current-root", "current-root", "test")
	require.NoError(t, err)
	digest := mkDigest(issued.Token)

	var id, pubHex, storedDigest, sealKind string
	var salt, sealed []byte
	require.NoError(t, s.conn.QueryRowContext(ctx, `
		SELECT id, token_pubkey, token_sha256, token_privkey_seal,
		       token_privkey_salt, token_privkey_sealed
		  FROM mcp_tokens WHERE token_sha256 = ?`, digest,
	).Scan(&id, &pubHex, &storedDigest, &sealKind, &salt, &sealed))
	require.Equal(t, mcpTokenPrivateKeySealBearerV1, sealKind)
	require.Len(t, salt, mcpTokenBearerSealSaltSize)
	require.NotContains(t, string(sealed), issued.Token)
	_, err = openMCPTokenPrivateKeyWithBearer(
		storedDigest,
		salt,
		mcpTokenPrivateKeyAAD(id, pubHex, storedDigest),
		sealed,
	)
	require.Error(t, err, "the SHA-256 value stored in SQLite is not an envelope key")

	s.SetMCPTokenIdentityRegistrar(nil)
	s.SetMCPTokenKeyedIdentityRequirement(nil)
	require.NoError(t, s.Close())

	reopened, err := NewSQLiteStore(ctx, dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	reopened.SetMCPTokenKeyedIdentityRequirement(func() bool { return true })
	t.Cleanup(func() { reopened.SetMCPTokenKeyedIdentityRequirement(nil) })

	agentID, signer, err := reopened.LookupMCPTokenSignerWithBearer(ctx, issued.Token, digest)
	require.NoError(t, err)
	require.Equal(t, issued.AgentID, agentID)
	require.Equal(t, issued.AgentID, hex.EncodeToString(signer.Public().(ed25519.PublicKey)))

	_, _, err = reopened.LookupMCPTokenSignerWithBearer(ctx, "wrong-bearer", digest)
	require.ErrorContains(t, err, "bearer does not unlock")
}

func TestMCPTokenSealTransitionsAcrossLedgerToggleLockAndRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "seal-transitions.db")
	keyPath := filepath.Join(dir, "vault.key")
	require.NoError(t, vault.Init(keyPath, "transition-passphrase"))
	unlocked, err := vault.Open(keyPath, "transition-passphrase")
	require.NoError(t, err)

	s, err := NewSQLiteStore(ctx, dbPath)
	require.NoError(t, err)
	s.SetVault(unlocked)
	s.SetVaultExpected(true)
	s.SetMCPTokenIdentityRegistrar(func(
		context.Context,
		ed25519.PublicKey,
		ed25519.PrivateKey,
		string,
		string,
	) error {
		return nil
	})
	// A pre-v23/vault-active row uses the historical vault-v1 envelope.
	issued, err := s.IssueMCPToken(ctx, "legacy-vault", "issuer", "operator", "test")
	require.NoError(t, err)
	digest := mkDigest(issued.Token)
	var sealKind string
	require.NoError(t, s.conn.QueryRowContext(ctx,
		`SELECT token_privkey_seal FROM mcp_tokens WHERE id = ?`, issued.ID,
	).Scan(&sealKind))
	require.Equal(t, mcpTokenPrivateKeySealVaultV1, sealKind)
	s.SetMCPTokenIdentityRegistrar(nil)
	require.NoError(t, s.Close())

	// A restart while the ledger is locked cannot decrypt the old vault row,
	// but it fails closed rather than falling back to Root.
	reopened, err := NewSQLiteStore(ctx, dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	reopened.SetVaultExpected(true)
	reopened.SetMCPTokenKeyedIdentityRequirement(func() bool { return true })
	t.Cleanup(func() { reopened.SetMCPTokenKeyedIdentityRequirement(nil) })
	_, _, err = reopened.LookupMCPTokenSignerWithBearer(ctx, issued.Token, digest)
	require.ErrorContains(t, err, "vault is locked")

	// Unlocking permits the old row once and atomically rewraps it under the
	// bearer. It then remains usable if optional ledger encryption is disabled
	// or locked later.
	reopened.SetVault(unlocked)
	agentID, signer, err := reopened.LookupMCPTokenSignerWithBearer(ctx, issued.Token, digest)
	require.NoError(t, err)
	require.Equal(t, issued.AgentID, agentID)
	require.Equal(t, issued.AgentID, hex.EncodeToString(signer.Public().(ed25519.PublicKey)))
	require.NoError(t, reopened.conn.QueryRowContext(ctx,
		`SELECT token_privkey_seal FROM mcp_tokens WHERE id = ?`, issued.ID,
	).Scan(&sealKind))
	require.Equal(t, mcpTokenPrivateKeySealBearerV1, sealKind)

	reopened.SetVault(nil)
	agentID, signer, err = reopened.LookupMCPTokenSignerWithBearer(ctx, issued.Token, digest)
	require.NoError(t, err)
	require.Equal(t, issued.AgentID, agentID)
	require.Len(t, signer, ed25519.PrivateKeySize)
}

func TestMCPTokenBearerSealSurvivesLedgerEnableAndPassphraseChange(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bearer-to-vault.db")
	keyPath := filepath.Join(dir, "vault.key")
	s, err := NewSQLiteStore(ctx, dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	s.SetMCPTokenKeyedIdentityRequirement(func() bool { return true })
	t.Cleanup(func() { s.SetMCPTokenKeyedIdentityRequirement(nil) })
	s.SetMCPTokenIdentityRegistrar(func(
		context.Context,
		ed25519.PublicKey,
		ed25519.PrivateKey,
		string,
		string,
	) error {
		return nil
	})
	t.Cleanup(func() { s.SetMCPTokenIdentityRegistrar(nil) })
	issued, err := s.IssueMCPToken(ctx, "bearer-first", "issuer", "operator", "test")
	require.NoError(t, err)
	digest := mkDigest(issued.Token)

	require.NoError(t, vault.Init(keyPath, "old-passphrase"))
	v, err := vault.Open(keyPath, "old-passphrase")
	require.NoError(t, err)
	s.SetVaultExpected(true)
	s.SetVault(v)
	_, signer, err := s.LookupMCPTokenSignerWithBearer(ctx, issued.Token, digest)
	require.NoError(t, err, "enabling the ledger must not change a bearer-v1 credential")
	require.Len(t, signer, ed25519.PrivateKeySize)

	require.NoError(t, vault.ChangePassphrase(keyPath, "old-passphrase", "new-passphrase"))
	changed, err := vault.Open(keyPath, "new-passphrase")
	require.NoError(t, err)
	s.SetVault(changed)
	_, signer, err = s.LookupMCPTokenSignerWithBearer(ctx, issued.Token, digest)
	require.NoError(t, err, "passphrase changes must not change a bearer-v1 credential")
	require.Len(t, signer, ed25519.PrivateKeySize)
}

func TestMCPTokenMigrationInfersOldVaultSealRows(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "old-seal-row.db")
	keyPath := filepath.Join(dir, "vault.key")
	require.NoError(t, vault.Init(keyPath, "old-row-passphrase"))
	v, err := vault.Open(keyPath, "old-row-passphrase")
	require.NoError(t, err)
	s, err := NewSQLiteStore(ctx, dbPath)
	require.NoError(t, err)
	s.SetVault(v)
	s.SetMCPTokenIdentityRegistrar(func(
		context.Context,
		ed25519.PublicKey,
		ed25519.PrivateKey,
		string,
		string,
	) error {
		return nil
	})
	issued, err := s.IssueMCPToken(ctx, "old-row", "issuer", "operator", "test")
	require.NoError(t, err)
	_, err = s.writeExecContext(ctx,
		`UPDATE mcp_tokens SET token_privkey_seal = '' WHERE id = ?`, issued.ID)
	require.NoError(t, err)
	s.SetMCPTokenIdentityRegistrar(nil)
	require.NoError(t, s.Close())

	reopened, err := NewSQLiteStore(ctx, dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	reopened.SetVault(v)
	var sealKind string
	require.NoError(t, reopened.conn.QueryRowContext(ctx,
		`SELECT token_privkey_seal FROM mcp_tokens WHERE id = ?`, issued.ID,
	).Scan(&sealKind))
	require.Equal(t, mcpTokenPrivateKeySealVaultV1, sealKind)
	_, signer, err := reopened.LookupMCPTokenSignerWithBearer(
		ctx, issued.Token, mkDigest(issued.Token),
	)
	require.NoError(t, err)
	require.Len(t, signer, ed25519.PrivateKeySize)
}

func TestAppV23LegacyMCPBearerActivationRevokesDurablyAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "activation-reopen.db")
	s, err := NewSQLiteStore(ctx, dbPath)
	require.NoError(t, err)

	const (
		token   = "pre-v23-root-fallback-bearer"
		tokenID = "legacy-root-token"
	)
	digest := mkDigest(token)
	require.NoError(t, s.InsertMCPToken(ctx, tokenID, "legacy", "root-credential", digest))
	require.NoError(t, s.IssueAuthCode(
		ctx,
		"legacy-root-auth-code",
		tokenID,
		"challenge-value",
		"S256",
		"https://client.example/callback",
		"client",
		"",
		token,
		time.Minute,
	))

	active := false
	s.SetMCPTokenKeyedIdentityRequirement(func() bool { return active })
	agentID, signer, err := s.LookupMCPTokenSigner(ctx, digest)
	require.NoError(t, err, "pre-v23 keyless fallback remains compatible")
	require.Equal(t, "root-credential", agentID)
	require.Nil(t, signer)

	active = true
	_, _, err = s.LookupMCPTokenSigner(ctx, digest)
	require.ErrorIs(t, err, ErrTokenLegacyDisabled,
		"the activation edge must fail closed before durable reconciliation")

	revoked, err := s.RevokeAppV23LegacyMCPBearers(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, revoked)
	_, redeemErr := s.RedeemAuthCode(
		ctx,
		"legacy-root-auth-code",
		"verifier",
		"https://client.example/callback",
		"client",
	)
	require.Error(t, redeemErr, "outstanding OAuth delivery must be removed with the bearer")
	require.NoError(t, s.Close())
	s.SetMCPTokenKeyedIdentityRequirement(nil)

	reopened, err := NewSQLiteStore(ctx, dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	reopened.SetMCPTokenKeyedIdentityRequirement(func() bool { return true })
	t.Cleanup(func() { reopened.SetMCPTokenKeyedIdentityRequirement(nil) })
	_, _, err = reopened.LookupMCPTokenSigner(ctx, digest)
	require.ErrorIs(t, err, ErrTokenRevoked,
		"app-v23 revocation must survive process restart")
}

func TestAppV23MCPTokenPolicyKeepsDistinctKeyedIdentity(t *testing.T) {
	s := newTokenStore(t)
	attachTokenVault(t, s)
	s.SetMCPTokenKeyedIdentityRequirement(func() bool { return true })
	t.Cleanup(func() { s.SetMCPTokenKeyedIdentityRequirement(nil) })
	s.SetMCPTokenIdentityRegistrar(func(
		_ context.Context,
		_ ed25519.PublicKey,
		_ ed25519.PrivateKey,
		_, _ string,
	) error {
		return nil
	})
	t.Cleanup(func() { s.SetMCPTokenIdentityRegistrar(nil) })

	issued, err := s.IssueMCPToken(
		context.Background(), "keyed", "root-principal", "root-credential", "test",
	)
	require.NoError(t, err)
	require.NotNil(t, issued)
	require.NotEqual(t, "root-principal", issued.AgentID)
	require.NotEqual(t, "root-credential", issued.AgentID)

	agentID, signer, err := s.LookupMCPTokenSignerWithBearer(
		context.Background(), issued.Token, mkDigest(issued.Token),
	)
	require.NoError(t, err)
	require.Equal(t, issued.AgentID, agentID)
	require.Len(t, signer, ed25519.PrivateKeySize)
}

func TestPendingMCPTokenCannotAuthenticateUntilActivatedOrCleanupPurges(t *testing.T) {
	s := newTokenStore(t)
	issued, err := s.IssuePendingMCPToken(context.Background(), "oauth", "issuer", "operator", "oauth-mcp-token")
	require.NoError(t, err)
	digest := mkDigest(issued.Token)
	_, _, err = s.LookupMCPTokenSigner(context.Background(), digest)
	require.ErrorIs(t, err, ErrTokenIssuancePending)

	require.NoError(t, s.ActivatePendingMCPToken(context.Background(), issued.ID))
	got, _, err := s.LookupMCPTokenSigner(context.Background(), digest)
	require.NoError(t, err)
	require.Equal(t, "operator", got)

	pending, err := s.IssuePendingMCPToken(context.Background(), "orphan", "issuer", "operator", "oauth-mcp-token")
	require.NoError(t, err)
	n, err := s.PurgeMCPTokenCleanup(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	_, err = s.LookupMCPToken(context.Background(), mkDigest(pending.Token))
	require.ErrorIs(t, err, ErrTokenRevoked)
}

func TestMCPTokenIssue_KnownRegistrationFinalizesAfterRequestCancellation(t *testing.T) {
	s := newTokenStore(t)
	attachTokenVault(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.SetMCPTokenIdentityRegistrar(func(_ context.Context, _ ed25519.PublicKey, _ ed25519.PrivateKey, _, _ string) error {
		// Simulate a caller disconnecting after CometBFT has definitively replied
		// success but before the local pending-state write begins.
		cancel()
		return nil
	})
	t.Cleanup(func() { s.SetMCPTokenIdentityRegistrar(nil) })

	issued, err := s.IssueMCPToken(ctx, "known-success", "issuer", "operator", "test")
	require.NoError(t, err)
	_, _, err = s.LookupMCPTokenSigner(context.Background(), mkDigest(issued.Token))
	require.NoError(t, err, "local confirmation must not inherit the canceled request context")
}

func TestMCPTokenMigration_PreexistingKeyedRowsFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre-registration-state.db")
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE mcp_tokens (
		id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', agent_id TEXT NOT NULL,
		token_sha256 TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,
		last_used_at TEXT, revoked_at TEXT, token_pubkey TEXT, token_privkey_sealed BLOB
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO mcp_tokens
		(id,name,agent_id,token_sha256,created_at,token_pubkey,token_privkey_sealed)
		VALUES ('legacy','legacy','operator','digest-legacy','2026-01-01T00:00:00Z',NULL,NULL),
		       ('keyed','keyed',?,'digest-keyed','2026-01-01T00:00:00Z',?,x'01')`,
		strings.Repeat("a", 64), strings.Repeat("a", 64))
	require.NoError(t, err)
	require.NoError(t, db.Close())

	s, err := NewSQLiteStore(context.Background(), path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	states := map[string]string{}
	rows, err := s.conn.QueryContext(context.Background(), `SELECT id, registration_state FROM mcp_tokens`)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var id, state string
		require.NoError(t, rows.Scan(&id, &state))
		states[id] = state
	}
	require.NoError(t, rows.Err())
	require.Equal(t, "confirmed", states["legacy"])
	require.Equal(t, "pending", states["keyed"], "old keyed issuance had no durable confirmation proof")
}

func TestMCPTokenSigner_PendingRegistrationCannotAuthenticate(t *testing.T) {
	s := newTokenStore(t)
	attachTokenVault(t, s)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	agentID := hex.EncodeToString(pub)
	digest := mkDigest("pending")
	require.NoError(t, s.insertMCPTokenWithIdentity(context.Background(), "pending-id", "pending", agentID, "issuer", digest, agentID, priv, "test", false))

	_, _, err = s.LookupMCPTokenSigner(context.Background(), digest)
	require.ErrorIs(t, err, ErrTokenIdentityPending)
}

func TestMCPTokenSigner_PartialKeyStateNeverFallsBackToOperator(t *testing.T) {
	s := newTokenStore(t)
	require.NoError(t, s.InsertMCPToken(context.Background(), "partial", "partial", "operator", mkDigest("partial")))
	_, err := s.writeExecContext(context.Background(), `UPDATE mcp_tokens SET token_pubkey = ? WHERE id = 'partial'`, strings.Repeat("b", 64))
	require.NoError(t, err)

	_, signer, err := s.LookupMCPTokenSigner(context.Background(), mkDigest("partial"))
	require.Error(t, err)
	require.Nil(t, signer)
	require.Contains(t, err.Error(), "incomplete signing key state")
}

func TestMCPTokenSigner_CorruptIdentityBindingFailsClosed(t *testing.T) {
	s := newTokenStore(t)
	attachTokenVault(t, s)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	agentID := hex.EncodeToString(pub)
	digest := mkDigest("corrupt-binding")
	require.NoError(t, s.insertMCPTokenWithIdentity(context.Background(), "corrupt", "corrupt", agentID, "issuer", digest, agentID, priv, "test", false))
	_, err = s.writeExecContext(context.Background(), `UPDATE mcp_tokens SET registration_state = 'confirmed', agent_id = ? WHERE id = 'corrupt'`, strings.Repeat("c", 64))
	require.NoError(t, err)

	_, _, err = s.LookupMCPTokenSigner(context.Background(), digest)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match")
}

func TestMCPTokenIssue_AmbiguousRegistrationRemainsPendingUntilReconciled(t *testing.T) {
	s := newTokenStore(t)
	attachTokenVault(t, s)
	oldWait := mcpTokenRegistrationWait
	mcpTokenRegistrationWait = 10 * time.Millisecond
	t.Cleanup(func() { mcpTokenRegistrationWait = oldWait })
	registrarStopped := make(chan struct{})
	s.SetMCPTokenIdentityRegistrar(func(ctx context.Context, _ ed25519.PublicKey, _ ed25519.PrivateKey, _, _ string) error {
		defer close(registrarStopped)
		<-ctx.Done()
		return ctx.Err()
	})
	t.Cleanup(func() { s.SetMCPTokenIdentityRegistrar(nil) })

	issued, err := s.IssueMCPToken(context.Background(), "timeout", "issuer", "operator", "test")
	require.Nil(t, issued, "plaintext bearer must never escape before registration confirmation")
	require.ErrorContains(t, err, "outcome unknown")
	rows, err := s.ListMCPTokens(context.Background())
	require.NoError(t, err)
	require.Len(t, rows, 1, "an ambiguous RPC result may already be on-chain; retain a sealed pending row")
	var digest string
	require.NoError(t, s.conn.QueryRowContext(context.Background(), `SELECT token_sha256 FROM mcp_tokens WHERE id = ?`, rows[0].ID).Scan(&digest))
	_, _, err = s.LookupMCPTokenSigner(context.Background(), digest)
	require.ErrorIs(t, err, ErrTokenIdentityPending)
	var state string
	require.NoError(t, s.conn.QueryRowContext(context.Background(), `SELECT registration_state FROM mcp_tokens WHERE id = ?`, rows[0].ID).Scan(&state))
	require.Equal(t, "pending", state)
	select {
	case <-registrarStopped:
	case <-time.After(time.Second):
		t.Fatal("timed-out identity registrar was not cancelled")
	}

	// A later bounded idempotent registration retry makes the sealed token
	// usable; before then the bearer is not available to any caller.
	s.SetMCPTokenIdentityRegistrar(func(_ context.Context, _ ed25519.PublicKey, _ ed25519.PrivateKey, _, _ string) error { return nil })
	confirmed, err := s.ReconcilePendingMCPTokenIdentities(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, confirmed)
	require.NoError(t, s.conn.QueryRowContext(context.Background(), `SELECT registration_state FROM mcp_tokens WHERE id = ?`, rows[0].ID).Scan(&state))
	require.Equal(t, "confirmed", state)
}
