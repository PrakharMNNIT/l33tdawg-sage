package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOAuthClientMigrationFailsStartupOnMalformedTrustSchema(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "malformed-oauth-client-schema.db")
	raw, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	_, err = raw.ExecContext(ctx, `CREATE TABLE oauth_clients (client_id TEXT PRIMARY KEY)`)
	require.NoError(t, err)
	require.NoError(t, raw.Close())

	reopened, err := NewSQLiteStore(ctx, dbPath)
	require.Nil(t, reopened)
	require.ErrorContains(t, err, "migrate OAuth clients")
	require.ErrorContains(t, err, "no such column: created_at")
}
