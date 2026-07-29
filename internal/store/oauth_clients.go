package store

// Persisted OAuth 2.0 Dynamic Client Registration records.
//
// RFC 7591 lets an MCP client (ChatGPT, Cursor, etc.) POST a registration
// payload to /oauth/register and receive a client_id back. Without
// persistence the client_id is unverifiable later — anything the caller
// passes through /oauth/authorize is accepted, including arbitrary
// redirect_uris pointing at attacker-controlled hosts.
//
// We persist (client_id, redirect_uris[], client_name, created_at) at
// /oauth/register and require redirect_uri at /oauth/authorize and
// /oauth/token to be in the registered list.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// OAuthClient is one DCR-registered MCP client.
type OAuthClient struct {
	ClientID     string
	RedirectURIs []string
	ClientName   string
	CreatedAt    time.Time
}

// ErrOAuthClientNotFound — distinct from sql.ErrNoRows so callers can branch.
var ErrOAuthClientNotFound = errors.New("oauth client not registered")

// migrateOAuthClients creates and validates the oauth_clients table on first
// boot. This table is the redirect-URI trust root for OAuth DCR, so startup
// must fail rather than serve OAuth against a partial or malformed schema.
func (s *SQLiteStore) migrateOAuthClients(ctx context.Context) error {
	if _, err := s.writeExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS oauth_clients (
		client_id     TEXT PRIMARY KEY,
		redirect_uris TEXT NOT NULL DEFAULT '[]',
		client_name   TEXT NOT NULL DEFAULT '',
		created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
	)`); err != nil {
		return fmt.Errorf("create oauth client table: %w", err)
	}
	if _, err := s.writeExecContext(ctx,
		`CREATE INDEX IF NOT EXISTS idx_oauth_clients_created ON oauth_clients(created_at)`); err != nil {
		return fmt.Errorf("create oauth client retention index: %w", err)
	}
	rows, err := s.conn.QueryContext(ctx,
		`SELECT client_id, redirect_uris, client_name, created_at FROM oauth_clients LIMIT 0`)
	if err != nil {
		return fmt.Errorf("validate oauth client schema: %w", err)
	}
	return rows.Close()
}

// InsertOAuthClient persists a freshly-registered client. redirect_uris is
// stored as a JSON array. client_name is informational.
func (s *SQLiteStore) InsertOAuthClient(ctx context.Context, clientID string, redirectURIs []string, clientName string) error {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if redirectURIs == nil {
		redirectURIs = []string{}
	}
	uriBlob, err := json.Marshal(redirectURIs)
	if err != nil {
		return fmt.Errorf("encode redirect_uris: %w", err)
	}
	_, err = s.writeExecContext(ctx,
		`INSERT INTO oauth_clients (client_id, redirect_uris, client_name) VALUES (?, ?, ?)`,
		clientID, string(uriBlob), clientName)
	if err != nil {
		return fmt.Errorf("insert oauth client: %w", err)
	}
	return nil
}

// GetOAuthClient returns the persisted record for clientID. Returns
// ErrOAuthClientNotFound if the client_id was never registered (or was
// pruned).
func (s *SQLiteStore) GetOAuthClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, ErrOAuthClientNotFound
	}
	row := s.conn.QueryRowContext(ctx,
		`SELECT client_id, redirect_uris, client_name, created_at FROM oauth_clients WHERE client_id = ?`,
		clientID)
	var (
		c         OAuthClient
		uriBlob   string
		createdAt string
	)
	if err := row.Scan(&c.ClientID, &uriBlob, &c.ClientName, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrOAuthClientNotFound
		}
		return nil, fmt.Errorf("query oauth client: %w", err)
	}
	if err := json.Unmarshal([]byte(uriBlob), &c.RedirectURIs); err != nil {
		return nil, fmt.Errorf("decode redirect_uris: %w", err)
	}
	if t, perr := time.Parse(time.RFC3339Nano, createdAt); perr == nil {
		c.CreatedAt = t
	} else if t, perr2 := time.Parse("2006-01-02T15:04:05.999Z", createdAt); perr2 == nil {
		c.CreatedAt = t
	}
	return &c, nil
}

// PurgeOldOAuthClients deletes registrations older than the given retention
// window. Called periodically from the same cleanup loop that prunes
// auth-codes. Returns the number of rows removed.
func (s *SQLiteStore) PurgeOldOAuthClients(ctx context.Context, olderThan time.Duration) (int64, error) {
	if olderThan <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-olderThan).Format("2006-01-02T15:04:05.000Z")
	res, err := s.writeExecContext(ctx, `DELETE FROM oauth_clients WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("purge oauth clients: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
