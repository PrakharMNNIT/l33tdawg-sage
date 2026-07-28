package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// AgentClaimStore is the deliberately narrow persistence contract for the
// unauthenticated agent-install redemption route. Implementations must consume
// a valid token atomically before returning its agent ID.
type AgentClaimStore interface {
	RedeemAgentClaim(ctx context.Context, token string, now time.Time) (agentID string, err error)
}

var (
	ErrAgentClaimInvalid = errors.New("invalid or already redeemed agent claim token")
	ErrAgentClaimExpired = errors.New("agent claim token expired")
)

const sqliteRedeemAgentClaimSQL = `
	UPDATE network_agents
	SET claim_token = '', claim_expires_at = NULL
	WHERE claim_token = ?
	  AND (claim_expires_at IS NULL OR julianday(claim_expires_at) > julianday(?))
	RETURNING agent_id`

const sqliteExpireAgentClaimSQL = `
	UPDATE network_agents
	SET claim_token = '', claim_expires_at = NULL
	WHERE claim_token = ?
	  AND claim_expires_at IS NOT NULL
	  AND (
		julianday(claim_expires_at) IS NULL
		OR julianday(claim_expires_at) <= julianday(?)
	  )`

// RedeemAgentClaim atomically clears a valid SQLite claim token and returns its
// exact agent. A malformed stored expiry fails closed and is retired as expired.
func (s *SQLiteStore) RedeemAgentClaim(ctx context.Context, token string, now time.Time) (string, error) {
	if s.db != nil {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
	}

	var agentID string
	err := s.conn.QueryRowContext(ctx, sqliteRedeemAgentClaimSQL, token, now.UTC().Format(time.RFC3339Nano)).Scan(&agentID)
	if err == nil {
		return agentID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("redeem agent claim: %w", err)
	}

	result, err := s.conn.ExecContext(ctx, sqliteExpireAgentClaimSQL, token, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return "", fmt.Errorf("retire expired agent claim: %w", err)
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil {
		return "", fmt.Errorf("count retired agent claims: %w", rowsErr)
	} else if affected > 0 {
		return "", ErrAgentClaimExpired
	}
	return "", ErrAgentClaimInvalid
}

const postgresRedeemAgentClaimSQL = `
	UPDATE agents
	SET claim_token = '', claim_expires_at = NULL
	WHERE claim_token = $1
	  AND (claim_expires_at IS NULL OR claim_expires_at > $2)
	RETURNING agent_id`

const postgresExpireAgentClaimSQL = `
	UPDATE agents
	SET claim_token = '', claim_expires_at = NULL
	WHERE claim_token = $1
	  AND claim_expires_at IS NOT NULL
	  AND claim_expires_at <= $2`

// RedeemAgentClaim provides the same single-statement compare-and-clear
// operation for PostgreSQL. Concurrent callers cannot both observe a token as
// redeemable because the UPDATE takes the row lock before RETURNING.
func (s *PostgresStore) RedeemAgentClaim(ctx context.Context, token string, now time.Time) (string, error) {
	var agentID string
	err := s.db.QueryRow(ctx, postgresRedeemAgentClaimSQL, token, now.UTC()).Scan(&agentID)
	if err == nil {
		return agentID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("redeem agent claim: %w", err)
	}

	result, err := s.db.Exec(ctx, postgresExpireAgentClaimSQL, token, now.UTC())
	if err != nil {
		return "", fmt.Errorf("retire expired agent claim: %w", err)
	}
	if result.RowsAffected() > 0 {
		return "", ErrAgentClaimExpired
	}
	return "", ErrAgentClaimInvalid
}
