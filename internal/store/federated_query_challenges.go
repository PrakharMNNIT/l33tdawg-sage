package store

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// Bound durable preflight state per authenticated remote node. Expired and
	// consumed rows are pruned before this limit is checked.
	MaxFederatedQueryChallengesPerPeer = 1024
)

// FederatedQueryChallenge is a destination-issued, durable, single-use token.
// The original local agent signs it into the final recall request.
type FederatedQueryChallenge struct {
	ChallengeID            string
	RemoteChainID          string
	PeerAgentID            string
	RequestedAgentID       string
	DomainTag              string
	AgreementBindingDigest string
	ExpiresAt              int64
}

func validateFederatedQueryChallenge(c FederatedQueryChallenge) error {
	challenge, err := hex.DecodeString(c.ChallengeID)
	if err != nil || len(challenge) != 32 || c.ChallengeID != strings.ToLower(c.ChallengeID) {
		return errors.New("federated query challenge must be a canonical 32-byte hex value")
	}
	digest, err := hex.DecodeString(c.AgreementBindingDigest)
	if err != nil || len(digest) != 32 || c.AgreementBindingDigest != strings.ToLower(c.AgreementBindingDigest) {
		return errors.New("federated query challenge agreement binding is invalid")
	}
	peer, err := hex.DecodeString(c.PeerAgentID)
	if err != nil || len(peer) != ed25519.PublicKeySize || c.PeerAgentID != strings.ToLower(c.PeerAgentID) {
		return errors.New("federated query challenge peer agent is invalid")
	}
	requested, err := hex.DecodeString(c.RequestedAgentID)
	if err != nil || len(requested) != ed25519.PublicKeySize || c.RequestedAgentID != strings.ToLower(c.RequestedAgentID) {
		return errors.New("federated query challenge requested agent is invalid")
	}
	if c.RemoteChainID == "" || c.RemoteChainID != strings.TrimSpace(c.RemoteChainID) ||
		len(c.RemoteChainID) > 256 || strings.ContainsAny(c.RemoteChainID, "\x00\r\n") {
		return errors.New("federated query challenge remote chain is invalid")
	}
	if c.DomainTag == "" || c.DomainTag != strings.TrimSpace(c.DomainTag) ||
		len(c.DomainTag) > 256 || strings.ContainsAny(c.DomainTag, "\x00\r\n") {
		return errors.New("federated query challenge domain is invalid")
	}
	if c.ExpiresAt <= 0 {
		return errors.New("federated query challenge expiry is invalid")
	}
	return nil
}

func (s *SQLiteStore) migrateFederatedQueryChallenges(ctx context.Context) error {
	if _, err := s.writeExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS federated_query_challenge (
		challenge_id                 TEXT PRIMARY KEY,
		remote_chain_id              TEXT NOT NULL,
		peer_agent_id                TEXT NOT NULL,
		requested_agent_id           TEXT NOT NULL,
		domain_tag                   TEXT NOT NULL,
		agreement_binding_digest     TEXT NOT NULL,
		expires_at                   INTEGER NOT NULL,
		consumed_at                  INTEGER NOT NULL DEFAULT 0,
		created_at                   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
	)`); err != nil {
		return fmt.Errorf("create federated query challenge table: %w", err)
	}
	if _, err := s.writeExecContext(ctx, `
	CREATE INDEX IF NOT EXISTS idx_federated_query_challenge_peer
	ON federated_query_challenge(remote_chain_id, peer_agent_id, expires_at, consumed_at)`); err != nil {
		return fmt.Errorf("create federated query challenge index: %w", err)
	}
	return nil
}

// FederationV23SchemaReady is deliberately a runtime readiness check rather
// than an optimistic migration flag: older/readonly SQLite databases must not
// advertise a v23 query capability they cannot enforce.
func (s *SQLiteStore) FederationV23SchemaReady(ctx context.Context) error {
	for _, table := range []string{
		"federated_group_guest",
		"federated_query_challenge",
		"federated_admin_elevation_nonce",
		"fed_linked_message_consent",
	} {
		var name string
		err := s.conn.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("required federation v23 table %q is unavailable", table)
			}
			return fmt.Errorf("check federation v23 schema %q: %w", table, err)
		}
	}
	for table, columns := range map[string]string{
		"federated_group_guest": `group_id, remote_chain_id, remote_agent_id,
			agreement_binding_digest, max_classification, revision, state,
			authorized_by, authority_kind, authority_root_generation,
			authority_role_revision, authority_enrollment_revision, signature`,
		"federated_query_challenge": `challenge_id, remote_chain_id, peer_agent_id,
			requested_agent_id, domain_tag, agreement_binding_digest, expires_at,
			consumed_at`,
		"federated_admin_elevation_nonce": `scope, root_generation, admin_id,
			nonce, expires_at, consumed_at`,
		"fed_linked_message_consent": `remote_chain_id, remote_agent_id,
			local_agent_id, peer_agent_id, policy_epoch, remote_ca_pin,
			policy_revision, revision, accepting`,
		"pipeline_messages": `pipe_id, from_agent, to_agent, payload, status,
			created_at, expires_at, source_chain_id, source_pipe_id,
			destination_chain_id, federation_policy_epoch,
			federation_agreement_id, federation_contact_id,
			federation_contact_revision, federation_authorization_mode,
			federation_linked_relation`,
		"pipeline_transport_outbox": `event_id, pipe_id, remote_chain_id,
			event_kind, policy_epoch, agreement_id, contact_id,
			contact_revision, source_agent_id, target_agent_id, proof_canonical,
			state, next_attempt_at, created_at, expires_at,
			authorization_mode, linked_relation`,
		"pipeline_transport_dedup": `remote_chain_id, policy_epoch,
			agreement_id, contact_id, contact_revision, source_agent_id,
			target_agent_id, event_kind, remote_pipe_id, content_hash,
			proof_hash, local_pipe_id, outcome, expires_at,
			authorization_mode, linked_relation_digest`,
	} {
		rows, err := s.conn.QueryContext(ctx,
			`SELECT `+columns+` FROM `+table+` LIMIT 0`)
		if err != nil {
			return fmt.Errorf("required federation v23 table %q is malformed: %w", table, err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("verify federation v23 table %q: %w", table, err)
		}
	}
	var replayIndex string
	if err := s.conn.QueryRowContext(ctx, `
		SELECT name FROM sqlite_master
		WHERE type='index' AND name='idx_pipe_transport_proof_once'`).
		Scan(&replayIndex); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("required federation pipeline replay index is unavailable")
		}
		return fmt.Errorf("check federation pipeline replay index: %w", err)
	}
	return nil
}

// IssueFederatedQueryChallenge persists a destination-generated challenge.
// Callers hold the federation policy read lease; writeMu serializes the SQL
// mutation beneath that lease (lock order: policy -> SQLite writeMu).
func (s *SQLiteStore) IssueFederatedQueryChallenge(ctx context.Context, challenge FederatedQueryChallenge, now time.Time) error {
	if err := validateFederatedQueryChallenge(challenge); err != nil {
		return err
	}
	if !challenge.ExpiresAtTime().After(now) {
		return errors.New("federated query challenge must expire in the future")
	}
	return s.RunInTx(ctx, func(txStore OffchainStore) error {
		tx := txStore.(*SQLiteStore)
		nowUnix := now.Unix()
		if _, err := tx.conn.ExecContext(ctx, `
			DELETE FROM federated_query_challenge
			WHERE expires_at < ? OR (consumed_at > 0 AND consumed_at < ?)`,
			nowUnix, now.Add(-10*time.Minute).Unix()); err != nil {
			return err
		}
		var count int
		if err := tx.conn.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM federated_query_challenge
			WHERE remote_chain_id=? AND peer_agent_id=? AND consumed_at=0 AND expires_at>=?`,
			challenge.RemoteChainID, challenge.PeerAgentID, nowUnix).Scan(&count); err != nil {
			return err
		}
		if count >= MaxFederatedQueryChallengesPerPeer {
			return errors.New("federated query challenge capacity reached for peer")
		}
		_, err := tx.conn.ExecContext(ctx, `
			INSERT INTO federated_query_challenge (
				challenge_id, remote_chain_id, peer_agent_id, requested_agent_id, domain_tag,
				agreement_binding_digest, expires_at, consumed_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
			challenge.ChallengeID, challenge.RemoteChainID, challenge.PeerAgentID,
			challenge.RequestedAgentID, challenge.DomainTag,
			challenge.AgreementBindingDigest, challenge.ExpiresAt)
		return err
	})
}

func (c FederatedQueryChallenge) ExpiresAtTime() time.Time {
	return time.Unix(c.ExpiresAt, 0)
}

// ConsumeFederatedQueryChallenge atomically transitions exactly one live,
// generation-bound challenge. RowsAffected==1 is the authorization decision;
// restart, concurrent replay, and duplicate delivery all fail closed.
func (s *SQLiteStore) ConsumeFederatedQueryChallenge(ctx context.Context, challenge FederatedQueryChallenge, now time.Time) error {
	if err := validateFederatedQueryChallenge(challenge); err != nil {
		return err
	}
	result, err := s.writeExecContext(ctx, `
		UPDATE federated_query_challenge
		SET consumed_at=?
		WHERE challenge_id=? AND remote_chain_id=? AND peer_agent_id=?
			AND requested_agent_id=? AND domain_tag=?
			AND agreement_binding_digest=? AND consumed_at=0 AND expires_at>=?`,
		now.Unix(), challenge.ChallengeID, challenge.RemoteChainID,
		challenge.PeerAgentID, challenge.RequestedAgentID, challenge.DomainTag,
		challenge.AgreementBindingDigest, now.Unix())
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("federated query challenge is expired, stale, or already consumed")
	}
	return nil
}
