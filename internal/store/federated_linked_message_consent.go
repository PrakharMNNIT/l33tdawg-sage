package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var ErrLinkedMessageConsentConflict = errors.New("linked-message consent revision changed")

// FederatedLinkedMessageConsent is receiver-local consent for one exact
// foreign sender to address one exact local agent. It is deliberately
// independent of domain/contact acceptance: a Linked-reader relation grants
// no memory or domain authority.
type FederatedLinkedMessageConsent struct {
	RemoteChainID string
	RemoteAgentID string
	LocalAgentID  string
	Revision      int64
	Accepting     bool
}

func (s *SQLiteStore) migrateFederatedLinkedMessageConsent(ctx context.Context) error {
	if _, err := s.writeExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS fed_linked_message_consent (
		remote_chain_id TEXT NOT NULL,
		remote_agent_id TEXT NOT NULL,
		local_agent_id  TEXT NOT NULL,
		peer_agent_id   TEXT NOT NULL,
		policy_epoch    TEXT NOT NULL,
		remote_ca_pin   TEXT NOT NULL,
		policy_revision INTEGER NOT NULL CHECK (policy_revision > 0),
		revision        INTEGER NOT NULL CHECK (revision > 0),
		accepting       INTEGER NOT NULL CHECK (accepting IN (0,1)),
		updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
		PRIMARY KEY (remote_chain_id, remote_agent_id, local_agent_id)
	)`); err != nil {
		return fmt.Errorf("create linked-message consent table: %w", err)
	}
	if _, err := s.writeExecContext(ctx, `
	CREATE INDEX IF NOT EXISTS idx_fed_linked_message_consent_local
	ON fed_linked_message_consent(remote_chain_id, local_agent_id, accepting)`); err != nil {
		return fmt.Errorf("create linked-message consent index: %w", err)
	}
	return nil
}

func validateFederatedLinkedMessageConsentIDs(remoteAgentID, localAgentID string) error {
	if err := validateFederatedPipeAgentID(remoteAgentID); err != nil {
		return fmt.Errorf("remote linked-message agent id: %w", err)
	}
	if err := validateFederatedPipeAgentID(localAgentID); err != nil {
		return fmt.Errorf("local linked-message agent id: %w", err)
	}
	return nil
}

// GetBoundFederatedLinkedMessageConsent returns consent only when every
// current JOIN/operator/CA/policy field still matches. Missing, disabled and
// stale rows are all non-authorizing; callers may retain the disabled row's
// revision only for an operator-facing CAS projection.
func (s *SQLiteStore) GetBoundFederatedLinkedMessageConsent(
	ctx context.Context,
	policy PeerRBACPolicy,
	remoteAgentID, localAgentID string,
) (*FederatedLinkedMessageConsent, error) {
	if err := validateFederatedPipeContactBinding(policy); err != nil {
		return nil, err
	}
	if err := validateFederatedLinkedMessageConsentIDs(remoteAgentID, localAgentID); err != nil {
		return nil, err
	}
	var out FederatedLinkedMessageConsent
	var accepting int
	err := s.conn.QueryRowContext(ctx, `
		SELECT c.remote_chain_id, c.remote_agent_id, c.local_agent_id,
			c.revision, c.accepting
		FROM fed_linked_message_consent c
		JOIN sync_control sc ON sc.remote_chain_id=c.remote_chain_id
			AND sc.peer_agent_id=c.peer_agent_id
			AND sc.policy_epoch=c.policy_epoch
			AND sc.remote_ca_pin=c.remote_ca_pin
			AND sc.binding_state='active'
		JOIN peer_rbac_policy p ON p.remote_chain_id=c.remote_chain_id
			AND p.peer_agent_id=c.peer_agent_id
			AND p.policy_epoch=c.policy_epoch
			AND p.remote_ca_pin=c.remote_ca_pin
			AND p.revision=c.policy_revision
		WHERE c.remote_chain_id=? AND c.remote_agent_id=? AND c.local_agent_id=?
			AND c.peer_agent_id=? AND c.policy_epoch=? AND c.remote_ca_pin=?
			AND c.policy_revision=?`,
		policy.RemoteChainID, remoteAgentID, localAgentID,
		policy.PeerAgentID, policy.PolicyEpoch, policy.RemoteCAPin, policy.Revision).
		Scan(&out.RemoteChainID, &out.RemoteAgentID, &out.LocalAgentID,
			&out.Revision, &accepting)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read linked-message consent: %w", err)
	}
	out.Accepting = accepting == 1
	return &out, nil
}

// SetBoundFederatedLinkedMessageConsentCAS atomically advances one exact
// consent tuple. expectedRevision=0 creates a tuple or explicitly re-consents
// after a stale JOIN/policy generation; it never overwrites a row in the
// current generation. A disabled row is retained so an old signed relation
// cannot revive after acceptance is toggled off and on.
func (s *SQLiteStore) SetBoundFederatedLinkedMessageConsentCAS(
	ctx context.Context,
	policy PeerRBACPolicy,
	remoteAgentID, localAgentID string,
	expectedRevision int64,
	accepting bool,
) (int64, error) {
	if err := validateFederatedPipeContactBinding(policy); err != nil {
		return 0, err
	}
	if policy.Paused && accepting {
		return 0, fmt.Errorf("%w: peer policy is paused", ErrPeerRBACBindingMismatch)
	}
	if err := validateFederatedLinkedMessageConsentIDs(remoteAgentID, localAgentID); err != nil {
		return 0, err
	}
	if expectedRevision < 0 {
		return 0, ErrLinkedMessageConsentConflict
	}

	unlock := s.LockSyncPolicyWrite()
	defer unlock()
	var nextRevision int64
	err := s.RunInTx(ctx, func(txStore OffchainStore) error {
		tx := txStore.(*SQLiteStore)
		var currentPeer, currentEpoch, currentCAPin, controlState string
		var currentVersion int
		var currentPolicyRevision int64
		var currentPaused int
		err := tx.conn.QueryRowContext(ctx, `
			SELECT p.peer_agent_id, p.policy_epoch, p.remote_ca_pin,
				p.policy_version, p.revision, p.paused, c.binding_state
			FROM peer_rbac_policy p
			JOIN sync_control c ON c.remote_chain_id=p.remote_chain_id
				AND c.peer_agent_id=p.peer_agent_id
				AND c.policy_epoch=p.policy_epoch
				AND c.remote_ca_pin=p.remote_ca_pin
			WHERE p.remote_chain_id=?`, policy.RemoteChainID).
			Scan(&currentPeer, &currentEpoch, &currentCAPin, &currentVersion,
				&currentPolicyRevision, &currentPaused, &controlState)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: active peer RBAC policy is required", ErrPeerRBACBindingMismatch)
		}
		if err != nil {
			return fmt.Errorf("read linked-message policy binding: %w", err)
		}
		if controlState != "active" || currentPeer != policy.PeerAgentID ||
			currentEpoch != policy.PolicyEpoch || currentCAPin != policy.RemoteCAPin ||
			currentVersion != policy.PolicyVersion ||
			currentPolicyRevision != policy.Revision ||
			(currentPaused == 1) != policy.Paused {
			return fmt.Errorf("%w: peer policy changed during linked-message consent update",
				ErrPeerRBACBindingMismatch)
		}
		if currentPaused == 1 && accepting {
			return fmt.Errorf("%w: peer policy is paused", ErrPeerRBACBindingMismatch)
		}

		var heldRevision int64
		var heldPeer, heldEpoch, heldCAPin string
		var heldPolicyRevision int64
		err = tx.conn.QueryRowContext(ctx, `
			SELECT revision, peer_agent_id, policy_epoch, remote_ca_pin, policy_revision
			FROM fed_linked_message_consent
			WHERE remote_chain_id=? AND remote_agent_id=? AND local_agent_id=?`,
			policy.RemoteChainID, remoteAgentID, localAgentID).
			Scan(&heldRevision, &heldPeer, &heldEpoch, &heldCAPin, &heldPolicyRevision)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if expectedRevision != 0 {
				return ErrLinkedMessageConsentConflict
			}
			nextRevision = 1
		case err != nil:
			return fmt.Errorf("read linked-message consent revision: %w", err)
		default:
			heldCurrent := heldPeer == policy.PeerAgentID &&
				heldEpoch == policy.PolicyEpoch &&
				heldCAPin == policy.RemoteCAPin &&
				heldPolicyRevision == policy.Revision
			if (heldCurrent && expectedRevision != heldRevision) ||
				(!heldCurrent && expectedRevision != 0) {
				return ErrLinkedMessageConsentConflict
			}
			nextRevision = heldRevision + 1
		}

		acceptingInt := 0
		if accepting {
			acceptingInt = 1
		}
		_, err = tx.writeExecContext(ctx, `
			INSERT INTO fed_linked_message_consent
				(remote_chain_id, remote_agent_id, local_agent_id,
				 peer_agent_id, policy_epoch, remote_ca_pin, policy_revision,
				 revision, accepting)
			VALUES(?,?,?,?,?,?,?,?,?)
			ON CONFLICT(remote_chain_id,remote_agent_id,local_agent_id) DO UPDATE SET
				peer_agent_id=excluded.peer_agent_id,
				policy_epoch=excluded.policy_epoch,
				remote_ca_pin=excluded.remote_ca_pin,
				policy_revision=excluded.policy_revision,
				revision=excluded.revision,
				accepting=excluded.accepting,
				updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')`,
			policy.RemoteChainID, remoteAgentID, localAgentID,
			policy.PeerAgentID, policy.PolicyEpoch, policy.RemoteCAPin,
			policy.Revision, nextRevision, acceptingInt)
		if err != nil {
			return fmt.Errorf("write linked-message consent: %w", err)
		}
		return nil
	})
	return nextRevision, err
}
