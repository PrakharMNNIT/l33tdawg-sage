package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	FederatedReaderRestrictionStateActive  = "active"
	FederatedReaderRestrictionStateRevoked = "revoked"

	MaxFederatedReaderRestrictionsPerPeer = 256
	MaxFederatedReaderDeniedDomains       = MaxPeerRBACPolicyDomains
)

var (
	ErrFederatedReaderRestrictionRevisionConflict = errors.New("federated reader restriction revision conflict")
	ErrFederatedReaderRestrictionBindingMismatch  = errors.New("federated reader restriction agreement binding mismatch")
)

// FederatedReaderRestriction is the requester-side exception to federation's
// default-allow read contract. It is local/off-consensus and never leaves this
// SAGE. An absent or revoked current row permits an active ordinary local agent
// to read domains exported by this peer. An active row may block every domain
// or a bounded set of overlapping domain subtrees.
//
// The frozen peer/operator/epoch/CA tuple prevents a restriction from being
// transplanted to a different JOIN generation. Controlled re-pair reset is an
// explicit broadening action; an unexpected active-row mismatch fails closed.
type FederatedReaderRestriction struct {
	RemoteChainID string   `json:"remote_chain_id"`
	LocalAgentID  string   `json:"local_agent_id"`
	PeerAgentID   string   `json:"peer_agent_id"`
	PolicyEpoch   string   `json:"policy_epoch"`
	RemoteCAPin   string   `json:"remote_ca_pin"`
	DenyAll       bool     `json:"deny_all"`
	DeniedDomains []string `json:"denied_domains"`
	Revision      int64    `json:"revision"`
	State         string   `json:"state"`
}

// FederatedReaderBinding is the exact live trust generation supplied by the
// federation Manager. Browser/API callers must not choose these fields.
type FederatedReaderBinding struct {
	RemoteChainID string
	PeerAgentID   string
	PolicyEpoch   string
	RemoteCAPin   string
}

func (s *SQLiteStore) migrateFederatedReaderRestrictions(ctx context.Context) error {
	if _, err := s.writeExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS federated_reader_restriction (
		remote_chain_id TEXT NOT NULL,
		local_agent_id  TEXT NOT NULL,
		peer_agent_id   TEXT NOT NULL,
		policy_epoch    TEXT NOT NULL,
		remote_ca_pin   TEXT NOT NULL,
		deny_all        INTEGER NOT NULL CHECK (deny_all IN (0,1)),
		revision        INTEGER NOT NULL CHECK (revision > 0),
		state           TEXT NOT NULL CHECK (state IN ('active','revoked')),
		updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
		PRIMARY KEY (remote_chain_id, local_agent_id)
	)`); err != nil {
		return fmt.Errorf("create federated reader restriction table: %w", err)
	}
	if _, err := s.writeExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS federated_reader_denied_domain (
		remote_chain_id TEXT NOT NULL,
		local_agent_id  TEXT NOT NULL,
		domain_tag      TEXT NOT NULL,
		PRIMARY KEY (remote_chain_id, local_agent_id, domain_tag),
		FOREIGN KEY (remote_chain_id, local_agent_id)
			REFERENCES federated_reader_restriction(remote_chain_id, local_agent_id)
			ON DELETE CASCADE
	)`); err != nil {
		return fmt.Errorf("create federated reader denied-domain table: %w", err)
	}
	if _, err := s.writeExecContext(ctx, `
	CREATE INDEX IF NOT EXISTS idx_federated_reader_restriction_peer_state
	ON federated_reader_restriction(remote_chain_id, state, local_agent_id)`); err != nil {
		return fmt.Errorf("create federated reader restriction peer index: %w", err)
	}
	return nil
}

func canonicalFederatedReaderBinding(binding FederatedReaderBinding) error {
	if binding.RemoteChainID == "" || binding.RemoteChainID != strings.TrimSpace(binding.RemoteChainID) ||
		len(binding.RemoteChainID) > 256 || strings.ContainsAny(binding.RemoteChainID, "\x00\r\n") {
		return errors.New("federated reader remote chain id is invalid")
	}
	if !isCanonicalAgentID(binding.PeerAgentID) {
		return errors.New("federated reader peer agent id must be canonical")
	}
	if binding.PolicyEpoch == "" || binding.PolicyEpoch != strings.TrimSpace(binding.PolicyEpoch) ||
		len(binding.PolicyEpoch) > 256 || strings.ContainsAny(binding.PolicyEpoch, "\x00\r\n") {
		return errors.New("federated reader policy epoch is invalid")
	}
	pin, err := hex.DecodeString(binding.RemoteCAPin)
	if err != nil || len(pin) == 0 || binding.RemoteCAPin != strings.ToLower(binding.RemoteCAPin) {
		return errors.New("federated reader remote CA pin must be canonical non-empty hex")
	}
	return nil
}

func canonicalFederatedReaderRestriction(in FederatedReaderRestriction) (FederatedReaderRestriction, error) {
	binding := FederatedReaderBinding{
		RemoteChainID: in.RemoteChainID, PeerAgentID: in.PeerAgentID,
		PolicyEpoch: in.PolicyEpoch, RemoteCAPin: in.RemoteCAPin,
	}
	if err := canonicalFederatedReaderBinding(binding); err != nil {
		return FederatedReaderRestriction{}, err
	}
	if !isCanonicalAgentID(in.LocalAgentID) {
		return FederatedReaderRestriction{}, errors.New("federated reader local agent id must be canonical")
	}
	if in.Revision <= 0 {
		return FederatedReaderRestriction{}, errors.New("federated reader restriction revision must be positive")
	}
	switch in.State {
	case FederatedReaderRestrictionStateActive, FederatedReaderRestrictionStateRevoked:
	default:
		return FederatedReaderRestriction{}, errors.New("federated reader restriction state is invalid")
	}
	if len(in.DeniedDomains) > MaxFederatedReaderDeniedDomains {
		return FederatedReaderRestriction{}, fmt.Errorf(
			"federated reader restriction is capped at %d denied domains",
			MaxFederatedReaderDeniedDomains,
		)
	}
	permissions := make([]PeerRBACDomainPermission, len(in.DeniedDomains))
	for i, domain := range in.DeniedDomains {
		permissions[i] = PeerRBACDomainPermission{Domain: domain, Read: true}
	}
	canonical, err := canonicalPeerRBACDomains(permissions)
	if err != nil {
		return FederatedReaderRestriction{}, fmt.Errorf("federated reader denied domains: %w", err)
	}
	in.DeniedDomains = make([]string, len(canonical))
	for i := range canonical {
		in.DeniedDomains[i] = canonical[i].Domain
	}
	return in, nil
}

func federatedReaderBindingMatches(row FederatedReaderRestriction, binding FederatedReaderBinding) bool {
	return row.RemoteChainID == binding.RemoteChainID && row.PeerAgentID == binding.PeerAgentID &&
		row.PolicyEpoch == binding.PolicyEpoch && row.RemoteCAPin == binding.RemoteCAPin
}

// federatedReaderDomainsOverlap is intentionally symmetric. A denied parent
// blocks a child query; a denied child also blocks a parent query because that
// parent query could return records from the denied subtree.
func federatedReaderDomainsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+".") || strings.HasPrefix(b, a+".")
}

// PutBoundFederatedReaderRestrictionCAS additionally verifies the exact active
// sync_control generation in the same SQLite transaction.
func (s *SQLiteStore) PutBoundFederatedReaderRestrictionCAS(
	ctx context.Context, restriction FederatedReaderRestriction, expectedRevision int64,
) (*FederatedReaderRestriction, error) {
	return s.putFederatedReaderRestrictionCAS(ctx, restriction, expectedRevision)
}

func (s *SQLiteStore) putFederatedReaderRestrictionCAS(
	ctx context.Context, restriction FederatedReaderRestriction, expectedRevision int64,
) (*FederatedReaderRestriction, error) {
	if s != nil && s.db == nil {
		return nil, errors.New("federated reader restriction mutation is not permitted inside SQLite transaction")
	}
	canonical, err := canonicalFederatedReaderRestriction(restriction)
	if err != nil {
		return nil, err
	}
	if expectedRevision < 0 || canonical.Revision != expectedRevision+1 {
		return nil, fmt.Errorf("%w: next revision must equal expected revision plus one", ErrFederatedReaderRestrictionRevisionConflict)
	}

	releaseAuthorization := s.beginFederationAuthorizationMutation(canonical.RemoteChainID)
	defer releaseAuthorization()
	unlock := s.LockSyncPolicyWrite()
	defer unlock()

	err = s.RunInTx(ctx, func(txStore OffchainStore) error {
		tx := txStore.(*SQLiteStore)
		if bindingErr := tx.requireFederatedReaderSyncControl(ctx, FederatedReaderBinding{
			RemoteChainID: canonical.RemoteChainID, PeerAgentID: canonical.PeerAgentID,
			PolicyEpoch: canonical.PolicyEpoch, RemoteCAPin: canonical.RemoteCAPin,
		}); bindingErr != nil {
			return bindingErr
		}

		var currentRevision int64
		var currentState, currentPeer, currentEpoch, currentPin string
		getErr := tx.conn.QueryRowContext(ctx, `
			SELECT revision, state, peer_agent_id, policy_epoch, remote_ca_pin
			FROM federated_reader_restriction
			WHERE remote_chain_id=? AND local_agent_id=?`,
			canonical.RemoteChainID, canonical.LocalAgentID).
			Scan(&currentRevision, &currentState, &currentPeer, &currentEpoch, &currentPin)
		switch {
		case errors.Is(getErr, sql.ErrNoRows) && expectedRevision != 0:
			return ErrFederatedReaderRestrictionRevisionConflict
		case getErr == nil && currentRevision != expectedRevision:
			return ErrFederatedReaderRestrictionRevisionConflict
		case getErr != nil && !errors.Is(getErr, sql.ErrNoRows):
			return fmt.Errorf("read federated reader restriction revision: %w", getErr)
		}
		if errors.Is(getErr, sql.ErrNoRows) && canonical.State != FederatedReaderRestrictionStateActive {
			return errors.New("new federated reader restriction must be active")
		}
		if getErr == nil && currentState != FederatedReaderRestrictionStateRevoked &&
			(currentPeer != canonical.PeerAgentID || currentEpoch != canonical.PolicyEpoch || currentPin != canonical.RemoteCAPin) {
			return ErrFederatedReaderRestrictionBindingMismatch
		}
		if errors.Is(getErr, sql.ErrNoRows) {
			var liveCount int
			if countErr := tx.conn.QueryRowContext(ctx, `
				SELECT COUNT(*) FROM federated_reader_restriction
				WHERE remote_chain_id=?`, canonical.RemoteChainID).Scan(&liveCount); countErr != nil {
				return fmt.Errorf("count federated reader restrictions: %w", countErr)
			}
			if liveCount >= MaxFederatedReaderRestrictionsPerPeer {
				return fmt.Errorf("federated reader restriction limit %d reached", MaxFederatedReaderRestrictionsPerPeer)
			}
		}

		denyAll := 0
		if canonical.DenyAll {
			denyAll = 1
		}
		if _, execErr := tx.conn.ExecContext(ctx, `
			INSERT INTO federated_reader_restriction (
				remote_chain_id, local_agent_id, peer_agent_id, policy_epoch,
				remote_ca_pin, deny_all, revision, state, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
			ON CONFLICT(remote_chain_id, local_agent_id) DO UPDATE SET
				peer_agent_id=excluded.peer_agent_id,
				policy_epoch=excluded.policy_epoch,
				remote_ca_pin=excluded.remote_ca_pin,
				deny_all=excluded.deny_all,
				revision=excluded.revision,
				state=excluded.state,
				updated_at=excluded.updated_at`,
			canonical.RemoteChainID, canonical.LocalAgentID, canonical.PeerAgentID,
			canonical.PolicyEpoch, canonical.RemoteCAPin, denyAll,
			canonical.Revision, canonical.State); execErr != nil {
			return fmt.Errorf("upsert federated reader restriction: %w", execErr)
		}
		if _, execErr := tx.conn.ExecContext(ctx, `
			DELETE FROM federated_reader_denied_domain
			WHERE remote_chain_id=? AND local_agent_id=?`,
			canonical.RemoteChainID, canonical.LocalAgentID); execErr != nil {
			return fmt.Errorf("replace federated reader denied domains: %w", execErr)
		}
		for _, domain := range canonical.DeniedDomains {
			if _, execErr := tx.conn.ExecContext(ctx, `
				INSERT INTO federated_reader_denied_domain (
					remote_chain_id, local_agent_id, domain_tag
				) VALUES (?, ?, ?)`, canonical.RemoteChainID, canonical.LocalAgentID, domain); execErr != nil {
				return fmt.Errorf("insert federated reader denied domain %q: %w", domain, execErr)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.GetFederatedReaderRestriction(ctx, canonical.RemoteChainID, canonical.LocalAgentID)
}

func (s *SQLiteStore) requireFederatedReaderSyncControl(ctx context.Context, binding FederatedReaderBinding) error {
	var peer, epoch, pin, state string
	err := s.conn.QueryRowContext(ctx, `
		SELECT peer_agent_id, policy_epoch, remote_ca_pin, binding_state
		FROM sync_control WHERE remote_chain_id=?`, binding.RemoteChainID).
		Scan(&peer, &epoch, &pin, &state)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("%w: active sync control is required", ErrFederatedReaderRestrictionBindingMismatch)
	case err != nil:
		return fmt.Errorf("read federated reader sync control: %w", err)
	case state != "active" || peer != binding.PeerAgentID || epoch != binding.PolicyEpoch || pin != binding.RemoteCAPin:
		return ErrFederatedReaderRestrictionBindingMismatch
	default:
		return nil
	}
}

func (s *SQLiteStore) GetFederatedReaderRestriction(
	ctx context.Context, remoteChainID, localAgentID string,
) (*FederatedReaderRestriction, error) {
	var out FederatedReaderRestriction
	var denyAll int
	err := s.conn.QueryRowContext(ctx, `
		SELECT remote_chain_id, local_agent_id, peer_agent_id, policy_epoch,
			remote_ca_pin, deny_all, revision, state
		FROM federated_reader_restriction
		WHERE remote_chain_id=? AND local_agent_id=?`, remoteChainID, localAgentID).
		Scan(&out.RemoteChainID, &out.LocalAgentID, &out.PeerAgentID, &out.PolicyEpoch,
			&out.RemoteCAPin, &denyAll, &out.Revision, &out.State)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get federated reader restriction: %w", err)
	}
	if denyAll != 0 && denyAll != 1 {
		return nil, errors.New("stored federated reader deny-all value is invalid")
	}
	out.DenyAll = denyAll == 1
	out.DeniedDomains, err = s.listFederatedReaderDeniedDomains(ctx, remoteChainID, localAgentID)
	if err != nil {
		return nil, err
	}
	canonical, err := canonicalFederatedReaderRestriction(out)
	if err != nil {
		return nil, fmt.Errorf("stored federated reader restriction is invalid: %w", err)
	}
	return &canonical, nil
}

// ListFederatedReaderRestrictions returns the complete, revision-bearing
// requester restriction snapshot for one peer. Revoked rows are retained so a
// dashboard can perform safe CAS updates without silently reusing revisions.
func (s *SQLiteStore) ListFederatedReaderRestrictions(
	ctx context.Context, remoteChainID string,
) ([]FederatedReaderRestriction, error) {
	if remoteChainID == "" || remoteChainID != strings.TrimSpace(remoteChainID) ||
		len(remoteChainID) > 256 || strings.ContainsAny(remoteChainID, "\x00\r\n") {
		return nil, errors.New("federated reader remote chain id is invalid")
	}
	rows, err := s.conn.QueryContext(ctx, `
		SELECT local_agent_id FROM federated_reader_restriction
		WHERE remote_chain_id=? ORDER BY local_agent_id`, remoteChainID)
	if err != nil {
		return nil, fmt.Errorf("list federated reader restrictions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var agentIDs []string
	for rows.Next() {
		var agentID string
		if err := rows.Scan(&agentID); err != nil {
			return nil, err
		}
		agentIDs = append(agentIDs, agentID)
		if len(agentIDs) > MaxFederatedReaderRestrictionsPerPeer {
			return nil, fmt.Errorf("stored federated reader restriction limit %d exceeded", MaxFederatedReaderRestrictionsPerPeer)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	out := make([]FederatedReaderRestriction, 0, len(agentIDs))
	for _, agentID := range agentIDs {
		restriction, err := s.GetFederatedReaderRestriction(ctx, remoteChainID, agentID)
		if err != nil {
			return nil, err
		}
		if restriction == nil {
			return nil, errors.New("federated reader restriction disappeared while listing")
		}
		out = append(out, *restriction)
	}
	return out, nil
}

func (s *SQLiteStore) listFederatedReaderDeniedDomains(
	ctx context.Context, remoteChainID, localAgentID string,
) ([]string, error) {
	rows, err := s.conn.QueryContext(ctx, `
		SELECT domain_tag FROM federated_reader_denied_domain
		WHERE remote_chain_id=? AND local_agent_id=? ORDER BY domain_tag`, remoteChainID, localAgentID)
	if err != nil {
		return nil, fmt.Errorf("list federated reader denied domains: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		out = append(out, domain)
		if len(out) > MaxFederatedReaderDeniedDomains {
			return nil, fmt.Errorf("stored federated reader denied-domain limit %d exceeded", MaxFederatedReaderDeniedDomains)
		}
	}
	return out, rows.Err()
}

// FederatedReaderAllows evaluates only the node-local exception overlay. The
// caller must separately enforce active ordinary-agent identity, peer export,
// agreement, and classification. Absence/revocation is the documented default
// allow; corrupt state and an unexpected active-generation mismatch return an
// error so callers fail closed.
func (s *SQLiteStore) FederatedReaderAllows(
	ctx context.Context, binding FederatedReaderBinding, localAgentID, domain string,
) (bool, error) {
	unlock := s.LockSyncPolicyRead()
	defer unlock()
	return s.FederatedReaderAllowsLocked(ctx, binding, localAgentID, domain)
}

// FederatedReaderAllowsLocked avoids a second RWMutex acquisition for
// federation callers that already hold LockSyncPolicyRead across the complete
// authorization-and-send decision.
func (s *SQLiteStore) FederatedReaderAllowsLocked(
	ctx context.Context, binding FederatedReaderBinding, localAgentID, domain string,
) (bool, error) {
	if err := canonicalFederatedReaderBinding(binding); err != nil {
		return false, err
	}
	if !isCanonicalAgentID(localAgentID) {
		return false, errors.New("federated reader local agent id must be canonical")
	}
	if err := s.requireFederatedReaderSyncControl(ctx, binding); err != nil {
		return false, err
	}
	permissions, err := canonicalPeerRBACDomains([]PeerRBACDomainPermission{{Domain: domain, Read: true}})
	if err != nil || len(permissions) != 1 {
		return false, errors.New("federated reader query domain is invalid")
	}
	restriction, err := s.GetFederatedReaderRestriction(ctx, binding.RemoteChainID, localAgentID)
	if err != nil {
		return false, err
	}
	if restriction == nil || restriction.State == FederatedReaderRestrictionStateRevoked {
		return true, nil
	}
	if !federatedReaderBindingMatches(*restriction, binding) {
		return false, ErrFederatedReaderRestrictionBindingMismatch
	}
	if restriction.DenyAll {
		return false, nil
	}
	for _, denied := range restriction.DeniedDomains {
		if federatedReaderDomainsOverlap(denied, domain) {
			return false, nil
		}
	}
	return true, nil
}

// ResetFederatedReaderRestrictionsForBinding is the controlled re-pair reset.
// It first proves the new sync_control generation, then revokes every active
// restriction bound to an older generation and advances each revision. The new
// connection therefore returns to its documented default-allow posture.
func (s *SQLiteStore) ResetFederatedReaderRestrictionsForBinding(
	ctx context.Context, binding FederatedReaderBinding,
) (int64, error) {
	if err := canonicalFederatedReaderBinding(binding); err != nil {
		return 0, err
	}
	releaseAuthorization := s.beginFederationAuthorizationMutation(binding.RemoteChainID)
	defer releaseAuthorization()
	unlock := s.LockSyncPolicyWrite()
	defer unlock()
	var affected int64
	err := s.RunInTx(ctx, func(txStore OffchainStore) error {
		tx := txStore.(*SQLiteStore)
		if err := tx.requireFederatedReaderSyncControl(ctx, binding); err != nil {
			return err
		}
		result, err := tx.conn.ExecContext(ctx, `
			UPDATE federated_reader_restriction
			SET state=?, revision=revision+1,
				updated_at=strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
			WHERE remote_chain_id=? AND state=?
				AND (peer_agent_id<>? OR policy_epoch<>? OR remote_ca_pin<>?)`,
			FederatedReaderRestrictionStateRevoked, binding.RemoteChainID,
			FederatedReaderRestrictionStateActive, binding.PeerAgentID,
			binding.PolicyEpoch, binding.RemoteCAPin)
		if err != nil {
			return fmt.Errorf("reset federated reader restrictions: %w", err)
		}
		affected, err = result.RowsAffected()
		return err
	})
	return affected, err
}
