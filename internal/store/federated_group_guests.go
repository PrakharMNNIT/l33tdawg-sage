package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	FederatedGuestStateActive         = "active"
	FederatedGuestStatePaused         = "paused"
	FederatedGuestStateRevoked        = "revoked"
	FederatedGuestStateRebindRequired = "rebind_required"
	FederatedGuestAuthorityRoot       = "root"
	FederatedGuestAuthorityAdmin      = "admin"
	MaxFederatedGuestGroupsPerAgent   = AppV23MaxGroupsPerAgent
	MaxFederatedGuestIdentities       = 256
)

// FederatedGuestIdentity is the bounded local inventory key for one foreign
// agent with at least one non-revoked Linked-reader row. It is a browsing hint,
// never a substitute for the live authenticated target verification required
// when a new link is attached.
type FederatedGuestIdentity struct {
	RemoteChainID string `json:"remote_chain_id"`
	RemoteAgentID string `json:"remote_agent_id"`
	LinkCount     int    `json:"link_count"`
}

// FederatedGroupGuest is a node-local, read-only capability link from one
// exact foreign agent to one local group. It is not group membership and can
// never authorize Write or Copy. AgreementBindingDigest makes the link stale
// after a federation ceremony or policy-generation change.
type FederatedGroupGuest struct {
	GroupID                     string `json:"group_id"`
	RemoteChainID               string `json:"remote_chain_id"`
	RemoteAgentID               string `json:"remote_agent_id"`
	AgreementBindingDigest      string `json:"agreement_binding_digest"`
	MaxClassification           uint8  `json:"max_classification"`
	Revision                    int64  `json:"revision"`
	State                       string `json:"state"`
	AuthorizedBy                string `json:"authorized_by"`
	AuthorityKind               string `json:"authority_kind,omitempty"`
	AuthorityRootGeneration     uint64 `json:"authority_root_generation,omitempty"`
	AuthorityRoleRevision       uint64 `json:"authority_role_revision,omitempty"`
	AuthorityEnrollmentRevision uint64 `json:"authority_enrollment_revision,omitempty"`
	Signature                   []byte `json:"signature"`
}

// FederatedAdminElevationUse is the already-verified projection of one
// off-consensus root elevation. SQLite consumes it atomically with the guest
// CAS; it is intentionally unrelated to consensus AppV23ElevationUse.
type FederatedAdminElevationUse struct {
	Scope          string
	RootGeneration uint64
	AdminID        string
	Nonce          string
	ExpiresAt      int64
}

type federatedGroupGuestSignedFields struct {
	Purpose                     string `json:"purpose"`
	GroupID                     string `json:"group_id"`
	RemoteChainID               string `json:"remote_chain_id"`
	RemoteAgentID               string `json:"remote_agent_id"`
	AgreementBindingDigest      string `json:"agreement_binding_digest"`
	MaxClassification           uint8  `json:"max_classification"`
	Revision                    int64  `json:"revision"`
	State                       string `json:"state"`
	AuthorizedBy                string `json:"authorized_by"`
	AuthorityKind               string `json:"authority_kind,omitempty"`
	AuthorityRootGeneration     uint64 `json:"authority_root_generation,omitempty"`
	AuthorityRoleRevision       uint64 `json:"authority_role_revision,omitempty"`
	AuthorityEnrollmentRevision uint64 `json:"authority_enrollment_revision,omitempty"`
}

func (g FederatedGroupGuest) SigningBytes() ([]byte, error) {
	return json.Marshal(federatedGroupGuestSignedFields{
		Purpose:                     "sage-federated-group-guest-v23",
		GroupID:                     g.GroupID,
		RemoteChainID:               g.RemoteChainID,
		RemoteAgentID:               g.RemoteAgentID,
		AgreementBindingDigest:      g.AgreementBindingDigest,
		MaxClassification:           g.MaxClassification,
		Revision:                    g.Revision,
		State:                       g.State,
		AuthorizedBy:                g.AuthorizedBy,
		AuthorityKind:               g.AuthorityKind,
		AuthorityRootGeneration:     g.AuthorityRootGeneration,
		AuthorityRoleRevision:       g.AuthorityRoleRevision,
		AuthorityEnrollmentRevision: g.AuthorityEnrollmentRevision,
	})
}

func SignFederatedGroupGuest(g *FederatedGroupGuest, key ed25519.PrivateKey) error {
	if g == nil {
		return errors.New("federated guest is required")
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return errors.New("valid Ed25519 operator key is required")
	}
	g.AuthorizedBy = hex.EncodeToString(pub)
	body, err := g.SigningBytes()
	if err != nil {
		return err
	}
	g.Signature = ed25519.Sign(key, body)
	return nil
}

func validateFederatedGroupGuest(g FederatedGroupGuest) error {
	for label, value := range map[string]string{
		"group id":        g.GroupID,
		"remote chain id": g.RemoteChainID,
	} {
		if value == "" || value != strings.TrimSpace(value) || len(value) > 256 ||
			strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("federated guest %s is invalid", label)
		}
	}
	for label, value := range map[string]string{
		"remote agent id": g.RemoteAgentID,
		"authorized by":   g.AuthorizedBy,
	} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != ed25519.PublicKeySize || value != strings.ToLower(value) {
			return fmt.Errorf("federated guest %s must be a canonical Ed25519 agent id", label)
		}
	}
	digest, err := hex.DecodeString(g.AgreementBindingDigest)
	if err != nil || len(digest) != 32 || g.AgreementBindingDigest != strings.ToLower(g.AgreementBindingDigest) {
		return errors.New("federated guest agreement binding must be a canonical SHA-256 digest")
	}
	if g.MaxClassification > 4 {
		return errors.New("federated guest max classification must be between 0 and 4")
	}
	if g.Revision <= 0 {
		return errors.New("federated guest revision must be positive")
	}
	switch g.State {
	case FederatedGuestStateActive, FederatedGuestStatePaused, FederatedGuestStateRevoked, FederatedGuestStateRebindRequired:
	default:
		return errors.New("federated guest state is invalid")
	}
	switch g.AuthorityKind {
	case "":
		if g.AuthorityRootGeneration != 0 ||
			g.AuthorityRoleRevision != 0 ||
			g.AuthorityEnrollmentRevision != 0 {
			return errors.New("legacy federated guest authority metadata is invalid")
		}
	case FederatedGuestAuthorityRoot:
		if g.AuthorityRootGeneration == 0 ||
			g.AuthorityRoleRevision != 0 ||
			g.AuthorityEnrollmentRevision != 0 {
			return errors.New("federated Root authority metadata is invalid")
		}
	case FederatedGuestAuthorityAdmin:
		if g.AuthorityRootGeneration == 0 ||
			g.AuthorityRoleRevision == 0 ||
			g.AuthorityEnrollmentRevision == 0 {
			return errors.New("federated Admin authority metadata is invalid")
		}
	default:
		return errors.New("federated guest authority kind is invalid")
	}
	if len(g.Signature) != ed25519.SignatureSize {
		return errors.New("federated guest signature is invalid")
	}
	body, err := g.SigningBytes()
	if err != nil {
		return err
	}
	pub, _ := hex.DecodeString(g.AuthorizedBy)
	if !ed25519.Verify(ed25519.PublicKey(pub), body, g.Signature) {
		return errors.New("federated guest signature verification failed")
	}
	return nil
}

// VerifyFederatedGroupGuest verifies both structural invariants and the
// operator signature. Federation transport repeats this check even when its
// store implementation already validates rows, keeping interface fakes and
// alternate stores fail-closed.
func VerifyFederatedGroupGuest(g FederatedGroupGuest) error {
	return validateFederatedGroupGuest(g)
}

func (s *SQLiteStore) migrateFederatedGroupGuests(ctx context.Context) error {
	if _, err := s.writeExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS federated_group_guest (
		group_id                    TEXT NOT NULL,
		remote_chain_id             TEXT NOT NULL,
		remote_agent_id             TEXT NOT NULL,
		agreement_binding_digest    TEXT NOT NULL,
		max_classification          INTEGER NOT NULL CHECK (max_classification BETWEEN 0 AND 4),
		revision                    INTEGER NOT NULL CHECK (revision > 0),
		state                       TEXT NOT NULL CHECK (state IN ('active','paused','revoked','rebind_required')),
		authorized_by               TEXT NOT NULL,
		authority_kind              TEXT NOT NULL DEFAULT '',
		authority_root_generation   INTEGER NOT NULL DEFAULT 0,
		authority_role_revision     INTEGER NOT NULL DEFAULT 0,
		authority_enrollment_revision INTEGER NOT NULL DEFAULT 0,
		signature                   BLOB NOT NULL,
		updated_at                  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
		PRIMARY KEY (group_id, remote_chain_id, remote_agent_id)
	)`); err != nil {
		return fmt.Errorf("create federated group guest table: %w", err)
	}
	for column, statement := range map[string]string{
		"authority_kind":                `ALTER TABLE federated_group_guest ADD COLUMN authority_kind TEXT NOT NULL DEFAULT ''`,
		"authority_root_generation":     `ALTER TABLE federated_group_guest ADD COLUMN authority_root_generation INTEGER NOT NULL DEFAULT 0`,
		"authority_role_revision":       `ALTER TABLE federated_group_guest ADD COLUMN authority_role_revision INTEGER NOT NULL DEFAULT 0`,
		"authority_enrollment_revision": `ALTER TABLE federated_group_guest ADD COLUMN authority_enrollment_revision INTEGER NOT NULL DEFAULT 0`,
	} {
		if err := s.addSQLiteColumnIfMissing(ctx, "federated_group_guest", column, statement); err != nil {
			return err
		}
	}
	if _, err := s.writeExecContext(ctx, `
	CREATE INDEX IF NOT EXISTS idx_federated_group_guest_agent
	ON federated_group_guest(remote_chain_id, remote_agent_id, state)`); err != nil {
		return fmt.Errorf("create federated group guest index: %w", err)
	}
	if _, err := s.writeExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS federated_admin_elevation_nonce (
		scope             TEXT NOT NULL,
		root_generation   INTEGER NOT NULL,
		admin_id          TEXT NOT NULL,
		nonce              TEXT NOT NULL,
		expires_at         INTEGER NOT NULL,
		consumed_at        INTEGER NOT NULL,
		PRIMARY KEY (scope, root_generation, admin_id, nonce)
	)`); err != nil {
		return fmt.Errorf("create federated admin elevation nonce table: %w", err)
	}
	return nil
}

// PutFederatedGroupGuest stores a complete signed snapshot. Revisions are
// monotonic for the exact (group, chain, agent) key; equal-revision replacement
// is allowed only when every signed byte is identical.
func (s *SQLiteStore) PutFederatedGroupGuest(ctx context.Context, guest FederatedGroupGuest) error {
	if s != nil && s.db == nil {
		return errors.New(
			"federated guest authorization mutation is not permitted inside SQLite transaction",
		)
	}
	if err := validateFederatedGroupGuest(guest); err != nil {
		return err
	}
	releaseAuthorization :=
		s.beginFederationAuthorizationMutation(guest.RemoteChainID)
	defer releaseAuthorization()
	unlock := s.LockSyncPolicyWrite()
	defer unlock()
	return s.PutFederatedGroupGuestLocked(ctx, guest)
}

// PutFederatedGroupGuestLocked is the policy-lease-aware form used when a
// federation Manager must atomically bind a guest snapshot to the current
// agreement/policy generation. The caller MUST hold LockSyncPolicyWrite.
func (s *SQLiteStore) PutFederatedGroupGuestLocked(ctx context.Context, guest FederatedGroupGuest) error {
	if err := validateFederatedGroupGuest(guest); err != nil {
		return err
	}
	return s.RunInTx(ctx, func(txStore OffchainStore) error {
		tx := txStore.(*SQLiteStore)
		var existingRevision int64
		var existingSignature []byte
		var existingState string
		err := tx.conn.QueryRowContext(ctx, `
			SELECT revision, signature, state FROM federated_group_guest
			WHERE group_id=? AND remote_chain_id=? AND remote_agent_id=?`,
			guest.GroupID, guest.RemoteChainID, guest.RemoteAgentID).
			Scan(&existingRevision, &existingSignature, &existingState)
		switch {
		case err == nil && guest.Revision < existingRevision:
			return errors.New("federated guest revision rollback refused")
		case err == nil && guest.Revision == existingRevision &&
			!bytes.Equal(existingSignature, guest.Signature):
			return errors.New("federated guest equal-revision replacement refused")
		case err != nil && !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("read federated guest revision: %w", err)
		}
		if (errors.Is(err, sql.ErrNoRows) || existingState == FederatedGuestStateRevoked) &&
			guest.State != FederatedGuestStateRevoked {
			var liveCount int
			if countErr := tx.conn.QueryRowContext(ctx, `
				SELECT COUNT(*) FROM federated_group_guest
				WHERE remote_chain_id=? AND remote_agent_id=? AND state<>?`,
				guest.RemoteChainID, guest.RemoteAgentID, FederatedGuestStateRevoked).
				Scan(&liveCount); countErr != nil {
				return fmt.Errorf("count federated guest groups: %w", countErr)
			}
			if liveCount >= MaxFederatedGuestGroupsPerAgent {
				return fmt.Errorf("federated guest group limit %d reached", MaxFederatedGuestGroupsPerAgent)
			}
		}
		_, err = tx.conn.ExecContext(ctx, `
			INSERT INTO federated_group_guest (
				group_id, remote_chain_id, remote_agent_id, agreement_binding_digest,
				max_classification, revision, state, authorized_by,
				authority_kind, authority_root_generation, authority_role_revision,
				authority_enrollment_revision, signature, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
			ON CONFLICT(group_id, remote_chain_id, remote_agent_id) DO UPDATE SET
				agreement_binding_digest=excluded.agreement_binding_digest,
				max_classification=excluded.max_classification,
				revision=excluded.revision, state=excluded.state,
				authorized_by=excluded.authorized_by,
				authority_kind=excluded.authority_kind,
				authority_root_generation=excluded.authority_root_generation,
				authority_role_revision=excluded.authority_role_revision,
				authority_enrollment_revision=excluded.authority_enrollment_revision,
				signature=excluded.signature,
				updated_at=excluded.updated_at`,
			guest.GroupID, guest.RemoteChainID, guest.RemoteAgentID, guest.AgreementBindingDigest,
			guest.MaxClassification, guest.Revision, guest.State, guest.AuthorizedBy,
			guest.AuthorityKind, guest.AuthorityRootGeneration, guest.AuthorityRoleRevision,
			guest.AuthorityEnrollmentRevision, guest.Signature)
		return err
	})
}

func (s *SQLiteStore) GetFederatedGroupGuest(ctx context.Context, groupID, remoteChainID, remoteAgentID string) (*FederatedGroupGuest, error) {
	var guest FederatedGroupGuest
	err := s.conn.QueryRowContext(ctx, `
		SELECT group_id, remote_chain_id, remote_agent_id, agreement_binding_digest,
			max_classification, revision, state, authorized_by,
			authority_kind, authority_root_generation, authority_role_revision,
			authority_enrollment_revision, signature
		FROM federated_group_guest
		WHERE group_id=? AND remote_chain_id=? AND remote_agent_id=?`,
		groupID, remoteChainID, remoteAgentID).
		Scan(&guest.GroupID, &guest.RemoteChainID, &guest.RemoteAgentID,
			&guest.AgreementBindingDigest, &guest.MaxClassification, &guest.Revision,
			&guest.State, &guest.AuthorizedBy, &guest.AuthorityKind,
			&guest.AuthorityRootGeneration, &guest.AuthorityRoleRevision,
			&guest.AuthorityEnrollmentRevision, &guest.Signature)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := validateFederatedGroupGuest(guest); err != nil {
		return nil, fmt.Errorf("stored federated guest is invalid: %w", err)
	}
	return &guest, nil
}

// CommitFederatedGroupGuestLocked performs the exact-revision guest update and
// optional promoted-Admin elevation replay consumption in one SQLite
// transaction. Caller lock order is agreement mutation -> policy write ->
// Badger authorization read -> this SQL transaction.
func (s *SQLiteStore) CommitFederatedGroupGuestLocked(
	ctx context.Context,
	guest FederatedGroupGuest,
	expectedRevision int64,
	elevation *FederatedAdminElevationUse,
	now int64,
) error {
	if err := validateFederatedGroupGuest(guest); err != nil {
		return err
	}
	if expectedRevision < 0 || guest.Revision != expectedRevision+1 {
		return errors.New("federated guest expected revision is invalid")
	}
	return s.RunInTx(ctx, func(txStore OffchainStore) error {
		tx := txStore.(*SQLiteStore)
		var currentRevision int64
		var currentState string
		err := tx.conn.QueryRowContext(ctx, `
			SELECT revision, state FROM federated_group_guest
			WHERE group_id=? AND remote_chain_id=? AND remote_agent_id=?`,
			guest.GroupID, guest.RemoteChainID, guest.RemoteAgentID).
			Scan(&currentRevision, &currentState)
		switch {
		case errors.Is(err, sql.ErrNoRows) && expectedRevision != 0:
			return ErrAppV23RevisionConflict
		case err == nil && currentRevision != expectedRevision:
			return ErrAppV23RevisionConflict
		case err != nil && !errors.Is(err, sql.ErrNoRows):
			return err
		}
		if (errors.Is(err, sql.ErrNoRows) || currentState == FederatedGuestStateRevoked) &&
			guest.State != FederatedGuestStateRevoked {
			var liveCount int
			if countErr := tx.conn.QueryRowContext(ctx, `
				SELECT COUNT(*) FROM federated_group_guest
				WHERE remote_chain_id=? AND remote_agent_id=? AND state<>?`,
				guest.RemoteChainID, guest.RemoteAgentID, FederatedGuestStateRevoked).
				Scan(&liveCount); countErr != nil {
				return countErr
			}
			if liveCount >= MaxFederatedGuestGroupsPerAgent {
				return fmt.Errorf("federated guest group limit %d reached", MaxFederatedGuestGroupsPerAgent)
			}
		}
		if elevation != nil {
			if elevation.Scope != "sage-federated-guest-admin-v23" ||
				elevation.RootGeneration == 0 || elevation.AdminID != guest.AuthorizedBy ||
				elevation.ExpiresAt < now {
				return errors.New("federated Admin elevation is invalid or expired")
			}
			nonce, nonceErr := hex.DecodeString(elevation.Nonce)
			if nonceErr != nil || len(nonce) != 16 || elevation.Nonce != strings.ToLower(elevation.Nonce) {
				return errors.New("federated Admin elevation nonce is invalid")
			}
			if _, deleteErr := tx.conn.ExecContext(ctx, `
				DELETE FROM federated_admin_elevation_nonce WHERE expires_at < ?`, now-600); deleteErr != nil {
				return deleteErr
			}
			if _, insertErr := tx.conn.ExecContext(ctx, `
				INSERT INTO federated_admin_elevation_nonce (
					scope, root_generation, admin_id, nonce, expires_at, consumed_at
				) VALUES (?, ?, ?, ?, ?, ?)`,
				elevation.Scope, elevation.RootGeneration, elevation.AdminID,
				elevation.Nonce, elevation.ExpiresAt, now); insertErr != nil {
				return errors.New("federated Admin elevation replay refused")
			}
		}
		_, err = tx.conn.ExecContext(ctx, `
			INSERT INTO federated_group_guest (
				group_id, remote_chain_id, remote_agent_id, agreement_binding_digest,
				max_classification, revision, state, authorized_by,
				authority_kind, authority_root_generation, authority_role_revision,
				authority_enrollment_revision, signature, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
			ON CONFLICT(group_id, remote_chain_id, remote_agent_id) DO UPDATE SET
				agreement_binding_digest=excluded.agreement_binding_digest,
				max_classification=excluded.max_classification,
				revision=excluded.revision, state=excluded.state,
				authorized_by=excluded.authorized_by,
				authority_kind=excluded.authority_kind,
				authority_root_generation=excluded.authority_root_generation,
				authority_role_revision=excluded.authority_role_revision,
				authority_enrollment_revision=excluded.authority_enrollment_revision,
				signature=excluded.signature,
				updated_at=excluded.updated_at`,
			guest.GroupID, guest.RemoteChainID, guest.RemoteAgentID,
			guest.AgreementBindingDigest, guest.MaxClassification, guest.Revision,
			guest.State, guest.AuthorizedBy, guest.AuthorityKind,
			guest.AuthorityRootGeneration, guest.AuthorityRoleRevision,
			guest.AuthorityEnrollmentRevision, guest.Signature)
		return err
	})
}

// ListFederatedGroupGuests returns every signed link for an exact foreign
// identity. Callers must still check state, current agreement binding, signer,
// classification ceiling, and the local group resolver.
func (s *SQLiteStore) ListFederatedGroupGuests(ctx context.Context, remoteChainID, remoteAgentID string) ([]FederatedGroupGuest, error) {
	rows, err := s.conn.QueryContext(ctx, `
		SELECT group_id, remote_chain_id, remote_agent_id, agreement_binding_digest,
			max_classification, revision, state, authorized_by,
			authority_kind, authority_root_generation, authority_role_revision,
			authority_enrollment_revision, signature
		FROM federated_group_guest
		WHERE remote_chain_id=? AND remote_agent_id=? AND state<>?
		ORDER BY group_id
		LIMIT ?`, remoteChainID, remoteAgentID, FederatedGuestStateRevoked,
		MaxFederatedGuestGroupsPerAgent+1)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []FederatedGroupGuest
	for rows.Next() {
		var g FederatedGroupGuest
		if err := rows.Scan(&g.GroupID, &g.RemoteChainID, &g.RemoteAgentID,
			&g.AgreementBindingDigest, &g.MaxClassification, &g.Revision,
			&g.State, &g.AuthorizedBy, &g.AuthorityKind,
			&g.AuthorityRootGeneration, &g.AuthorityRoleRevision,
			&g.AuthorityEnrollmentRevision, &g.Signature); err != nil {
			return nil, err
		}
		if err := validateFederatedGroupGuest(g); err != nil {
			return nil, fmt.Errorf("stored federated guest is invalid: %w", err)
		}
		out = append(out, g)
		if len(out) > MaxFederatedGuestGroupsPerAgent {
			return nil, fmt.Errorf("stored federated guest group limit %d exceeded", MaxFederatedGuestGroupsPerAgent)
		}
	}
	return out, rows.Err()
}

// ListFederatedGuestIdentities returns a bounded distinct inventory of exact
// foreign principals which already have a live local Linked-reader record.
// Callers must still enforce current local Admin authority, active agreement
// binding, and Root exclusion.
func (s *SQLiteStore) ListFederatedGuestIdentities(ctx context.Context) ([]FederatedGuestIdentity, error) {
	rows, err := s.conn.QueryContext(ctx, `
		SELECT remote_chain_id, remote_agent_id, COUNT(*)
		FROM federated_group_guest
		WHERE state<>?
		GROUP BY remote_chain_id, remote_agent_id
		ORDER BY remote_chain_id, remote_agent_id
		LIMIT ?`, FederatedGuestStateRevoked, MaxFederatedGuestIdentities+1)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]FederatedGuestIdentity, 0)
	for rows.Next() {
		var identity FederatedGuestIdentity
		if err := rows.Scan(
			&identity.RemoteChainID, &identity.RemoteAgentID, &identity.LinkCount,
		); err != nil {
			return nil, err
		}
		if identity.RemoteChainID == "" || !isCanonicalAgentID(identity.RemoteAgentID) ||
			identity.LinkCount <= 0 ||
			identity.LinkCount > MaxFederatedGuestGroupsPerAgent {
			return nil, errors.New("stored federated guest identity is invalid")
		}
		out = append(out, identity)
		if len(out) > MaxFederatedGuestIdentities {
			return nil, fmt.Errorf(
				"stored federated guest identity limit %d exceeded",
				MaxFederatedGuestIdentities,
			)
		}
	}
	return out, rows.Err()
}
