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
	FederatedAgentExportStateActive  = "active"
	FederatedAgentExportStatePaused  = "paused"
	FederatedAgentExportStateRevoked = "revoked"

	MaxFederatedAgentExportsPerPeer       = 256
	MaxFederatedAgentExportDomainExcludes = MaxPeerRBACPolicyDomains
)

var (
	ErrFederatedAgentExportRevisionConflict = errors.New("federated agent export revision conflict")
	ErrFederatedAgentExportBindingMismatch  = errors.New("federated agent export agreement binding mismatch")
)

// FederatedAgentExport is the node-local declaration that one exact local
// agent is visible to one exact federated peer. An active export independently
// exposes that agent's current owned-domain tree for Read, subject to live
// ordinary-agent/ownership checks, this ceiling, and these exclusions. PeerRBAC
// remains an additive manual domain-only lane: it does not implicitly export a
// domain owner, and this snapshot does not materialize or rewrite PeerRBAC rows.
//
// The agreement fields freeze the JOIN generation which authorized the export.
// Readers must compare all three fields with the current active agreement.
// DomainExclusions is a complete, sorted deny list within the agent's otherwise
// exported owned domains. MaxClassification is an additional export ceiling;
// caller clearance and the federation agreement can only reduce it.
type FederatedAgentExport struct {
	RemoteChainID     string   `json:"remote_chain_id"`
	LocalAgentID      string   `json:"local_agent_id"`
	PeerAgentID       string   `json:"peer_agent_id"`
	PolicyEpoch       string   `json:"policy_epoch"`
	RemoteCAPin       string   `json:"remote_ca_pin"`
	MaxClassification uint8    `json:"max_classification"`
	DomainExclusions  []string `json:"domain_exclusions"`
	Revision          int64    `json:"revision"`
	State             string   `json:"state"`
}

func (s *SQLiteStore) migrateFederatedAgentExports(ctx context.Context) error {
	if _, err := s.writeExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS federated_agent_export (
		remote_chain_id       TEXT NOT NULL,
		local_agent_id        TEXT NOT NULL,
		peer_agent_id         TEXT NOT NULL,
		policy_epoch          TEXT NOT NULL,
		remote_ca_pin         TEXT NOT NULL,
		max_classification    INTEGER NOT NULL CHECK (max_classification BETWEEN 0 AND 4),
		revision              INTEGER NOT NULL CHECK (revision > 0),
		state                 TEXT NOT NULL CHECK (state IN ('active','paused','revoked')),
		updated_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
		PRIMARY KEY (remote_chain_id, local_agent_id)
	)`); err != nil {
		return fmt.Errorf("create federated agent export table: %w", err)
	}
	if _, err := s.writeExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS federated_agent_export_exclusion (
		remote_chain_id TEXT NOT NULL,
		local_agent_id  TEXT NOT NULL,
		domain_tag      TEXT NOT NULL,
		PRIMARY KEY (remote_chain_id, local_agent_id, domain_tag),
		FOREIGN KEY (remote_chain_id, local_agent_id)
			REFERENCES federated_agent_export(remote_chain_id, local_agent_id)
			ON DELETE CASCADE
	)`); err != nil {
		return fmt.Errorf("create federated agent export exclusion table: %w", err)
	}
	if _, err := s.writeExecContext(ctx, `
	CREATE INDEX IF NOT EXISTS idx_federated_agent_export_peer_state
	ON federated_agent_export(remote_chain_id, state, local_agent_id)`); err != nil {
		return fmt.Errorf("create federated agent export peer index: %w", err)
	}
	return nil
}

func canonicalFederatedAgentExport(export FederatedAgentExport) (FederatedAgentExport, error) {
	for label, value := range map[string]string{
		"remote chain id": export.RemoteChainID,
		"policy epoch":    export.PolicyEpoch,
	} {
		if value == "" || strings.TrimSpace(value) != value || len(value) > 256 ||
			strings.ContainsAny(value, "\x00\r\n") {
			return FederatedAgentExport{}, fmt.Errorf("federated agent export %s is invalid", label)
		}
	}
	if !isCanonicalAgentID(export.LocalAgentID) {
		return FederatedAgentExport{}, errors.New("federated agent export local agent id must be canonical")
	}
	if !isCanonicalAgentID(export.PeerAgentID) {
		return FederatedAgentExport{}, errors.New("federated agent export peer agent id must be canonical")
	}
	caPin, err := hex.DecodeString(export.RemoteCAPin)
	if err != nil || len(caPin) == 0 || export.RemoteCAPin != strings.ToLower(export.RemoteCAPin) {
		return FederatedAgentExport{}, errors.New("federated agent export remote CA pin must be a canonical non-empty hex digest")
	}
	if export.MaxClassification > 4 {
		return FederatedAgentExport{}, errors.New("federated agent export max classification must be between 0 and 4")
	}
	if export.Revision <= 0 {
		return FederatedAgentExport{}, errors.New("federated agent export revision must be positive")
	}
	switch export.State {
	case FederatedAgentExportStateActive, FederatedAgentExportStatePaused, FederatedAgentExportStateRevoked:
	default:
		return FederatedAgentExport{}, errors.New("federated agent export state is invalid")
	}
	if len(export.DomainExclusions) > MaxFederatedAgentExportDomainExcludes {
		return FederatedAgentExport{}, fmt.Errorf(
			"federated agent export is capped at %d domain exclusions",
			MaxFederatedAgentExportDomainExcludes,
		)
	}
	permissions := make([]PeerRBACDomainPermission, 0, len(export.DomainExclusions))
	seen := make(map[string]struct{}, len(export.DomainExclusions))
	for _, domain := range export.DomainExclusions {
		if _, duplicate := seen[domain]; duplicate {
			continue
		}
		seen[domain] = struct{}{}
		permissions = append(permissions, PeerRBACDomainPermission{Domain: domain, Read: true})
	}
	canonical, err := canonicalPeerRBACDomains(permissions)
	if err != nil {
		return FederatedAgentExport{}, fmt.Errorf("federated agent export exclusions: %w", err)
	}
	export.DomainExclusions = make([]string, len(canonical))
	for i := range canonical {
		export.DomainExclusions[i] = canonical[i].Domain
	}
	return export, nil
}

// PutFederatedAgentExportCAS commits a complete export snapshot when the exact
// stored revision still equals expectedRevision. It is the standalone store
// form; production federation control paths should use the bound variant.
func (s *SQLiteStore) PutFederatedAgentExportCAS(
	ctx context.Context,
	export FederatedAgentExport,
	expectedRevision int64,
) (*FederatedAgentExport, error) {
	return s.putFederatedAgentExportCAS(ctx, export, expectedRevision, false)
}

// PutBoundFederatedAgentExportCAS additionally requires the exact active
// sync_control JOIN generation to exist in the same SQLite transaction.
func (s *SQLiteStore) PutBoundFederatedAgentExportCAS(
	ctx context.Context,
	export FederatedAgentExport,
	expectedRevision int64,
) (*FederatedAgentExport, error) {
	return s.putFederatedAgentExportCAS(ctx, export, expectedRevision, true)
}

func (s *SQLiteStore) putFederatedAgentExportCAS(
	ctx context.Context,
	export FederatedAgentExport,
	expectedRevision int64,
	requireControl bool,
) (*FederatedAgentExport, error) {
	if s != nil && s.db == nil {
		return nil, errors.New("federated agent export mutation is not permitted inside SQLite transaction")
	}
	canonical, err := canonicalFederatedAgentExport(export)
	if err != nil {
		return nil, err
	}
	if expectedRevision < 0 || canonical.Revision != expectedRevision+1 {
		return nil, fmt.Errorf("%w: next revision must equal expected revision plus one", ErrFederatedAgentExportRevisionConflict)
	}

	releaseAuthorization := s.beginFederationAuthorizationMutation(canonical.RemoteChainID)
	defer releaseAuthorization()
	unlock := s.LockSyncPolicyWrite()
	defer unlock()

	err = s.RunInTx(ctx, func(txStore OffchainStore) error {
		tx := txStore.(*SQLiteStore)
		if requireControl {
			var peerAgentID, policyEpoch, remoteCAPin, bindingState string
			controlErr := tx.conn.QueryRowContext(ctx, `
				SELECT peer_agent_id, policy_epoch, remote_ca_pin, binding_state
				FROM sync_control WHERE remote_chain_id=?`, canonical.RemoteChainID).
				Scan(&peerAgentID, &policyEpoch, &remoteCAPin, &bindingState)
			switch {
			case errors.Is(controlErr, sql.ErrNoRows):
				return fmt.Errorf("%w: active sync control is required", ErrFederatedAgentExportBindingMismatch)
			case controlErr != nil:
				return fmt.Errorf("read federated agent export sync control: %w", controlErr)
			case bindingState != "active" || peerAgentID != canonical.PeerAgentID ||
				policyEpoch != canonical.PolicyEpoch || remoteCAPin != canonical.RemoteCAPin:
				return fmt.Errorf("%w: sync control does not match export", ErrFederatedAgentExportBindingMismatch)
			}
		}

		var currentRevision int64
		var currentState, currentPeer, currentEpoch, currentCAPin string
		getErr := tx.conn.QueryRowContext(ctx, `
			SELECT revision, state, peer_agent_id, policy_epoch, remote_ca_pin
			FROM federated_agent_export
			WHERE remote_chain_id=? AND local_agent_id=?`,
			canonical.RemoteChainID, canonical.LocalAgentID).
			Scan(&currentRevision, &currentState, &currentPeer, &currentEpoch, &currentCAPin)
		switch {
		case errors.Is(getErr, sql.ErrNoRows) && expectedRevision != 0:
			return ErrFederatedAgentExportRevisionConflict
		case getErr == nil && currentRevision != expectedRevision:
			return ErrFederatedAgentExportRevisionConflict
		case getErr != nil && !errors.Is(getErr, sql.ErrNoRows):
			return fmt.Errorf("read federated agent export revision: %w", getErr)
		}
		if getErr == nil && currentState != FederatedAgentExportStateRevoked &&
			(currentPeer != canonical.PeerAgentID || currentEpoch != canonical.PolicyEpoch || currentCAPin != canonical.RemoteCAPin) {
			return ErrFederatedAgentExportBindingMismatch
		}
		if getErr == nil && currentState == FederatedAgentExportStateRevoked &&
			canonical.State != FederatedAgentExportStateRevoked &&
			currentPeer == canonical.PeerAgentID && currentEpoch == canonical.PolicyEpoch &&
			currentCAPin == canonical.RemoteCAPin {
			return fmt.Errorf("%w: revoked export requires a fresh agreement generation", ErrFederatedAgentExportBindingMismatch)
		}
		if errors.Is(getErr, sql.ErrNoRows) {
			var totalCount int
			if countErr := tx.conn.QueryRowContext(ctx, `
				SELECT COUNT(*) FROM federated_agent_export
				WHERE remote_chain_id=?`, canonical.RemoteChainID).Scan(&totalCount); countErr != nil {
				return fmt.Errorf("count all federated agent exports: %w", countErr)
			}
			if totalCount >= MaxFederatedAgentExportsPerPeer {
				return fmt.Errorf("federated agent export limit %d reached", MaxFederatedAgentExportsPerPeer)
			}
		}

		if (errors.Is(getErr, sql.ErrNoRows) || currentState == FederatedAgentExportStateRevoked) &&
			canonical.State != FederatedAgentExportStateRevoked {
			var liveCount int
			if countErr := tx.conn.QueryRowContext(ctx, `
				SELECT COUNT(*) FROM federated_agent_export
				WHERE remote_chain_id=? AND state<>?`, canonical.RemoteChainID,
				FederatedAgentExportStateRevoked).Scan(&liveCount); countErr != nil {
				return fmt.Errorf("count federated agent exports: %w", countErr)
			}
			if liveCount >= MaxFederatedAgentExportsPerPeer {
				return fmt.Errorf("federated agent export limit %d reached", MaxFederatedAgentExportsPerPeer)
			}
		}

		if _, execErr := tx.conn.ExecContext(ctx, `
			INSERT INTO federated_agent_export (
				remote_chain_id, local_agent_id, peer_agent_id, policy_epoch,
				remote_ca_pin, max_classification, revision, state, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
			ON CONFLICT(remote_chain_id, local_agent_id) DO UPDATE SET
				peer_agent_id=excluded.peer_agent_id,
				policy_epoch=excluded.policy_epoch,
				remote_ca_pin=excluded.remote_ca_pin,
				max_classification=excluded.max_classification,
				revision=excluded.revision,
				state=excluded.state,
				updated_at=excluded.updated_at`,
			canonical.RemoteChainID, canonical.LocalAgentID, canonical.PeerAgentID,
			canonical.PolicyEpoch, canonical.RemoteCAPin, canonical.MaxClassification,
			canonical.Revision, canonical.State); execErr != nil {
			return fmt.Errorf("upsert federated agent export: %w", execErr)
		}
		if _, execErr := tx.conn.ExecContext(ctx, `
			DELETE FROM federated_agent_export_exclusion
			WHERE remote_chain_id=? AND local_agent_id=?`,
			canonical.RemoteChainID, canonical.LocalAgentID); execErr != nil {
			return fmt.Errorf("replace federated agent export exclusions: %w", execErr)
		}
		for _, domain := range canonical.DomainExclusions {
			if _, execErr := tx.conn.ExecContext(ctx, `
				INSERT INTO federated_agent_export_exclusion (
					remote_chain_id, local_agent_id, domain_tag
				) VALUES (?, ?, ?)`, canonical.RemoteChainID, canonical.LocalAgentID,
				domain); execErr != nil {
				return fmt.Errorf("insert federated agent export exclusion %q: %w", domain, execErr)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.GetFederatedAgentExport(ctx, canonical.RemoteChainID, canonical.LocalAgentID)
}

// GetFederatedAgentExport returns nil,nil only when the exact peer/agent key
// has never been configured. Revoked snapshots remain readable for audit and
// monotonic revision enforcement.
func (s *SQLiteStore) GetFederatedAgentExport(
	ctx context.Context,
	remoteChainID, localAgentID string,
) (*FederatedAgentExport, error) {
	var export FederatedAgentExport
	var maxClassification int
	err := s.conn.QueryRowContext(ctx, `
		SELECT remote_chain_id, local_agent_id, peer_agent_id, policy_epoch,
			remote_ca_pin, max_classification, revision, state
		FROM federated_agent_export
		WHERE remote_chain_id=? AND local_agent_id=?`, remoteChainID, localAgentID).
		Scan(&export.RemoteChainID, &export.LocalAgentID, &export.PeerAgentID,
			&export.PolicyEpoch, &export.RemoteCAPin, &maxClassification,
			&export.Revision, &export.State)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get federated agent export: %w", err)
	}
	if maxClassification < 0 || maxClassification > 4 {
		return nil, errors.New("stored federated agent export classification is invalid")
	}
	export.MaxClassification = uint8(maxClassification)
	exclusions, err := s.listFederatedAgentExportExclusions(ctx, remoteChainID, localAgentID)
	if err != nil {
		return nil, err
	}
	export.DomainExclusions = exclusions
	canonical, err := canonicalFederatedAgentExport(export)
	if err != nil {
		return nil, fmt.Errorf("stored federated agent export is invalid: %w", err)
	}
	return &canonical, nil
}

// ListFederatedAgentExports returns every state for one peer, including
// revoked rows. Authorization callers must select active rows and compare the
// frozen agreement binding; presentation callers can retain revoked history.
func (s *SQLiteStore) ListFederatedAgentExports(
	ctx context.Context,
	remoteChainID string,
) ([]FederatedAgentExport, error) {
	rows, err := s.conn.QueryContext(ctx, `
		SELECT local_agent_id FROM federated_agent_export
		WHERE remote_chain_id=? ORDER BY local_agent_id`, remoteChainID)
	if err != nil {
		return nil, fmt.Errorf("list federated agent export ids: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
		if len(ids) > MaxFederatedAgentExportsPerPeer {
			_ = rows.Close()
			return nil, fmt.Errorf("stored federated agent export limit %d exceeded", MaxFederatedAgentExportsPerPeer)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	out := make([]FederatedAgentExport, 0, len(ids))
	for _, id := range ids {
		export, err := s.GetFederatedAgentExport(ctx, remoteChainID, id)
		if err != nil {
			return nil, err
		}
		if export == nil {
			return nil, errors.New("federated agent export disappeared while listing")
		}
		out = append(out, *export)
	}
	return out, nil
}

// ListActiveFederatedAgentExports returns only active export snapshots. The
// caller must still compare the frozen binding with the current agreement and
// resolve each agent's live ordinary-agent status and current domain ownership.
func (s *SQLiteStore) ListActiveFederatedAgentExports(
	ctx context.Context,
	remoteChainID string,
) ([]FederatedAgentExport, error) {
	all, err := s.ListFederatedAgentExports(ctx, remoteChainID)
	if err != nil {
		return nil, err
	}
	active := make([]FederatedAgentExport, 0, len(all))
	for _, export := range all {
		if export.State == FederatedAgentExportStateActive {
			active = append(active, export)
		}
	}
	return active, nil
}

func (s *SQLiteStore) listFederatedAgentExportExclusions(
	ctx context.Context,
	remoteChainID, localAgentID string,
) ([]string, error) {
	rows, err := s.conn.QueryContext(ctx, `
		SELECT domain_tag FROM federated_agent_export_exclusion
		WHERE remote_chain_id=? AND local_agent_id=? ORDER BY domain_tag`,
		remoteChainID, localAgentID)
	if err != nil {
		return nil, fmt.Errorf("list federated agent export exclusions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]string, 0)
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		out = append(out, domain)
		if len(out) > MaxFederatedAgentExportDomainExcludes {
			return nil, fmt.Errorf(
				"stored federated agent export exclusion limit %d exceeded",
				MaxFederatedAgentExportDomainExcludes,
			)
		}
	}
	return out, rows.Err()
}

// ResetFederatedAgentExportsForBinding retires membership from an older JOIN
// generation after the new sync_control binding is active. Membership never
// carries across trust re-pairing implicitly; the operator must explicitly
// export agents again on the fresh connection.
func (s *SQLiteStore) ResetFederatedAgentExportsForBinding(
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
			UPDATE federated_agent_export
			SET state=?, revision=revision+1,
				updated_at=strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
			WHERE remote_chain_id=? AND state<>?
				AND (peer_agent_id<>? OR policy_epoch<>? OR remote_ca_pin<>?)`,
			FederatedAgentExportStateRevoked, binding.RemoteChainID,
			FederatedAgentExportStateRevoked, binding.PeerAgentID,
			binding.PolicyEpoch, binding.RemoteCAPin)
		if err != nil {
			return fmt.Errorf("reset federated agent exports: %w", err)
		}
		affected, err = result.RowsAffected()
		return err
	})
	return affected, err
}
