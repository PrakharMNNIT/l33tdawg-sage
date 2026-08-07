package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	badger "github.com/dgraph-io/badger/v4"
)

const legacyUpgradeLineageAuditKey = "upgrade:lineage-repair:app-v22"

// LegacyUpgradeLineageRepairAudit is immutable consensus evidence that a
// validator quorum approved creation of an exact set of missing legacy applied
// records. Existing records are never replaced.
type LegacyUpgradeLineageRepairAudit struct {
	Schema             string                 `json:"schema"`
	GovernanceDomain   string                 `json:"governance_domain"`
	PriorLineageDigest string                 `json:"prior_lineage_digest"`
	ManifestDigest     string                 `json:"manifest_digest"`
	Manifest           string                 `json:"manifest"`
	ApprovedHeight     int64                  `json:"approved_height"`
	ProposalID         string                 `json:"proposal_id"`
	Records            []AppliedUpgradeRecord `json:"records"`
}

// ApplyLegacyUpgradeLineageRepair creates only absent applied-upgrade records
// and one immutable audit record in the caller's consensus transaction. Exact
// replay is idempotent; any pre-existing conflicting record fails closed.
func (s *BadgerStore) ApplyLegacyUpgradeLineageRepair(audit LegacyUpgradeLineageRepairAudit) error {
	if audit.Schema == "" || audit.GovernanceDomain == "" || audit.ManifestDigest == "" || audit.Manifest == "" ||
		audit.PriorLineageDigest == "" || audit.ApprovedHeight <= 0 || audit.ProposalID == "" ||
		len(audit.Records) == 0 {
		return errors.New("legacy upgrade lineage repair audit is incomplete")
	}
	payload, err := json.Marshal(audit)
	if err != nil {
		return fmt.Errorf("marshal legacy upgrade lineage audit: %w", err)
	}
	return s.update(func(txn *badger.Txn) error {
		if item, getErr := txn.Get([]byte(legacyUpgradeLineageAuditKey)); getErr == nil {
			var existing []byte
			if valueErr := item.Value(func(value []byte) error {
				existing = append(existing, value...)
				return nil
			}); valueErr != nil {
				return valueErr
			}
			if string(existing) == string(payload) {
				return nil
			}
			return errors.New("legacy upgrade lineage repair audit already exists with different content")
		} else if !errors.Is(getErr, badger.ErrKeyNotFound) {
			return getErr
		}

		for _, rec := range audit.Records {
			key := upgradeAppliedKey(rec.Name)
			if item, getErr := txn.Get(key); getErr == nil {
				var existing AppliedUpgradeRecord
				if valueErr := item.Value(func(value []byte) error { return json.Unmarshal(value, &existing) }); valueErr != nil {
					return fmt.Errorf("decode existing applied %s: %w", rec.Name, valueErr)
				}
				if existing == rec {
					continue
				}
				return fmt.Errorf("refuse to overwrite existing applied %s record", rec.Name)
			} else if !errors.Is(getErr, badger.ErrKeyNotFound) {
				return getErr
			}
			encoded, marshalErr := json.Marshal(rec)
			if marshalErr != nil {
				return marshalErr
			}
			if setErr := s.txnSet(txn, key, encoded); setErr != nil {
				return setErr
			}
		}
		return s.txnSet(txn, []byte(legacyUpgradeLineageAuditKey), payload)
	})
}

// ValidateLegacyUpgradeLineageRepairAudit verifies that the immutable repair
// receipt still binds the exact canonical manifest and every record it
// created. It is safe on states without a repair receipt.
func (s *BadgerStore) ValidateLegacyUpgradeLineageRepairAudit() error {
	audit, err := s.GetLegacyUpgradeLineageRepairAudit()
	if err != nil || audit == nil {
		return err
	}
	digest := sha256.Sum256([]byte(audit.Manifest))
	if hex.EncodeToString(digest[:]) != audit.ManifestDigest {
		return errors.New("legacy upgrade lineage repair manifest digest mismatch")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(audit.Manifest)); err != nil {
		return fmt.Errorf("decode legacy upgrade lineage repair manifest: %w", err)
	}
	if compact.String() != audit.Manifest {
		return errors.New("legacy upgrade lineage repair manifest is not canonical JSON")
	}
	var manifest struct {
		Schema             string `json:"schema"`
		GovernanceDomain   string `json:"governance_domain"`
		PriorLineageDigest string `json:"prior_lineage_digest"`
		Evidence           []struct {
			Version       uint64 `json:"version"`
			Name          string `json:"name"`
			AppliedHeight int64  `json:"applied_height"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal([]byte(audit.Manifest), &manifest); err != nil {
		return fmt.Errorf("decode legacy upgrade lineage repair manifest fields: %w", err)
	}
	if audit.Schema != manifest.Schema || audit.GovernanceDomain != manifest.GovernanceDomain ||
		audit.PriorLineageDigest != manifest.PriorLineageDigest {
		return errors.New("legacy upgrade lineage repair audit fields do not match its manifest")
	}
	if len(audit.Records) != len(manifest.Evidence) {
		return errors.New("legacy upgrade lineage repair audit record set does not match its manifest")
	}
	seen := make(map[string]struct{}, len(audit.Records))
	for i, expected := range audit.Records {
		if expected.Name == "" || expected.TargetAppVersion == 0 || expected.AppliedHeight <= 0 {
			return errors.New("legacy upgrade lineage repair audit contains an invalid record")
		}
		evidence := manifest.Evidence[i]
		if evidence.Name != expected.Name || evidence.Version != expected.TargetAppVersion ||
			evidence.AppliedHeight != expected.AppliedHeight {
			return errors.New("legacy upgrade lineage repair audit record order or content does not match its manifest")
		}
		if _, duplicate := seen[expected.Name]; duplicate {
			return fmt.Errorf("legacy upgrade lineage repair audit repeats %s", expected.Name)
		}
		seen[expected.Name] = struct{}{}
		actual, getErr := s.GetAppliedUpgrade(expected.Name)
		if getErr != nil {
			return getErr
		}
		if actual == nil || *actual != expected {
			return fmt.Errorf("legacy upgrade lineage repair record %s does not match its audit", expected.Name)
		}
	}
	return nil
}

func (s *BadgerStore) GetLegacyUpgradeLineageRepairAudit() (*LegacyUpgradeLineageRepairAudit, error) {
	var audit *LegacyUpgradeLineageRepairAudit
	err := s.view(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(legacyUpgradeLineageAuditKey))
		if err != nil {
			return err
		}
		return item.Value(func(value []byte) error {
			var decoded LegacyUpgradeLineageRepairAudit
			if err := json.Unmarshal(value, &decoded); err != nil {
				return err
			}
			audit = &decoded
			return nil
		})
	})
	if errors.Is(err, badger.ErrKeyNotFound) {
		return nil, nil
	}
	return audit, err
}
