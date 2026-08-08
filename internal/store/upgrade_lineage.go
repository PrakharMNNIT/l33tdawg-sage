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
// validator quorum approved exact historical lineage coverage. Legacy v1
// receipts bind created records; v2 receipts bind virtual transition coverage
// and never create predecessor applied records.
type LegacyUpgradeLineageRepairAudit struct {
	Schema             string                        `json:"schema"`
	GovernanceDomain   string                        `json:"governance_domain"`
	PriorLineageDigest string                        `json:"prior_lineage_digest"`
	ManifestDigest     string                        `json:"manifest_digest"`
	Manifest           string                        `json:"manifest"`
	ApprovedHeight     int64                         `json:"approved_height"`
	ProposalID         string                        `json:"proposal_id"`
	Records            []AppliedUpgradeRecord        `json:"records"`
	Transitions        []LineageActivationTransition `json:"transitions,omitempty"`
}

// LineageActivationTransition is retained-Comet evidence for one real
// version.app jump. SubsumedVersions are virtual predecessor coverage only;
// they are never written as applied-upgrade records or used to arm fork gates.
type LineageActivationTransition struct {
	FromVersion      uint64   `json:"from_version"`
	ToVersion        uint64   `json:"to_version"`
	AppliedHeight    int64    `json:"applied_height"`
	Source           string   `json:"source"`
	BlockHash        string   `json:"block_hash,omitempty"`
	SubsumedVersions []uint64 `json:"subsumed_versions"`
}

// ApplyLegacyUpgradeLineageRepair creates only absent applied-upgrade records
// and one immutable audit record in the caller's consensus transaction. Exact
// replay is idempotent; any pre-existing conflicting record fails closed.
func (s *BadgerStore) ApplyLegacyUpgradeLineageRepair(audit LegacyUpgradeLineageRepairAudit) error {
	if audit.Schema == "sage-upgrade-lineage-repair/v2" {
		return errors.New("v2 virtual lineage audit may be installed only atomically with app-v22 activation")
	}
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

// MarkUpgradeAppliedWithLineageAudit atomically consumes the pending app-v22
// plan, writes its real activation record, and installs the immutable virtual
// lineage receipt. There is no crash window with an applied app-v22 record but
// no receipt (or vice versa).
func (s *BadgerStore) MarkUpgradeAppliedWithLineageAudit(name string, target uint64, height int64, audit LegacyUpgradeLineageRepairAudit) error {
	if audit.Schema != "sage-upgrade-lineage-repair/v2" || name == "" || target == 0 || height <= 0 {
		return errors.New("app-v22 lineage activation audit is incomplete")
	}
	digest := sha256.Sum256([]byte(audit.Manifest))
	if hex.EncodeToString(digest[:]) != audit.ManifestDigest {
		return errors.New("app-v22 lineage activation manifest digest mismatch")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(audit.Manifest)); err != nil || compact.String() != audit.Manifest {
		return errors.New("app-v22 lineage activation manifest is not canonical JSON")
	}
	if err := s.validateVirtualLineageAudit(&audit); err != nil {
		return err
	}
	auditPayload, err := json.Marshal(audit)
	if err != nil {
		return err
	}
	recPayload, err := json.Marshal(AppliedUpgradeRecord{Name: name, TargetAppVersion: target, AppliedHeight: height})
	if err != nil {
		return err
	}
	return s.update(func(txn *badger.Txn) error {
		planItem, getPlanErr := txn.Get(upgradePlanKey())
		if getPlanErr != nil {
			return fmt.Errorf("app-v22 lineage activation requires its pending plan: %w", getPlanErr)
		}
		var plan UpgradePlanRecord
		if err := planItem.Value(func(value []byte) error { return json.Unmarshal(value, &plan) }); err != nil {
			return err
		}
		if plan.Name != name || plan.TargetAppVersion != target || plan.ActivationHeight != height || plan.LineageRepair != audit.Manifest || plan.LineageProposalID != audit.ProposalID || plan.LineageApprovedHeight != audit.ApprovedHeight {
			return errors.New("app-v22 lineage activation audit does not match its pending plan")
		}
		if _, getErr := txn.Get([]byte(legacyUpgradeLineageAuditKey)); getErr == nil {
			return errors.New("legacy upgrade lineage repair audit already exists")
		} else if !errors.Is(getErr, badger.ErrKeyNotFound) {
			return getErr
		}
		if err := s.txnSet(txn, upgradeAppliedKey(name), recPayload); err != nil {
			return err
		}
		if err := s.txnSet(txn, []byte(legacyUpgradeLineageAuditKey), auditPayload); err != nil {
			return err
		}
		if err := s.txnDelete(txn, upgradePlanKey()); err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		return nil
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
	if audit.Schema == "sage-upgrade-lineage-repair/v2" {
		return s.validateVirtualLineageAudit(audit)
	}
	var manifest struct {
		Schema             string `json:"schema"`
		GovernanceDomain   string `json:"governance_domain"`
		PriorLineageDigest string `json:"prior_lineage_digest"`
		AnchorDigest       string `json:"anchor_digest"`
		AnchorAttestation  string `json:"anchor_attestation"`
		Evidence           []struct {
			Version       uint64 `json:"version"`
			Name          string `json:"name"`
			AppliedHeight int64  `json:"applied_height"`
			Source        string `json:"source"`
			BlockHash     string `json:"block_hash"`
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

func (s *BadgerStore) validateVirtualLineageAudit(audit *LegacyUpgradeLineageRepairAudit) error {
	var manifest struct {
		Schema             string `json:"schema"`
		GovernanceDomain   string `json:"governance_domain"`
		PriorLineageDigest string `json:"prior_lineage_digest"`
		AnchorDigest       string `json:"anchor_digest"`
		AnchorAttestation  string `json:"anchor_attestation"`
		Evidence           []struct {
			Version       uint64 `json:"version"`
			Name          string `json:"name"`
			AppliedHeight int64  `json:"applied_height"`
			Source        string `json:"source"`
			BlockHash     string `json:"block_hash"`
		} `json:"evidence"`
		Transitions []LineageActivationTransition `json:"transitions"`
	}
	if err := json.Unmarshal([]byte(audit.Manifest), &manifest); err != nil {
		return err
	}
	if manifest.Schema != audit.Schema || manifest.GovernanceDomain != audit.GovernanceDomain || manifest.PriorLineageDigest != audit.PriorLineageDigest {
		return errors.New("virtual lineage audit fields do not match its manifest")
	}
	if len(manifest.Transitions) != len(audit.Transitions) {
		return errors.New("virtual lineage transition set does not match its manifest")
	}
	for i := range manifest.Transitions {
		if !equalLineageTransition(manifest.Transitions[i], audit.Transitions[i]) {
			return errors.New("virtual lineage transition content does not match its manifest")
		}
	}
	expected := make([]AppliedUpgradeRecord, 0)
	expectedSource := ""
	validatedCoverage := make(map[uint64]int64)
	for _, e := range manifest.Evidence {
		if expectedSource == "" {
			expectedSource = e.Source
		}
		if e.Source != expectedSource || (e.Source != "comet-block-results" && e.Source != "legacy-anchor") {
			return errors.New("virtual lineage evidence uses mixed or unsupported sources")
		}
		if e.Source == "legacy-anchor" {
			decoded, err := hex.DecodeString(manifest.AnchorDigest)
			if e.BlockHash != "" || err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != manifest.AnchorDigest || manifest.AnchorAttestation != "operator-quorum-attested-unverified-history" {
				return errors.New("legacy-anchor virtual lineage evidence lacks canonical attestation")
			}
		} else {
			decoded, err := hex.DecodeString(e.BlockHash)
			if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != e.BlockHash {
				return errors.New("virtual lineage Comet evidence has invalid block hash")
			}
		}
		expected = append(expected, AppliedUpgradeRecord{Name: e.Name, TargetAppVersion: e.Version, AppliedHeight: e.AppliedHeight})
		validatedCoverage[e.Version] = e.AppliedHeight
	}
	for transitionIndex, tr := range manifest.Transitions {
		if expectedSource == "" {
			expectedSource = tr.Source
		}
		if tr.Source != expectedSource {
			return errors.New("virtual lineage evidence and transitions use mixed sources")
		}
		if tr.FromVersion >= tr.ToVersion || tr.ToVersion > 21 || tr.AppliedHeight <= 0 || len(tr.SubsumedVersions) == 0 || (tr.Source != "comet-block-results" && tr.Source != "legacy-anchor") {
			return errors.New("virtual lineage audit contains an invalid transition")
		}
		if transitionIndex > 0 && tr.AppliedHeight <= manifest.Transitions[transitionIndex-1].AppliedHeight {
			return errors.New("virtual lineage transition heights are not strictly increasing")
		}
		if tr.Source == "comet-block-results" {
			decoded, err := hex.DecodeString(tr.BlockHash)
			if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != tr.BlockHash {
				return errors.New("virtual lineage transition has invalid block hash")
			}
		} else {
			decoded, err := hex.DecodeString(manifest.AnchorDigest)
			if tr.BlockHash != "" || err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != manifest.AnchorDigest || manifest.AnchorAttestation != "operator-quorum-attested-unverified-history" {
				return errors.New("legacy-anchor virtual lineage transition lacks canonical attested anchor evidence")
			}
		}
		target, err := s.GetAppliedUpgrade(fmt.Sprintf("app-v%d", tr.ToVersion))
		if err != nil {
			return err
		}
		if target == nil && tr.ToVersion > 19 {
			return fmt.Errorf("virtual lineage ceremony target app-v%d is missing", tr.ToVersion)
		}
		if target != nil && (target.TargetAppVersion != tr.ToVersion || target.AppliedHeight != tr.AppliedHeight) {
			return fmt.Errorf("virtual lineage transition target app-v%d is not a real activation at height %d", tr.ToVersion, tr.AppliedHeight)
		}
		var latestPriorVersion uint64
		var latestPriorHeight int64
		for version := uint64(6); version < tr.ToVersion; version++ {
			rec, err := s.GetAppliedUpgrade(fmt.Sprintf("app-v%d", version))
			if err != nil {
				return err
			}
			if rec != nil && rec.AppliedHeight < tr.AppliedHeight && (rec.AppliedHeight > latestPriorHeight || rec.AppliedHeight == latestPriorHeight && version > latestPriorVersion) {
				latestPriorVersion, latestPriorHeight = version, rec.AppliedHeight
			}
			if height := validatedCoverage[version]; height > 0 && height < tr.AppliedHeight && (height > latestPriorHeight || height == latestPriorHeight && version > latestPriorVersion) {
				latestPriorVersion, latestPriorHeight = version, height
			}
		}
		if tr.FromVersion >= 6 && latestPriorVersion != tr.FromVersion {
			return fmt.Errorf("virtual lineage transition source app-v%d is not the latest validated prior point", tr.FromVersion)
		}
		if tr.FromVersion < 6 && latestPriorVersion != 0 {
			return fmt.Errorf("virtual lineage genesis transition has later prior app-v%d", latestPriorVersion)
		}
		var prior uint64
		for _, v := range tr.SubsumedVersions {
			if v <= tr.FromVersion || v >= tr.ToVersion || v > 19 || (prior != 0 && v <= prior) {
				return errors.New("virtual lineage transition has invalid subsumed versions")
			}
			prior = v
			expected = append(expected, AppliedUpgradeRecord{Name: fmt.Sprintf("app-v%d", v), TargetAppVersion: v, AppliedHeight: tr.AppliedHeight})
			validatedCoverage[v] = tr.AppliedHeight
		}
		if target == nil {
			validatedCoverage[tr.ToVersion] = tr.AppliedHeight
		}
	}
	if len(expected) != len(audit.Records) {
		return errors.New("virtual lineage normalized coverage does not match its manifest")
	}
	for i := range expected {
		if expected[i] != audit.Records[i] {
			return errors.New("virtual lineage normalized coverage order or content does not match its manifest")
		}
		actual, err := s.GetAppliedUpgrade(expected[i].Name)
		if err != nil {
			return err
		}
		if actual != nil {
			return fmt.Errorf("virtual lineage coverage %s collides with a real applied record", expected[i].Name)
		}
	}
	return nil
}

func equalLineageTransition(a, b LineageActivationTransition) bool {
	if a.FromVersion != b.FromVersion || a.ToVersion != b.ToVersion || a.AppliedHeight != b.AppliedHeight || a.Source != b.Source || a.BlockHash != b.BlockHash || len(a.SubsumedVersions) != len(b.SubsumedVersions) {
		return false
	}
	for i := range a.SubsumedVersions {
		if a.SubsumedVersions[i] != b.SubsumedVersions[i] {
			return false
		}
	}
	return true
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
