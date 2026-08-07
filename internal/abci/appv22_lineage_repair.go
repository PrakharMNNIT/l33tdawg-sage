package abci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/l33tdawg/sage/internal/governance"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

const legacyLineageRepairSchema = "sage-upgrade-lineage-repair/v1"

type LegacyLineageEvidence struct {
	Version       uint64 `json:"version"`
	Name          string `json:"name"`
	AppliedHeight int64  `json:"applied_height"`
	Source        string `json:"source"` // comet-block-results or legacy-anchor
	BlockHash     string `json:"block_hash,omitempty"`
}

type LegacyLineageRepairManifest struct {
	Schema             string                  `json:"schema"`
	ChainID            string                  `json:"chain_id"`
	GovernanceDomain   string                  `json:"governance_domain"`
	CurrentAppVersion  uint64                  `json:"current_app_version"`
	PriorLineageDigest string                  `json:"prior_lineage_digest"`
	AnchorDigest       string                  `json:"anchor_digest,omitempty"`
	AnchorAttestation  string                  `json:"anchor_attestation,omitempty"`
	Evidence           []LegacyLineageEvidence `json:"evidence"`
}

type legacyLineageRungStatus struct {
	Version       uint64 `json:"version"`
	Name          string `json:"name"`
	Present       bool   `json:"present"`
	AppliedHeight int64  `json:"applied_height,omitempty"`
	Valid         bool   `json:"valid"`
	Problem       string `json:"problem,omitempty"`
}

type legacyLineageStatus struct {
	Schema             string                                 `json:"schema"`
	CurrentAppVersion  uint64                                 `json:"current_app_version"`
	PersistedHeight    int64                                  `json:"persisted_height"`
	GovernanceDomain   string                                 `json:"governance_domain"`
	ValidLineageDigest string                                 `json:"valid_lineage_digest"`
	RepairAudit        *store.LegacyUpgradeLineageRepairAudit `json:"repair_audit,omitempty"`
	Rungs              []legacyLineageRungStatus              `json:"rungs"`
}

func (app *SageApp) legacyUpgradeLineageStatus() (*legacyLineageStatus, error) {
	digest, err := validLegacyLineageDigest(app.badgerStore)
	if err != nil {
		return nil, err
	}
	audit, err := app.badgerStore.GetLegacyUpgradeLineageRepairAudit()
	if err != nil {
		return nil, err
	}
	status := &legacyLineageStatus{
		Schema: legacyLineageRepairSchema, CurrentAppVersion: app.currentAppVersion(),
		GovernanceDomain: app.GovernanceDelegationDomain(), ValidLineageDigest: digest,
		RepairAudit: audit,
	}
	if app.state != nil {
		status.PersistedHeight = app.state.Height
	}
	var previous int64
	for version := uint64(6); version <= 21; version++ {
		name := tx.CanonicalUpgradeName(version)
		rung := legacyLineageRungStatus{Version: version, Name: name}
		rec, getErr := app.badgerStore.GetAppliedUpgrade(name)
		switch {
		case getErr != nil:
			rung.Problem = getErr.Error()
		case rec == nil:
			rung.Problem = "missing"
		default:
			rung.Present = true
			rung.AppliedHeight = rec.AppliedHeight
			rung.Valid = rec.Name == name && rec.TargetAppVersion == version && rec.AppliedHeight > previous && rec.AppliedHeight <= status.PersistedHeight
			if !rung.Valid {
				rung.Problem = "invalid canonical name, target, height, or order"
			} else {
				previous = rec.AppliedHeight
			}
		}
		status.Rungs = append(status.Rungs, rung)
	}
	return status, nil
}

func canonicalLegacyLineageRepair(raw string) (*LegacyLineageRepairManifest, string, error) {
	if raw == "" {
		return nil, "", nil
	}
	var manifest LegacyLineageRepairManifest
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, "", fmt.Errorf("decode lineage repair manifest: %w", err)
	}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return nil, "", err
	}
	if string(canonical) != raw {
		return nil, "", errors.New("lineage repair manifest must use canonical compact JSON")
	}
	digest := sha256.Sum256(canonical)
	return &manifest, hex.EncodeToString(digest[:]), nil
}

// CanonicalizeLegacyLineageRepair converts an operator-authored manifest into
// the exact compact JSON bytes committed by UpgradePropose.
func CanonicalizeLegacyLineageRepair(raw []byte) (string, error) {
	var manifest LegacyLineageRepairManifest
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(manifest)
	return string(canonical), err
}

func validLegacyLineageDigest(bs *store.BadgerStore) (string, error) {
	type digestRecord struct {
		Version uint64 `json:"version"`
		Name    string `json:"name"`
		Height  int64  `json:"height"`
	}
	records := make([]digestRecord, 0, 16)
	for version := uint64(6); version <= 21; version++ {
		name := tx.CanonicalUpgradeName(version)
		rec, err := bs.GetAppliedUpgrade(name)
		if err != nil {
			return "", err
		}
		if rec == nil {
			continue
		}
		if rec.Name != name || rec.TargetAppVersion != version || rec.AppliedHeight <= 0 {
			continue
		}
		records = append(records, digestRecord{Version: version, Name: name, Height: rec.AppliedHeight})
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (app *SageApp) validateLegacyLineageRepair(raw string) (*LegacyLineageRepairManifest, string, error) {
	manifest, digest, err := canonicalLegacyLineageRepair(raw)
	if err != nil || manifest == nil {
		return manifest, digest, err
	}
	if manifest.Schema != legacyLineageRepairSchema || manifest.CurrentAppVersion != 21 {
		return nil, "", errors.New("lineage repair is admitted only for the app-v21 to app-v22 transition")
	}
	if len(manifest.Evidence) == 0 || len(manifest.Evidence) > 16 {
		return nil, "", errors.New("lineage repair must contain one to sixteen missing records")
	}
	domain, err := governance.DelegationDomainForChainID(manifest.ChainID)
	if err != nil || domain != manifest.GovernanceDomain ||
		manifest.GovernanceDomain != app.expectedGovernanceDelegationDomain() ||
		manifest.GovernanceDomain != app.GovernanceDelegationDomain() {
		return nil, "", errors.New("lineage repair is not bound to this chain governance domain")
	}
	priorDigest, err := validLegacyLineageDigest(app.badgerStore)
	if err != nil {
		return nil, "", err
	}
	if manifest.PriorLineageDigest != priorDigest {
		return nil, "", errors.New("lineage repair prior_lineage_digest does not match current consensus state")
	}

	entries := append([]LegacyLineageEvidence(nil), manifest.Evidence...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Version < entries[j].Version })
	source := entries[0].Source
	if source != "comet-block-results" && source != "legacy-anchor" {
		return nil, "", fmt.Errorf("unsupported lineage evidence source %q", source)
	}
	for i := range entries {
		if entries[i] != manifest.Evidence[i] {
			return nil, "", errors.New("lineage repair evidence must be sorted by version")
		}
		e := entries[i]
		if e.Source != source {
			return nil, "", errors.New("lineage repair evidence must use exactly one source; mixed Comet and legacy-anchor claims are forbidden")
		}
		if e.Version < 6 || e.Version > 21 || e.Name != tx.CanonicalUpgradeName(e.Version) || e.AppliedHeight <= 0 {
			return nil, "", fmt.Errorf("invalid lineage evidence for app-v%d", e.Version)
		}
		if i > 0 && entries[i-1].Version == e.Version {
			return nil, "", errors.New("lineage repair contains a duplicate version")
		}
		if existing, getErr := app.badgerStore.GetAppliedUpgrade(e.Name); getErr != nil {
			return nil, "", getErr
		} else if existing != nil {
			return nil, "", fmt.Errorf("lineage repair may create only missing records; %s already exists", e.Name)
		}
		switch e.Source {
		case "comet-block-results":
			decoded, decodeErr := hex.DecodeString(e.BlockHash)
			if decodeErr != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != e.BlockHash {
				return nil, "", fmt.Errorf("app-v%d Comet evidence has no canonical block hash", e.Version)
			}
		case "legacy-anchor":
			if e.BlockHash != "" {
				return nil, "", fmt.Errorf("app-v%d legacy anchor must not claim a Comet block hash", e.Version)
			}
			decoded, decodeErr := hex.DecodeString(manifest.AnchorDigest)
			if decodeErr != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != manifest.AnchorDigest {
				return nil, "", errors.New("legacy-anchor evidence requires a canonical audited anchor_digest")
			}
			if manifest.AnchorAttestation != "operator-quorum-attested-unverified-history" {
				return nil, "", errors.New("legacy-anchor evidence requires explicit unverified-history quorum attestation")
			}
		default:
			return nil, "", fmt.Errorf("app-v%d has unsupported lineage evidence source %q", e.Version, e.Source)
		}
	}

	// Validate the complete prospective ladder, using existing records wherever
	// present and proposed evidence only for an exact absent rung.
	byVersion := make(map[uint64]LegacyLineageEvidence, len(entries))
	for _, entry := range entries {
		byVersion[entry.Version] = entry
	}
	var previous int64
	for version := uint64(6); version <= 21; version++ {
		name := tx.CanonicalUpgradeName(version)
		rec, getErr := app.badgerStore.GetAppliedUpgrade(name)
		if getErr != nil {
			return nil, "", getErr
		}
		height := int64(0)
		if rec != nil {
			if rec.Name != name || rec.TargetAppVersion != version || rec.AppliedHeight <= 0 {
				return nil, "", fmt.Errorf("existing applied %s record is invalid and cannot be repaired", name)
			}
			height = rec.AppliedHeight
		} else if evidence, ok := byVersion[version]; ok {
			height = evidence.AppliedHeight
		}
		if height <= 0 {
			return nil, "", fmt.Errorf("lineage repair does not cover missing canonical applied %s predecessor", name)
		}
		if height <= previous || app.state == nil || height > app.state.Height {
			return nil, "", fmt.Errorf("prospective app-v%d height %d is outside the strict lineage order", version, height)
		}
		previous = height
	}
	return manifest, digest, nil
}

func (app *SageApp) applyLegacyLineageRepair(raw, proposalID string, height int64) error {
	manifest, manifestDigest, err := app.validateLegacyLineageRepair(raw)
	if err != nil {
		return err
	}
	if manifest == nil {
		return nil
	}
	records := make([]store.AppliedUpgradeRecord, 0, len(manifest.Evidence))
	for _, evidence := range manifest.Evidence {
		records = append(records, store.AppliedUpgradeRecord{Name: evidence.Name, TargetAppVersion: evidence.Version, AppliedHeight: evidence.AppliedHeight})
	}
	return app.badgerStore.ApplyLegacyUpgradeLineageRepair(store.LegacyUpgradeLineageRepairAudit{
		Schema: manifest.Schema, GovernanceDomain: manifest.GovernanceDomain,
		PriorLineageDigest: manifest.PriorLineageDigest, ManifestDigest: manifestDigest, Manifest: raw,
		ApprovedHeight: height, ProposalID: proposalID, Records: records,
	})
}
