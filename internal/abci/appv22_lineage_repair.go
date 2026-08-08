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

const (
	legacyLineageRepairSchema   = "sage-upgrade-lineage-repair/v2"
	legacyLineageRepairSchemaV1 = "sage-upgrade-lineage-repair/v1"
)

type LegacyLineageEvidence struct {
	Version       uint64 `json:"version"`
	Name          string `json:"name"`
	AppliedHeight int64  `json:"applied_height"`
	Source        string `json:"source"` // comet-block-results or legacy-anchor
	BlockHash     string `json:"block_hash,omitempty"`
}

type LegacyLineageRepairManifest struct {
	Schema             string                        `json:"schema"`
	ChainID            string                        `json:"chain_id"`
	GovernanceDomain   string                        `json:"governance_domain"`
	CurrentAppVersion  uint64                        `json:"current_app_version"`
	PriorLineageDigest string                        `json:"prior_lineage_digest"`
	AnchorDigest       string                        `json:"anchor_digest,omitempty"`
	AnchorAttestation  string                        `json:"anchor_attestation,omitempty"`
	Evidence           []LegacyLineageEvidence       `json:"evidence,omitempty"`
	Transitions        []LineageActivationTransition `json:"transitions,omitempty"`
}

// LineageActivationTransition describes one observed version.app jump. The
// skipped predecessors are virtual coverage only, never independent applied
// activations and never persisted under upgrade:applied:*.
type LineageActivationTransition struct {
	FromVersion      uint64   `json:"from_version"`
	ToVersion        uint64   `json:"to_version"`
	AppliedHeight    int64    `json:"applied_height"`
	Source           string   `json:"source"`
	BlockHash        string   `json:"block_hash,omitempty"`
	SubsumedVersions []uint64 `json:"subsumed_versions"`
}

type legacyLineageRungStatus struct {
	Version           uint64 `json:"version"`
	Name              string `json:"name"`
	Present           bool   `json:"present"`
	AppliedHeight     int64  `json:"applied_height,omitempty"`
	Valid             bool   `json:"valid"`
	Problem           string `json:"problem,omitempty"`
	Provenance        string `json:"provenance,omitempty"`
	Virtual           bool   `json:"virtual,omitempty"`
	SubsumedByVersion uint64 `json:"subsumed_by_version,omitempty"`
	TransitionTarget  bool   `json:"transition_target,omitempty"`
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
	if audit != nil {
		if err := app.badgerStore.ValidateLegacyUpgradeLineageRepairAudit(); err != nil {
			return nil, err
		}
	}
	rungs, _, _ := app.resolveAppV22Lineage(nil)
	status.Rungs = rungs
	return status, nil
}

func (app *SageApp) resolveAppV22Lineage(pending *LegacyLineageRepairManifest) ([]legacyLineageRungStatus, int64, error) {
	virtual := make(map[uint64]legacyLineageRungStatus)
	audit, err := app.badgerStore.GetLegacyUpgradeLineageRepairAudit()
	if err != nil {
		return nil, 0, err
	}
	manifest := pending
	if manifest == nil && audit != nil && audit.Schema == legacyLineageRepairSchema {
		var decoded LegacyLineageRepairManifest
		if err := json.Unmarshal([]byte(audit.Manifest), &decoded); err != nil {
			return nil, 0, err
		}
		manifest = &decoded
	}
	if manifest != nil {
		for _, e := range manifest.Evidence {
			if e.Version > 19 {
				return nil, 0, fmt.Errorf("app-v%d ceremony cannot be virtualized", e.Version)
			}
			virtual[e.Version] = legacyLineageRungStatus{Version: e.Version, Name: e.Name, Present: true, Valid: true, AppliedHeight: e.AppliedHeight, Provenance: e.Source, Virtual: true}
		}
		for _, tr := range manifest.Transitions {
			for _, version := range tr.SubsumedVersions {
				virtual[version] = legacyLineageRungStatus{Version: version, Name: tx.CanonicalUpgradeName(version), Present: true, Valid: true, AppliedHeight: tr.AppliedHeight, Provenance: tr.Source + "-transition", Virtual: true, SubsumedByVersion: tr.ToVersion}
			}
			targetName := tx.CanonicalUpgradeName(tr.ToVersion)
			target, targetErr := app.badgerStore.GetAppliedUpgrade(targetName)
			if targetErr != nil {
				return nil, 0, targetErr
			}
			if target == nil {
				if tr.ToVersion > 19 {
					return nil, 0, fmt.Errorf("app-v%d ceremony target cannot be virtualized", tr.ToVersion)
				}
				virtual[tr.ToVersion] = legacyLineageRungStatus{Version: tr.ToVersion, Name: targetName, Present: true, Valid: true, AppliedHeight: tr.AppliedHeight, Provenance: tr.Source + "-transition-target", Virtual: true, SubsumedByVersion: tr.ToVersion, TransitionTarget: true}
			}
		}
	}
	if audit != nil && audit.Schema == legacyLineageRepairSchemaV1 && app.currentAppVersion() < 22 {
		plan, planErr := app.badgerStore.GetUpgradePlan()
		if planErr != nil || app.validateApprovedLegacyV1LineagePlan(plan) != nil {
			return nil, 0, errors.New("unsafe v1 lineage receipt is valid only for an already-activated app-v22 chain or its exactly bound pending plan")
		}
	}
	legacyV1Records := make(map[uint64]store.AppliedUpgradeRecord)
	if audit != nil && audit.Schema == legacyLineageRepairSchemaV1 {
		for _, rec := range audit.Records {
			legacyV1Records[rec.TargetAppVersion] = rec
		}
	}
	rungs := make([]legacyLineageRungStatus, 0, 16)
	var previous int64
	var previousRung legacyLineageRungStatus
	for version := uint64(6); version <= 21; version++ {
		name := tx.CanonicalUpgradeName(version)
		rung := legacyLineageRungStatus{Version: version, Name: name}
		rec, getErr := app.badgerStore.GetAppliedUpgrade(name)
		if getErr != nil {
			return nil, 0, getErr
		}
		if rec != nil {
			rung.Present, rung.AppliedHeight, rung.Provenance = true, rec.AppliedHeight, "applied-record"
			if legacy, ok := legacyV1Records[version]; ok && legacy == *rec {
				rung.Provenance = "legacy-v1"
			}
			rung.Valid = rec.Name == name && rec.TargetAppVersion == version && rec.AppliedHeight > 0
		} else if v, ok := virtual[version]; ok {
			rung = v
		} else {
			rung.Problem = fmt.Sprintf("missing canonical applied %s predecessor", name)
			rungs = append(rungs, rung)
			continue
		}
		equalAllowed := rung.AppliedHeight == previous && (rung.SubsumedByVersion != 0 || previousRung.SubsumedByVersion == version)
		if rung.Valid && (rung.AppliedHeight < previous || (rung.AppliedHeight == previous && !equalAllowed)) {
			rung.Valid = false
			rung.Problem = fmt.Sprintf("%s predecessor height %d must be after app-v%d height %d", name, rung.AppliedHeight, version-1, previous)
		} else if !rung.Valid || app.state == nil || rung.AppliedHeight > app.state.Height+1 {
			rung.Valid = false
			rung.Problem = "invalid canonical name, target, height, order, or provenance"
		}
		if rung.Valid {
			previous = rung.AppliedHeight
			previousRung = rung
		}
		rungs = append(rungs, rung)
	}
	for _, rung := range rungs {
		if !rung.Present || !rung.Valid {
			return rungs, previous, fmt.Errorf("invalid app-v22 predecessor %s: %s", rung.Name, rung.Problem)
		}
	}
	return rungs, previous, nil
}

func (app *SageApp) validateApprovedLegacyV1LineagePlan(plan *store.UpgradePlanRecord) error {
	if plan == nil || plan.Name != appV22UpgradeName || plan.TargetAppVersion != 22 || plan.LineageRepair == "" {
		return errors.New("legacy v1 lineage audit has no pending app-v22 plan")
	}
	audit, err := app.badgerStore.GetLegacyUpgradeLineageRepairAudit()
	if err != nil || audit == nil {
		return errors.New("legacy v1 pending plan has no lineage audit")
	}
	if audit.Schema != legacyLineageRepairSchemaV1 || audit.Manifest != plan.LineageRepair {
		return errors.New("legacy v1 pending plan does not match its lineage audit manifest")
	}
	if err := app.badgerStore.ValidateLegacyUpgradeLineageRepairAudit(); err != nil {
		return err
	}
	proposal, err := app.govEngine.LoadProposal(audit.ProposalID)
	if err != nil || proposal == nil {
		return errors.New("legacy v1 lineage audit has no retained governance proposal")
	}
	if proposal.Status != governance.StatusExecuted || proposal.Operation != governance.OpUpgrade || proposal.TargetID != appV22UpgradeName || proposal.ProposerID != plan.ProposerID {
		return errors.New("legacy v1 retained governance proposal execution context does not match its pending plan")
	}
	if audit.ApprovedHeight < proposal.CreatedHeight || audit.ApprovedHeight > proposal.ExpiryHeight {
		return errors.New("legacy v1 lineage approval height is outside its retained governance proposal window")
	}
	var payload UpgradeProposalPayload
	if err := json.Unmarshal(proposal.Payload, &payload); err != nil {
		return fmt.Errorf("decode legacy v1 retained upgrade proposal: %w", err)
	}
	if payload.Name != plan.Name || payload.TargetAppVersion != plan.TargetAppVersion || payload.LineageRepair != plan.LineageRepair {
		return errors.New("legacy v1 retained governance proposal payload does not match its pending plan")
	}
	delay := payload.UpgradeDelayBlocks
	if floor := effectiveUpgradeDelayFloorBlocks(); delay < floor {
		delay = floor
	}
	if audit.ApprovedHeight != plan.ProposedAt || plan.ActivationHeight != plan.ProposedAt+delay {
		return errors.New("legacy v1 pending plan approval or activation height does not match its audit and proposal")
	}
	if plan.LineageProposalID != "" && plan.LineageProposalID != audit.ProposalID {
		return errors.New("legacy v1 pending plan lineage proposal ID does not match its audit")
	}
	if plan.LineageApprovedHeight != 0 && plan.LineageApprovedHeight != audit.ApprovedHeight {
		return errors.New("legacy v1 pending plan lineage approval height does not match its audit")
	}
	return nil
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
	if len(manifest.Evidence)+len(manifest.Transitions) == 0 || len(manifest.Evidence)+len(manifest.Transitions) > 16 {
		return nil, "", errors.New("lineage repair must contain one to sixteen evidence claims")
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
	source := "comet-block-results"
	if len(entries) > 0 {
		source = entries[0].Source
	} else if len(manifest.Transitions) > 0 {
		source = manifest.Transitions[0].Source
	}
	if source != "comet-block-results" && source != "legacy-anchor" {
		return nil, "", fmt.Errorf("unsupported lineage evidence source %q", source)
	}
	coverage := make(map[uint64]int64)
	for i := range entries {
		if entries[i] != manifest.Evidence[i] {
			return nil, "", errors.New("lineage repair evidence must be sorted by version")
		}
		e := entries[i]
		if e.Source != source {
			return nil, "", errors.New("lineage repair evidence must use exactly one source; mixed Comet and legacy-anchor claims are forbidden")
		}
		if e.Version < 6 || e.Version > 19 || e.Name != tx.CanonicalUpgradeName(e.Version) || e.AppliedHeight <= 0 {
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
		coverage[e.Version] = e.AppliedHeight
	}
	transitions := append([]LineageActivationTransition(nil), manifest.Transitions...)
	sort.Slice(transitions, func(i, j int) bool {
		if transitions[i].AppliedHeight == transitions[j].AppliedHeight {
			return transitions[i].ToVersion < transitions[j].ToVersion
		}
		return transitions[i].AppliedHeight < transitions[j].AppliedHeight
	})
	for i, tr := range transitions {
		if !equalActivationTransition(tr, manifest.Transitions[i]) {
			return nil, "", errors.New("lineage transitions must be sorted by applied height and target version")
		}
		if tr.Source != source || (tr.Source != "comet-block-results" && tr.Source != "legacy-anchor") {
			return nil, "", errors.New("lineage transitions must use exactly one supported evidence source")
		}
		if i > 0 && tr.AppliedHeight <= transitions[i-1].AppliedHeight {
			return nil, "", errors.New("lineage transition heights must be strictly increasing")
		}
		if tr.FromVersion >= tr.ToVersion || tr.ToVersion > 21 || tr.AppliedHeight <= 0 || len(tr.SubsumedVersions) == 0 {
			return nil, "", errors.New("invalid lineage activation transition")
		}
		if tr.Source == "comet-block-results" {
			decoded, decodeErr := hex.DecodeString(tr.BlockHash)
			if decodeErr != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != tr.BlockHash {
				return nil, "", errors.New("retained-Comet transition has no canonical block hash")
			}
		} else {
			if tr.BlockHash != "" {
				return nil, "", errors.New("legacy-anchor transition must not claim a Comet block hash")
			}
			decoded, decodeErr := hex.DecodeString(manifest.AnchorDigest)
			if decodeErr != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != manifest.AnchorDigest || manifest.AnchorAttestation != "operator-quorum-attested-unverified-history" {
				return nil, "", errors.New("legacy-anchor transition requires canonical digest and explicit quorum attestation")
			}
		}
		target, getErr := app.badgerStore.GetAppliedUpgrade(tx.CanonicalUpgradeName(tr.ToVersion))
		if getErr != nil {
			return nil, "", getErr
		}
		if target == nil && tr.ToVersion > 19 {
			return nil, "", fmt.Errorf("app-v%d ceremony transition target must be a real applied record", tr.ToVersion)
		}
		if target == nil {
			if coverage[tr.ToVersion] != 0 {
				return nil, "", fmt.Errorf("transition target app-v%d overlaps direct evidence", tr.ToVersion)
			}
			coverage[tr.ToVersion] = tr.AppliedHeight
		}
		if target != nil && (target.TargetAppVersion != tr.ToVersion || target.AppliedHeight != tr.AppliedHeight) {
			return nil, "", fmt.Errorf("transition target app-v%d is not a real activation at height %d", tr.ToVersion, tr.AppliedHeight)
		}
		var latestPriorVersion uint64
		var latestPriorHeight int64
		for version := uint64(6); version < tr.ToVersion; version++ {
			rec, recErr := app.badgerStore.GetAppliedUpgrade(tx.CanonicalUpgradeName(version))
			if recErr != nil {
				return nil, "", recErr
			}
			if rec != nil && rec.AppliedHeight < tr.AppliedHeight && (rec.AppliedHeight > latestPriorHeight || rec.AppliedHeight == latestPriorHeight && version > latestPriorVersion) {
				latestPriorVersion, latestPriorHeight = version, rec.AppliedHeight
			}
			if height := coverage[version]; height > 0 && height < tr.AppliedHeight && (height > latestPriorHeight || height == latestPriorHeight && version > latestPriorVersion) {
				latestPriorVersion, latestPriorHeight = version, height
			}
		}
		if tr.FromVersion >= 6 && latestPriorVersion != tr.FromVersion {
			return nil, "", fmt.Errorf("transition source app-v%d is not the latest validated lineage point before app-v%d", tr.FromVersion, tr.ToVersion)
		}
		if tr.FromVersion < 6 && latestPriorVersion != 0 {
			return nil, "", fmt.Errorf("transition source app-v%d is not the latest real activation before app-v%d", tr.FromVersion, tr.ToVersion)
		}
		expected := make([]uint64, 0)
		for version := tr.FromVersion + 1; version < tr.ToVersion; version++ {
			if version < 6 {
				continue
			}
			rec, recErr := app.badgerStore.GetAppliedUpgrade(tx.CanonicalUpgradeName(version))
			if recErr != nil {
				return nil, "", recErr
			}
			if rec == nil {
				expected = append(expected, version)
			}
		}
		if len(expected) != len(tr.SubsumedVersions) {
			return nil, "", errors.New("transition subsumed_versions is not the exact missing predecessor set")
		}
		for j, version := range expected {
			if tr.SubsumedVersions[j] != version || coverage[version] != 0 {
				return nil, "", errors.New("transition subsumed_versions is unsorted, duplicated, or overlaps direct evidence")
			}
			coverage[version] = tr.AppliedHeight
		}
	}
	if _, _, resolveErr := app.resolveAppV22Lineage(manifest); resolveErr != nil {
		return nil, "", resolveErr
	}
	return manifest, digest, nil
}

func equalActivationTransition(a, b LineageActivationTransition) bool {
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

func (app *SageApp) legacyLineageRepairAudit(raw, proposalID string, height int64) (*store.LegacyUpgradeLineageRepairAudit, error) {
	manifest, manifestDigest, err := app.validateLegacyLineageRepair(raw)
	if err != nil {
		return nil, err
	}
	if manifest == nil {
		return nil, nil
	}
	records := make([]store.AppliedUpgradeRecord, 0, len(manifest.Evidence))
	for _, evidence := range manifest.Evidence {
		records = append(records, store.AppliedUpgradeRecord{Name: evidence.Name, TargetAppVersion: evidence.Version, AppliedHeight: evidence.AppliedHeight})
	}
	transitions := make([]store.LineageActivationTransition, 0, len(manifest.Transitions))
	for _, tr := range manifest.Transitions {
		transitions = append(transitions, store.LineageActivationTransition{FromVersion: tr.FromVersion, ToVersion: tr.ToVersion, AppliedHeight: tr.AppliedHeight, Source: tr.Source, BlockHash: tr.BlockHash, SubsumedVersions: append([]uint64(nil), tr.SubsumedVersions...)})
		for _, version := range tr.SubsumedVersions {
			records = append(records, store.AppliedUpgradeRecord{Name: tx.CanonicalUpgradeName(version), TargetAppVersion: version, AppliedHeight: tr.AppliedHeight})
		}
	}
	audit := &store.LegacyUpgradeLineageRepairAudit{
		Schema: manifest.Schema, GovernanceDomain: manifest.GovernanceDomain,
		PriorLineageDigest: manifest.PriorLineageDigest, ManifestDigest: manifestDigest, Manifest: raw,
		ApprovedHeight: height, ProposalID: proposalID, Records: records, Transitions: transitions,
	}
	return audit, nil
}
