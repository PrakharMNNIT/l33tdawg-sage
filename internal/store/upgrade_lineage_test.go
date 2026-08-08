package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func virtualLineageAuditFixture(t *testing.T, s *BadgerStore) LegacyUpgradeLineageRepairAudit {
	t.Helper()
	require.NoError(t, s.MarkUpgradeApplied("app-v7", 7, 376))
	require.NoError(t, s.MarkUpgradeApplied("app-v8", 8, 741))
	require.NoError(t, s.MarkUpgradeApplied("app-v11", 11, 992))
	h1 := sha256.Sum256([]byte("376"))
	h2 := sha256.Sum256([]byte("992"))
	manifestValue := map[string]any{
		"schema": "sage-upgrade-lineage-repair/v2", "governance_domain": "scope", "prior_lineage_digest": "prior",
		"transitions": []LineageActivationTransition{
			{FromVersion: 1, ToVersion: 7, AppliedHeight: 376, Source: "comet-block-results", BlockHash: hex.EncodeToString(h1[:]), SubsumedVersions: []uint64{6}},
			{FromVersion: 8, ToVersion: 11, AppliedHeight: 992, Source: "comet-block-results", BlockHash: hex.EncodeToString(h2[:]), SubsumedVersions: []uint64{9, 10}},
		},
	}
	manifestBytes, err := json.Marshal(manifestValue)
	require.NoError(t, err)
	digest := sha256.Sum256(manifestBytes)
	return LegacyUpgradeLineageRepairAudit{
		Schema: "sage-upgrade-lineage-repair/v2", GovernanceDomain: "scope", PriorLineageDigest: "prior", ManifestDigest: hex.EncodeToString(digest[:]), Manifest: string(manifestBytes), ApprovedHeight: 1100, ProposalID: "proposal-v2",
		Records:     []AppliedUpgradeRecord{{Name: "app-v6", TargetAppVersion: 6, AppliedHeight: 376}, {Name: "app-v9", TargetAppVersion: 9, AppliedHeight: 992}, {Name: "app-v10", TargetAppVersion: 10, AppliedHeight: 992}},
		Transitions: []LineageActivationTransition{{FromVersion: 1, ToVersion: 7, AppliedHeight: 376, Source: "comet-block-results", BlockHash: hex.EncodeToString(h1[:]), SubsumedVersions: []uint64{6}}, {FromVersion: 8, ToVersion: 11, AppliedHeight: 992, Source: "comet-block-results", BlockHash: hex.EncodeToString(h2[:]), SubsumedVersions: []uint64{9, 10}}},
	}
}

func setVirtualLineagePlan(t *testing.T, s *BadgerStore, audit LegacyUpgradeLineageRepairAudit, height int64) {
	t.Helper()
	require.NoError(t, s.SetUpgradePlan(&UpgradePlanRecord{Name: "app-v22", TargetAppVersion: 22, ActivationHeight: height, LineageRepair: audit.Manifest, LineageProposalID: audit.ProposalID, LineageApprovedHeight: audit.ApprovedHeight, ProposedAt: audit.ApprovedHeight, ProposerID: "operator"}))
}

func TestVirtualLineageAuditInstallsOnlyAtomicallyWithAppV22(t *testing.T) {
	s := newTestBadger(t)
	audit := virtualLineageAuditFixture(t, s)
	require.ErrorContains(t, s.ApplyLegacyUpgradeLineageRepair(audit), "only atomically")
	setVirtualLineagePlan(t, s, audit, 1200)
	require.NoError(t, s.MarkUpgradeAppliedWithLineageAudit("app-v22", 22, 1200, audit))
	require.NoError(t, s.ValidateLegacyUpgradeLineageRepairAudit())
	for _, name := range []string{"app-v6", "app-v9", "app-v10"} {
		rec, err := s.GetAppliedUpgrade(name)
		require.NoError(t, err)
		require.Nil(t, rec)
	}
	rec, err := s.GetAppliedUpgrade("app-v22")
	require.NoError(t, err)
	require.Equal(t, int64(1200), rec.AppliedHeight)
}

func TestVirtualLineageAuditRejectsTamperedNormalizedCoverageAndTarget(t *testing.T) {
	t.Run("coverage", func(t *testing.T) {
		s := newTestBadger(t)
		audit := virtualLineageAuditFixture(t, s)
		audit.Records[1].AppliedHeight++
		setVirtualLineagePlan(t, s, audit, 1200)
		require.Error(t, s.MarkUpgradeAppliedWithLineageAudit("app-v22", 22, 1200, audit))
	})
	t.Run("target", func(t *testing.T) {
		s := newTestBadger(t)
		audit := virtualLineageAuditFixture(t, s)
		require.NoError(t, s.MarkUpgradeApplied("app-v11", 11, 993))
		setVirtualLineagePlan(t, s, audit, 1200)
		require.ErrorContains(t, s.MarkUpgradeAppliedWithLineageAudit("app-v22", 22, 1200, audit), "target app-v11")
	})
}

func TestApplyLegacyUpgradeLineageRepairCreateOnlyAndReplay(t *testing.T) {
	s := newTestBadger(t)
	manifest := `{"schema":"v1","governance_domain":"scope","prior_lineage_digest":"prior","evidence":[{"version":9,"name":"app-v9","applied_height":20}]}`
	digest := sha256.Sum256([]byte(manifest))
	audit := LegacyUpgradeLineageRepairAudit{Schema: "v1", GovernanceDomain: "scope", PriorLineageDigest: "prior", ManifestDigest: hex.EncodeToString(digest[:]), Manifest: manifest, ApprovedHeight: 50, ProposalID: "p", Records: []AppliedUpgradeRecord{{Name: "app-v9", TargetAppVersion: 9, AppliedHeight: 20}}}
	require.NoError(t, s.ApplyLegacyUpgradeLineageRepair(audit))
	require.NoError(t, s.ValidateLegacyUpgradeLineageRepairAudit())
	require.NoError(t, s.ApplyLegacyUpgradeLineageRepair(audit), "exact replay is idempotent")
	require.NoError(t, s.MarkUpgradeApplied("app-v10", 10, 30))
	conflict := audit
	conflict.ProposalID = "different"
	conflict.Records = []AppliedUpgradeRecord{{Name: "app-v10", TargetAppVersion: 10, AppliedHeight: 31}}
	require.Error(t, s.ApplyLegacyUpgradeLineageRepair(conflict))
	rec, err := s.GetAppliedUpgrade("app-v10")
	require.NoError(t, err)
	require.Equal(t, int64(30), rec.AppliedHeight)
}

func TestLegacyUpgradeLineageRepairSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "badger")
	s, err := NewBadgerStore(path)
	require.NoError(t, err)
	manifest := `{"schema":"v1","chain_id":"chain-a","governance_domain":"scope","prior_lineage_digest":"prior","evidence":[{"version":9,"name":"app-v9","applied_height":20}]}`
	digest := sha256.Sum256([]byte(manifest))
	audit := LegacyUpgradeLineageRepairAudit{
		Schema: "v1", GovernanceDomain: "scope", PriorLineageDigest: "prior",
		ManifestDigest: hex.EncodeToString(digest[:]), Manifest: manifest,
		ApprovedHeight: 50, ProposalID: "proposal-a",
		Records: []AppliedUpgradeRecord{{Name: "app-v9", TargetAppVersion: 9, AppliedHeight: 20}},
	}
	require.NoError(t, s.ApplyLegacyUpgradeLineageRepair(audit))
	require.NoError(t, s.CloseBadger())

	reopened, err := NewBadgerStore(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.CloseBadger() })
	require.NoError(t, reopened.ValidateLegacyUpgradeLineageRepairAudit())
	got, err := reopened.GetLegacyUpgradeLineageRepairAudit()
	require.NoError(t, err)
	require.Equal(t, &audit, got)
}

func TestValidateLegacyUpgradeLineageRepairAuditRejectsManifestDrift(t *testing.T) {
	manifest := `{"schema":"v1","governance_domain":"scope","prior_lineage_digest":"prior","evidence":[{"version":9,"name":"app-v9","applied_height":20}]}`
	digest := sha256.Sum256([]byte(manifest))
	base := LegacyUpgradeLineageRepairAudit{
		Schema: "v1", GovernanceDomain: "scope", PriorLineageDigest: "prior",
		ManifestDigest: hex.EncodeToString(digest[:]), Manifest: manifest,
		ApprovedHeight: 50, ProposalID: "proposal-a",
		Records: []AppliedUpgradeRecord{{Name: "app-v9", TargetAppVersion: 9, AppliedHeight: 20}},
	}
	for _, test := range []struct {
		name   string
		mutate func(*LegacyUpgradeLineageRepairAudit)
	}{
		{"domain", func(a *LegacyUpgradeLineageRepairAudit) { a.GovernanceDomain = "other" }},
		{"prior-digest", func(a *LegacyUpgradeLineageRepairAudit) { a.PriorLineageDigest = "other" }},
		{"record", func(a *LegacyUpgradeLineageRepairAudit) { a.Records[0].AppliedHeight++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := newTestBadger(t)
			audit := base
			audit.Records = append([]AppliedUpgradeRecord(nil), base.Records...)
			test.mutate(&audit)
			require.NoError(t, s.ApplyLegacyUpgradeLineageRepair(audit))
			require.Error(t, s.ValidateLegacyUpgradeLineageRepairAudit())
		})
	}
}

func TestValidateLegacyUpgradeLineageRepairAuditRejectsRecordOrderDrift(t *testing.T) {
	s := newTestBadger(t)
	manifest := `{"schema":"v1","governance_domain":"scope","prior_lineage_digest":"prior","evidence":[{"version":9,"name":"app-v9","applied_height":20},{"version":10,"name":"app-v10","applied_height":30}]}`
	digest := sha256.Sum256([]byte(manifest))
	audit := LegacyUpgradeLineageRepairAudit{
		Schema: "v1", GovernanceDomain: "scope", PriorLineageDigest: "prior",
		ManifestDigest: hex.EncodeToString(digest[:]), Manifest: manifest,
		ApprovedHeight: 50, ProposalID: "proposal-a",
		Records: []AppliedUpgradeRecord{
			{Name: "app-v10", TargetAppVersion: 10, AppliedHeight: 30},
			{Name: "app-v9", TargetAppVersion: 9, AppliedHeight: 20},
		},
	}
	require.NoError(t, s.ApplyLegacyUpgradeLineageRepair(audit))
	require.ErrorContains(t, s.ValidateLegacyUpgradeLineageRepairAudit(), "order or content")
}
