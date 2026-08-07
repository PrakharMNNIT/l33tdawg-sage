package store

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

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
