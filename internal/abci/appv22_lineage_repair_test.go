package abci

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	badger "github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/governance"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
	"github.com/l33tdawg/sage/internal/validator"
)

func lineageRepairFixture(t *testing.T, missing uint64) (*SageApp, string) {
	t.Helper()
	app := setupTestApp(t)
	app.state.Height = 100
	app.appV21AppliedHeight = 90
	chainID := "lineage-test-chain"
	domain, err := governance.DelegationDomainForChainID(chainID)
	require.NoError(t, err)
	require.NoError(t, app.SetExpectedGovernanceDelegationDomain(chainID))
	require.NoError(t, app.ensureGovernanceDelegationDomain(domain))
	seedAppV22PredecessorLadder(t, app.badgerStore, 10, missing, nil)
	digest, err := validLegacyLineageDigest(app.badgerStore)
	require.NoError(t, err)
	proof := sha256.Sum256([]byte("retained-comet-block"))
	manifest := LegacyLineageRepairManifest{
		Schema: legacyLineageRepairSchema, ChainID: chainID, GovernanceDomain: domain,
		CurrentAppVersion: 21, PriorLineageDigest: digest,
		Evidence: []LegacyLineageEvidence{{Version: missing, Name: tx.CanonicalUpgradeName(missing), AppliedHeight: 10 + int64(missing-6), Source: "comet-block-results", BlockHash: hex.EncodeToString(proof[:])}},
	}
	raw, err := json.Marshal(manifest)
	require.NoError(t, err)
	return app, string(raw)
}

func skipAheadLineageFixture(t *testing.T) (*SageApp, string) {
	t.Helper()
	app := setupTestApp(t)
	app.state.Height = 1200
	chainID := "skip-ahead-lineage-chain"
	domain, err := governance.DelegationDomainForChainID(chainID)
	require.NoError(t, err)
	require.NoError(t, app.SetExpectedGovernanceDelegationDomain(chainID))
	require.NoError(t, app.ensureGovernanceDelegationDomain(domain))
	heights := map[uint64]int64{7: 376, 8: 741, 11: 992}
	next := int64(1000)
	for version := uint64(6); version <= 21; version++ {
		if version == 6 || version == 9 || version == 10 {
			continue
		}
		height, ok := heights[version]
		if !ok {
			height = next
			next += 10
		}
		require.NoError(t, app.badgerStore.MarkUpgradeApplied(tx.CanonicalUpgradeName(version), version, height))
	}
	app.appV21AppliedHeight = 1090
	digest, err := validLegacyLineageDigest(app.badgerStore)
	require.NoError(t, err)
	hash376 := sha256.Sum256([]byte("block-376"))
	hash992 := sha256.Sum256([]byte("block-992"))
	manifest := LegacyLineageRepairManifest{
		Schema: legacyLineageRepairSchema, ChainID: chainID, GovernanceDomain: domain, CurrentAppVersion: 21, PriorLineageDigest: digest,
		Transitions: []LineageActivationTransition{
			{FromVersion: 1, ToVersion: 7, AppliedHeight: 376, Source: "comet-block-results", BlockHash: hex.EncodeToString(hash376[:]), SubsumedVersions: []uint64{6}},
			{FromVersion: 8, ToVersion: 11, AppliedHeight: 992, Source: "comet-block-results", BlockHash: hex.EncodeToString(hash992[:]), SubsumedVersions: []uint64{9, 10}},
		},
	}
	raw, err := json.Marshal(manifest)
	require.NoError(t, err)
	return app, string(raw)
}

func TestSkipAheadLineageUsesTruthfulVirtualTransitionBundle(t *testing.T) {
	app, raw := skipAheadLineageFixture(t)
	manifest, _, err := app.validateLegacyLineageRepair(raw)
	require.NoError(t, err)
	require.Len(t, manifest.Transitions, 2)
	audit, err := app.legacyLineageRepairAudit(raw, "proposal-skip", 1190)
	require.NoError(t, err)
	require.NoError(t, app.badgerStore.SetUpgradePlan(&store.UpgradePlanRecord{Name: appV22UpgradeName, TargetAppVersion: 22, ActivationHeight: 1201, LineageRepair: raw, LineageProposalID: "proposal-skip", LineageApprovedHeight: 1190, ProposedAt: 1190, ProposerID: "operator"}))
	for _, version := range []uint64{6, 9, 10} {
		rec, getErr := app.badgerStore.GetAppliedUpgrade(tx.CanonicalUpgradeName(version))
		require.NoError(t, getErr)
		require.Nil(t, rec, "approval/build must not synthesize app-v%d", version)
	}
	require.NoError(t, app.badgerStore.MarkUpgradeAppliedWithLineageAudit(appV22UpgradeName, 22, 1201, *audit))
	for _, version := range []uint64{6, 9, 10} {
		rec, getErr := app.badgerStore.GetAppliedUpgrade(tx.CanonicalUpgradeName(version))
		require.NoError(t, getErr)
		require.Nil(t, rec, "activation must keep app-v%d virtual", version)
	}
	last, err := app.validatePersistedAppV22PredecessorLadder()
	require.NoError(t, err)
	require.Equal(t, int64(1090), last)
	status, err := app.legacyUpgradeLineageStatus()
	require.NoError(t, err)
	require.Equal(t, uint64(7), status.Rungs[0].SubsumedByVersion)
	require.Equal(t, "comet-block-results-transition", status.Rungs[0].Provenance)
	require.True(t, status.Rungs[0].Virtual)
	target, ok := app.appliedUpgradeTargetAtHeight(992)
	require.True(t, ok)
	require.Equal(t, uint64(11), target, "crash replay must resolve the real jump target, never a virtual predecessor")
}

func TestSkipAheadTransitionMaySupplyVirtualMissingTarget(t *testing.T) {
	app, raw := skipAheadLineageFixture(t)
	require.NoError(t, app.badgerStore.DB().Update(func(txn *badger.Txn) error { return txn.Delete([]byte("upgrade:applied:app-v11")) }))
	var manifest LegacyLineageRepairManifest
	require.NoError(t, json.Unmarshal([]byte(raw), &manifest))
	digest, err := validLegacyLineageDigest(app.badgerStore)
	require.NoError(t, err)
	manifest.PriorLineageDigest = digest
	changed, err := json.Marshal(manifest)
	require.NoError(t, err)
	raw = string(changed)
	_, _, err = app.validateLegacyLineageRepair(raw)
	require.NoError(t, err)
	rungs, _, err := app.resolveAppV22Lineage(&manifest)
	require.NoError(t, err)
	require.True(t, rungs[5].Virtual)
	require.True(t, rungs[5].TransitionTarget)
	require.Equal(t, "comet-block-results-transition-target", rungs[5].Provenance)
	audit, err := app.legacyLineageRepairAudit(raw, "proposal-target", 1190)
	require.NoError(t, err)
	require.NoError(t, app.badgerStore.SetUpgradePlan(&store.UpgradePlanRecord{Name: appV22UpgradeName, TargetAppVersion: 22, ActivationHeight: 1201, LineageRepair: raw, LineageProposalID: "proposal-target", LineageApprovedHeight: 1190, ProposedAt: 1190, ProposerID: "operator"}))
	require.NoError(t, app.badgerStore.MarkUpgradeAppliedWithLineageAudit(appV22UpgradeName, 22, 1201, *audit))
	rec, err := app.badgerStore.GetAppliedUpgrade("app-v11")
	require.NoError(t, err)
	require.Nil(t, rec)
	_, err = app.validatePersistedAppV22PredecessorLadder()
	require.NoError(t, err)
}

func TestLegacyAnchorTransitionMaySupplyVirtualMissingTarget(t *testing.T) {
	app, raw := skipAheadLineageFixture(t)
	require.NoError(t, app.badgerStore.DB().Update(func(txn *badger.Txn) error { return txn.Delete([]byte("upgrade:applied:app-v11")) }))
	var manifest LegacyLineageRepairManifest
	require.NoError(t, json.Unmarshal([]byte(raw), &manifest))
	for i := range manifest.Transitions {
		manifest.Transitions[i].Source = "legacy-anchor"
		manifest.Transitions[i].BlockHash = ""
	}
	anchor := sha256.Sum256([]byte("audited transition ledger"))
	manifest.AnchorDigest = hex.EncodeToString(anchor[:])
	manifest.AnchorAttestation = "operator-quorum-attested-unverified-history"
	digest, err := validLegacyLineageDigest(app.badgerStore)
	require.NoError(t, err)
	manifest.PriorLineageDigest = digest
	changed, err := json.Marshal(manifest)
	require.NoError(t, err)
	_, _, err = app.validateLegacyLineageRepair(string(changed))
	require.NoError(t, err)
	anchorRaw := string(changed)
	audit, err := app.legacyLineageRepairAudit(anchorRaw, "anchor-proposal", 1190)
	require.NoError(t, err)
	require.NoError(t, app.badgerStore.SetUpgradePlan(&store.UpgradePlanRecord{Name: appV22UpgradeName, TargetAppVersion: 22, ActivationHeight: 1201, LineageRepair: anchorRaw, LineageProposalID: "anchor-proposal", LineageApprovedHeight: 1190, ProposedAt: 1190, ProposerID: "operator"}))
	require.NoError(t, app.badgerStore.MarkUpgradeAppliedWithLineageAudit(appV22UpgradeName, 22, 1201, *audit))
	require.NoError(t, app.badgerStore.ValidateLegacyUpgradeLineageRepairAudit())
	manifest.Transitions[1].ToVersion = 20
	changed, _ = json.Marshal(manifest)
	_, _, err = app.validateLegacyLineageRepair(string(changed))
	require.Error(t, err)
}

func TestChainedTransitionsUseEarlierVirtualTargetAsSource(t *testing.T) {
	app, raw := skipAheadLineageFixture(t)
	for _, version := range []uint64{7, 8, 11} {
		require.NoError(t, app.badgerStore.DB().Update(func(txn *badger.Txn) error {
			return txn.Delete([]byte(fmt.Sprintf("upgrade:applied:app-v%d", version)))
		}))
	}
	var manifest LegacyLineageRepairManifest
	require.NoError(t, json.Unmarshal([]byte(raw), &manifest))
	manifest.Transitions[1].FromVersion = 7
	manifest.Transitions[1].SubsumedVersions = []uint64{8, 9, 10}
	digest, err := validLegacyLineageDigest(app.badgerStore)
	require.NoError(t, err)
	manifest.PriorLineageDigest = digest
	changed, err := json.Marshal(manifest)
	require.NoError(t, err)
	_, _, err = app.validateLegacyLineageRepair(string(changed))
	require.NoError(t, err)
	var anchorChain LegacyLineageRepairManifest
	require.NoError(t, json.Unmarshal(changed, &anchorChain))
	for i := range anchorChain.Transitions {
		anchorChain.Transitions[i].Source = "legacy-anchor"
		anchorChain.Transitions[i].BlockHash = ""
	}
	anchorDigest := sha256.Sum256([]byte("chained anchor ledger"))
	anchorChain.AnchorDigest = hex.EncodeToString(anchorDigest[:])
	anchorChain.AnchorAttestation = "operator-quorum-attested-unverified-history"
	anchorBytes, err := json.Marshal(anchorChain)
	require.NoError(t, err)
	_, _, err = app.validateLegacyLineageRepair(string(anchorBytes))
	require.NoError(t, err)
	chainRaw := string(changed)
	audit, err := app.legacyLineageRepairAudit(chainRaw, "chain-proposal", 1190)
	require.NoError(t, err)
	require.NoError(t, app.badgerStore.SetUpgradePlan(&store.UpgradePlanRecord{Name: appV22UpgradeName, TargetAppVersion: 22, ActivationHeight: 1201, LineageRepair: chainRaw, LineageProposalID: "chain-proposal", LineageApprovedHeight: 1190, ProposedAt: 1190, ProposerID: "operator"}))
	require.NoError(t, app.badgerStore.MarkUpgradeAppliedWithLineageAudit(appV22UpgradeName, 22, 1201, *audit))
	require.NoError(t, app.badgerStore.ValidateLegacyUpgradeLineageRepairAudit())
	rungs, _, err := app.resolveAppV22Lineage(&manifest)
	require.NoError(t, err)
	require.True(t, rungs[1].TransitionTarget)
	require.Equal(t, uint64(7), rungs[1].Version)
	require.True(t, rungs[5].TransitionTarget)
	require.Equal(t, uint64(11), rungs[5].Version)
}

func TestDirectEvidenceMaySourceLaterVirtualTargetTransition(t *testing.T) {
	app, raw := skipAheadLineageFixture(t)
	for _, version := range []uint64{7, 8, 11} {
		require.NoError(t, app.badgerStore.DB().Update(func(txn *badger.Txn) error {
			return txn.Delete([]byte(fmt.Sprintf("upgrade:applied:app-v%d", version)))
		}))
	}
	var manifest LegacyLineageRepairManifest
	require.NoError(t, json.Unmarshal([]byte(raw), &manifest))
	h6 := sha256.Sum256([]byte("direct-v6"))
	h7 := sha256.Sum256([]byte("direct-v7"))
	manifest.Evidence = []LegacyLineageEvidence{{Version: 6, Name: "app-v6", AppliedHeight: 300, Source: "comet-block-results", BlockHash: hex.EncodeToString(h6[:])}, {Version: 7, Name: "app-v7", AppliedHeight: 376, Source: "comet-block-results", BlockHash: hex.EncodeToString(h7[:])}}
	manifest.Transitions = []LineageActivationTransition{{FromVersion: 7, ToVersion: 11, AppliedHeight: 992, Source: "comet-block-results", BlockHash: manifest.Transitions[1].BlockHash, SubsumedVersions: []uint64{8, 9, 10}}}
	digest, err := validLegacyLineageDigest(app.badgerStore)
	require.NoError(t, err)
	manifest.PriorLineageDigest = digest
	changed, err := json.Marshal(manifest)
	require.NoError(t, err)
	_, _, err = app.validateLegacyLineageRepair(string(changed))
	require.NoError(t, err)
}

func TestSkipAheadLineageRejectsTamperedTransitionShape(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*LegacyLineageRepairManifest)
	}{
		{"height", func(m *LegacyLineageRepairManifest) { m.Transitions[0].AppliedHeight++ }},
		{"target", func(m *LegacyLineageRepairManifest) { m.Transitions[0].ToVersion = 8 }},
		{"source", func(m *LegacyLineageRepairManifest) { m.Transitions[1].FromVersion = 7 }},
		{"hash", func(m *LegacyLineageRepairManifest) { m.Transitions[0].BlockHash = "AA" }},
		{"subsumed", func(m *LegacyLineageRepairManifest) { m.Transitions[1].SubsumedVersions = []uint64{9} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, raw := skipAheadLineageFixture(t)
			var manifest LegacyLineageRepairManifest
			require.NoError(t, json.Unmarshal([]byte(raw), &manifest))
			tc.mutate(&manifest)
			changed, _ := json.Marshal(manifest)
			_, _, err := app.validateLegacyLineageRepair(string(changed))
			require.Error(t, err)
		})
	}
}

func TestLegacyV1ReceiptIsReadOnlyCompatibilityAfterAppV22(t *testing.T) {
	app, _ := lineageRepairFixture(t, 9)
	manifest := `{"schema":"sage-upgrade-lineage-repair/v1","governance_domain":"scope","prior_lineage_digest":"prior","evidence":[{"version":9,"name":"app-v9","applied_height":13}]}`
	_, _, err := app.validateLegacyLineageRepair(manifest)
	require.Error(t, err, "new app-v21 proposals must fail closed on the retired v1 schema")
	var compact map[string]any
	require.NoError(t, json.Unmarshal([]byte(manifest), &compact))
	digest := sha256.Sum256([]byte(manifest))
	audit := store.LegacyUpgradeLineageRepairAudit{Schema: legacyLineageRepairSchemaV1, GovernanceDomain: "scope", PriorLineageDigest: "prior", ManifestDigest: hex.EncodeToString(digest[:]), Manifest: manifest, ApprovedHeight: 99, ProposalID: "legacy-v1", Records: []store.AppliedUpgradeRecord{{Name: "app-v9", TargetAppVersion: 9, AppliedHeight: 13}}}
	require.NoError(t, app.badgerStore.ApplyLegacyUpgradeLineageRepair(audit))
	_, _, err = app.resolveAppV22Lineage(nil)
	require.ErrorContains(t, err, "only for an already-activated app-v22")
	require.NoError(t, app.badgerStore.MarkUpgradeApplied(appV22UpgradeName, 22, 101))
	app.appV22AppliedHeight = 101
	_, _, err = app.resolveAppV22Lineage(nil)
	require.NoError(t, err)
}

func TestAlreadyApprovedLegacyV1PendingPlanActivatesWithoutReinstallingAudit(t *testing.T) {
	app, _ := lineageRepairFixture(t, 9)
	manifest := `{"schema":"sage-upgrade-lineage-repair/v1","governance_domain":"scope","prior_lineage_digest":"prior","evidence":[{"version":9,"name":"app-v9","applied_height":13}]}`
	digest := sha256.Sum256([]byte(manifest))
	audit := store.LegacyUpgradeLineageRepairAudit{Schema: legacyLineageRepairSchemaV1, GovernanceDomain: "scope", PriorLineageDigest: "prior", ManifestDigest: hex.EncodeToString(digest[:]), Manifest: manifest, ApprovedHeight: 99, ProposalID: "legacy-approved", Records: []store.AppliedUpgradeRecord{{Name: "app-v9", TargetAppVersion: 9, AppliedHeight: 13}}}
	require.NoError(t, app.badgerStore.ApplyLegacyUpgradeLineageRepair(audit))
	payload, err := json.Marshal(UpgradeProposalPayload{Name: appV22UpgradeName, TargetAppVersion: 22, UpgradeDelayBlocks: 200, LineageRepair: manifest})
	require.NoError(t, err)
	proposal := governance.ProposalState{ProposalID: audit.ProposalID, Operation: governance.OpUpgrade, TargetID: appV22UpgradeName, ProposerID: "operator-agent", Status: governance.StatusExecuted, CreatedHeight: 50, ExpiryHeight: 500, Payload: payload}
	proposalBytes, err := json.Marshal(proposal)
	require.NoError(t, err)
	require.NoError(t, app.badgerStore.SetState("gov:proposal:"+proposal.ProposalID, proposalBytes))
	plan := &store.UpgradePlanRecord{Name: appV22UpgradeName, TargetAppVersion: 22, ActivationHeight: 299, LineageRepair: manifest, ProposedAt: 99, ProposerID: "operator-agent"}
	require.NoError(t, app.badgerStore.SetUpgradePlan(plan))
	require.NoError(t, app.validateApprovedLegacyV1LineagePlan(plan))
	mismatch := *plan
	mismatch.ProposerID = "other"
	require.ErrorContains(t, app.validateApprovedLegacyV1LineagePlan(&mismatch), "execution context")
	require.NoError(t, app.badgerStore.SetUpgradePlan(&mismatch))
	_, activationErr := app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{Height: 299, Time: time.Now()})
	require.ErrorContains(t, activationErr, "mismatched legacy v1 lineage approval")
	mismatch = *plan
	mismatch.LineageRepair = strings.Replace(manifest, "app-v9", "app-v8", 1)
	require.ErrorContains(t, app.validateApprovedLegacyV1LineagePlan(&mismatch), "manifest")
	badProposal := proposal
	badProposal.Status = governance.StatusVoting
	badBytes, marshalErr := json.Marshal(badProposal)
	require.NoError(t, marshalErr)
	require.NoError(t, app.badgerStore.SetState("gov:proposal:"+proposal.ProposalID, badBytes))
	require.ErrorContains(t, app.validateApprovedLegacyV1LineagePlan(plan), "execution context")
	require.NoError(t, app.badgerStore.SetState("gov:proposal:"+proposal.ProposalID, proposalBytes))
	require.NoError(t, app.badgerStore.SetUpgradePlan(plan))
	_ = finalizeBlock(t, app, 299)
	applied, err := app.badgerStore.GetAppliedUpgrade(appV22UpgradeName)
	require.NoError(t, err)
	require.Equal(t, int64(299), applied.AppliedHeight)
	stored, err := app.badgerStore.GetLegacyUpgradeLineageRepairAudit()
	require.NoError(t, err)
	require.Equal(t, &audit, stored)
}

func TestLegacyLineageRepairCreatesOnlyVirtualMissingEvidenceAtActivation(t *testing.T) {
	app, raw := lineageRepairFixture(t, 9)
	_, _, err := app.validateLegacyLineageRepair(raw)
	require.NoError(t, err)
	audit, err := app.legacyLineageRepairAudit(raw, "proposal-1", 100)
	require.NoError(t, err)
	require.NoError(t, app.badgerStore.SetUpgradePlan(&store.UpgradePlanRecord{Name: appV22UpgradeName, TargetAppVersion: 22, ActivationHeight: 101, LineageRepair: raw, LineageProposalID: "proposal-1", LineageApprovedHeight: 100, ProposedAt: 100, ProposerID: "operator"}))
	require.NoError(t, app.badgerStore.MarkUpgradeAppliedWithLineageAudit(appV22UpgradeName, 22, 101, *audit))
	rec, err := app.badgerStore.GetAppliedUpgrade("app-v9")
	require.NoError(t, err)
	require.Nil(t, rec, "virtual coverage must not arm historical fork gates")
	_, err = app.validatePersistedAppV22PredecessorLadder()
	require.NoError(t, err)
	storedAudit, err := app.badgerStore.GetLegacyUpgradeLineageRepairAudit()
	require.NoError(t, err)
	require.Equal(t, "proposal-1", storedAudit.ProposalID)
}

func TestLegacyLineageRepairDeterministicAcrossIndependentStores(t *testing.T) {
	left, rawLeft := lineageRepairFixture(t, 12)
	right, rawRight := lineageRepairFixture(t, 12)
	require.Equal(t, rawLeft, rawRight)
	leftAudit, err := left.legacyLineageRepairAudit(rawLeft, "proposal-shared", 100)
	require.NoError(t, err)
	rightAudit, err := right.legacyLineageRepairAudit(rawRight, "proposal-shared", 100)
	require.NoError(t, err)
	require.NoError(t, left.badgerStore.SetUpgradePlan(&store.UpgradePlanRecord{Name: appV22UpgradeName, TargetAppVersion: 22, ActivationHeight: 101, LineageRepair: rawLeft, LineageProposalID: "proposal-shared", LineageApprovedHeight: 100, ProposedAt: 100, ProposerID: "operator"}))
	require.NoError(t, right.badgerStore.SetUpgradePlan(&store.UpgradePlanRecord{Name: appV22UpgradeName, TargetAppVersion: 22, ActivationHeight: 101, LineageRepair: rawRight, LineageProposalID: "proposal-shared", LineageApprovedHeight: 100, ProposedAt: 100, ProposerID: "operator"}))
	require.NoError(t, left.badgerStore.MarkUpgradeAppliedWithLineageAudit(appV22UpgradeName, 22, 101, *leftAudit))
	require.NoError(t, right.badgerStore.MarkUpgradeAppliedWithLineageAudit(appV22UpgradeName, 22, 101, *rightAudit))
	leftHash, err := left.badgerStore.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	rightHash, err := right.badgerStore.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	require.Equal(t, leftHash, rightHash)
	status, err := left.legacyUpgradeLineageStatus()
	require.NoError(t, err)
	require.NotNil(t, status.RepairAudit)
}

func TestLegacyLineageRepairDenials(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*LegacyLineageRepairManifest)
	}{
		{"cross-chain", func(m *LegacyLineageRepairManifest) { m.ChainID = "other-chain" }},
		{"wrong-prior-digest", func(m *LegacyLineageRepairManifest) { m.PriorLineageDigest = string(make([]byte, 64)) }},
		{"wrong-order-height", func(m *LegacyLineageRepairManifest) { m.Evidence[0].AppliedHeight = 99 }},
		{"proposal-height", func(m *LegacyLineageRepairManifest) { m.Evidence[0].AppliedHeight = 101 }},
		{"future-height", func(m *LegacyLineageRepairManifest) { m.Evidence[0].AppliedHeight = 102 }},
		{"unsupported-source", func(m *LegacyLineageRepairManifest) { m.Evidence[0].Source = "operator-says-so" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			app, raw := lineageRepairFixture(t, 9)
			var manifest LegacyLineageRepairManifest
			require.NoError(t, json.Unmarshal([]byte(raw), &manifest))
			tc.mutate(&manifest)
			changed, _ := json.Marshal(manifest)
			_, _, err := app.validateLegacyLineageRepair(string(changed))
			require.Error(t, err)
			rec, getErr := app.badgerStore.GetAppliedUpgrade("app-v9")
			require.NoError(t, getErr)
			require.Nil(t, rec)
		})
	}
}

func TestLegacyLineageRepairRejectsMixedEvidenceSources(t *testing.T) {
	app, _ := lineageRepairFixture(t, 9)
	require.NoError(t, app.badgerStore.DB().Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte("upgrade:applied:app-v10"))
	}))
	digest, err := validLegacyLineageDigest(app.badgerStore)
	require.NoError(t, err)
	domain := app.GovernanceDelegationDomain()
	proof := sha256.Sum256([]byte("retained-comet-block"))
	manifest := LegacyLineageRepairManifest{
		Schema: legacyLineageRepairSchema, ChainID: "lineage-test-chain", GovernanceDomain: domain,
		CurrentAppVersion: 21, PriorLineageDigest: digest,
		AnchorDigest: strings.Repeat("a", 64), AnchorAttestation: "operator-quorum-attested-unverified-history",
		Evidence: []LegacyLineageEvidence{
			{Version: 9, Name: "app-v9", AppliedHeight: 13, Source: "comet-block-results", BlockHash: hex.EncodeToString(proof[:])},
			{Version: 10, Name: "app-v10", AppliedHeight: 14, Source: "legacy-anchor"},
		},
	}
	raw, err := json.Marshal(manifest)
	require.NoError(t, err)
	_, _, err = app.validateLegacyLineageRepair(string(raw))
	require.ErrorContains(t, err, "mixed Comet and legacy-anchor")
}

func TestLegacyLineageRepairRefusesExistingRecord(t *testing.T) {
	app, raw := lineageRepairFixture(t, 9)
	require.NoError(t, app.badgerStore.MarkUpgradeApplied("app-v9", 9, 13))
	_, _, err := app.validateLegacyLineageRepair(raw)
	require.Error(t, err)
}

func TestLegacyLineageRepairProposalNeverAutoVotesEvenWithOneValidator(t *testing.T) {
	app, raw := lineageRepairFixture(t, 9)
	validatorKey := newAgentKey(t)
	registerAgent(t, app, validatorKey, "lineage-operator", "admin")
	require.NoError(t, app.validators.AddValidator(&validator.ValidatorInfo{
		ID: validatorKey.id, PublicKey: validatorKey.pub, Power: 10,
	}))
	require.NoError(t, app.badgerStore.SaveValidators(map[string]int64{validatorKey.id: 10}))
	propose := makeUpgradeProposeTx(t, validatorKey, appV22UpgradeName, 22, "", 200)
	propose.UpgradePropose.LineageRepair = raw
	require.NoError(t, tx.SignTx(propose, validatorKey.priv))
	result := app.processUpgradePropose(propose, 101, time.Now())
	require.Zero(t, result.Code, result.Log)
	active, err := app.govEngine.GetActiveProposal()
	require.NoError(t, err)
	require.NotNil(t, active)
	proposalID := active.ProposalID
	votes, err := app.badgerStore.GetGovVotes(proposalID)
	require.NoError(t, err)
	require.Empty(t, votes, "creating a repair proposal must not mirror the proposer's ACCEPT vote")
	for _, write := range app.pendingWrites {
		require.NotEqual(t, "gov_vote", write.writeType,
			"the off-chain projection must not invent a proposer vote absent from consensus")
	}
	requireNoPendingPlan(t, app)

	gotID, target, supported, ok := app.ActiveUpgradeVote()
	require.True(t, ok)
	require.Equal(t, proposalID, gotID)
	require.Equal(t, uint64(22), target)
	require.False(t, supported, "lineage evidence always requires an explicit operator vote")
}

func TestLegacyLineageRepairProposalRejectsAppV20DomainTail(t *testing.T) {
	app, raw := lineageRepairFixture(t, 9)
	operator := newAgentKey(t)
	registerAgent(t, app, operator, "lineage-operator", "admin")
	require.NoError(t, app.validators.AddValidator(&validator.ValidatorInfo{ID: operator.id, PublicKey: operator.pub, Power: 10}))
	require.NoError(t, app.badgerStore.SaveValidators(map[string]int64{operator.id: 10}))
	propose := makeUpgradeProposeTx(t, operator, appV22UpgradeName, 22, "", 200)
	propose.UpgradePropose.LineageRepair = raw
	propose.UpgradePropose.GovernanceDomain = strings.Repeat("a", 64)
	require.NoError(t, tx.SignTx(propose, operator.priv))
	result := app.processUpgradePropose(propose, 101, time.Now())
	require.Equal(t, uint32(47), result.Code)
	require.Contains(t, result.Log, "must not carry")
}

func TestLegacyLineageRepairRequiresExplicitFourValidatorQuorum(t *testing.T) {
	app, raw := lineageRepairFixture(t, 9)
	validators := []agentKey{newAgentKey(t), newAgentKey(t), newAgentKey(t), newAgentKey(t)}
	powers := make(map[string]int64, len(validators))
	for i, key := range validators {
		role := "member"
		if i == 0 {
			role = "admin"
		}
		registerAgent(t, app, key, fmt.Sprintf("validator-%d", i+1), role)
		require.NoError(t, app.validators.AddValidator(&validator.ValidatorInfo{ID: key.id, PublicKey: key.pub, Power: 10}))
		powers[key.id] = 10
	}
	require.NoError(t, app.badgerStore.SaveValidators(powers))
	propose := makeUpgradeProposeTx(t, validators[0], appV22UpgradeName, 22, "", 200)
	propose.Nonce = 1
	propose.UpgradePropose.LineageRepair = raw
	require.NoError(t, tx.SignTx(propose, validators[0].priv))
	encodedPropose, err := tx.EncodeTx(propose)
	require.NoError(t, err)
	proposed := finalizeBlock(t, app, 101, encodedPropose)
	require.Zero(t, proposed.TxResults[0].Code, proposed.TxResults[0].Log)
	active, err := app.govEngine.GetActiveProposal()
	require.NoError(t, err)
	require.NotNil(t, active)

	for i := 0; i < 3; i++ {
		nonce := uint64(1)
		if i == 0 {
			nonce = 2
		}
		vote := &tx.ParsedTx{
			Type: tx.TxTypeGovVote, Nonce: nonce, Timestamp: time.Now(),
			GovVote: &tx.GovVote{ProposalID: active.ProposalID, Decision: tx.VoteDecisionAccept},
		}
		require.NoError(t, tx.SignTx(vote, validators[i].priv))
		encodedVote, encodeErr := tx.EncodeTx(vote)
		require.NoError(t, encodeErr)
		response := finalizeBlock(t, app, int64(102+i), encodedVote)
		require.Zero(t, response.TxResults[0].Code, response.TxResults[0].Log)
		plan, planErr := app.badgerStore.GetUpgradePlan()
		require.ErrorIs(t, planErr, store.ErrNoUpgradePlan, "repair must not execute before quorum and the minimum voting window")
		require.Nil(t, plan)
	}
	_ = finalizeBlock(t, app, 101+governance.MinVotingBlocks)
	plan, err := app.badgerStore.GetUpgradePlan()
	require.NoError(t, err)
	require.Equal(t, raw, plan.LineageRepair)
	repaired, err := app.badgerStore.GetAppliedUpgrade("app-v9")
	require.NoError(t, err)
	require.Nil(t, repaired, "approval must not arm a historical fork gate")
	audit, err := app.badgerStore.GetLegacyUpgradeLineageRepairAudit()
	require.NoError(t, err)
	require.Nil(t, audit, "immutable receipt is installed only with app-v22 activation")
	require.Equal(t, active.ProposalID, plan.LineageProposalID)
	require.Positive(t, plan.LineageApprovedHeight)
	restarted := &SageApp{badgerStore: app.badgerStore, logger: app.logger}
	restarted.refreshAppV9Fork() // the boot-time gate loader
	require.Zero(t, restarted.appV9AppliedHeight, "restart during the delay must not arm the repaired historical gate")
	_ = finalizeBlock(t, app, plan.ActivationHeight)
	storedAudit, err := app.badgerStore.GetLegacyUpgradeLineageRepairAudit()
	require.NoError(t, err)
	require.NotNil(t, storedAudit)
	repaired, err = app.badgerStore.GetAppliedUpgrade("app-v9")
	require.NoError(t, err)
	require.Nil(t, repaired)
	appliedV22, err := app.badgerStore.GetAppliedUpgrade(appV22UpgradeName)
	require.NoError(t, err)
	require.Equal(t, plan.ActivationHeight, appliedV22.AppliedHeight)
}
