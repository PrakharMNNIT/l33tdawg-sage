package abci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

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

func TestLegacyLineageRepairCreatesOnlyExactMissingEvidence(t *testing.T) {
	app, raw := lineageRepairFixture(t, 9)
	_, _, err := app.validateLegacyLineageRepair(raw)
	require.NoError(t, err)
	require.NoError(t, app.applyLegacyLineageRepair(raw, "proposal-1", 101))
	rec, err := app.badgerStore.GetAppliedUpgrade("app-v9")
	require.NoError(t, err)
	require.Equal(t, &store.AppliedUpgradeRecord{Name: "app-v9", TargetAppVersion: 9, AppliedHeight: 13}, rec)
	_, err = app.validatePersistedAppV22PredecessorLadder()
	require.NoError(t, err)
	audit, err := app.badgerStore.GetLegacyUpgradeLineageRepairAudit()
	require.NoError(t, err)
	require.Equal(t, "proposal-1", audit.ProposalID)
}

func TestLegacyLineageRepairDeterministicAcrossIndependentStores(t *testing.T) {
	left, rawLeft := lineageRepairFixture(t, 12)
	right, rawRight := lineageRepairFixture(t, 12)
	require.Equal(t, rawLeft, rawRight)
	require.NoError(t, left.applyLegacyLineageRepair(rawLeft, "proposal-shared", 101))
	require.NoError(t, right.applyLegacyLineageRepair(rawRight, "proposal-shared", 101))
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
	require.Equal(t, int64(13), repaired.AppliedHeight)
}
