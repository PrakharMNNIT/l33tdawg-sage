package abci

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/governance"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
	"github.com/l33tdawg/sage/internal/validator"
)

type appV24ReanchorGovernanceFixture struct {
	app       *SageApp
	root      agentKey
	validator agentKey
	admin     agentKey
}

func setupAppV24ReanchorGovernanceFixture(
	t *testing.T,
	appV24AppliedHeight int64,
) appV24ReanchorGovernanceFixture {
	t.Helper()
	app := setupTestApp(t)
	root := newAgentKey(t)
	validatorKey := newAgentKey(t)
	admin := newAgentKey(t)

	registerAgent(t, app, root, "cerebrum-root", "admin")
	registerAgent(t, app, validatorKey, "local-validator", "member")
	registerAgent(t, app, admin, "delegated-admin", "member")
	require.NoError(t, app.validators.AddValidator(&validator.ValidatorInfo{
		ID: validatorKey.id, PublicKey: validatorKey.pub, Power: 10,
	}))
	require.NoError(t, app.badgerStore.SaveValidators(map[string]int64{
		validatorKey.id: 10,
	}))
	seedTestGovernanceDelegationDomain(t, app.badgerStore)
	require.NoError(t, app.badgerStore.EnsureAppV23Root("app-v24-reanchor-tests", 1))
	promoteAppV23TestAdmin(t, app, root, admin, 1)

	// These direct fork heights keep each test focused on op 9. Dedicated replay
	// tests cover the complete upgrade ladder and activation persistence.
	app.appV20AppliedHeight = 1
	app.appV21AppliedHeight = 1
	app.appV22AppliedHeight = 1
	app.appV23AppliedHeight = 1
	app.appV24AppliedHeight = appV24AppliedHeight
	return appV24ReanchorGovernanceFixture{
		app: app, root: root, validator: validatorKey, admin: admin,
	}
}

func seedAppV24ReanchorMemory(
	t *testing.T,
	app *SageApp,
	memoryID, expectedStatus, content string,
) []byte {
	t.Helper()
	digest := sha256.Sum256([]byte(content))
	require.NoError(t, app.badgerStore.SetMemoryHash(memoryID, nil, expectedStatus))
	require.NoError(t, app.badgerStore.SetMemoryDomain(memoryID, "app-v24/repair"))
	require.NoError(t, app.badgerStore.SetMemoryAuthor(memoryID, "author-"+memoryID))
	require.NoError(t, app.badgerStore.SetMemoryAuthorPrincipal(memoryID, "principal-"+memoryID))
	require.NoError(t, app.badgerStore.SetMemoryClassification(memoryID, uint8(store.ClearanceInternal)))
	return append([]byte(nil), digest[:]...)
}

func appV24ReanchorPayload(
	t *testing.T,
	root agentKey,
	generation uint64,
	entries []tx.MemoryHashReanchorEntry,
) ([]byte, string) {
	t.Helper()
	payload, err := tx.EncodeMemoryHashReanchorPayload(tx.MemoryHashReanchorPayload{
		Version:          tx.MemoryHashReanchorPayloadVersion,
		RootCredentialID: root.id,
		RootGeneration:   generation,
		Entries:          entries,
	})
	require.NoError(t, err)
	targetID, err := tx.MemoryHashReanchorTargetID(payload)
	require.NoError(t, err)
	return payload, targetID
}

func appV24ReanchorProposal(
	t *testing.T,
	fixture appV24ReanchorGovernanceFixture,
	authorizer agentKey,
	payload []byte,
	targetID string,
	targetPubKey []byte,
	targetPower int64,
	nonce uint64,
	blockTime time.Time,
	requestNonce string,
) *tx.ParsedTx {
	t.Helper()
	body := governanceJSON(t, struct {
		ValidatorID      string `json:"validator_id"`
		GovernanceDomain string `json:"governance_domain"`
		Operation        string `json:"operation"`
		TargetID         string `json:"target_id"`
		TargetPubKey     string `json:"target_pubkey,omitempty"`
		TargetPower      int64  `json:"target_power,omitempty"`
		Reason           string `json:"reason"`
		Payload          string `json:"payload"`
	}{
		ValidatorID:      fixture.validator.id,
		GovernanceDomain: governanceReplayTestDomain,
		Operation:        appV24MemoryHashReanchorOperationName,
		TargetID:         targetID,
		TargetPubKey:     hex.EncodeToString(targetPubKey),
		TargetPower:      targetPower,
		Reason:           "repair app-v23 terminal memory hashes",
		Payload:          base64.StdEncoding.EncodeToString(payload),
	})
	parsed := &tx.ParsedTx{
		Type: tx.TxTypeGovPropose, Nonce: nonce, Timestamp: blockTime,
		GovPropose: &tx.GovPropose{
			Operation:    tx.GovOpMemoryHashReanchor,
			TargetID:     targetID,
			TargetPubKey: append([]byte(nil), targetPubKey...),
			TargetPower:  targetPower,
			Reason:       "repair app-v23 terminal memory hashes",
			Payload:      append([]byte(nil), payload...),
		},
	}
	attachGovernanceRequestProof(
		t,
		parsed,
		authorizer,
		fixture.validator,
		"POST",
		"/v1/governance/propose",
		body,
		blockTime,
		[]byte(requestNonce),
	)
	return parsed
}

func directAppV24ReanchorProposal(
	t *testing.T,
	signer agentKey,
	payload []byte,
	targetID string,
	nonce uint64,
	blockTime time.Time,
) *tx.ParsedTx {
	t.Helper()
	parsed := &tx.ParsedTx{
		Type: tx.TxTypeGovPropose, Nonce: nonce, Timestamp: blockTime,
		GovPropose: &tx.GovPropose{
			Operation: tx.GovOpMemoryHashReanchor,
			TargetID:  targetID,
			Reason:    "direct Root proposal must fail",
			Payload:   append([]byte(nil), payload...),
		},
	}
	require.NoError(t, tx.SignTx(parsed, signer.priv))
	return parsed
}

func encodeAppV24ReanchorTx(t *testing.T, parsed *tx.ParsedTx) []byte {
	t.Helper()
	raw, err := tx.EncodeTx(parsed)
	require.NoError(t, err)
	return raw
}

func TestAppV24MemoryHashReanchorIsStrictHPlusOneAndExplicitVote(t *testing.T) {
	fixture := setupAppV24ReanchorGovernanceFixture(t, 10)
	hash := seedAppV24ReanchorMemory(
		t, fixture.app, "memory-h-boundary", "committed", "boundary content",
	)
	payload, targetID := appV24ReanchorPayload(t, fixture.root, 1, []tx.MemoryHashReanchorEntry{{
		MemoryID:       "memory-h-boundary",
		ExpectedStatus: "committed",
		ContentHash:    hash,
	}})

	atActivation := appV24ReanchorProposal(
		t, fixture, fixture.root, payload, targetID, nil, 0, 1,
		time.Unix(20_010, 0).UTC(), "boundh00",
	)
	result := fixture.app.processTx(atActivation, 10, atActivation.Timestamp)
	require.Equal(t, uint32(72), result.Code, result.Log)
	require.Contains(t, result.Log, "unknown operation 9")

	afterActivation := appV24ReanchorProposal(
		t, fixture, fixture.root, payload, targetID, nil, 0, 2,
		time.Unix(20_011, 0).UTC(), "boundhp1",
	)
	result = fixture.app.processTx(afterActivation, 11, afterActivation.Timestamp)
	require.Zero(t, result.Code, result.Log)

	proposalID := governance.ComputeProposalID(
		fixture.validator.id, 11, governance.OpMemoryHashReanchor, targetID,
	)
	proposal, err := fixture.app.govEngine.LoadProposal(proposalID)
	require.NoError(t, err)
	require.Equal(t, governance.StatusVoting, proposal.Status)
	vote, err := fixture.app.badgerStore.GetState(
		"gov:vote:" + proposalID + ":" + fixture.validator.id,
	)
	require.NoError(t, err)
	require.Empty(t, vote, "op 9 must not inherit the historical proposal-time auto-vote")
	for _, pending := range fixture.app.pendingWrites {
		require.NotEqual(t, "gov_vote", pending.writeType,
			"op 9 must not project a synthetic off-chain vote")
	}
	require.Equal(
		t,
		appV24MemoryHashReanchorOperationName,
		fixture.app.governanceOperationName(governance.OpMemoryHashReanchor, 11),
	)
	require.Equal(
		t,
		"unknown_9",
		fixture.app.governanceOperationName(governance.OpMemoryHashReanchor, 10),
	)
}

func TestAppV24MemoryHashReanchorRequiresExactCurrentRootAndActiveOuterValidator(t *testing.T) {
	tests := []struct {
		name       string
		build      func(*testing.T, appV24ReanchorGovernanceFixture, []byte, string) *tx.ParsedTx
		want       uint32
		wantLog    string
		rotateRoot bool
	}{
		{
			name: "direct current Root is not a delegated validator action",
			build: func(t *testing.T, f appV24ReanchorGovernanceFixture, payload []byte, target string) *tx.ParsedTx {
				return directAppV24ReanchorProposal(
					t, f.root, payload, target, 1, time.Unix(21_002, 0).UTC(),
				)
			},
			want:    72,
			wantLog: "requires the current Root credential delegated through an active validator",
		},
		{
			name: "delegated Admin is not Root",
			build: func(t *testing.T, f appV24ReanchorGovernanceFixture, payload []byte, target string) *tx.ParsedTx {
				return appV24ReanchorProposal(
					t, f, f.admin, payload, target, nil, 0, 1,
					time.Unix(21_002, 0).UTC(), "admin001",
				)
			},
			want:    72,
			wantLog: "only the exact current Root credential",
		},
		{
			name: "retired Root credential is denied",
			build: func(t *testing.T, f appV24ReanchorGovernanceFixture, payload []byte, target string) *tx.ParsedTx {
				return appV24ReanchorProposal(
					t, f, f.root, payload, target, nil, 0, 1,
					time.Unix(21_002, 0).UTC(), "retired1",
				)
			},
			want:       72,
			wantLog:    "delegated governance authorizer is invalid",
			rotateRoot: true,
		},
		{
			name: "current Root through active validator is accepted",
			build: func(t *testing.T, f appV24ReanchorGovernanceFixture, payload []byte, target string) *tx.ParsedTx {
				return appV24ReanchorProposal(
					t, f, f.root, payload, target, nil, 0, 1,
					time.Unix(21_002, 0).UTC(), "current1",
				)
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
			hash := seedAppV24ReanchorMemory(
				t, fixture.app, "memory-auth", "committed", "authorization content",
			)
			payload, targetID := appV24ReanchorPayload(t, fixture.root, 1, []tx.MemoryHashReanchorEntry{{
				MemoryID:       "memory-auth",
				ExpectedStatus: "committed",
				ContentHash:    hash,
			}})
			if tt.rotateRoot {
				newRoot := newAgentKey(t)
				require.NoError(t, fixture.app.badgerStore.RotateAppV23RootCredential(
					1, newRoot.id, 2,
				))
			}
			parsed := tt.build(t, fixture, payload, targetID)
			result := fixture.app.processGovPropose(parsed, 2, parsed.Timestamp)
			require.Equal(t, tt.want, result.Code, result.Log)
			if tt.wantLog != "" {
				require.Contains(t, result.Log, tt.wantLog)
			}
		})
	}
}

func TestAppV24MemoryHashReanchorRejectsPayloadAndTargetMutations(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func([]byte, string) ([]byte, string, []byte, int64)
		wantError string
	}{
		{
			name: "target mismatch",
			mutate: func(payload []byte, target string) ([]byte, string, []byte, int64) {
				prefix := "0"
				if target[0] == '0' {
					prefix = "1"
				}
				return payload, prefix + target[1:], nil, 0
			},
			wantError: "target_id does not match",
		},
		{
			name: "trailing payload byte",
			mutate: func(payload []byte, target string) ([]byte, string, []byte, int64) {
				return append(append([]byte(nil), payload...), 0), target, nil, 0
			},
			wantError: "trailing bytes",
		},
		{
			name: "unused target pubkey",
			mutate: func(payload []byte, target string) ([]byte, string, []byte, int64) {
				return payload, target, []byte{1}, 0
			},
			wantError: "target_pubkey must be empty",
		},
		{
			name: "unused target power",
			mutate: func(payload []byte, target string) ([]byte, string, []byte, int64) {
				return payload, target, nil, 1
			},
			wantError: "target_power must be zero",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
			hash := seedAppV24ReanchorMemory(
				t, fixture.app, "memory-mutation", "committed", "mutation content",
			)
			payload, targetID := appV24ReanchorPayload(t, fixture.root, 1, []tx.MemoryHashReanchorEntry{{
				MemoryID:       "memory-mutation",
				ExpectedStatus: "committed",
				ContentHash:    hash,
			}})
			payload, targetID, pubKey, power := tt.mutate(payload, targetID)
			parsed := appV24ReanchorProposal(
				t, fixture, fixture.root, payload, targetID, pubKey, power, 1,
				time.Unix(22_002, 0).UTC(), "mutate01",
			)
			result := fixture.app.processTx(parsed, 2, parsed.Timestamp)
			require.Equal(t, uint32(72), result.Code, result.Log)
			require.Contains(t, result.Log, tt.wantError)
		})
	}

	t.Run("payload Root generation does not match current state", func(t *testing.T) {
		fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
		hash := seedAppV24ReanchorMemory(
			t, fixture.app, "memory-generation", "committed", "generation content",
		)
		payload, targetID := appV24ReanchorPayload(t, fixture.root, 2, []tx.MemoryHashReanchorEntry{{
			MemoryID:       "memory-generation",
			ExpectedStatus: "committed",
			ContentHash:    hash,
		}})
		parsed := appV24ReanchorProposal(
			t, fixture, fixture.root, payload, targetID, nil, 0, 1,
			time.Unix(22_002, 0).UTC(), "rootgen1",
		)
		result := fixture.app.processTx(parsed, 2, parsed.Timestamp)
		require.Equal(t, uint32(72), result.Code, result.Log)
		require.Contains(t, result.Log, "Root binding is stale")
	})
}

func TestAppV24MemoryHashReanchorSingleValidatorNeedsExplicitVoteAndAppliesAtomically(t *testing.T) {
	fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
	firstHash := seedAppV24ReanchorMemory(
		t, fixture.app, "memory-a", "committed", "first repaired content",
	)
	secondHash := seedAppV24ReanchorMemory(
		t, fixture.app, "memory-b", "deprecated", "second repaired content",
	)
	payload, targetID := appV24ReanchorPayload(t, fixture.root, 1, []tx.MemoryHashReanchorEntry{
		{MemoryID: "memory-a", ExpectedStatus: "committed", ContentHash: firstHash},
		{MemoryID: "memory-b", ExpectedStatus: "deprecated", ContentHash: secondHash},
	})
	proposal := appV24ReanchorProposal(
		t, fixture, fixture.root, payload, targetID, nil, 0, 1,
		time.Unix(23_002, 0).UTC(), "propose1",
	)
	response, err := fixture.app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{
		Height: 2,
		Time:   proposal.Timestamp,
		Txs:    [][]byte{encodeAppV24ReanchorTx(t, proposal)},
	})
	require.NoError(t, err)
	require.Len(t, response.TxResults, 1)
	require.Zero(t, response.TxResults[0].Code, response.TxResults[0].Log)
	require.NotNil(t, fixture.app.pendingAppV20Finalize)
	for _, pending := range fixture.app.pendingAppV20Finalize.app.pendingWrites {
		require.NotEqual(t, "gov_vote", pending.writeType)
	}
	proposalID := governance.ComputeProposalID(
		fixture.validator.id, 2, governance.OpMemoryHashReanchor, targetID,
	)
	active, err := fixture.app.pendingAppV20Finalize.app.govEngine.LoadProposal(proposalID)
	require.NoError(t, err)
	require.Equal(t, governance.StatusVoting, active.Status)
	for _, memoryID := range []string{"memory-a", "memory-b"} {
		contentHash, _, hashErr := fixture.app.pendingAppV20Finalize.app.badgerStore.GetMemoryHash(memoryID)
		require.NoError(t, hashErr)
		require.Empty(t, contentHash, "proposal creation alone must never apply a repair")
	}
	commitGovernanceReplayBlock(t, fixture.app)

	vote := &tx.ParsedTx{
		Type: tx.TxTypeGovVote, Nonce: 2, Timestamp: time.Unix(23_003, 0).UTC(),
		GovVote: &tx.GovVote{
			ProposalID: proposalID,
			Decision:   tx.VoteDecisionAccept,
		},
	}
	require.NoError(t, tx.SignTx(vote, fixture.validator.priv))
	response, err = fixture.app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{
		Height: 3,
		Time:   vote.Timestamp,
		Txs:    [][]byte{encodeAppV24ReanchorTx(t, vote)},
	})
	require.NoError(t, err)
	require.Zero(t, response.TxResults[0].Code, response.TxResults[0].Log)
	require.NotNil(t, fixture.app.pendingAppV20Finalize)
	executed, err := fixture.app.pendingAppV20Finalize.app.govEngine.LoadProposal(proposalID)
	require.NoError(t, err)
	require.Equal(t, governance.StatusExecuted, executed.Status)
	gotFirst, firstStatus, err := fixture.app.pendingAppV20Finalize.app.badgerStore.GetMemoryHash("memory-a")
	require.NoError(t, err)
	require.Equal(t, firstHash, gotFirst)
	require.Equal(t, "committed", firstStatus)
	gotSecond, secondStatus, err := fixture.app.pendingAppV20Finalize.app.badgerStore.GetMemoryHash("memory-b")
	require.NoError(t, err)
	require.Equal(t, secondHash, gotSecond)
	require.Equal(t, "deprecated", secondStatus)
	commitGovernanceReplayBlock(t, fixture.app)

	// The exact same approved evidence remains an idempotent no-op if replayed
	// through the apply helper; neither hash nor terminal status changes.
	_, err = fixture.app.applyGovernanceProposal(executed, 4)
	require.NoError(t, err)
	gotFirst, firstStatus, err = fixture.app.badgerStore.GetMemoryHash("memory-a")
	require.NoError(t, err)
	require.Equal(t, firstHash, gotFirst)
	require.Equal(t, "committed", firstStatus)
}

func TestAppV24MemoryHashReanchorRevalidatesRootAndEligibilityBeforeExecution(t *testing.T) {
	t.Run("Root handover leaves stale proposal voting and vote uncommitted", func(t *testing.T) {
		fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
		hash := seedAppV24ReanchorMemory(
			t, fixture.app, "memory-root-handover", "committed", "handover content",
		)
		payload, targetID := appV24ReanchorPayload(t, fixture.root, 1, []tx.MemoryHashReanchorEntry{{
			MemoryID:       "memory-root-handover",
			ExpectedStatus: "committed",
			ContentHash:    hash,
		}})
		proposal := appV24ReanchorProposal(
			t, fixture, fixture.root, payload, targetID, nil, 0, 1,
			time.Unix(24_002, 0).UTC(), "staler01",
		)
		response, err := fixture.app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{
			Height: 2, Time: proposal.Timestamp,
			Txs: [][]byte{encodeAppV24ReanchorTx(t, proposal)},
		})
		require.NoError(t, err)
		require.Zero(t, response.TxResults[0].Code, response.TxResults[0].Log)
		commitGovernanceReplayBlock(t, fixture.app)

		newRoot := newAgentKey(t)
		require.NoError(t, fixture.app.badgerStore.RotateAppV23RootCredential(
			1, newRoot.id, 3,
		))
		proposalID := governance.ComputeProposalID(
			fixture.validator.id, 2, governance.OpMemoryHashReanchor, targetID,
		)
		vote := &tx.ParsedTx{
			Type: tx.TxTypeGovVote, Nonce: 2, Timestamp: time.Unix(24_003, 0).UTC(),
			GovVote: &tx.GovVote{
				ProposalID: proposalID, Decision: tx.VoteDecisionAccept,
			},
		}
		require.NoError(t, tx.SignTx(vote, fixture.validator.priv))
		_, err = fixture.app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{
			Height: 3, Time: vote.Timestamp,
			Txs: [][]byte{encodeAppV24ReanchorTx(t, vote)},
		})
		require.ErrorContains(t, err, "Root binding is stale")
		require.Nil(t, fixture.app.pendingAppV20Finalize)
		stillVoting, err := fixture.app.govEngine.LoadProposal(proposalID)
		require.NoError(t, err)
		require.Equal(t, governance.StatusVoting, stillVoting.Status)
		recordedVote, err := fixture.app.badgerStore.GetState(
			"gov:vote:" + proposalID + ":" + fixture.validator.id,
		)
		require.NoError(t, err)
		require.Empty(t, recordedVote)
		gotHash, status, err := fixture.app.badgerStore.GetMemoryHash("memory-root-handover")
		require.NoError(t, err)
		require.Empty(t, gotHash)
		require.Equal(t, "committed", status)
	})

	t.Run("eligibility drift rejects the whole chunk before any entry is written", func(t *testing.T) {
		fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
		firstHash := seedAppV24ReanchorMemory(
			t, fixture.app, "memory-atomic-a", "committed", "atomic first",
		)
		secondHash := seedAppV24ReanchorMemory(
			t, fixture.app, "memory-atomic-b", "committed", "atomic second",
		)
		payload, targetID := appV24ReanchorPayload(t, fixture.root, 1, []tx.MemoryHashReanchorEntry{
			{MemoryID: "memory-atomic-a", ExpectedStatus: "committed", ContentHash: firstHash},
			{MemoryID: "memory-atomic-b", ExpectedStatus: "committed", ContentHash: secondHash},
		})
		proposal := appV24ReanchorProposal(
			t, fixture, fixture.root, payload, targetID, nil, 0, 1,
			time.Unix(25_002, 0).UTC(), "atomic01",
		)
		response, err := fixture.app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{
			Height: 2, Time: proposal.Timestamp,
			Txs: [][]byte{encodeAppV24ReanchorTx(t, proposal)},
		})
		require.NoError(t, err)
		require.Zero(t, response.TxResults[0].Code, response.TxResults[0].Log)
		commitGovernanceReplayBlock(t, fixture.app)

		// A deterministic state change between proposal and vote makes the
		// second entry ineligible. The pre-execution read-only pass must reject
		// before ReanchorMemoryHashes can write the first.
		require.NoError(t, fixture.app.badgerStore.SetMemoryHash(
			"memory-atomic-b", nil, "proposed",
		))
		proposalID := governance.ComputeProposalID(
			fixture.validator.id, 2, governance.OpMemoryHashReanchor, targetID,
		)
		vote := &tx.ParsedTx{
			Type: tx.TxTypeGovVote, Nonce: 2, Timestamp: time.Unix(25_003, 0).UTC(),
			GovVote: &tx.GovVote{
				ProposalID: proposalID, Decision: tx.VoteDecisionAccept,
			},
		}
		require.NoError(t, tx.SignTx(vote, fixture.validator.priv))
		_, err = fixture.app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{
			Height: 3, Time: vote.Timestamp,
			Txs: [][]byte{encodeAppV24ReanchorTx(t, vote)},
		})
		require.ErrorContains(t, err, "status mismatch")
		for _, memoryID := range []string{"memory-atomic-a", "memory-atomic-b"} {
			gotHash, _, hashErr := fixture.app.badgerStore.GetMemoryHash(memoryID)
			require.NoError(t, hashErr)
			require.Empty(t, gotHash, fmt.Sprintf("%s must remain untouched", memoryID))
		}
		stillVoting, err := fixture.app.govEngine.LoadProposal(proposalID)
		require.NoError(t, err)
		require.Equal(t, governance.StatusVoting, stillVoting.Status)
	})
}

func TestGovernanceOperationNameIncludesForkAwareAppV24Reanchor(t *testing.T) {
	fixture := setupAppV24ReanchorGovernanceFixture(t, 10)
	require.Equal(t, appV24MemoryHashReanchorOperationName, opToString(governance.OpMemoryHashReanchor))
	require.Equal(t, "unknown_9", fixture.app.governanceOperationName(governance.OpMemoryHashReanchor, 10))
	require.Equal(t, appV24MemoryHashReanchorOperationName, fixture.app.governanceOperationName(governance.OpMemoryHashReanchor, 11))
}

func TestAppV24MemoryHashReanchorRequestParserSupportsGenericAndDashboardRoutes(t *testing.T) {
	op, err := governanceProposalOpFromRequest(appV24MemoryHashReanchorOperationName, false)
	require.NoError(t, err)
	require.Equal(t, tx.GovOpMemoryHashReanchor, op)
	op, err = governanceProposalOpFromRequest(appV24MemoryHashReanchorOperationName, true)
	require.NoError(t, err)
	require.Equal(t, tx.GovOpMemoryHashReanchor, op)
}

func TestAppV24MemoryHashReanchorTargetDigestCannotBeDecodedAsValidatorKey(t *testing.T) {
	fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
	hash := seedAppV24ReanchorMemory(
		t, fixture.app, "memory-dispatch", "committed", "dispatch content",
	)
	payload, targetID := appV24ReanchorPayload(t, fixture.root, 1, []tx.MemoryHashReanchorEntry{{
		MemoryID:       "memory-dispatch",
		ExpectedStatus: "committed",
		ContentHash:    hash,
	}})
	proposal := &governance.ProposalState{
		ProposalID: "dispatch-before-pubkey",
		Operation:  governance.OpMemoryHashReanchor,
		TargetID:   targetID,
		Payload:    payload,
	}
	update, err := fixture.app.applyGovernanceProposal(proposal, 2)
	require.NoError(t, err)
	require.Nil(t, update)
	gotHash, status, err := fixture.app.badgerStore.GetMemoryHash("memory-dispatch")
	require.NoError(t, err)
	require.Equal(t, hash, gotHash)
	require.Equal(t, "committed", status)
}

func TestAppV24MemoryHashReanchorProposalIDUsesExactTargetDigest(t *testing.T) {
	fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
	hash := seedAppV24ReanchorMemory(
		t, fixture.app, "memory-proposal-id", "committed", "proposal identity",
	)
	payload, targetID := appV24ReanchorPayload(t, fixture.root, 1, []tx.MemoryHashReanchorEntry{{
		MemoryID:       "memory-proposal-id",
		ExpectedStatus: "committed",
		ContentHash:    hash,
	}})
	parsed := appV24ReanchorProposal(
		t, fixture, fixture.root, payload, targetID, nil, 0, 1,
		time.Unix(26_002, 0).UTC(), "propid01",
	)
	result := fixture.app.processTx(parsed, 2, parsed.Timestamp)
	require.Zero(t, result.Code, result.Log)
	active, err := fixture.app.govEngine.GetActiveProposal()
	require.NoError(t, err)
	require.Equal(
		t,
		governance.ComputeProposalID(
			fixture.validator.id, 2, governance.OpMemoryHashReanchor, targetID,
		),
		active.ProposalID,
	)
}

func TestAppV24MemoryHashReanchorPayloadProofRejectsDeliveredMutation(t *testing.T) {
	fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
	hash := seedAppV24ReanchorMemory(
		t, fixture.app, "memory-proof-binding", "committed", "proof binding",
	)
	payload, targetID := appV24ReanchorPayload(t, fixture.root, 1, []tx.MemoryHashReanchorEntry{{
		MemoryID:       "memory-proof-binding",
		ExpectedStatus: "committed",
		ContentHash:    hash,
	}})
	parsed := appV24ReanchorProposal(
		t, fixture, fixture.root, payload, targetID, nil, 0, 1,
		time.Unix(27_002, 0).UTC(), "proof001",
	)
	mutated := append([]byte(nil), parsed.GovPropose.Payload...)
	mutated[len(mutated)-1] ^= 0xff
	parsed.GovPropose.Payload = mutated
	require.NoError(t, tx.SignTx(parsed, fixture.validator.priv))

	result := fixture.app.processTx(parsed, 2, parsed.Timestamp)
	require.Equal(t, uint32(109), result.Code, result.Log)
	require.Contains(t, result.Log, "transaction payload differs from the signed request")
}
