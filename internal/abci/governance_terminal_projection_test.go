package abci

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/governance"
	"github.com/l33tdawg/sage/internal/store"
)

func TestGovernanceTerminalProjectionMirrorsRejectedAndExpired(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		terminal    governance.ProposalStatus
		prepare     func(*testing.T, appV24ReanchorGovernanceFixture, string, int64)
		finalHeight int64
	}{
		{
			name:     "rejected",
			terminal: governance.StatusRejected,
			prepare: func(t *testing.T, fixture appV24ReanchorGovernanceFixture, proposalID string, createdHeight int64) {
				require.NoError(t, fixture.app.govEngine.Vote(
					proposalID, fixture.validator.id, "reject", createdHeight,
				))
			},
			finalHeight: 3,
		},
		{
			name:        "expired",
			terminal:    governance.StatusExpired,
			prepare:     func(*testing.T, appV24ReanchorGovernanceFixture, string, int64) {},
			finalHeight: 2 + governance.MinExpiryBlocks + 1,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
			const createdHeight int64 = 2
			proposalID, err := fixture.app.govEngine.ProposeWithoutAutoVote(
				fixture.validator.id,
				governance.OpUpdatePower,
				fixture.validator.id,
				fixture.validator.pub,
				10,
				governance.MinExpiryBlocks,
				"terminal SQL projection regression",
				createdHeight,
				nil,
			)
			require.NoError(t, err)
			require.NoError(t, fixture.app.offchainStore.InsertGovProposal(
				context.Background(),
				&store.GovProposal{
					ProposalID:    proposalID,
					Operation:     "update_power",
					TargetAgentID: fixture.validator.id,
					TargetPower:   10,
					ProposerID:    fixture.validator.id,
					Status:        string(governance.StatusVoting),
					CreatedHeight: createdHeight,
					ExpiryHeight:  createdHeight + governance.MinExpiryBlocks,
					Reason:        "terminal SQL projection regression",
				},
			))
			testCase.prepare(t, fixture, proposalID, createdHeight)

			finalizeAndCommitAppV24ReanchorBlock(
				t, fixture.app, testCase.finalHeight,
				time.Unix(testCase.finalHeight, 0).UTC(),
			)

			canonical, err := fixture.app.govEngine.LoadProposal(proposalID)
			require.NoError(t, err)
			require.Equal(t, testCase.terminal, canonical.Status)
			projected, err := fixture.app.offchainStore.GetGovProposal(
				context.Background(), proposalID,
			)
			require.NoError(t, err)
			require.Equal(t, string(testCase.terminal), projected.Status)
			require.Nil(t, projected.ExecutedHeight)
		})
	}
}

func TestGovernanceTerminalProjectionDoesNotDuplicateOwnedStatuses(t *testing.T) {
	for _, status := range []governance.ProposalStatus{
		governance.StatusVoting,
		governance.StatusExecuted,
		governance.StatusCancelled,
	} {
		projected, ok := governanceTerminalProjectionStatus(status)
		require.False(t, ok, "status %s already has another owner", status)
		require.Empty(t, projected)
	}
	for _, status := range []governance.ProposalStatus{
		governance.StatusRejected,
		governance.StatusExpired,
	} {
		projected, ok := governanceTerminalProjectionStatus(status)
		require.True(t, ok)
		require.Equal(t, string(status), projected)
	}
}
