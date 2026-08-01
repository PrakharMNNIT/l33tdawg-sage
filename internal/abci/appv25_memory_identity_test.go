package abci

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

func TestAppV25ProposedMemoryIDIsAnImmutableCanonicalEnvelope(t *testing.T) {
	fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
	fixture.app.appV25AppliedHeight = 10
	blockTime := time.Unix(25_100, 0).UTC()

	first := makeMemorySubmitTx(t, fixture.root, "general", "first canonical content")
	first.MemorySubmit.MemoryID = "app-v25-fixed-id"
	accepted := fixture.app.processMemorySubmit(first, 11, blockTime)
	require.Equal(t, uint32(0), accepted.Code, accepted.Log)
	submittedHeight, found, err :=
		fixture.app.badgerStore.GetMemorySubmissionHeight(first.MemorySubmit.MemoryID)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, int64(11), submittedHeight)

	exactReplay := makeMemorySubmitTx(t, fixture.root, "general", "first canonical content")
	exactReplay.MemorySubmit.MemoryID = first.MemorySubmit.MemoryID
	replayed := fixture.app.processMemorySubmit(exactReplay, 12, blockTime.Add(time.Second))
	require.Equal(t, uint32(0), replayed.Code, replayed.Log)
	require.Contains(t, replayed.Log, "idempotent replay")
	submittedHeight, found, err =
		fixture.app.badgerStore.GetMemorySubmissionHeight(first.MemorySubmit.MemoryID)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, int64(11), submittedHeight)

	conflicting := makeMemorySubmitTx(t, fixture.root, "general", "different visible content")
	conflicting.MemorySubmit.MemoryID = first.MemorySubmit.MemoryID
	rejected := fixture.app.processMemorySubmit(conflicting, 13, blockTime.Add(2*time.Second))
	require.NotEqual(t, uint32(0), rejected.Code, rejected.Log)
	require.Contains(t, rejected.Log, "different canonical envelope")

	contentHash, status, err := fixture.app.badgerStore.GetMemoryHash(first.MemorySubmit.MemoryID)
	require.NoError(t, err)
	expectedHash := sha256.Sum256([]byte("first canonical content"))
	require.Equal(t, expectedHash[:], contentHash)
	require.Equal(t, string(memory.StatusProposed), status)
}

func TestAppV25SubmissionHeightStartsStrictlyAfterActivationBlock(t *testing.T) {
	fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
	fixture.app.appV25AppliedHeight = 10
	blockTime := time.Unix(25_050, 0).UTC()

	activationBlock := makeMemorySubmitTx(
		t, fixture.root, "general", "activation block remains app v24",
	)
	activationBlock.MemorySubmit.MemoryID = "app-v25-activation-boundary"
	accepted := fixture.app.processMemorySubmit(activationBlock, 10, blockTime)
	require.Equal(t, uint32(0), accepted.Code, accepted.Log)
	_, found, err := fixture.app.badgerStore.GetMemorySubmissionHeight(
		activationBlock.MemorySubmit.MemoryID,
	)
	require.NoError(t, err)
	require.False(t, found,
		"the activation block must replay under app-v24 without a new AppHash key")

	historicalReplay := makeMemorySubmitTx(
		t, fixture.root, "general", "activation block remains app v24",
	)
	historicalReplay.MemorySubmit.MemoryID = activationBlock.MemorySubmit.MemoryID
	replayed := fixture.app.processMemorySubmit(
		historicalReplay, 11, blockTime.Add(time.Second),
	)
	require.Equal(t, uint32(0), replayed.Code, replayed.Log)
	require.Contains(t, replayed.Log, "idempotent replay")
	_, found, err = fixture.app.badgerStore.GetMemorySubmissionHeight(
		activationBlock.MemorySubmit.MemoryID,
	)
	require.NoError(t, err)
	require.False(t, found,
		"an exact post-activation replay must not relabel historical evidence")

	firstV25Block := makeMemorySubmitTx(
		t, fixture.root, "general", "first app v25 block is marked",
	)
	firstV25Block.MemorySubmit.MemoryID = "app-v25-first-active-block"
	accepted = fixture.app.processMemorySubmit(
		firstV25Block, 12, blockTime.Add(2*time.Second),
	)
	require.Equal(t, uint32(0), accepted.Code, accepted.Log)
	submittedHeight, found, err := fixture.app.badgerStore.GetMemorySubmissionHeight(
		firstV25Block.MemorySubmit.MemoryID,
	)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, int64(12), submittedHeight)
}

func TestAppV25TerminalMemoryIDCannotBeReusedByAnotherAuthor(t *testing.T) {
	fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
	fixture.app.appV25AppliedHeight = 10
	const memoryID = "app-v25-cross-author-id"
	contentHash := sha256.Sum256([]byte("canonical content"))

	require.NoError(t, fixture.app.badgerStore.SetMemoryHash(
		memoryID, contentHash[:], string(memory.StatusCommitted),
	))
	require.NoError(t, fixture.app.badgerStore.SetMemoryDomain(memoryID, "general"))
	require.NoError(t, fixture.app.badgerStore.SetMemoryAuthor(memoryID, "different-local-author"))
	require.NoError(t, fixture.app.badgerStore.SetMemoryClassification(memoryID, 1))

	attempt := makeMemorySubmitTx(t, fixture.root, "general", "canonical content")
	attempt.MemorySubmit.MemoryID = memoryID
	rejected := fixture.app.processMemorySubmit(
		attempt, 11, time.Unix(25_200, 0).UTC(),
	)
	require.NotEqual(t, uint32(0), rejected.Code, rejected.Log)
	require.Contains(t, rejected.Log, "different canonical envelope")

	author, err := fixture.app.badgerStore.GetMemoryAuthor(memoryID)
	require.NoError(t, err)
	require.Equal(t, "different-local-author", author)
}

func TestAppV25ExactTerminalReplayIsIdempotentButConflictingReplayIsRejected(t *testing.T) {
	fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
	fixture.app.appV25AppliedHeight = 10
	blockTime := time.Unix(25_300, 0).UTC()

	first := makeMemorySubmitTx(t, fixture.root, "general", "terminal canonical content")
	first.MemorySubmit.MemoryID = "app-v25-terminal-replay"
	accepted := fixture.app.processMemorySubmit(first, 11, blockTime)
	require.Equal(t, uint32(0), accepted.Code, accepted.Log)
	require.NoError(t, fixture.app.badgerStore.SetMemoryStatusPreservingHash(
		first.MemorySubmit.MemoryID, string(memory.StatusCommitted),
	))

	exact := makeMemorySubmitTx(t, fixture.root, "general", "terminal canonical content")
	exact.MemorySubmit.MemoryID = first.MemorySubmit.MemoryID
	replayed := fixture.app.processMemorySubmit(exact, 12, blockTime.Add(time.Second))
	require.Equal(t, uint32(0), replayed.Code, replayed.Log)
	require.Contains(t, replayed.Log, "idempotent replay")

	conflicting := makeMemorySubmitTx(t, fixture.root, "general", "terminal collision")
	conflicting.MemorySubmit.MemoryID = first.MemorySubmit.MemoryID
	rejected := fixture.app.processMemorySubmit(conflicting, 13, blockTime.Add(2*time.Second))
	require.NotEqual(t, uint32(0), rejected.Code, rejected.Log)
	require.Contains(t, rejected.Log, "different canonical envelope")
}

func TestAppV25VoteRequiresExistingProposedCanonicalMemory(t *testing.T) {
	fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
	fixture.app.appV25AppliedHeight = 10
	vote := func(memoryID string, height int64) *abcitypes.ExecTxResult {
		return fixture.app.processMemoryVote(&tx.ParsedTx{
			PublicKey: fixture.validator.pub,
			MemoryVote: &tx.MemoryVote{
				MemoryID: memoryID,
				Decision: tx.VoteDecisionAccept,
			},
		}, height, time.Unix(height, 0).UTC())
	}

	unknown := vote("sql-only-orphan", 11)
	require.Equal(t, uint32(13), unknown.Code, unknown.Log)
	require.Contains(t, unknown.Log, "unknown canonical memory")
	_, _, err := fixture.app.badgerStore.GetMemoryHash("sql-only-orphan")
	require.Error(t, err)

	require.NoError(t, fixture.app.badgerStore.SetMemoryHash(
		"hashless-vote-target", nil, string(memory.StatusProposed),
	))
	hashless := vote("hashless-vote-target", 12)
	require.Equal(t, uint32(13), hashless.Code, hashless.Log)
	require.Contains(t, hashless.Log, "no verifiable content hash")

	contentHash := sha256.Sum256([]byte("terminal vote target"))
	require.NoError(t, fixture.app.badgerStore.SetMemoryHash(
		"terminal-vote-target", contentHash[:], string(memory.StatusCommitted),
	))
	terminal := vote("terminal-vote-target", 13)
	require.Equal(t, uint32(13), terminal.Code, terminal.Log)
	require.Contains(t, terminal.Log, "not proposed")
}

func TestAppV25DuplicateUnscopedVoteCannotInflateValidatorStats(t *testing.T) {
	fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
	addAppV24ReanchorValidators(t, fixture, 2)
	fixture.app.appV25AppliedHeight = 10

	contentHash := sha256.Sum256([]byte("canonical multi-validator vote target"))
	require.NoError(t, fixture.app.badgerStore.SetMemoryHash(
		"app-v25-duplicate-vote", contentHash[:], string(memory.StatusProposed),
	))
	require.NoError(t, fixture.app.badgerStore.SetMemoryDomain(
		"app-v25-duplicate-vote", "general",
	))
	vote := func(height int64) *abcitypes.ExecTxResult {
		return fixture.app.processMemoryVote(&tx.ParsedTx{
			PublicKey: fixture.validator.pub,
			MemoryVote: &tx.MemoryVote{
				MemoryID: "app-v25-duplicate-vote",
				Decision: tx.VoteDecisionAccept,
			},
		}, height, time.Unix(height, 0).UTC())
	}

	first := vote(11)
	require.Equal(t, uint32(0), first.Code, first.Log)
	_, status, err := fixture.app.badgerStore.GetMemoryHash(
		"app-v25-duplicate-vote",
	)
	require.NoError(t, err)
	require.Equal(t, string(memory.StatusProposed), status)

	statsBefore, err := fixture.app.badgerStore.GetValidatorStats(
		fixture.validator.id,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(1), statsBefore.TotalVotes)

	duplicate := vote(12)
	require.Equal(t, uint32(13), duplicate.Code, duplicate.Log)
	require.Contains(t, duplicate.Log, "already voted")

	statsAfter, err := fixture.app.badgerStore.GetValidatorStats(
		fixture.validator.id,
	)
	require.NoError(t, err)
	require.Equal(t, statsBefore.TotalVotes, statsAfter.TotalVotes)
	require.Equal(t, statsBefore.AcceptVotes, statsAfter.AcceptVotes)
}

func TestAppV25AdoptedProposedMemoryRevoteDoesNotDoubleCreditPoE(t *testing.T) {
	fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
	fixture.app.appV25AppliedHeight = 10
	const memoryID = "app-v25-adopted-proposed-revote"
	contentHash := sha256.Sum256([]byte("adopted proposed vote target"))

	require.NoError(t, fixture.app.badgerStore.IncrementVoteStats(
		fixture.validator.id, true, 9, true,
	))
	require.NoError(t, fixture.app.badgerStore.SetState(
		"vote:"+memoryID+":"+fixture.validator.id,
		[]byte("accept"),
	))
	_, err := fixture.app.badgerStore.AdoptLegacyMemories(
		bytes.Repeat([]byte{0xd5}, sha256.Size),
		[]store.MemoryLegacyAdoptionEntry{{
			MemoryID: memoryID, Status: string(memory.StatusProposed),
			ContentHash: contentHash[:], Domain: "general",
			Author: fixture.root.id, AuthorPrincipal: fixture.root.id,
			Classification: uint8(store.ClearanceInternal),
		}},
	)
	require.NoError(t, err)
	staleVote, err := fixture.app.badgerStore.GetState(
		"vote:" + memoryID + ":" + fixture.validator.id,
	)
	require.NoError(t, err)
	require.Empty(t, staleVote)

	result := fixture.app.processMemoryVote(&tx.ParsedTx{
		PublicKey: fixture.validator.pub,
		MemoryVote: &tx.MemoryVote{
			MemoryID: memoryID,
			Decision: tx.VoteDecisionAccept,
		},
	}, 11, time.Unix(11, 0).UTC())
	require.Equal(t, uint32(0), result.Code, result.Log)
	stats, err := fixture.app.badgerStore.GetValidatorStats(fixture.validator.id)
	require.NoError(t, err)
	require.Equal(t, uint64(1), stats.TotalVotes,
		"repair quorum may recast the ballot but must not credit PoE twice")
	require.Equal(t, uint64(1), stats.AcceptVotes)
}

func TestMemoryAutoVoterNeverAdmitsSQLOnlyOrHashlessTargets(t *testing.T) {
	fixture := setupAppV24ReanchorGovernanceFixture(t, 1)
	const voterID = "local-validator"

	eligible, recorded := fixture.app.MemoryVoteTargetState(
		"sql-only-proposed-row", voterID,
	)
	require.False(t, eligible)
	require.False(t, recorded)

	require.NoError(t, fixture.app.badgerStore.SetMemoryHash(
		"hashless-canonical-row", nil, string(memory.StatusProposed),
	))
	eligible, recorded = fixture.app.MemoryVoteTargetState(
		"hashless-canonical-row", voterID,
	)
	require.False(t, eligible)
	require.False(t, recorded)

	contentHash := sha256.Sum256([]byte("canonical vote target"))
	require.NoError(t, fixture.app.badgerStore.SetMemoryHash(
		"canonical-proposed-row", contentHash[:], string(memory.StatusProposed),
	))
	eligible, recorded = fixture.app.MemoryVoteTargetState(
		"canonical-proposed-row", voterID,
	)
	require.True(t, eligible)
	require.False(t, recorded)

	require.NoError(t, fixture.app.badgerStore.SetState(
		"vote:canonical-proposed-row:"+voterID,
		[]byte("accept"),
	))
	eligible, recorded = fixture.app.MemoryVoteTargetState(
		"canonical-proposed-row", voterID,
	)
	require.False(t, eligible)
	require.True(t, recorded)
}
