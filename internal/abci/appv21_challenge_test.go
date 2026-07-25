package abci

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
)

func appV21ChallengeFixture(t *testing.T, holderCount int) (*SageApp, []agentKey, string) {
	t.Helper()
	require.GreaterOrEqual(t, holderCount, 1)
	app := setupTestApp(t)
	app.appV20AppliedHeight = 1
	app.appV21AppliedHeight = 2

	holders := make([]agentKey, holderCount)
	for i := range holders {
		holders[i] = newAgentKey(t)
	}
	require.NoError(t, app.badgerStore.RegisterDomain("research", holders[0].id, "", 1))
	for _, holder := range holders[1:] {
		require.NoError(t, app.badgerStore.SetAccessGrant("research", holder.id, 3, 0, holders[0].id))
	}
	const memoryID = "weighted-memory"
	require.NoError(t, app.badgerStore.SetMemoryDomain(memoryID, "research"))
	require.NoError(t, app.badgerStore.SetMemoryHash(memoryID, []byte("canonical-content-hash"), string(memory.StatusCommitted)))
	return app, holders, memoryID
}

func TestAppV21WeightedChallengeZeroCorroboratorsStillDeprecates(t *testing.T) {
	app, holders, memoryID := appV21ChallengeFixture(t, 1)

	result := app.processMemoryChallenge(makeMemoryChallengeTx(t, holders[0], memoryID, "refuted"), 10, time.Unix(100, 0))
	require.Zero(t, result.Code, result.Log)
	assert.Contains(t, result.Log, "0 eligible corroborators")

	hash, status, err := app.badgerStore.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, string(memory.StatusDeprecated), status)
	assert.Empty(t, hash)
	record, err := app.badgerStore.GetChallengeRecordV21(memoryID)
	require.NoError(t, err)
	assert.Nil(t, record, "the 1/1 round resolves in the opening transaction")
	vote, err := app.badgerStore.GetChallengeVoteV21(memoryID, holders[0].id)
	require.NoError(t, err)
	require.NotNil(t, vote, "the decisive challenge remains first-class consensus evidence")
	assert.Equal(t, uint64(1), vote.Round)
}

func TestAppV21CorroborationRequiresCurrentDomainReadAccess(t *testing.T) {
	app, holders, memoryID := appV21ChallengeFixture(t, 1)
	reader := newAgentKey(t)

	rejected := app.processMemoryCorroborate(
		makeMemoryCorroborateTx(t, reader, memoryID, "saw it too"),
		10, time.Unix(100, 0),
	)
	assert.Equal(t, uint32(17), rejected.Code)
	assert.Contains(t, rejected.Log, "lacks current read access")

	require.NoError(t, app.badgerStore.SetAccessGrant("research", reader.id, 1, 0, holders[0].id))
	accepted := app.processMemoryCorroborate(
		makeMemoryCorroborateTx(t, reader, memoryID, "saw it too"),
		11, time.Unix(101, 0),
	)
	require.Zero(t, accepted.Code, accepted.Log)
	has, err := app.badgerStore.HasCorroborated(memoryID, reader.id)
	require.NoError(t, err)
	assert.True(t, has)
}

func TestAppV21WeightedChallengeProtectsAllCanonicalCorroborators(t *testing.T) {
	app, holders, memoryID := appV21ChallengeFixture(t, 3)
	outsider := newAgentKey(t)
	require.NoError(t, app.badgerStore.SetAccessGrant("research", outsider.id, 1, 0, holders[0].id))
	require.NoError(t, app.badgerStore.SetCorroborated(memoryID, holders[2].id))
	require.NoError(t, app.badgerStore.SetCorroborated(memoryID, outsider.id))

	rejectedOpen := app.processMemoryChallenge(
		makeMemoryChallengeTx(t, outsider, memoryID, "supporter cannot open"),
		9, time.Unix(99, 0),
	)
	assert.Equal(t, uint32(92), rejectedOpen.Code,
		"a corroborator without modify access may endorse a dispute but cannot open one")

	open := app.processMemoryChallenge(makeMemoryChallengeTx(t, holders[0], memoryID, "open"), 10, time.Unix(100, 0))
	require.Zero(t, open.Code, open.Log)
	assert.Contains(t, open.Log, "1/3 distinct challengers")
	assert.Contains(t, open.Log, "2 eligible corroborators")

	record, err := app.badgerStore.GetChallengeRecordV21(memoryID)
	require.NoError(t, err)
	require.NotNil(t, record)
	assert.Equal(t, uint32(2), record.EligibleCorroborators,
		"every canonical corroborator must protect the memory, even without modify access")
	assert.Equal(t, uint32(3), record.RequiredChallengers)
	assert.Equal(t, uint32(1), record.ChallengerCount)
	assert.Contains(t, record.Electorate, outsider.id,
		"a canonical corroborator may reverse their support only after a modifier opens the dispute")

	duplicate := app.processMemoryChallenge(makeMemoryChallengeTx(t, holders[0], memoryID, "retry"), 11, time.Unix(101, 0))
	assert.Equal(t, uint32(93), duplicate.Code)

	second := app.processMemoryChallenge(makeMemoryChallengeTx(t, holders[1], memoryID, "confirm"), 12, time.Unix(102, 0))
	require.Zero(t, second.Code, second.Log)
	assert.Contains(t, second.Log, "2/3")
	_, status, err := app.badgerStore.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, string(memory.StatusChallenged), status)

	confirm := app.processMemoryChallenge(makeMemoryChallengeTx(t, outsider, memoryID, "withdraw support"), 13, time.Unix(103, 0))
	require.Zero(t, confirm.Code, confirm.Log)
	assert.Contains(t, confirm.Log, "3/3")
	_, status, err = app.badgerStore.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, string(memory.StatusDeprecated), status)
}

func TestAppV21ChallengeElectorateIsFrozenAcrossGrantChurn(t *testing.T) {
	app, holders, memoryID := appV21ChallengeFixture(t, 3)
	require.NoError(t, app.badgerStore.SetCorroborated(memoryID, holders[2].id))

	open := app.processMemoryChallenge(makeMemoryChallengeTx(t, holders[0], memoryID, "open"), 10, time.Unix(100, 0))
	require.Zero(t, open.Code, open.Log)

	newHolder := newAgentKey(t)
	require.NoError(t, app.badgerStore.SetAccessGrant("research", newHolder.id, 3, 0, holders[0].id))
	require.NoError(t, app.badgerStore.DeleteAccessGrant("research", holders[1].id))

	rejected := app.processMemoryChallenge(makeMemoryChallengeTx(t, newHolder, memoryID, "late grant"), 11, time.Unix(101, 0))
	assert.Equal(t, uint32(92), rejected.Code, "a post-open grant cannot join the frozen round")

	accepted := app.processMemoryChallenge(makeMemoryChallengeTx(t, holders[1], memoryID, "snapshotted voter"), 12, time.Unix(102, 0))
	require.Zero(t, accepted.Code, accepted.Log)
	_, status, err := app.badgerStore.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, string(memory.StatusDeprecated), status, "a snapshotted voter remains eligible after revocation")
}

func TestAppV21ReinstateStartsANewRoundWithoutOldVotes(t *testing.T) {
	app, holders, memoryID := appV21ChallengeFixture(t, 4)
	require.NoError(t, app.badgerStore.SetCorroborated(memoryID, holders[2].id))
	require.NoError(t, app.badgerStore.SetCorroborated(memoryID, holders[3].id))

	open := app.processMemoryChallenge(makeMemoryChallengeTx(t, holders[0], memoryID, "open"), 10, time.Unix(100, 0))
	require.Zero(t, open.Code, open.Log)
	firstEndorse := app.processMemoryChallenge(makeMemoryChallengeTx(t, holders[1], memoryID, "endorse"), 11, time.Unix(101, 0))
	require.Zero(t, firstEndorse.Code, firstEndorse.Log)
	record, err := app.badgerStore.GetChallengeRecordV21(memoryID)
	require.NoError(t, err)
	require.NotNil(t, record)
	assert.Equal(t, uint32(2), record.ChallengerCount)
	assert.Equal(t, uint32(3), record.RequiredChallengers)

	reinstate := app.processMemoryReinstate(makeMemoryReinstateTx(t, holders[2], memoryID, "insufficient evidence"), 12, time.Unix(102, 0))
	require.Zero(t, reinstate.Code, reinstate.Log)
	originalHash, status, err := app.badgerStore.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, string(memory.StatusCommitted), status)
	assert.Equal(t, []byte("canonical-content-hash"), originalHash)

	secondOpen := app.processMemoryChallenge(makeMemoryChallengeTx(t, holders[0], memoryID, "new evidence"), 13, time.Unix(103, 0))
	require.Zero(t, secondOpen.Code, secondOpen.Log)
	second, err := app.badgerStore.GetChallengeRecordV21(memoryID)
	require.NoError(t, err)
	require.NotNil(t, second)
	assert.Equal(t, uint64(2), second.Round)
	assert.Equal(t, uint32(1), second.ChallengerCount, "round-one endorsements must not leak into round two")
	assert.Equal(t, uint32(3), second.RequiredChallengers)
}

func TestAppV21EightCorroboratorsRequireNineDistinctChallengers(t *testing.T) {
	app, holders, memoryID := appV21ChallengeFixture(t, 1)
	corroborators := make([]agentKey, 8)
	for i := range corroborators {
		corroborators[i] = newAgentKey(t)
		require.NoError(t, app.badgerStore.SetAccessGrant("research", corroborators[i].id, 1, 0, holders[0].id))
		require.NoError(t, app.badgerStore.SetCorroborated(memoryID, corroborators[i].id))
	}

	result := app.processMemoryChallenge(makeMemoryChallengeTx(t, holders[0], memoryID, "open"), 10, time.Unix(100, 0))
	require.Zero(t, result.Code, result.Log)
	record, err := app.badgerStore.GetChallengeRecordV21(memoryID)
	require.NoError(t, err)
	require.NotNil(t, record)
	assert.Equal(t, uint32(8), record.EligibleCorroborators)
	assert.Equal(t, uint32(9), record.RequiredChallengers)

	for i := 0; i < len(corroborators)-1; i++ {
		result = app.processMemoryChallenge(makeMemoryChallengeTx(t, corroborators[i], memoryID, "endorse"), int64(11+i), time.Unix(int64(101+i), 0))
		require.Zero(t, result.Code, result.Log)
		_, status, getErr := app.badgerStore.GetMemoryHash(memoryID)
		require.NoError(t, getErr)
		assert.Equal(t, string(memory.StatusChallenged), status)
	}
	result = app.processMemoryChallenge(makeMemoryChallengeTx(t, corroborators[7], memoryID, "decisive"), 18, time.Unix(108, 0))
	require.Zero(t, result.Code, result.Log)
	_, status, err := app.badgerStore.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, string(memory.StatusDeprecated), status)
}

func TestAppV21CorroboratorOverflowUsesReachableBoundedCommittee(t *testing.T) {
	app, holders, memoryID := appV21ChallengeFixture(t, 1)
	for i := 0; i < store.MaxChallengeElectorateV21+1; i++ {
		supporter := newAgentKey(t)
		require.NoError(t, app.badgerStore.SetAccessGrant("research", supporter.id, 1, 0, holders[0].id))
		require.NoError(t, app.badgerStore.SetCorroborated(memoryID, supporter.id))
	}

	result := app.processMemoryChallenge(
		makeMemoryChallengeTx(t, holders[0], memoryID, "bounded committee"),
		10, time.Unix(100, 0),
	)
	require.Zero(t, result.Code, result.Log)
	weighted, err := app.badgerStore.GetChallengeRecordV21(memoryID)
	require.NoError(t, err)
	require.NotNil(t, weighted)
	assert.Len(t, weighted.Electorate, store.MaxChallengeElectorateV21)
	assert.Equal(t, uint32(store.MaxChallengeElectorateV21-1), weighted.EligibleCorroborators)
	assert.Equal(t, uint32(store.MaxChallengeElectorateV21), weighted.RequiredChallengers)
	legacy, err := app.badgerStore.GetChallengeRecord(memoryID)
	require.NoError(t, err)
	assert.Nil(t, legacy, "supporter overflow must not fall back to an unreachable legacy confirm")
}

func TestAppV21UnauthorizedHistoricalPrefixCannotHideAuthorizedSupporter(t *testing.T) {
	app, holders, memoryID := appV21ChallengeFixture(t, 1)
	for i := 1; i <= store.MaxChallengeElectorateV21+1; i++ {
		require.NoError(t, app.badgerStore.SetCorroborated(memoryID, fmt.Sprintf("%064x", i)))
	}
	authorizedSupporter := strings.Repeat("f", 64)
	require.NoError(t, app.badgerStore.SetAccessGrant("research", authorizedSupporter, 1, 0, holders[0].id))
	require.NoError(t, app.badgerStore.SetCorroborated(memoryID, authorizedSupporter))

	result := app.processMemoryChallenge(
		makeMemoryChallengeTx(t, holders[0], memoryID, "authorized supporter must remain visible"),
		10, time.Unix(100, 0),
	)
	require.Zero(t, result.Code, result.Log)
	record, err := app.badgerStore.GetChallengeRecordV21(memoryID)
	require.NoError(t, err)
	require.NotNil(t, record, "one authorized supporter must prevent one-strike deprecation")
	assert.Equal(t, uint32(1), record.EligibleCorroborators)
	assert.Equal(t, uint32(2), record.RequiredChallengers)
	_, status, err := app.badgerStore.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, string(memory.StatusChallenged), status)
}

func TestAppV21IndeterminateHistoricalSupporterScanFailsClosed(t *testing.T) {
	app, holders, memoryID := appV21ChallengeFixture(t, 1)
	for i := 1; i <= store.MaxChallengeCorroboratorScanV21+1; i++ {
		require.NoError(t, app.badgerStore.SetCorroborated(memoryID, fmt.Sprintf("%064x", i)))
	}
	authorizedSupporter := strings.Repeat("f", 64)
	require.NoError(t, app.badgerStore.SetAccessGrant("research", authorizedSupporter, 1, 0, holders[0].id))
	require.NoError(t, app.badgerStore.SetCorroborated(memoryID, authorizedSupporter))

	result := app.processMemoryChallenge(
		makeMemoryChallengeTx(t, holders[0], memoryID, "bounded scan cannot prove k"),
		10, time.Unix(100, 0),
	)
	assert.Equal(t, uint32(95), result.Code, result.Log)
	assert.Contains(t, result.Log, "before a complete bounded read-authorized electorate")
	_, status, err := app.badgerStore.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, string(memory.StatusCommitted), status,
		"an indeterminate supporter suffix must never collapse to one-strike")
}

func TestAppV21LegacyOpenChallengeFinishesUnderLegacyV17(t *testing.T) {
	app, holders, memoryID := appV21ChallengeFixture(t, 2)
	app.appV17AppliedHeight = 1
	app.appV21AppliedHeight = 100

	open := app.processMemoryChallenge(makeMemoryChallengeTx(t, holders[0], memoryID, "legacy open"), 50, time.Unix(100, 0))
	require.Zero(t, open.Code, open.Log)
	legacy, err := app.badgerStore.GetChallengeRecord(memoryID)
	require.NoError(t, err)
	require.NotNil(t, legacy)

	confirm := app.processMemoryChallenge(makeMemoryChallengeTx(t, holders[1], memoryID, "legacy confirm"), 101, time.Unix(101, 0))
	require.Zero(t, confirm.Code, confirm.Log)
	assert.Contains(t, confirm.Log, "challenge confirmed")
	weighted, err := app.badgerStore.GetChallengeRecordV21(memoryID)
	require.NoError(t, err)
	assert.Nil(t, weighted)
}

func TestAppV21ElectorateCapUsesBoundedLegacyFallback(t *testing.T) {
	app, holders, memoryID := appV21ChallengeFixture(t, store.MaxChallengeElectorateV21+1)

	bounded, overLimit, err := app.badgerStore.ModifyVerbHoldersUpTo(
		"research", time.Unix(100, 0), store.MaxChallengeElectorateV21,
	)
	require.NoError(t, err)
	assert.True(t, overLimit)
	assert.Nil(t, bounded)

	result := app.processMemoryChallenge(makeMemoryChallengeTx(t, holders[0], memoryID, "too broad"), 10, time.Unix(100, 0))
	require.Zero(t, result.Code, result.Log)
	assert.Contains(t, result.Log, "awaiting confirm/reinstate")
	_, status, err := app.badgerStore.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, string(memory.StatusChallenged), status)
	legacy, err := app.badgerStore.GetChallengeRecord(memoryID)
	require.NoError(t, err)
	require.NotNil(t, legacy)
	assert.Equal(t, uint32(store.MaxChallengeElectorateV21+1), legacy.QuorumCount)
}
