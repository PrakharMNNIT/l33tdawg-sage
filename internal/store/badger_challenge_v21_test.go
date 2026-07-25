package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	challengeV21AgentA = strings.Repeat("a", canonicalAgentIDHexBytes)
	challengeV21AgentB = strings.Repeat("b", canonicalAgentIDHexBytes)
	challengeV21AgentC = strings.Repeat("c", canonicalAgentIDHexBytes)
	challengeV21AgentD = strings.Repeat("d", canonicalAgentIDHexBytes)
)

func challengeV21TestHash(label string) []byte {
	sum := sha256.Sum256([]byte(label))
	return sum[:]
}

func TestChallengeRecordV21EncodingIsVersionedCanonicalAndBounded(t *testing.T) {
	rec := &ChallengeRecordV21{
		Round:                 7,
		Domain:                "research",
		ExecutionHeight:       42,
		EligibleCorroborators: 2,
		RequiredChallengers:   3,
		ChallengerCount:       1,
		PriorHash:             challengeV21TestHash("prior"),
		PriorStatus:           "committed",
		Electorate:            []string{challengeV21AgentA, challengeV21AgentB, challengeV21AgentC},
	}
	encoded, err := encodeChallengeRecordV21(rec)
	require.NoError(t, err)
	require.Equal(t, challengeRecordV21Magic[:], encoded[:len(challengeRecordV21Magic)])

	decoded, err := decodeChallengeRecordV21(encoded)
	require.NoError(t, err)
	assert.Equal(t, rec, decoded)

	unsorted := *rec
	unsorted.Electorate = []string{challengeV21AgentB, challengeV21AgentA, challengeV21AgentC}
	_, err = encodeChallengeRecordV21(&unsorted)
	require.ErrorContains(t, err, "strictly sorted")

	thresholdReached := *rec
	thresholdReached.ChallengerCount = thresholdReached.RequiredChallengers
	_, err = encodeChallengeRecordV21(&thresholdReached)
	require.ErrorContains(t, err, "required-1")

	t.Run("oversized record rejected before parsing", func(t *testing.T) {
		_, decodeErr := decodeChallengeRecordV21(make([]byte, maxChallengeV21RecordBytes+1))
		require.ErrorContains(t, decodeErr, "exceeds limit")
	})

	t.Run("oversized string length rejected before slicing", func(t *testing.T) {
		corrupt := append([]byte(nil), encoded...)
		// The fixed header ends immediately before the length-prefixed domain.
		binary.BigEndian.PutUint32(corrupt[32:36], math.MaxUint32)
		_, decodeErr := decodeChallengeRecordV21(corrupt)
		require.ErrorContains(t, decodeErr, "domain length")
	})

	t.Run("oversized electorate count rejected before allocation", func(t *testing.T) {
		corrupt := append([]byte(nil), encoded...)
		off := 32
		for _, variable := range []string{"domain", "prior hash", "prior status"} {
			require.GreaterOrEqual(t, len(corrupt)-off, 4, variable)
			n := int(binary.BigEndian.Uint32(corrupt[off : off+4]))
			off += 4 + n
			require.LessOrEqual(t, off, len(corrupt), variable)
		}
		binary.BigEndian.PutUint32(corrupt[off:off+4], math.MaxUint32)
		_, decodeErr := decodeChallengeRecordV21(corrupt)
		require.ErrorContains(t, decodeErr, "electorate count")
	})

	t.Run("noncanonical encoded electorate rejected", func(t *testing.T) {
		corrupt := append([]byte(nil), encoded...)
		bb := bytes.Index(corrupt, []byte(challengeV21AgentB))
		cc := bytes.Index(corrupt, []byte(challengeV21AgentC))
		require.NotEqual(t, -1, bb)
		require.NotEqual(t, -1, cc)
		copy(corrupt[bb:bb+len(challengeV21AgentB)], challengeV21AgentC)
		copy(corrupt[cc:cc+len(challengeV21AgentC)], challengeV21AgentB)
		_, decodeErr := decodeChallengeRecordV21(corrupt)
		require.ErrorContains(t, decodeErr, "strictly sorted")
	})

	t.Run("trailing bytes rejected", func(t *testing.T) {
		_, decodeErr := decodeChallengeRecordV21(append(encoded, 0))
		require.ErrorContains(t, decodeErr, "trailing bytes")
	})

	t.Run("vote encoding is fixed-size and versioned", func(t *testing.T) {
		vote := &ChallengeVoteV21{
			Round:        7,
			Height:       43,
			EvidenceHash: challengeV21TestHash("evidence"),
		}
		voteBytes, encodeErr := encodeChallengeVoteV21(vote)
		require.NoError(t, encodeErr)
		assert.Equal(t, challengeVoteV21Magic[:], voteBytes[:4])
		got, decodeErr := decodeChallengeVoteV21(voteBytes)
		require.NoError(t, decodeErr)
		assert.Equal(t, vote, got)
		_, decodeErr = decodeChallengeVoteV21(append(voteBytes, 0))
		require.Error(t, decodeErr)
	})
}

func TestChallengeV21WeightedOpenEndorseAndResolve(t *testing.T) {
	bs := newTestBadger(t)
	const memoryID = "memory-weighted"
	opener := challengeV21AgentA
	voterB := challengeV21AgentB
	voterC := challengeV21AgentC
	outsider := challengeV21AgentD
	priorHash := challengeV21TestHash("weighted-prior")
	resolvedHash := challengeV21TestHash("weighted-resolved")
	require.NoError(t, bs.SetMemoryHash(memoryID, priorHash, "committed"))
	for _, agentID := range []string{opener, voterB, voterC, outsider} {
		require.NoError(t, bs.SetCorroborated(memoryID, agentID))
	}

	electorate := []string{voterC, opener, voterB, voterB}
	count, err := bs.CountCanonicalCorroboratorsV21(memoryID, electorate, opener)
	require.NoError(t, err)
	require.Equal(t, uint32(2), count, "opener and outsider must not enter k")

	outcome, err := bs.OpenChallengeV21(OpenChallengeV21Input{
		MemoryID:            memoryID,
		OpenerID:            opener,
		Domain:              "sage.research",
		ExecutionHeight:     100,
		ExpectedPriorStatus: "committed",
		ChallengedStatus:    "challenged",
		ResolvedStatus:      "deprecated",
		ResolvedHash:        resolvedHash,
		Electorate:          electorate,
		EvidenceHash:        challengeV21TestHash("open evidence"),
	})
	require.NoError(t, err)
	require.False(t, outcome.Resolved)
	require.Equal(t, uint64(1), outcome.Record.Round)
	require.Equal(t, uint32(2), outcome.Record.EligibleCorroborators)
	require.Equal(t, uint32(3), outcome.Record.RequiredChallengers)
	require.Equal(t, uint32(1), outcome.Record.ChallengerCount)
	require.Equal(t, []string{opener, voterB, voterC}, outcome.Record.Electorate)
	require.Equal(t, priorHash, outcome.Record.PriorHash)

	contentHash, status, err := bs.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, priorHash, contentHash)
	assert.Equal(t, "challenged", status)
	round, err := bs.GetChallengeRoundV21(memoryID)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), round)
	openRecord, err := bs.GetChallengeRecordV21(memoryID)
	require.NoError(t, err)
	assert.Equal(t, outcome.Record, openRecord)
	openerVote, err := bs.GetChallengeVoteV21(memoryID, opener)
	require.NoError(t, err)
	require.NotNil(t, openerVote)
	assert.Equal(t, uint64(1), openerVote.Round)

	_, err = bs.EndorseChallengeV21(EndorseChallengeV21Input{
		MemoryID:         memoryID,
		ChallengerID:     outsider,
		ExecutionHeight:  101,
		ChallengedStatus: "challenged",
		ResolvedStatus:   "deprecated",
		ResolvedHash:     resolvedHash,
		EvidenceHash:     challengeV21TestHash("outsider"),
	})
	require.ErrorIs(t, err, ErrChallengeV21NotEligible)
	_, err = bs.EndorseChallengeV21(EndorseChallengeV21Input{
		MemoryID:         memoryID,
		ChallengerID:     opener,
		ExecutionHeight:  101,
		ChallengedStatus: "challenged",
		ResolvedStatus:   "deprecated",
		ResolvedHash:     resolvedHash,
		EvidenceHash:     challengeV21TestHash("duplicate"),
	})
	require.ErrorIs(t, err, ErrChallengeV21AlreadyVoted)

	firstEndorsement, err := bs.EndorseChallengeV21(EndorseChallengeV21Input{
		MemoryID:         memoryID,
		ChallengerID:     voterB,
		ExecutionHeight:  102,
		ChallengedStatus: "challenged",
		ResolvedStatus:   "deprecated",
		ResolvedHash:     resolvedHash,
		EvidenceHash:     challengeV21TestHash("voter-b"),
	})
	require.NoError(t, err)
	require.False(t, firstEndorsement.Resolved)
	require.Equal(t, uint32(2), firstEndorsement.Record.ChallengerCount)

	finalEndorsement, err := bs.EndorseChallengeV21(EndorseChallengeV21Input{
		MemoryID:         memoryID,
		ChallengerID:     voterC,
		ExecutionHeight:  103,
		ChallengedStatus: "challenged",
		ResolvedStatus:   "deprecated",
		ResolvedHash:     resolvedHash,
		EvidenceHash:     challengeV21TestHash("voter-c"),
	})
	require.NoError(t, err)
	require.True(t, finalEndorsement.Resolved)
	require.Equal(t, uint32(3), finalEndorsement.Record.ChallengerCount)

	contentHash, status, err = bs.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, resolvedHash, contentHash)
	assert.Equal(t, "deprecated", status)
	openRecord, err = bs.GetChallengeRecordV21(memoryID)
	require.NoError(t, err)
	assert.Nil(t, openRecord, "threshold resolution must remove the open record")
	distinct, err := bs.CountDistinctChallengeVotersV21(memoryID)
	require.NoError(t, err)
	assert.Equal(t, uint32(3), distinct)
	voters, overLimit, err := bs.ListChallengeVotersV21UpTo(memoryID, 3)
	require.NoError(t, err)
	require.False(t, overLimit)
	assert.Equal(t, []string{opener, voterB, voterC}, voters)
	voters, overLimit, err = bs.ListChallengeVotersV21UpTo(memoryID, 2)
	require.NoError(t, err)
	assert.True(t, overLimit)
	assert.Nil(t, voters)
	for _, agentID := range []string{opener, voterB, voterC} {
		vote, voteErr := bs.GetChallengeVoteV21(memoryID, agentID)
		require.NoError(t, voteErr)
		require.NotNil(t, vote)
		assert.Equal(t, uint64(1), vote.Round)
	}
}

func TestChallengeV21ZeroCorroboratorsResolveOnOpen(t *testing.T) {
	bs := newTestBadger(t)
	const memoryID = "memory-zero"
	priorHash := challengeV21TestHash("zero-prior")
	resolvedHash := challengeV21TestHash("zero-resolved")
	require.NoError(t, bs.SetMemoryHash(memoryID, priorHash, "committed"))
	require.NoError(t, bs.SetCorroborated(memoryID, challengeV21AgentA))

	outcome, err := bs.OpenChallengeV21(OpenChallengeV21Input{
		MemoryID:            memoryID,
		OpenerID:            challengeV21AgentA,
		Domain:              "sage.noise",
		ExecutionHeight:     200,
		ExpectedPriorStatus: "committed",
		ChallengedStatus:    "challenged",
		ResolvedStatus:      "deprecated",
		ResolvedHash:        resolvedHash,
		Electorate:          []string{challengeV21AgentB, challengeV21AgentA},
		EvidenceHash:        challengeV21TestHash("zero evidence"),
	})
	require.NoError(t, err)
	require.True(t, outcome.Resolved)
	assert.Equal(t, uint32(0), outcome.Record.EligibleCorroborators)
	assert.Equal(t, uint32(1), outcome.Record.RequiredChallengers)
	assert.Equal(t, uint32(1), outcome.Record.ChallengerCount)

	contentHash, status, err := bs.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, resolvedHash, contentHash)
	assert.Equal(t, "deprecated", status)
	rec, err := bs.GetChallengeRecordV21(memoryID)
	require.NoError(t, err)
	assert.Nil(t, rec)
	round, err := bs.GetChallengeRoundV21(memoryID)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), round)
	vote, err := bs.GetChallengeVoteV21(memoryID, challengeV21AgentA)
	require.NoError(t, err)
	require.NotNil(t, vote)
	assert.Equal(t, uint64(1), vote.Round)
}

func TestChallengeV21ReinstatePreservesRoundsAndIsolatesStaleVotes(t *testing.T) {
	bs := newTestBadger(t)
	const memoryID = "memory-rounds"
	priorHash := challengeV21TestHash("round-prior")
	require.NoError(t, bs.SetMemoryHash(memoryID, priorHash, "committed"))
	require.NoError(t, bs.SetCorroborated(memoryID, challengeV21AgentB))
	require.NoError(t, bs.SetCorroborated(memoryID, challengeV21AgentC))

	open := func(height int64, evidence string) *ChallengeOutcomeV21 {
		t.Helper()
		outcome, err := bs.OpenChallengeV21(OpenChallengeV21Input{
			MemoryID:            memoryID,
			OpenerID:            challengeV21AgentA,
			Domain:              "sage.rounds",
			ExecutionHeight:     height,
			ExpectedPriorStatus: "committed",
			ChallengedStatus:    "challenged",
			ResolvedStatus:      "deprecated",
			ResolvedHash:        challengeV21TestHash("round-resolved"),
			Electorate:          []string{challengeV21AgentC, challengeV21AgentA, challengeV21AgentB},
			EvidenceHash:        challengeV21TestHash(evidence),
		})
		require.NoError(t, err)
		return outcome
	}
	endorseB := func(height int64, evidence string) *ChallengeOutcomeV21 {
		t.Helper()
		outcome, err := bs.EndorseChallengeV21(EndorseChallengeV21Input{
			MemoryID:         memoryID,
			ChallengerID:     challengeV21AgentB,
			ExecutionHeight:  height,
			ChallengedStatus: "challenged",
			ResolvedStatus:   "deprecated",
			ResolvedHash:     challengeV21TestHash("round-resolved"),
			EvidenceHash:     challengeV21TestHash(evidence),
		})
		require.NoError(t, err)
		return outcome
	}

	require.Equal(t, uint64(1), open(300, "round-1-open").Record.Round)
	require.Equal(t, uint32(2), endorseB(301, "round-1-b").Record.ChallengerCount)
	restored, err := bs.ReinstateChallengeV21(memoryID, "challenged")
	require.NoError(t, err)
	require.Equal(t, uint64(1), restored.Round)
	contentHash, status, err := bs.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, priorHash, contentHash)
	assert.Equal(t, "committed", status)

	second := open(302, "round-2-open")
	require.Equal(t, uint64(2), second.Record.Round)
	require.Equal(t, uint32(1), second.Record.ChallengerCount,
		"round-one vote markers must not accrue into round two")
	oldBVote, err := bs.GetChallengeVoteV21(memoryID, challengeV21AgentB)
	require.NoError(t, err)
	require.NotNil(t, oldBVote)
	assert.Equal(t, uint64(1), oldBVote.Round)

	secondB := endorseB(303, "round-2-b")
	require.False(t, secondB.Resolved)
	require.Equal(t, uint32(2), secondB.Record.ChallengerCount)
	newBVote, err := bs.GetChallengeVoteV21(memoryID, challengeV21AgentB)
	require.NoError(t, err)
	require.NotNil(t, newBVote)
	assert.Equal(t, uint64(2), newBVote.Round)
	distinct, err := bs.CountDistinctChallengeVotersV21(memoryID)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), distinct, "repeat voters overwrite their bounded marker")
}

func TestChallengeV21PreservesAndRejectsConcurrentLegacyRecord(t *testing.T) {
	bs := newTestBadger(t)
	const memoryID = "memory-legacy"
	priorHash := challengeV21TestHash("legacy-prior")
	require.NoError(t, bs.SetMemoryHash(memoryID, priorHash, "committed"))
	legacy := &ChallengeRecord{
		ChallengerID:    "legacy-agent",
		Domain:          "sage.legacy",
		ExecutionHeight: 10,
		QuorumCount:     4,
		PriorHash:       priorHash,
		PriorStatus:     "committed",
	}
	require.NoError(t, bs.OpenChallenge(memoryID, priorHash, "challenged", legacy))

	_, err := bs.OpenChallengeV21(OpenChallengeV21Input{
		MemoryID:            memoryID,
		OpenerID:            challengeV21AgentA,
		Domain:              "sage.legacy",
		ExecutionHeight:     11,
		ExpectedPriorStatus: "challenged",
		ChallengedStatus:    "challenged",
		ResolvedStatus:      "deprecated",
		ResolvedHash:        challengeV21TestHash("legacy-resolved"),
		Electorate:          []string{challengeV21AgentA},
		EvidenceHash:        challengeV21TestHash("legacy evidence"),
	})
	require.ErrorIs(t, err, ErrChallengeV21AlreadyOpen)
	gotLegacy, err := bs.GetChallengeRecord(memoryID)
	require.NoError(t, err)
	assert.Equal(t, legacy, gotLegacy)
	gotV21, err := bs.GetChallengeRecordV21(memoryID)
	require.NoError(t, err)
	assert.Nil(t, gotV21)
}

func challengeV21OpenInput(memoryID string, electorate []string) OpenChallengeV21Input {
	return OpenChallengeV21Input{
		MemoryID:            memoryID,
		OpenerID:            challengeV21AgentA,
		Domain:              "sage.atomic",
		ExecutionHeight:     400,
		ExpectedPriorStatus: "committed",
		ChallengedStatus:    "challenged",
		ResolvedStatus:      "deprecated",
		ResolvedHash:        challengeV21TestHash("atomic-resolved"),
		Electorate:          electorate,
		EvidenceHash:        challengeV21TestHash("atomic evidence"),
	}
}

func challengeV21InjectWriteFailure(scoped *BadgerStore, failAt int) {
	scoped.writeFaultHook = func(attempt int) error {
		if attempt == failAt {
			return errors.New("injected app-v21 challenge write failure")
		}
		return nil
	}
}

func TestChallengeV21AtomicBoundariesDiscardPartialWrites(t *testing.T) {
	t.Run("weighted open", func(t *testing.T) {
		base := newTestBadger(t)
		const memoryID = "memory-atomic-open"
		priorHash := challengeV21TestHash("atomic-open-prior")
		require.NoError(t, base.SetMemoryHash(memoryID, priorHash, "committed"))
		require.NoError(t, base.SetCorroborated(memoryID, challengeV21AgentB))

		scoped := base.BeginConsensusTransaction(nil)
		challengeV21InjectWriteFailure(scoped, 2) // memory succeeded; record fails
		_, err := scoped.OpenChallengeV21(challengeV21OpenInput(memoryID, []string{challengeV21AgentA, challengeV21AgentB}))
		require.ErrorContains(t, err, "injected app-v21 challenge write failure")
		require.Error(t, scoped.ConsensusTransactionError())
		require.Error(t, scoped.CommitConsensusTransaction())

		contentHash, status, err := base.GetMemoryHash(memoryID)
		require.NoError(t, err)
		assert.Equal(t, priorHash, contentHash)
		assert.Equal(t, "committed", status)
		rec, err := base.GetChallengeRecordV21(memoryID)
		require.NoError(t, err)
		assert.Nil(t, rec)
		round, err := base.GetChallengeRoundV21(memoryID)
		require.NoError(t, err)
		assert.Zero(t, round)
		vote, err := base.GetChallengeVoteV21(memoryID, challengeV21AgentA)
		require.NoError(t, err)
		assert.Nil(t, vote)
	})

	t.Run("zero corroborator immediate resolution", func(t *testing.T) {
		base := newTestBadger(t)
		const memoryID = "memory-atomic-zero"
		priorHash := challengeV21TestHash("atomic-zero-prior")
		require.NoError(t, base.SetMemoryHash(memoryID, priorHash, "committed"))

		scoped := base.BeginConsensusTransaction(nil)
		challengeV21InjectWriteFailure(scoped, 2) // resolved memory succeeded; round fails
		_, err := scoped.OpenChallengeV21(challengeV21OpenInput(memoryID, []string{challengeV21AgentA}))
		require.ErrorContains(t, err, "injected app-v21 challenge write failure")
		require.Error(t, scoped.ConsensusTransactionError())
		require.Error(t, scoped.CommitConsensusTransaction())

		contentHash, status, err := base.GetMemoryHash(memoryID)
		require.NoError(t, err)
		assert.Equal(t, priorHash, contentHash)
		assert.Equal(t, "committed", status)
		round, err := base.GetChallengeRoundV21(memoryID)
		require.NoError(t, err)
		assert.Zero(t, round)
		vote, err := base.GetChallengeVoteV21(memoryID, challengeV21AgentA)
		require.NoError(t, err)
		assert.Nil(t, vote)
	})

	t.Run("threshold endorsement and resolution", func(t *testing.T) {
		base := newTestBadger(t)
		const memoryID = "memory-atomic-endorse"
		priorHash := challengeV21TestHash("atomic-endorse-prior")
		require.NoError(t, base.SetMemoryHash(memoryID, priorHash, "committed"))
		require.NoError(t, base.SetCorroborated(memoryID, challengeV21AgentB))
		_, err := base.OpenChallengeV21(challengeV21OpenInput(memoryID, []string{challengeV21AgentA, challengeV21AgentB}))
		require.NoError(t, err)

		scoped := base.BeginConsensusTransaction(nil)
		challengeV21InjectWriteFailure(scoped, 3) // vote+memory succeeded; record delete fails
		_, err = scoped.EndorseChallengeV21(EndorseChallengeV21Input{
			MemoryID:         memoryID,
			ChallengerID:     challengeV21AgentB,
			ExecutionHeight:  401,
			ChallengedStatus: "challenged",
			ResolvedStatus:   "deprecated",
			ResolvedHash:     challengeV21TestHash("atomic-resolved"),
			EvidenceHash:     challengeV21TestHash("atomic endorse evidence"),
		})
		require.ErrorContains(t, err, "injected app-v21 challenge write failure")
		require.Error(t, scoped.ConsensusTransactionError())
		require.Error(t, scoped.CommitConsensusTransaction())

		contentHash, status, err := base.GetMemoryHash(memoryID)
		require.NoError(t, err)
		assert.Equal(t, priorHash, contentHash)
		assert.Equal(t, "challenged", status)
		rec, err := base.GetChallengeRecordV21(memoryID)
		require.NoError(t, err)
		require.NotNil(t, rec)
		assert.Equal(t, uint32(1), rec.ChallengerCount)
		vote, err := base.GetChallengeVoteV21(memoryID, challengeV21AgentB)
		require.NoError(t, err)
		assert.Nil(t, vote)
	})

	t.Run("reinstate", func(t *testing.T) {
		base := newTestBadger(t)
		const memoryID = "memory-atomic-reinstate"
		priorHash := challengeV21TestHash("atomic-reinstate-prior")
		require.NoError(t, base.SetMemoryHash(memoryID, priorHash, "committed"))
		require.NoError(t, base.SetCorroborated(memoryID, challengeV21AgentB))
		_, err := base.OpenChallengeV21(challengeV21OpenInput(memoryID, []string{challengeV21AgentA, challengeV21AgentB}))
		require.NoError(t, err)

		scoped := base.BeginConsensusTransaction(nil)
		challengeV21InjectWriteFailure(scoped, 2) // restored memory succeeded; record delete fails
		_, err = scoped.ReinstateChallengeV21(memoryID, "challenged")
		require.ErrorContains(t, err, "injected app-v21 challenge write failure")
		require.Error(t, scoped.ConsensusTransactionError())
		require.Error(t, scoped.CommitConsensusTransaction())

		contentHash, status, err := base.GetMemoryHash(memoryID)
		require.NoError(t, err)
		assert.Equal(t, priorHash, contentHash)
		assert.Equal(t, "challenged", status)
		rec, err := base.GetChallengeRecordV21(memoryID)
		require.NoError(t, err)
		require.NotNil(t, rec)
		assert.Equal(t, uint32(1), rec.ChallengerCount)
	})
}

func TestChallengeV21ElectorateCapRejectsWithoutMutation(t *testing.T) {
	bs := newTestBadger(t)
	const memoryID = "memory-electorate-cap"
	priorHash := challengeV21TestHash("cap-prior")
	require.NoError(t, bs.SetMemoryHash(memoryID, priorHash, "committed"))
	electorate := make([]string, MaxChallengeElectorateV21+1)
	electorate[0] = "agent-a"
	for i := 1; i < len(electorate); i++ {
		electorate[i] = "agent-" + string(rune(0x100+i))
	}

	_, err := bs.OpenChallengeV21(challengeV21OpenInput(memoryID, electorate))
	require.ErrorIs(t, err, ErrChallengeV21ElectorateLimit)
	_, err = bs.CountCanonicalCorroboratorsV21(memoryID, electorate, challengeV21AgentA)
	require.ErrorIs(t, err, ErrChallengeV21ElectorateLimit)
	contentHash, status, err := bs.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, priorHash, contentHash)
	assert.Equal(t, "committed", status)
	rec, err := bs.GetChallengeRecordV21(memoryID)
	require.NoError(t, err)
	assert.Nil(t, rec)
}

func TestChallengeV21MonotonicRoundOverflowDoesNotMutate(t *testing.T) {
	bs := newTestBadger(t)
	const memoryID = "memory-overflow"
	priorHash := challengeV21TestHash("overflow-prior")
	require.NoError(t, bs.SetMemoryHash(memoryID, priorHash, "committed"))
	roundBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(roundBytes, math.MaxUint64)
	require.NoError(t, bs.SetState("challengeroundv21:"+memoryID, roundBytes))

	_, err := bs.OpenChallengeV21(OpenChallengeV21Input{
		MemoryID:            memoryID,
		OpenerID:            challengeV21AgentA,
		Domain:              "sage.overflow",
		ExecutionHeight:     500,
		ExpectedPriorStatus: "committed",
		ChallengedStatus:    "challenged",
		ResolvedStatus:      "deprecated",
		ResolvedHash:        challengeV21TestHash("overflow-resolved"),
		Electorate:          []string{challengeV21AgentA},
		EvidenceHash:        challengeV21TestHash("overflow evidence"),
	})
	require.ErrorContains(t, err, "round overflow")
	contentHash, status, err := bs.GetMemoryHash(memoryID)
	require.NoError(t, err)
	assert.Equal(t, priorHash, contentHash)
	assert.Equal(t, "committed", status)
	rec, err := bs.GetChallengeRecordV21(memoryID)
	require.NoError(t, err)
	assert.Nil(t, rec)
}

func TestChallengeV21PrefixScansKeepColonTuplesIsolated(t *testing.T) {
	bs := newTestBadger(t)
	const (
		memoryID       = "memory-colon"
		nestedMemoryID = "memory-colon:child"
	)
	for _, id := range []string{memoryID, nestedMemoryID} {
		require.NoError(t, bs.SetMemoryHash(id, challengeV21TestHash(id), "committed"))
	}
	require.NoError(t, bs.SetCorroborated(memoryID, challengeV21AgentA))
	require.NoError(t, bs.SetCorroborated(nestedMemoryID, challengeV21AgentB))

	corroborators, truncated, err := bs.ListCanonicalCorroboratorsV21UpTo(memoryID, "", 10)
	require.NoError(t, err)
	assert.False(t, truncated)
	assert.Equal(t, []string{challengeV21AgentA}, corroborators,
		"a nested memory tuple must not appear in its colon-prefix sibling")

	for id, opener := range map[string]string{
		memoryID:       challengeV21AgentA,
		nestedMemoryID: challengeV21AgentB,
	} {
		_, openErr := bs.OpenChallengeV21(OpenChallengeV21Input{
			MemoryID:            id,
			OpenerID:            opener,
			Domain:              "sage.colon",
			ExecutionHeight:     1,
			ExpectedPriorStatus: "committed",
			ChallengedStatus:    "challenged",
			ResolvedStatus:      "deprecated",
			ResolvedHash:        challengeV21TestHash("resolved-" + id),
			Electorate:          []string{opener},
			EvidenceHash:        challengeV21TestHash("evidence-" + id),
		})
		require.NoError(t, openErr)
	}
	voters, truncated, err := bs.ListChallengeVotersV21UpTo(memoryID, 10)
	require.NoError(t, err)
	assert.False(t, truncated)
	assert.Equal(t, []string{challengeV21AgentA}, voters)
	count, err := bs.CountDistinctChallengeVotersV21(memoryID)
	require.NoError(t, err)
	assert.Equal(t, uint32(1), count)
}

func TestModifyVerbHoldersUpToIgnoresColonDomainGrantTuples(t *testing.T) {
	bs := newTestBadger(t)
	require.NoError(t, bs.RegisterDomain("research", challengeV21AgentA, "", 1))
	require.NoError(t, bs.SetAccessGrant("research", challengeV21AgentB, 3, 0, challengeV21AgentA))
	require.NoError(t, bs.SetAccessGrant("research:other", challengeV21AgentC, 3, 0, challengeV21AgentD))

	holders, overLimit, err := bs.ModifyVerbHoldersUpTo("research", time.Unix(100, 0), MaxChallengeElectorateV21)
	require.NoError(t, err)
	assert.False(t, overLimit)
	assert.Equal(t, []string{challengeV21AgentA, challengeV21AgentB}, holders)
}

func TestChallengeV21PrefixScansBudgetSkippedNestedKeys(t *testing.T) {
	t.Run("corroborators", func(t *testing.T) {
		bs := newTestBadger(t)
		const memoryID = "memory-flood"
		require.NoError(t, bs.update(func(txn *badger.Txn) error {
			for i := 0; i <= maxChallengeV21PrefixScanSteps; i++ {
				nested := fmt.Sprintf("%s:%04d", memoryID, i)
				if err := txn.Set(corroborationKey(nested, challengeV21AgentA), []byte{1}); err != nil {
					return err
				}
			}
			return nil
		}))
		_, _, err := bs.ListCanonicalCorroboratorsV21UpTo(memoryID, "", MaxChallengeCorroboratorScanV21)
		require.ErrorIs(t, err, ErrChallengeV21PrefixScanLimit)
	})

	t.Run("modify grants", func(t *testing.T) {
		bs := newTestBadger(t)
		require.NoError(t, bs.RegisterDomain("research", challengeV21AgentA, "", 1))
		require.NoError(t, bs.update(func(txn *badger.Txn) error {
			value := make([]byte, 9)
			value[0] = 3
			for i := 0; i <= maxChallengeV21PrefixScanSteps; i++ {
				nested := fmt.Sprintf("research:%04d", i)
				if err := txn.Set(grantKey(nested, challengeV21AgentB), value); err != nil {
					return err
				}
			}
			return nil
		}))
		_, _, err := bs.ModifyVerbHoldersUpTo("research", time.Unix(100, 0), MaxChallengeElectorateV21)
		require.ErrorIs(t, err, ErrChallengeV21PrefixScanLimit)
	})
}

func TestCanonicalEvidenceRecoveryPagesAreRawBoundedExactAndProgressing(t *testing.T) {
	bs := newTestBadger(t)
	const memoryID = "memory-recovery-pages"
	want := []string{
		fmt.Sprintf("%064x", 1),
		fmt.Sprintf("%064x", 2),
		fmt.Sprintf("%064x", 3),
		fmt.Sprintf("%064x", 4),
		fmt.Sprintf("%064x", 5),
	}
	require.NoError(t, bs.update(func(txn *badger.Txn) error {
		for _, agentID := range want {
			if err := txn.Set(corroborationKey(memoryID, agentID), []byte{1}); err != nil {
				return err
			}
			if err := txn.Set(challengeVoteV21Key(memoryID, agentID), []byte{1}); err != nil {
				return err
			}
		}
		// Malformed legacy keys count against raw page work but are never
		// returned as identities. They exercise zero-result page progress too.
		for _, suffix := range []string{"!", "bad", "nested:value", strings.Repeat("f", 63)} {
			if err := txn.Set([]byte("corrob:"+memoryID+":"+suffix), []byte{1}); err != nil {
				return err
			}
			if err := txn.Set(append(challengeVoteV21Prefix(memoryID), suffix...), []byte{1}); err != nil {
				return err
			}
		}
		return nil
	}))

	for name, list := range map[string]canonicalEvidencePageForTest{
		"corroborators": bs.ListCanonicalCorroboratorsV21Page,
		"challengers":   bs.ListChallengeVotersV21Page,
	} {
		t.Run(name, func(t *testing.T) {
			var cursor []byte
			var got []string
			pages := 0
			for {
				agents, next, done, err := list(memoryID, cursor, 2)
				require.NoError(t, err)
				got = append(got, agents...)
				pages++
				if done {
					break
				}
				require.NotEmpty(t, next)
				require.False(t, bytes.Equal(cursor, next), "cursor must advance on malformed-only pages")
				cursor = next
			}
			assert.Greater(t, pages, 1)
			assert.Equal(t, want, got)
		})
	}
}

type canonicalEvidencePageForTest func(string, []byte, int) ([]string, []byte, bool, error)

func TestCanonicalEvidenceRecoveryPagesRejectUnboundedRequestsAndForeignCursors(t *testing.T) {
	bs := newTestBadger(t)
	_, _, _, err := bs.ListCanonicalCorroboratorsV21Page(
		"memory", nil, maxChallengeV21PrefixScanSteps+1,
	)
	require.ErrorContains(t, err, "exceeds maximum")
	_, _, _, err = bs.ListChallengeVotersV21Page(
		"memory", []byte("corrob:other:cursor"), 1,
	)
	require.ErrorContains(t, err, "cursor does not match prefix")
}

func TestChallengeV21RejectsNoncanonicalWriterAgentIDs(t *testing.T) {
	bs := newTestBadger(t)
	require.ErrorContains(t, bs.SetCorroborated("memory", "agent-a"), "lowercase 64-hex")
	require.NoError(t, bs.SetMemoryHash("memory", challengeV21TestHash("memory"), "committed"))

	_, err := bs.OpenChallengeV21(OpenChallengeV21Input{
		MemoryID:            "memory",
		OpenerID:            "agent-a",
		Domain:              "sage.invalid-agent",
		ExecutionHeight:     1,
		ExpectedPriorStatus: "committed",
		ChallengedStatus:    "challenged",
		ResolvedStatus:      "deprecated",
		ResolvedHash:        challengeV21TestHash("resolved"),
		Electorate:          []string{"agent-a"},
		EvidenceHash:        challengeV21TestHash("evidence"),
	})
	require.ErrorContains(t, err, "lowercase 64-hex")
}
