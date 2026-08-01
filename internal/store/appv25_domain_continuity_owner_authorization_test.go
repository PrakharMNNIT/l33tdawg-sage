package store

import (
	"crypto/sha256"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func reviewRecoveredAgentPolicy(
	t *testing.T,
	s *BadgerStore,
	rootID, agentID, role, profile string,
	capabilities AgentCapabilities,
	height int64,
) {
	t.Helper()
	enrollment, err := s.GetAppV23Enrollment(agentID)
	require.NoError(t, err)
	require.NotNil(t, enrollment)
	currentRole, err := s.GetAppV23Role(agentID)
	require.NoError(t, err)
	require.NotNil(t, currentRole)
	require.NoError(t, s.SetAppV23Policy(
		rootID, agentID, role,
		enrollment.Profile, profile,
		enrollment.Clearance, capabilities,
		currentRole.Revision, enrollment.Revision, height,
	))
}

func requireRecoveredDomainDecision(
	t *testing.T,
	s *BadgerStore,
	agentID, domain string,
	verb AppV23DomainVerb,
	want bool,
) AppV23Authorization {
	t.Helper()
	decision, err := s.AuthorizeAppV23LocalDomain(agentID, domain, verb, true)
	require.NoError(t, err)
	require.Equal(t, want, decision.Allowed)
	return decision
}

func TestAppV25RecoveredGroupOwnerAuthoritySurvivesReviewAndTransfers(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	rootID := appV23Register(t, s, "recovered-owner-root", AppV23RoleAdmin, 1, 0)
	// Deliberately make the earliest writer lexically later than the second
	// writer. Ownership is manifest provenance, never sorted-ID order.
	ownerID := appV23Register(t, s, "recovered-owner-z", AppV23RoleMember, 2, DefaultSelfRegisteredAgentCapabilities)
	memberID := appV23Register(t, s, "recovered-owner-a", AppV23RoleMember, 3, DefaultSelfRegisteredAgentCapabilities)
	newOwnerID := appV23Register(t, s, "recovered-owner-new", AppV23RoleMember, 4, 0)
	require.NoError(t, s.RegisterDomain("recovered-owned-team", rootID, "", 5))
	require.NoError(t, s.EnsureAppV23Root("recovered-owner", 100))

	writers := []string{ownerID, memberID}
	sort.Strings(writers)
	plan := sha256.Sum256([]byte("recovered-owner-plan"))
	require.NoError(t, s.ApplyAppV25DomainContinuityBatch(
		[]AppV25DomainContinuityBatchEntry{{
			Domain: "recovered-owned-team", Owner: ownerID, Writers: writers,
		}},
		plan[:], 1, 120,
	))
	record, err := s.GetAppV25DomainContinuity("recovered-owned-team")
	require.NoError(t, err)
	require.Equal(t, ownerID, record.Owner)
	currentOwner, err := s.GetDomainOwner("recovered-owned-team")
	require.NoError(t, err)
	require.Equal(t, ownerID, currentOwner)

	// The initial revision-bound entitlement bypasses the inherited mask 30
	// only for this exact recovered domain. The provenance owner also receives
	// exact domain-scoped Modify despite that legacy mask.
	for _, verb := range []AppV23DomainVerb{AppV23VerbRead, AppV23VerbWrite, AppV23VerbModify} {
		requireRecoveredDomainDecision(t, s, ownerID, "recovered-owned-team", verb, true)
	}
	requireRecoveredDomainDecision(t, s, memberID, "recovered-owned-team", AppV23VerbRead, true)
	requireRecoveredDomainDecision(t, s, memberID, "recovered-owned-team", AppV23VerbWrite, true)
	requireRecoveredDomainDecision(t, s, memberID, "recovered-owned-team", AppV23VerbModify, false)
	for _, verb := range []AppV23DomainVerb{AppV23VerbRead, AppV23VerbWrite, AppV23VerbModify} {
		requireRecoveredDomainDecision(t, s, newOwnerID, "recovered-owned-team", verb, false)
	}

	// A normal review invalidates the exact grant revision but current group
	// membership remains durable authority. Global Manager does not turn a
	// later writer into this domain's manager.
	reviewRecoveredAgentPolicy(t, s, rootID, ownerID, AppV23RoleMember, AppV23ProfileStandard, 0, 121)
	reviewRecoveredAgentPolicy(t, s, rootID, memberID, AppV23RoleManager, AppV23ProfileStandard, 0, 122)
	restored, err := s.AppV25AllowsHistoricalDomainWrite(ownerID, "recovered-owned-team")
	require.NoError(t, err)
	require.False(t, restored)
	for _, verb := range []AppV23DomainVerb{AppV23VerbRead, AppV23VerbWrite, AppV23VerbModify} {
		requireRecoveredDomainDecision(t, s, ownerID, "recovered-owned-team", verb, true)
	}
	requireRecoveredDomainDecision(t, s, memberID, "recovered-owned-team", AppV23VerbRead, true)
	requireRecoveredDomainDecision(t, s, memberID, "recovered-owned-team", AppV23VerbWrite, true)
	requireRecoveredDomainDecision(t, s, memberID, "recovered-owned-team", AppV23VerbModify, false)

	// A governed transfer changes current authority without rewriting the
	// immutable historical Owner. The old owner remains a group member (R/W),
	// while the new ordinary local owner receives R/W/Modify.
	require.NoError(t, s.TransferDomainAppV23(
		"recovered-owned-team", newOwnerID, "", 123, false,
	))
	require.Equal(t, ownerID, record.Owner)
	currentOwner, err = s.GetDomainOwner("recovered-owned-team")
	require.NoError(t, err)
	require.Equal(t, newOwnerID, currentOwner)
	requireRecoveredDomainDecision(t, s, ownerID, "recovered-owned-team", AppV23VerbRead, true)
	requireRecoveredDomainDecision(t, s, ownerID, "recovered-owned-team", AppV23VerbWrite, true)
	requireRecoveredDomainDecision(t, s, ownerID, "recovered-owned-team", AppV23VerbModify, false)
	for _, verb := range []AppV23DomainVerb{AppV23VerbRead, AppV23VerbWrite, AppV23VerbModify} {
		requireRecoveredDomainDecision(t, s, newOwnerID, "recovered-owned-team", verb, true)
	}

	// Current membership is authoritative: removal revokes the recovered path.
	group, err := s.GetAppV23AccessGroup(record.GroupID)
	require.NoError(t, err)
	require.NoError(t, s.MutateAppV23AccessGroup(
		rootID, group.GroupID, group.Name, []string{ownerID},
		group.Revision, false, 124,
	))
	requireRecoveredDomainDecision(t, s, memberID, "recovered-owned-team", AppV23VerbRead, false)
	requireRecoveredDomainDecision(t, s, memberID, "recovered-owned-team", AppV23VerbWrite, false)
	requireRecoveredDomainDecision(t, s, memberID, "recovered-owned-team", AppV23VerbModify, false)

	// Explicit current hard policy still outranks recovered ownership/group
	// compatibility after a review revision.
	reviewRecoveredAgentPolicy(
		t, s, rootID, newOwnerID, AppV23RoleMember, AppV23ProfileCompanion,
		AgentCapabilities(15), 125,
	)
	requireRecoveredDomainDecision(t, s, newOwnerID, "recovered-owned-team", AppV23VerbRead, true)
	write := requireRecoveredDomainDecision(t, s, newOwnerID, "recovered-owned-team", AppV23VerbWrite, false)
	require.True(t, write.ExplicitDeny)
	modify := requireRecoveredDomainDecision(t, s, newOwnerID, "recovered-owned-team", AppV23VerbModify, false)
	require.True(t, modify.ExplicitDeny)

	reviewRecoveredAgentPolicy(
		t, s, rootID, ownerID, AppV23RoleMember, AppV23ProfileReadOnly,
		AgentCapabilityReadAllDomains, 126,
	)
	requireRecoveredDomainDecision(t, s, ownerID, "recovered-owned-team", AppV23VerbRead, true)
	write = requireRecoveredDomainDecision(t, s, ownerID, "recovered-owned-team", AppV23VerbWrite, false)
	require.True(t, write.ExplicitDeny)
}

func TestAppV25RecoveredRootFallbackNeverPromotesLaterWriter(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	rootID := appV23Register(t, s, "recovered-fallback-root", AppV23RoleAdmin, 1, 0)
	writerA := appV23Register(t, s, "recovered-fallback-a", AppV23RoleMember, 2, DefaultSelfRegisteredAgentCapabilities)
	writerB := appV23Register(t, s, "recovered-fallback-b", AppV23RoleMember, 3, DefaultSelfRegisteredAgentCapabilities)
	require.NoError(t, s.RegisterDomain("recovered-root-fallback", rootID, "", 4))
	require.NoError(t, s.EnsureAppV23Root("recovered-fallback", 100))
	writers := []string{writerA, writerB}
	sort.Strings(writers)
	plan := sha256.Sum256([]byte("recovered-root-fallback-plan"))
	require.NoError(t, s.ApplyAppV25DomainContinuityBatch(
		[]AppV25DomainContinuityBatchEntry{{
			Domain: "recovered-root-fallback", Owner: rootID, Writers: writers,
		}},
		plan[:], 1, 120,
	))
	record, err := s.GetAppV25DomainContinuity("recovered-root-fallback")
	require.NoError(t, err)
	require.Equal(t, rootID, record.Owner)
	for _, writer := range writers {
		requireRecoveredDomainDecision(t, s, writer, "recovered-root-fallback", AppV23VerbRead, true)
		requireRecoveredDomainDecision(t, s, writer, "recovered-root-fallback", AppV23VerbWrite, true)
		requireRecoveredDomainDecision(t, s, writer, "recovered-root-fallback", AppV23VerbModify, false)
	}
	for _, verb := range []AppV23DomainVerb{AppV23VerbRead, AppV23VerbWrite, AppV23VerbModify} {
		requireRecoveredDomainDecision(t, s, rootID, "recovered-root-fallback", verb, true)
	}
}
