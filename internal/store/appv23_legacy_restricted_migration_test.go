package store

import (
	"fmt"
	"testing"
	"time"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/require"
)

func expectedAppV23MigratedProfile(mask AgentCapabilities) string {
	switch mask {
	case 0, AgentCapabilityDenyFederatedPipe:
		return AppV23ProfileStandard
	case 15, 15 | AgentCapabilityDenyFederatedPipe:
		return AppV23ProfileCompanion
	default:
		return AppV23ProfileLegacyRestricted
	}
}

func TestAppV23MigrationPreservesEveryLegacyMaskAndDomainlessClaimPosture(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	_ = appV23Register(t, s, "mask-matrix-root", AppV23RoleAdmin, 1, 0)
	ids := make(map[AgentCapabilities]string, 32)
	for mask := AgentCapabilities(0); mask <= KnownAgentCapabilities; mask++ {
		ids[mask] = appV23Register(
			t, s, fmt.Sprintf("domainless-mask-%02d", mask),
			AppV23RoleMember, int64(mask)+2, mask,
		)
	}

	require.NoError(t, s.EnsureAppV23Root("mask-matrix", 100))
	require.NoError(t, s.ValidateAppV23State())

	for mask := AgentCapabilities(0); mask <= KnownAgentCapabilities; mask++ {
		mask := mask
		t.Run(fmt.Sprintf("mask_%02d", mask), func(t *testing.T) {
			id := ids[mask]
			enrollment, err := s.GetAppV23Enrollment(id)
			require.NoError(t, err)
			require.NotNil(t, enrollment)
			role, err := s.GetAppV23Role(id)
			require.NoError(t, err)
			require.Equal(t, AppV23RoleMember, role.Role)
			require.Equal(t, mask, enrollment.Capabilities,
				"migration must preserve every exact known capability mask")

			if mask == DefaultSelfRegisteredAgentCapabilities {
				require.False(t, enrollment.Active)
				require.Empty(t, enrollment.HomeDomain)
				require.Equal(t, AppV23ProfileLegacyRestricted, enrollment.Profile)
				disposition, err := s.GetAppV23MigrationDisposition(id)
				require.NoError(t, err)
				require.Equal(t, "pending_review", disposition.Disposition)
				return
			}

			require.True(t, enrollment.Active)
			require.Equal(t, expectedAppV23MigratedProfile(mask), enrollment.Profile)
			if mask.Has(AgentCapabilityDenyDomainClaim) {
				require.Empty(t, enrollment.HomeDomain,
					"a deny-claim principal must not receive a newly-owned writable domain")
				require.True(t, AppV23AllowsMigratedDomainless(
					enrollment.Profile, enrollment.Capabilities,
				))
			} else {
				require.NotEmpty(t, enrollment.HomeDomain)
				owner, err := s.GetDomainOwner(enrollment.HomeDomain)
				require.NoError(t, err)
				require.Equal(t, id, owner)
			}
		})
	}
}

func TestAppV23MigrationPreservesOwnedAndGrantedWriteRestrictionsForEveryMask(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	rootID := appV23Register(t, s, "owned-mask-root", AppV23RoleAdmin, 1, 0)
	require.NoError(t, s.RegisterDomain("foreign-owned", rootID, "", 2))
	require.NoError(t, s.RegisterDomain("foreign-ungranted", rootID, "", 3))
	ids := make(map[AgentCapabilities]string, 32)
	for mask := AgentCapabilities(0); mask <= KnownAgentCapabilities; mask++ {
		id := appV23Register(
			t, s, fmt.Sprintf("owned-mask-%02d", mask),
			AppV23RoleMember, int64(mask)+3, mask,
		)
		ids[mask] = id
		require.NoError(t, s.RegisterDomain(fmt.Sprintf("owned-%02d", mask), id, "", int64(mask)+40))
		require.NoError(t, s.SetAccessGrant("foreign-owned", id, 2, 0, rootID))
	}

	require.NoError(t, s.EnsureAppV23Root("owned-mask-matrix", 100))
	require.NoError(t, s.ValidateAppV23State())

	for mask := AgentCapabilities(0); mask <= KnownAgentCapabilities; mask++ {
		id := ids[mask]
		enrollment, err := s.GetAppV23Enrollment(id)
		require.NoError(t, err)
		require.True(t, enrollment.Active)
		require.Equal(t, mask, enrollment.Capabilities)
		require.Equal(t, fmt.Sprintf("owned-%02d", mask), enrollment.HomeDomain)
		require.Equal(t, expectedAppV23MigratedProfile(mask), enrollment.Profile)

		own, err := s.AuthorizeAppV23LocalDomain(
			id, enrollment.HomeDomain, AppV23VerbWrite, false,
		)
		require.NoError(t, err)
		require.True(t, own.Allowed, "hard-deny bits never block existing ownership")

		foreign, err := s.AuthorizeAppV23LocalDomain(
			id, "foreign-owned", AppV23VerbWrite, false,
		)
		require.NoError(t, err)
		hasGrant, err := s.HasAppV23AccessOrAncestor(
			"foreign-owned", id, 2, time.Unix(1000, 0), false,
		)
		require.NoError(t, err)
		require.True(t, hasGrant)
		effectiveForeignWrite := hasGrant && !foreign.ExplicitDeny
		require.Equal(t,
			!mask.Has(AgentCapabilityDenyForeignDomainWrite),
			effectiveForeignWrite,
			"an existing level-2 grant must remain effective iff the exact old mask allowed it",
		)

		sharedWrite, err := s.AuthorizeAppV23LocalDomain(
			id, "general", AppV23VerbWrite, true,
		)
		require.NoError(t, err)
		require.Equal(t,
			!mask.Has(AgentCapabilityDenySharedDomainWrite),
			sharedWrite.Allowed,
			"unchanged migration must preserve legacy shared write iff bit 2 is absent",
		)
		require.Equal(t,
			mask.Has(AgentCapabilityDenySharedDomainWrite),
			sharedWrite.ExplicitDeny,
		)
		sharedModify, err := s.AuthorizeAppV23LocalDomain(
			id, "general", AppV23VerbModify, true,
		)
		require.NoError(t, err)
		require.False(t, sharedModify.Allowed,
			"legacy shared memory-submit authority must never imply level-3 modify")

		ungrantedRead, err := s.AuthorizeAppV23LocalDomain(
			id, "foreign-ungranted", AppV23VerbRead, false,
		)
		require.NoError(t, err)
		require.Equal(t,
			mask.Has(AgentCapabilityReadAllDomains),
			ungrantedRead.Allowed,
			"ReadAllDomains must preserve visibility of foreign-owned domains",
		)
	}
}

func TestAppV23SharedWriteGrandfatheringEndsOnReviewAndNeverAppliesFresh(t *testing.T) {
	t.Run("reviewed migration", func(t *testing.T) {
		s, err := NewBadgerStore(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

		rootID := appV23Register(t, s, "shared-review-root", AppV23RoleAdmin, 1, 0)
		memberID := appV23Register(t, s, "shared-review-member", AppV23RoleMember, 2, 0)
		require.NoError(t, s.EnsureAppV23Root("shared-review", 10))

		before, err := s.AuthorizeAppV23LocalDomain(
			memberID, "general", AppV23VerbWrite, true,
		)
		require.NoError(t, err)
		require.True(t, before.Allowed)
		require.True(t, mustAppV23GrandfatheredSharedWrite(t, s, memberID))

		enrollment, err := s.GetAppV23Enrollment(memberID)
		require.NoError(t, err)
		role, err := s.GetAppV23Role(memberID)
		require.NoError(t, err)
		require.NoError(t, s.SetAppV23Policy(
			rootID, memberID, AppV23RoleMember,
			enrollment.Profile, AppV23ProfileStandard,
			enrollment.Clearance, AgentCapabilityDenyFederatedPipe,
			role.Revision, enrollment.Revision, 11,
		))

		require.False(t, mustAppV23GrandfatheredSharedWrite(t, s, memberID))
		after, err := s.AuthorizeAppV23LocalDomain(
			memberID, "general", AppV23VerbWrite, true,
		)
		require.NoError(t, err)
		require.False(t, after.Allowed)
		require.False(t, after.ExplicitDeny,
			"reviewed Standard uses app-v23 explicit shared grants, not a hard deny")
	})

	t.Run("fresh bootstrap", func(t *testing.T) {
		s, err := NewBadgerStore(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

		rootID := appV23TestID("fresh-shared-root")
		memberID := appV23TestID("fresh-shared-member")
		require.NoError(t, s.BootstrapAppV23Genesis(AppV23GenesisBootstrap{
			RootID: rootID, AgentID: memberID, Scope: "fresh-shared",
			Profile: AppV23ProfileStandard, HomeDomain: "fresh-shared-home",
			Clearance: 1, Capabilities: 0, Height: 1,
			BootstrapDigest: "fresh-shared-bootstrap",
		}))

		require.False(t, mustAppV23GrandfatheredSharedWrite(t, s, memberID))
		decision, err := s.AuthorizeAppV23LocalDomain(
			memberID, "general", AppV23VerbWrite, true,
		)
		require.NoError(t, err)
		require.False(t, decision.Allowed)
		require.False(t, decision.ExplicitDeny)
	})
}

func mustAppV23GrandfatheredSharedWrite(
	t *testing.T,
	s *BadgerStore,
	agentID string,
) bool {
	t.Helper()
	allowed, err := s.AppV23AllowsGrandfatheredSharedWrite(agentID)
	require.NoError(t, err)
	return allowed
}

func TestAppV23Mask30ExplicitReadGrantStaysActiveAndDomainless(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	rootID := appV23Register(t, s, "reviewed-mask-root", AppV23RoleAdmin, 1, 0)
	reviewed := appV23Register(
		t, s, "reviewed-mask30", AppV23RoleMember, 2,
		DefaultSelfRegisteredAgentCapabilities,
	)
	require.NoError(t, s.RegisterDomain("reviewed-domain", rootID, "", 3))
	require.NoError(t, s.SetAccessGrant("reviewed-domain", reviewed, 1, 0, rootID))

	require.NoError(t, s.EnsureAppV23Root("reviewed-mask", 100))
	require.NoError(t, s.ValidateAppV23State())
	enrollment, err := s.GetAppV23Enrollment(reviewed)
	require.NoError(t, err)
	require.True(t, enrollment.Active,
		"an explicit read grant is deterministic operator-review evidence")
	require.Equal(t, AppV23ProfileLegacyRestricted, enrollment.Profile)
	require.Equal(t, DefaultSelfRegisteredAgentCapabilities, enrollment.Capabilities)
	require.Empty(t, enrollment.HomeDomain,
		"deny-claim migration must not manufacture a writable home")
	hasRead, err := s.HasAppV23AccessOrAncestor(
		"reviewed-domain", reviewed, 1, time.Unix(1000, 0), false,
	)
	require.NoError(t, err)
	require.True(t, hasRead)
}

func TestAppV23LegacyRestrictedCannotBeSelectedByOrdinaryMutations(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	rootID := appV23Register(t, s, "mutation-root", AppV23RoleAdmin, 1, 0)
	targetID := appV23Register(
		t, s, "mutation-target", AppV23RoleMember, 2,
		AgentCapabilityDenySharedDomainWrite,
	)
	require.NoError(t, s.RegisterDomain("mutation-target-home", targetID, "", 3))
	require.NoError(t, s.EnsureAppV23Root("mutation-scope", 100))

	enrollment, err := s.GetAppV23Enrollment(targetID)
	require.NoError(t, err)
	role, err := s.GetAppV23Role(targetID)
	require.NoError(t, err)
	require.Equal(t, AppV23ProfileLegacyRestricted, enrollment.Profile)

	err = s.SetAppV23Policy(
		rootID, targetID, AppV23RoleMember,
		enrollment.Profile, AppV23ProfileLegacyRestricted,
		enrollment.Clearance, enrollment.Capabilities,
		role.Revision, enrollment.Revision, 101,
	)
	require.ErrorContains(t, err, "migration-only")

	reapproval := *enrollment
	reapproval.ApprovedBy = rootID
	reapproval.UpdatedHeight = 101
	err = s.ApproveAppV23LocalAgent(
		reapproval, AppV23RoleMember, enrollment.Revision, role.Revision,
	)
	require.ErrorContains(t, err, "migration-only")

	err = s.BootstrapAppV23Genesis(AppV23GenesisBootstrap{
		RootID:  appV23TestID("forbidden-bootstrap-root"),
		AgentID: appV23TestID("forbidden-bootstrap-agent"),
		Scope:   "forbidden-bootstrap", Profile: AppV23ProfileLegacyRestricted,
		HomeDomain: "forbidden-home", Capabilities: 0, Height: 1,
	})
	require.ErrorContains(t, err, "invalid app-v23 bootstrap profile")
}

func TestAppV23LegacyMaskMappingInlineAndStagedAreIdentical(t *testing.T) {
	build := func(t *testing.T, count int) (*BadgerStore, []string) {
		t.Helper()
		s, err := NewBadgerStore(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
		ids := make([]string, count)
		for start := 0; start < count; start += 128 {
			end := start + 128
			if end > count {
				end = count
			}
			require.NoError(t, s.update(func(txn *badger.Txn) error {
				for i := start; i < end; i++ {
					id := fmt.Sprintf("%064x", i+1)
					ids[i] = id
					role := AppV23RoleMember
					mask := AgentCapabilities(i % 32)
					if i == 0 {
						role = AppV23RoleAdmin
						mask = 0
					}
					data, err := appV23Marshal(OnChainAgent{
						AgentID: id, Name: fmt.Sprintf("parity-%d", i),
						RegisteredName: fmt.Sprintf("parity-%d", i),
						Role:           role, Clearance: 2, Capabilities: mask,
						RegisteredAt: int64(i + 1),
					})
					if err != nil {
						return err
					}
					if err := s.txnSet(txn, agentOnChainKey(id), data); err != nil {
						return err
					}
				}
				return nil
			}))
		}
		require.NoError(t, s.EnsureAppV23Root("legacy-mask-parity", 100))
		require.NoError(t, s.ValidateAppV23State())
		return s, ids
	}

	inline, inlineIDs := build(t, appV23MaxInlineMigrationAgents)
	staged, stagedIDs := build(t, appV23MaxInlineMigrationAgents+1)
	for i := 0; i < 32; i++ {
		require.Equal(t, inlineIDs[i], stagedIDs[i])
		id := inlineIDs[i]
		inlineEnrollment, err := inline.GetAppV23Enrollment(id)
		require.NoError(t, err)
		stagedEnrollment, err := staged.GetAppV23Enrollment(id)
		require.NoError(t, err)
		require.Equal(t, inlineEnrollment, stagedEnrollment)
		inlineRole, err := inline.GetAppV23Role(id)
		require.NoError(t, err)
		stagedRole, err := staged.GetAppV23Role(id)
		require.NoError(t, err)
		require.Equal(t, inlineRole, stagedRole)
		inlineDisposition, err := inline.GetAppV23MigrationDisposition(id)
		require.NoError(t, err)
		stagedDisposition, err := staged.GetAppV23MigrationDisposition(id)
		require.NoError(t, err)
		require.Equal(t, inlineDisposition, stagedDisposition)
	}
}

func TestAppV23BootstrapReconcileMaskMappingInlineAndStagedAreIdentical(t *testing.T) {
	build := func(t *testing.T, count int) (*BadgerStore, []string) {
		t.Helper()
		s, err := NewBadgerStore(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

		rootID := fmt.Sprintf("%064x", 1)
		companionID := fmt.Sprintf("%064x", 2)
		require.NoError(t, s.BootstrapAppV23Genesis(AppV23GenesisBootstrap{
			RootID: rootID, AgentID: companionID,
			Scope:   "bootstrap-mask-parity",
			Profile: AppV23ProfileCompanion, HomeDomain: "voice-interface",
			Clearance: 1, Capabilities: 15, Height: 1,
			BootstrapDigest: "bootstrap-mask-parity",
		}))

		ids := make([]string, count-2)
		for i := 2; i < count; i++ {
			id := fmt.Sprintf("%064x", i+1)
			ids[i-2] = id
			require.NoError(t, s.RegisterAgentWithCapabilities(
				id, fmt.Sprintf("bootstrap-parity-%d", i),
				AppV23RoleMember, "", "", "", int64(i)+1,
				AgentCapabilities((i-2)%32),
			))
		}
		require.NoError(t, s.EnsureAppV23Root("bootstrap-mask-parity", 100))
		require.NoError(t, s.ValidateAppV23State())
		return s, ids
	}

	inline, inlineIDs := build(t, appV23MaxInlineMigrationAgents)
	staged, stagedIDs := build(t, appV23MaxInlineMigrationAgents+1)
	for i := 0; i < 32; i++ {
		require.Equal(t, inlineIDs[i], stagedIDs[i])
		id := inlineIDs[i]
		inlineEnrollment, err := inline.GetAppV23Enrollment(id)
		require.NoError(t, err)
		stagedEnrollment, err := staged.GetAppV23Enrollment(id)
		require.NoError(t, err)
		require.Equal(t, inlineEnrollment, stagedEnrollment)
		inlineRole, err := inline.GetAppV23Role(id)
		require.NoError(t, err)
		stagedRole, err := staged.GetAppV23Role(id)
		require.NoError(t, err)
		require.Equal(t, inlineRole, stagedRole)
		inlineDisposition, err := inline.GetAppV23MigrationDisposition(id)
		require.NoError(t, err)
		stagedDisposition, err := staged.GetAppV23MigrationDisposition(id)
		require.NoError(t, err)
		require.Equal(t, inlineDisposition, stagedDisposition)
	}
}
