package store

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAppV23DynamicSharedDomainBlocksGroupDerivedAuthority(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	root := appV23Register(t, s, "shared-barrier-root", AppV23RoleAdmin, 1, 0)
	owner := appV23Register(t, s, "shared-barrier-owner", AppV23RoleMember, 2, 0)
	member := appV23Register(t, s, "shared-barrier-member", AppV23RoleMember, 3, 0)
	manager := appV23Register(t, s, "shared-barrier-manager", AppV23RoleMember, 4, 0)
	require.NoError(t, s.EnsureAppV23Root("shared-barrier-scope", 10))

	managerEnrollment, err := s.GetAppV23Enrollment(manager)
	require.NoError(t, err)
	managerRole, err := s.GetAppV23Role(manager)
	require.NoError(t, err)
	require.NoError(t, s.SetAppV23Policy(
		root, manager, AppV23RoleManager,
		managerEnrollment.Profile, AppV23ProfileStandard,
		managerEnrollment.Clearance, 0,
		managerRole.Revision, managerEnrollment.Revision, 11,
	))

	members := []string{owner, member, manager}
	sort.Strings(members)
	require.NoError(t, s.MutateAppV23AccessGroup(
		root, "shared-barrier-team", "Shared barrier team",
		members, 0, false, 12,
	))

	// The less-specific owner is deliberate: a shared candidate must stop the
	// app-v23 ownership walk, not merely be skipped before falling back here.
	require.NoError(t, s.RegisterDomain("team", owner, "", 13))
	require.NoError(t, s.RegisterDomain("team.open", owner, "team", 14))
	require.NoError(t, s.SetSharedDomain("team.open"))
	require.NoError(t, s.SetSharedDomain("team.ownerless"))

	ancestorReader := appV23TestID("shared-barrier-ancestor-reader")
	ancestorWriter := appV23TestID("shared-barrier-ancestor-writer")
	ancestorModifier := appV23TestID("shared-barrier-ancestor-modifier")
	require.NoError(t, s.SetAccessGrant("team", ancestorReader, 1, 0, root))
	require.NoError(t, s.SetAccessGrant("team", ancestorWriter, 2, 0, root))
	require.NoError(t, s.SetAccessGrant("team", ancestorModifier, 3, 0, root))

	normalAllowed, err := s.FederatedGuestGroupAllowsDomain(
		context.Background(), "shared-barrier-team", "team.private",
	)
	require.NoError(t, err)
	require.True(t, normalAllowed, "ordinary descendants still inherit their owning ancestor")
	for _, tc := range []struct {
		principal string
		level     uint8
	}{
		{principal: ancestorReader, level: 1},
		{principal: ancestorWriter, level: 2},
		{principal: ancestorModifier, level: 3},
	} {
		allowed, accessErr := s.HasAppV23AccessOrAncestor(
			"team.private", tc.principal, tc.level, time.Unix(1_700_000_000, 0), false,
		)
		require.NoError(t, accessErr)
		require.True(t, allowed, "ordinary descendants retain level-%d ancestor grants", tc.level)
	}

	for _, domain := range []string{
		"team.open",
		"team.open.notes",
		"team.open.notes.archive",
		"team.ownerless",
		"team.ownerless.notes",
	} {
		guestAllowed, guestErr := s.FederatedGuestGroupAllowsDomain(
			context.Background(), "shared-barrier-team", domain,
		)
		require.NoError(t, guestErr)
		require.False(t, guestAllowed,
			"a dynamically shared domain or descendant must not enter linked-reader group scope: %s",
			domain,
		)

		for _, tc := range []struct {
			agent string
			verb  AppV23DomainVerb
		}{
			{agent: member, verb: AppV23VerbRead},
			{agent: member, verb: AppV23VerbWrite},
			{agent: member, verb: AppV23VerbModify},
			{agent: manager, verb: AppV23VerbRead},
			{agent: manager, verb: AppV23VerbWrite},
			{agent: manager, verb: AppV23VerbModify},
		} {
			// Only the exact shared name is reported as shared by the current
			// leaf classifier. The unchanged migrated Member retains its
			// app-v22 Write-only shared submission authority; the explicitly
			// promoted Manager is revision 2 and does not. Neither case is
			// group-derived, and descendants remain protected by the
			// consensus-state-aware ownership barrier.
			shared, sharedErr := s.IsAppV23SharedDomain(domain)
			require.NoError(t, sharedErr)
			decision, authErr := s.AuthorizeAppV23LocalDomain(
				tc.agent, domain, tc.verb, shared,
			)
			require.NoError(t, authErr)
			wantMigratedSharedWrite :=
				shared && tc.agent == member && tc.verb == AppV23VerbWrite
			require.Equal(t, wantMigratedSharedWrite, decision.Allowed,
				"%s verb %d has incorrect authority across dynamic shared boundary %s",
				tc.agent, tc.verb, domain,
			)
		}
		for _, tc := range []struct {
			principal string
			level     uint8
		}{
			{principal: ancestorReader, level: 1},
			{principal: ancestorWriter, level: 2},
			{principal: ancestorModifier, level: 3},
		} {
			allowed, accessErr := s.HasAppV23AccessOrAncestor(
				domain, tc.principal, tc.level, time.Unix(1_700_000_000, 0), false,
			)
			require.NoError(t, accessErr)
			require.False(t, allowed,
				"level-%d grant on a broader ancestor must stop at dynamic shared boundary %s",
				tc.level, domain,
			)
		}
	}

	// A grant created inside the shared subtree remains an ordinary explicit
	// authority source. It may cascade further inside that subtree, but the
	// broader owner and level-3 grant above team.open never enter the frozen
	// modify electorate.
	insideModifier := appV23TestID("shared-barrier-inside-modifier")
	require.NoError(t, s.SetAccessGrant("team.open.notes", insideModifier, 3, 0, root))
	insideAllowed, err := s.HasAppV23AccessOrAncestor(
		"team.open.notes.archive", insideModifier, 3, time.Unix(1_700_000_000, 0), false,
	)
	require.NoError(t, err)
	require.True(t, insideAllowed)

	holders, overLimit, err := s.AppV23ModifyVerbHoldersUpTo(
		"team.open.notes.archive", false, time.Unix(1_700_000_000, 0), 16,
	)
	require.NoError(t, err)
	require.False(t, overLimit)
	require.Equal(t, []string{insideModifier}, holders,
		"challenge electorate must include only modify authority below the shared boundary")

	require.NoError(t, s.SetAccessGrant("team.open", insideModifier, 3, 0, root))
	exactSharedHolders, overLimit, err := s.AppV23ModifyVerbHoldersUpTo(
		"team.open", true, time.Unix(1_700_000_000, 0), 16,
	)
	require.NoError(t, err)
	require.False(t, overLimit)
	require.Equal(t, []string{insideModifier}, exactSharedHolders,
		"an exact modify grant on a shared resource remains effective")
}
