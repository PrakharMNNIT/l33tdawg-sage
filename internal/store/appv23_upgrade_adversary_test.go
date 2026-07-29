package store

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"testing"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/require"
)

// An app-v22 node may legitimately contain many historical Admin rows. Only
// deterministic Root is promoted automatically because consensus cannot prove
// same-machine key locality for the rest. Their exact data-plane masks remain
// active while each awaits an explicit app-v23 promotion review.
func TestAppV23UpgradeHandlesLegacyAdminRosterAboveDelegationCap(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	legacyAdmins := make([]string, 0, AppV23MaxAdmins+1)
	legacyMasks := make(map[string]AgentCapabilities, AppV23MaxAdmins+1)
	for i := 0; i < AppV23MaxAdmins+1; i++ {
		mask := AgentCapabilities(0)
		if i%2 == 1 {
			mask = DefaultSelfRegisteredAgentCapabilities
		}
		id := appV23Register(
			t,
			s,
			fmt.Sprintf("legacy-admin-%02d", i),
			AppV23RoleAdmin,
			1,
			mask,
		)
		legacyAdmins = append(legacyAdmins, id)
		legacyMasks[id] = mask
	}
	sort.Strings(legacyAdmins)
	require.NoError(t, s.RegisterDomain("legacy-admin-foreign", legacyAdmins[0], "", 2))
	for i, id := range legacyAdmins[1:] {
		require.NoError(t, s.RegisterDomain(
			fmt.Sprintf("legacy-admin-own-%02d", i), id, "", int64(i)+3,
		))
		require.NoError(t, s.SetAccessGrant(
			"legacy-admin-foreign", id, 2, 0, legacyAdmins[0],
		))
	}

	require.NoError(t, s.EnsureAppV23Root("legacy-admin-overflow", 100))
	require.NoError(t, s.ValidateAppV23State())

	root, err := s.GetAppV23Root()
	require.NoError(t, err)
	require.Equal(t, legacyAdmins[0], root.PrincipalID,
		"same-height Root selection must use canonical AgentID order")

	adminCount := 0
	for i, id := range legacyAdmins {
		role, roleErr := s.GetAppV23Role(id)
		require.NoError(t, roleErr)
		enrollment, enrollmentErr := s.GetAppV23Enrollment(id)
		require.NoError(t, enrollmentErr)
		disposition, dispositionErr := s.GetAppV23MigrationDisposition(id)
		require.NoError(t, dispositionErr)

		if i == 0 {
			adminCount++
			require.Equal(t, AppV23RoleAdmin, role.Role)
			require.Equal(t, AppV23ProfileRoot, enrollment.Profile)
			require.Zero(t, enrollment.Capabilities)
			require.Equal(t, "root", disposition.Disposition)
			continue
		}
		require.Equal(t, AppV23RoleMember, role.Role)
		require.True(t, enrollment.Active,
			"a legacy Admin has operator history and must not be mistaken for bare self-registration")
		require.Equal(t, AppV23ProfileLegacyRestricted, enrollment.Profile)
		require.Equal(t, legacyMasks[id], enrollment.Capabilities)
		require.Equal(t, "legacy_admin_review", disposition.Disposition)
		own, ownErr := s.AuthorizeAppV23LocalDomain(
			id, enrollment.HomeDomain, AppV23VerbWrite, false,
		)
		require.NoError(t, ownErr)
		require.True(t, own.Allowed)
		foreign, foreignErr := s.AuthorizeAppV23LocalDomain(
			id, "legacy-admin-foreign", AppV23VerbWrite, false,
		)
		require.NoError(t, foreignErr)
		_, _, _, grantErr := s.GetAccessGrant("legacy-admin-foreign", id)
		require.NoError(t, grantErr)
		require.Equal(t,
			!legacyMasks[id].Has(AgentCapabilityDenyForeignDomainWrite),
			!foreign.ExplicitDeny,
			"pre-existing grant authority must remain controlled by the exact legacy mask",
		)
	}
	require.Equal(t, 1, adminCount,
		"historical Admin rows cannot prove app-v23 same-machine key locality")

	migration, err := s.GetAppV23MigrationState()
	require.NoError(t, err)
	require.Equal(t, legacyAdmins, migration.LegacyAdmins,
		"the audit ledger must retain the complete pre-v23 Admin roster")
}

func TestAppV23VendoredBootstrapReconcileHandlesLegacyAdminOverflow(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	rootID := appV23TestID("vendored-overflow-root")
	companionID := appV23TestID("vendored-overflow-companion")
	require.NoError(t, s.BootstrapAppV23Genesis(AppV23GenesisBootstrap{
		RootID: rootID, AgentID: companionID, Scope: "vendored-overflow",
		Profile: AppV23ProfileCompanion, HomeDomain: "voice-interface",
		Clearance: 1, Capabilities: 15, Height: 1,
		BootstrapDigest: "vendored-overflow-bootstrap",
	}))
	companionBefore, err := s.GetAppV23Enrollment(companionID)
	require.NoError(t, err)

	legacyAdmins := make([]string, 0, AppV23MaxAdmins)
	for i := 0; i < AppV23MaxAdmins; i++ {
		legacyAdmins = append(legacyAdmins, appV23Register(
			t,
			s,
			fmt.Sprintf("vendored-legacy-admin-%02d", i),
			AppV23RoleAdmin,
			2,
			DefaultSelfRegisteredAgentCapabilities,
		))
	}
	sort.Strings(legacyAdmins)

	require.NoError(t, s.EnsureAppV23Root("vendored-overflow", 100))
	require.NoError(t, s.ValidateAppV23State())

	root, err := s.GetAppV23Root()
	require.NoError(t, err)
	require.Equal(t, rootID, root.PrincipalID)

	companionAfter, err := s.GetAppV23Enrollment(companionID)
	require.NoError(t, err)
	require.Equal(t, companionBefore, companionAfter,
		"bootstrap Companion policy must be preserved byte-for-byte")

	adminCount := 1 // the vendored Root is the sole automatic Admin.
	for _, id := range legacyAdmins {
		role, roleErr := s.GetAppV23Role(id)
		require.NoError(t, roleErr)
		enrollment, enrollmentErr := s.GetAppV23Enrollment(id)
		require.NoError(t, enrollmentErr)
		disposition, dispositionErr := s.GetAppV23MigrationDisposition(id)
		require.NoError(t, dispositionErr)

		require.Equal(t, AppV23RoleMember, role.Role)
		require.True(t, enrollment.Active,
			"a historical Admin must remain data-plane active pending local promotion review")
		require.Equal(t, AppV23ProfileLegacyRestricted, enrollment.Profile)
		require.Equal(t, DefaultSelfRegisteredAgentCapabilities, enrollment.Capabilities)
		require.Equal(t, "legacy_admin_review", disposition.Disposition)
	}
	require.Equal(t, 1, adminCount)

	allLegacyAdmins := append([]string{rootID}, legacyAdmins...)
	sort.Strings(allLegacyAdmins)
	migration, err := s.GetAppV23MigrationState()
	require.NoError(t, err)
	require.Equal(t, allLegacyAdmins, migration.LegacyAdmins,
		"the audit ledger must retain Root plus the complete pre-v23 Admin roster")
}

// This stress sentinel is opt-in because it deliberately constructs the
// smallest valid legacy roster whose lossless app-v23 projection cannot fit
// in Badger's single-transaction entry bound.
func TestAppV23UpgradeLargeValidRosterFitsActivationTransaction(t *testing.T) {
	if os.Getenv("SAGE_RUN_APPV23_STRESS") != "1" {
		t.Skip("set SAGE_RUN_APPV23_STRESS=1 for the activation transaction-bound sentinel")
	}

	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	// Migration writes six keys for each ordinary zero-mask agent: projected
	// identity, enrollment, role, disposition, immutable legacy-read baseline,
	// and owned home domain.
	// Root plus the migration headers use slightly fewer, so this count is the
	// first conservative roster guaranteed to cross Badger's entry ceiling.
	agentCount := int((s.DB().MaxBatchCount()+5)/6) + 1
	if raw := os.Getenv("SAGE_APPV23_STRESS_AGENTS"); raw != "" {
		override, parseErr := strconv.Atoi(raw)
		require.NoError(t, parseErr)
		require.Positive(t, override)
		agentCount = override
	}
	t.Logf("Badger max entries=%d; valid legacy roster=%d", s.DB().MaxBatchCount(), agentCount)
	const seedChunk = 512
	for start := 0; start < agentCount; start += seedChunk {
		end := start + seedChunk
		if end > agentCount {
			end = agentCount
		}
		require.NoError(t, s.update(func(txn *badger.Txn) error {
			for i := start; i < end; i++ {
				id := fmt.Sprintf("%064x", i+1)
				role := AppV23RoleMember
				if i == 0 {
					role = AppV23RoleAdmin
				}
				agent := OnChainAgent{
					AgentID: id, Name: fmt.Sprintf("legacy-%d", i),
					RegisteredName: fmt.Sprintf("legacy-%d", i),
					Role:           role, Clearance: 1, RegisteredAt: int64(i + 1),
				}
				data, marshalErr := appV23Marshal(agent)
				if marshalErr != nil {
					return marshalErr
				}
				if setErr := s.txnSet(txn, agentOnChainKey(id), data); setErr != nil {
					return setErr
				}
			}
			return nil
		}))
	}

	require.NoError(t, s.EnsureAppV23Root("large-valid-roster", 100))
	require.NoError(t, s.ValidateAppV23State())
}
