package store

import (
	"fmt"
	"testing"
	"time"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/require"
)

func appV23MatrixCapabilities(role, profile string) AgentCapabilities {
	switch profile {
	case AppV23ProfileCompanion:
		return AgentCapabilities(15)
	case AppV23ProfileReadOnly:
		return AgentCapabilityReadAllDomains
	case AppV23ProfileStandard:
		if role == AppV23RoleAdmin {
			return AgentCapabilityReadAllDomains
		}
		return 0
	default:
		return 0
	}
}

func TestAppV23LevelThreeGrantEnumeratesModifyHolder(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	owner := appV23TestID("matrix-modify-owner")
	manager := appV23TestID("matrix-modify-manager")
	domain := "local-" + owner
	require.NoError(t, s.RegisterDomain(domain, owner, "", 1))
	require.NoError(t, s.SetAccessGrant(domain, manager, 3, 0, owner))

	holders, overLimit, err := s.ModifyVerbHoldersUpTo(
		domain, time.Unix(1_700_000_000, 0), MaxChallengeElectorateV21,
	)
	require.NoError(t, err)
	require.False(t, overLimit)
	require.Equal(t, []string{manager, owner}, holders)
}

func TestAppV23ExactSharedGrantIsForkScoped(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	principal := appV23TestID("matrix-shared-grantee")
	const domain = "general"
	blockTime := time.Unix(1_700_000_000, 0)
	require.NoError(t, s.SetAccessGrant(domain, principal, 3, 0, principal))

	legacyAccess, err := s.HasAccessOrAncestor(domain, principal, 3, blockTime)
	require.NoError(t, err)
	require.False(t, legacyAccess, "pre-v23 exact shared grants remain behind the legacy barrier")
	appV23Access, err := s.HasAppV23AccessOrAncestor(domain, principal, 3, blockTime, true)
	require.NoError(t, err)
	require.True(t, appV23Access)

	legacyHolders, legacyOverLimit, err := s.ModifyVerbHoldersUpTo(
		domain, blockTime, MaxChallengeElectorateV21,
	)
	require.NoError(t, err)
	require.False(t, legacyOverLimit)
	require.Empty(t, legacyHolders)
	appV23Holders, appV23OverLimit, err := s.AppV23ModifyVerbHoldersUpTo(
		domain, true, blockTime, MaxChallengeElectorateV21,
	)
	require.NoError(t, err)
	require.False(t, appV23OverLimit)
	require.Equal(t, []string{principal}, appV23Holders)

	descendantAccess, err := s.HasAppV23AccessOrAncestor(
		"pipeline.general", principal, 3, blockTime, false,
	)
	require.NoError(t, err)
	require.False(t, descendantAccess, "shared exact grants never become inheritable ancestors")
}

func TestAppV23SetPolicyCannotMintRootProfile(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	root := appV23Register(t, s, "matrix-root-profile-root", AppV23RoleAdmin, 1, 0)
	target := appV23Register(t, s, "matrix-root-profile-target", AppV23RoleMember, 2, 0)
	require.NoError(t, s.EnsureAppV23Root("matrix-root-profile-scope", 10))
	require.NoError(t, ValidateAppV23Policy(
		AppV23RoleAdmin, AppV23ProfileRoot, 0, 4,
	), "generic validation must continue accepting the actual singleton Root state")

	beforeEnrollment, err := s.GetAppV23Enrollment(target)
	require.NoError(t, err)
	beforeRole, err := s.GetAppV23Role(target)
	require.NoError(t, err)
	err = s.SetAppV23Policy(
		root,
		target,
		AppV23RoleAdmin,
		beforeEnrollment.Profile,
		AppV23ProfileRoot,
		4,
		0,
		beforeRole.Revision,
		beforeEnrollment.Revision,
		11,
	)
	require.ErrorContains(t, err, "root profile is reserved")
	afterEnrollment, err := s.GetAppV23Enrollment(target)
	require.NoError(t, err)
	require.Equal(t, beforeEnrollment, afterEnrollment)
	afterRole, err := s.GetAppV23Role(target)
	require.NoError(t, err)
	require.Equal(t, beforeRole, afterRole)
	require.NoError(t, s.ValidateAppV23State())
}

func TestAppV23StateRejectsNonRootRootProfile(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	_ = appV23Register(t, s, "matrix-root-state-root", AppV23RoleAdmin, 1, 0)
	target := appV23Register(t, s, "matrix-root-state-target", AppV23RoleMember, 2, 0)
	require.NoError(t, s.EnsureAppV23Root("matrix-root-state-scope", 10))
	require.NoError(t, s.ValidateAppV23State())

	require.NoError(t, s.update(func(txn *badger.Txn) error {
		var enrollment AppV23LocalEnrollment
		if err := appV23ReadJSON(txn, appV23EnrollmentKey(target), &enrollment); err != nil {
			return err
		}
		enrollment.Profile = AppV23ProfileRoot
		enrollment.Clearance = 4
		enrollment.Capabilities = 0
		enrollmentData, enrollmentMarshalErr := appV23Marshal(enrollment)
		if enrollmentMarshalErr != nil {
			return enrollmentMarshalErr
		}
		if err := s.txnSet(txn, appV23EnrollmentKey(target), enrollmentData); err != nil {
			return err
		}

		var role AppV23RoleState
		if err := appV23ReadJSON(txn, appV23RoleKey(target), &role); err != nil {
			return err
		}
		role.Role = AppV23RoleAdmin
		roleData, roleMarshalErr := appV23Marshal(role)
		if roleMarshalErr != nil {
			return roleMarshalErr
		}
		if err := s.txnSet(txn, appV23RoleKey(target), roleData); err != nil {
			return err
		}

		var agent OnChainAgent
		if err := appV23ReadJSON(txn, agentOnChainKey(target), &agent); err != nil {
			return err
		}
		agent.Role = AppV23RoleAdmin
		agent.Clearance = 4
		agent.Capabilities = 0
		agentData, agentMarshalErr := appV23Marshal(agent)
		if agentMarshalErr != nil {
			return agentMarshalErr
		}
		if err := s.txnSet(txn, agentOnChainKey(target), agentData); err != nil {
			return err
		}
		return s.txnSet(txn, appV23AdminKey(target), []byte{1})
	}))

	require.ErrorContains(
		t,
		s.ValidateAppV23State(),
		"reserved root profile",
	)
}

func appV23MatrixPolicyIsCanonical(role, profile string, clearance uint8) bool {
	switch profile {
	case AppV23ProfileStandard:
		return role == AppV23RoleMember ||
			role == AppV23RoleManager ||
			(role == AppV23RoleAdmin && clearance == 4)
	case AppV23ProfileCompanion, AppV23ProfileReadOnly:
		return role == AppV23RoleMember
	default:
		return false
	}
}

// TestAppV23RoleProfileClearanceCompatibilityMatrix exhausts the complete
// ordinary-agent policy product. Root is deliberately absent: it is the
// singleton authority principal, not an ordinary role/profile choice.
func TestAppV23RoleProfileClearanceCompatibilityMatrix(t *testing.T) {
	roles := []string{
		AppV23RoleMember,
		AppV23RoleManager,
		AppV23RoleAdmin,
	}
	profiles := []string{
		AppV23ProfileStandard,
		AppV23ProfileCompanion,
		AppV23ProfileReadOnly,
	}

	cases := 0
	for _, role := range roles {
		for _, profile := range profiles {
			for clearance := uint8(0); clearance <= 4; clearance++ {
				name := fmt.Sprintf("%s/%s/clearance-%d", role, profile, clearance)
				t.Run(name, func(t *testing.T) {
					cases++
					err := ValidateAppV23Policy(
						role,
						profile,
						appV23MatrixCapabilities(role, profile),
						clearance,
					)
					if appV23MatrixPolicyIsCanonical(role, profile, clearance) {
						require.NoError(t, err)
					} else {
						require.Error(t, err)
					}
				})
			}
		}
	}
	require.Equal(t, 45, cases)
}
