package store

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"testing"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/require"
)

func appV23TestID(label string) string {
	sum := sha256.Sum256([]byte(label))
	key := ed25519.NewKeyFromSeed(sum[:])
	return hex.EncodeToString(key.Public().(ed25519.PublicKey))
}

func appV23Register(t *testing.T, s *BadgerStore, label, role string, height int64, caps AgentCapabilities) string {
	t.Helper()
	id := appV23TestID(label)
	require.NoError(t, s.RegisterAgentWithCapabilities(id, label, role, "", "", "", height, caps))
	return id
}

func TestAppV23MigrationDispositionMatrixAndDeterminism(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	root := appV23Register(t, s, "root", "admin", 1, 0)
	admin2 := appV23Register(t, s, "admin2", "admin", 2, 0)
	observer := appV23Register(t, s, "observer", "observer", 3, 0)
	healthy := appV23Register(t, s, "healthy", "member", 4, 0)
	pending := appV23Register(t, s, "pending", "member", 5, DefaultSelfRegisteredAgentCapabilities)
	companion := appV23Register(t, s, "companion", "member", 6, 15)
	legacyReadAll := appV23Register(t, s, "legacy-read-all", "member", 7, AgentCapabilityReadAllDomains)
	require.NoError(t, s.RegisterDomain("voice-interface", companion, "", 8))

	require.NoError(t, s.EnsureAppV23Root("scope-a", 100))
	require.NoError(t, s.ValidateAppV23State())

	rootState, err := s.GetAppV23Root()
	require.NoError(t, err)
	require.Equal(t, root, rootState.PrincipalID)
	require.Equal(t, root, rootState.CredentialID)
	require.NotEmpty(t, rootState.BootstrapDigest)

	adminEnrollment, err := s.GetAppV23Enrollment(admin2)
	require.NoError(t, err)
	require.True(t, adminEnrollment.Active)
	require.Equal(t, AppV23ProfileLegacyRestricted, adminEnrollment.Profile)
	require.Equal(t, uint8(1), adminEnrollment.Clearance)
	require.Zero(t, adminEnrollment.Capabilities)
	adminRole, err := s.GetAppV23Role(admin2)
	require.NoError(t, err)
	require.Equal(t, AppV23RoleMember, adminRole.Role)
	adminDisposition, err := s.GetAppV23MigrationDisposition(admin2)
	require.NoError(t, err)
	require.Equal(t, "legacy_admin_review", adminDisposition.Disposition)

	observerEnrollment, err := s.GetAppV23Enrollment(observer)
	require.NoError(t, err)
	require.True(t, observerEnrollment.Active)
	require.Equal(t, AppV23ProfileReadOnly, observerEnrollment.Profile)
	require.Equal(t, AgentCapabilityReadAllDomains, observerEnrollment.Capabilities)

	healthyEnrollment, err := s.GetAppV23Enrollment(healthy)
	require.NoError(t, err)
	require.True(t, healthyEnrollment.Active)
	require.Equal(t, "local-"+healthy, healthyEnrollment.HomeDomain)
	owner, err := s.GetDomainOwner(healthyEnrollment.HomeDomain)
	require.NoError(t, err)
	require.Equal(t, healthy, owner)
	readDecision, err := s.AuthorizeAppV23LocalDomain(
		healthy, healthyEnrollment.HomeDomain, AppV23VerbRead, false,
	)
	require.NoError(t, err)
	require.True(t, readDecision.Allowed, "an active Member must read its own home domain")

	pendingEnrollment, err := s.GetAppV23Enrollment(pending)
	require.NoError(t, err)
	require.False(t, pendingEnrollment.Active)
	require.Empty(t, pendingEnrollment.HomeDomain)
	require.Equal(t, DefaultSelfRegisteredAgentCapabilities, pendingEnrollment.Capabilities,
		"pending policy retains the exact mask for immutable audit")
	pendingAgent, err := s.GetRegisteredAgent(pending)
	require.NoError(t, err)
	require.Equal(t, DefaultSelfRegisteredAgentCapabilities, pendingAgent.Capabilities)
	pendingDisposition, err := s.GetAppV23MigrationDisposition(pending)
	require.NoError(t, err)
	require.NotNil(t, pendingDisposition)
	require.Equal(t, "pending_review", pendingDisposition.Disposition,
		"immutable migration provenance, not a live capability mask, authorizes narrow repair")
	require.False(t, pendingDisposition.Active)
	require.Equal(t, AppV23ProfileLegacyRestricted, pendingDisposition.Profile)
	require.NotEmpty(t, pendingDisposition.LegacyPolicyDigest)

	legacyReadAllEnrollment, err := s.GetAppV23Enrollment(legacyReadAll)
	require.NoError(t, err)
	require.True(t, legacyReadAllEnrollment.Active)
	require.Equal(t, AppV23ProfileLegacyRestricted, legacyReadAllEnrollment.Profile)
	require.Equal(t, AgentCapabilityReadAllDomains, legacyReadAllEnrollment.Capabilities)
	legacyReadAllAgent, err := s.GetRegisteredAgent(legacyReadAll)
	require.NoError(t, err)
	require.Equal(t, AgentCapabilityReadAllDomains, legacyReadAllAgent.Capabilities)

	companionEnrollment, err := s.GetAppV23Enrollment(companion)
	require.NoError(t, err)
	require.True(t, companionEnrollment.Active)
	require.Equal(t, AppV23ProfileCompanion, companionEnrollment.Profile)
	require.Equal(t, "voice-interface", companionEnrollment.HomeDomain)

	// Re-entry is deterministic and does not rewrite revisions or the manifest.
	require.NoError(t, s.EnsureAppV23Root("scope-a", 101))
	rootAgain, err := s.GetAppV23Root()
	require.NoError(t, err)
	require.Equal(t, rootState, rootAgain)
}

func TestAppV23StateAcceptsOnlyExactPostActivationPendingRegistrations(t *testing.T) {
	t.Run("restricted pending identity remains bootable", func(t *testing.T) {
		s, err := NewBadgerStore(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

		_ = appV23Register(t, s, "root", AppV23RoleAdmin, 1, 0)
		require.NoError(t, s.EnsureAppV23Root("pending-registration-scope", 10))
		pending := appV23Register(
			t, s, "post-activation-pending", AppV23RoleMember, 11,
			DefaultSelfRegisteredAgentCapabilities,
		)

		enrollment, err := s.GetAppV23Enrollment(pending)
		require.NoError(t, err)
		require.Nil(t, enrollment)
		role, err := s.GetAppV23Role(pending)
		require.NoError(t, err)
		require.Nil(t, role)
		require.NoError(t, s.ValidateAppV23State(),
			"the consensus-defined pending-registration state must not brick restart")
	})

	t.Run("direct genesis pending identity remains bootable", func(t *testing.T) {
		s, err := NewBadgerStore(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

		rootID := appV23TestID("direct-genesis-root")
		companionID := appV23TestID("direct-genesis-companion")
		validatorID := appV23TestID("direct-genesis-validator")
		scope := sha256.Sum256([]byte("direct-genesis-scope"))
		bootstrap := sha256.Sum256([]byte("direct-genesis-bootstrap"))
		require.NoError(t, s.BootstrapAppV23Genesis(AppV23GenesisBootstrap{
			RootID:            rootID,
			Scope:             hex.EncodeToString(scope[:]),
			AgentID:           companionID,
			Profile:           AppV23ProfileCompanion,
			HomeDomain:        "voice-interface",
			Clearance:         1,
			Capabilities:      15,
			Height:            1,
			BootstrapDigest:   hex.EncodeToString(bootstrap[:]),
			ValidatorID:       validatorID,
			ValidatorPower:    10,
			ActivateAtGenesis: true,
		}))
		_ = appV23Register(
			t, s, "direct-genesis-pending", AppV23RoleMember, 2,
			DefaultSelfRegisteredAgentCapabilities,
		)
		require.NoError(t, s.ValidateAppV23State(),
			"a direct app-v23 genesis must accept the same exact pending identity shape")
	})

	for _, tc := range []struct {
		name   string
		height int64
		role   string
		caps   AgentCapabilities
	}{
		{
			name:   "registration is not after activation",
			height: 10,
			role:   AppV23RoleMember,
			caps:   DefaultSelfRegisteredAgentCapabilities,
		},
		{
			name:   "pending role is privileged",
			height: 11,
			role:   AppV23RoleManager,
			caps:   DefaultSelfRegisteredAgentCapabilities,
		},
		{
			name:   "pending capability mask is not fail closed",
			height: 11,
			role:   AppV23RoleMember,
			caps:   0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewBadgerStore(t.TempDir())
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

			_ = appV23Register(t, s, "root-"+tc.name, AppV23RoleAdmin, 1, 0)
			require.NoError(t, s.EnsureAppV23Root("pending-registration-scope", 10))
			_ = appV23Register(t, s, "invalid-"+tc.name, tc.role, tc.height, tc.caps)

			require.ErrorContains(t, s.ValidateAppV23State(), "has no valid pending enrollment")
		})
	}
}

func TestAppV23GenesisBootstrapRosterReconciliation(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
	root := appV23TestID("genesis-root")
	mynah := appV23TestID("genesis-mynah")
	require.NoError(t, s.BootstrapAppV23Genesis(AppV23GenesisBootstrap{
		RootID: root, Scope: "genesis-scope", AgentID: mynah,
		Profile: AppV23ProfileCompanion, HomeDomain: "voice-interface",
		Clearance: 0, Capabilities: 15, Height: 1,
		BootstrapDigest: "signed-genesis-manifest",
	}))
	rootBefore, err := s.GetAppV23Root()
	require.NoError(t, err)
	mynahBefore, err := s.GetAppV23Enrollment(mynah)
	require.NoError(t, err)
	healthy := appV23Register(t, s, "genesis-healthy", "member", 2, 0)
	observer := appV23Register(t, s, "genesis-observer", "observer", 3, 0)
	pending := appV23Register(t, s, "genesis-pending", "member", 4, DefaultSelfRegisteredAgentCapabilities)
	dynamicShared := appV23Register(t, s, "genesis-dynamic-shared", "member", 5, 0)
	require.NoError(t, s.RegisterDomain("genesis.open", dynamicShared, "", 6))
	require.NoError(t, s.SetSharedDomain("genesis.open"))

	require.NoError(t, s.EnsureAppV23Root("genesis-scope", 20))
	require.NoError(t, s.ValidateAppV23State())
	rootAfter, err := s.GetAppV23Root()
	require.NoError(t, err)
	require.Equal(t, rootBefore, rootAfter, "activation must not rewrite the signed bootstrap root")
	mynahAfter, err := s.GetAppV23Enrollment(mynah)
	require.NoError(t, err)
	require.Equal(t, mynahBefore, mynahAfter, "activation must preserve the bootstrapped Companion policy")
	healthyEnrollment, err := s.GetAppV23Enrollment(healthy)
	require.NoError(t, err)
	require.True(t, healthyEnrollment.Active)
	require.Equal(t, "local-"+healthy, healthyEnrollment.HomeDomain)
	observerEnrollment, err := s.GetAppV23Enrollment(observer)
	require.NoError(t, err)
	require.True(t, observerEnrollment.Active)
	require.Equal(t, AppV23ProfileReadOnly, observerEnrollment.Profile)
	require.Equal(t, AgentCapabilityReadAllDomains, observerEnrollment.Capabilities)
	pendingEnrollment, err := s.GetAppV23Enrollment(pending)
	require.NoError(t, err)
	require.False(t, pendingEnrollment.Active)
	require.Equal(t, DefaultSelfRegisteredAgentCapabilities, pendingEnrollment.Capabilities)
	pendingDisposition, err := s.GetAppV23MigrationDisposition(pending)
	require.NoError(t, err)
	require.NotNil(t, pendingDisposition)
	require.Equal(t, "pending_review", pendingDisposition.Disposition)
	dynamicEnrollment, err := s.GetAppV23Enrollment(dynamicShared)
	require.NoError(t, err)
	require.Equal(t, "local-"+dynamicShared, dynamicEnrollment.HomeDomain,
		"genesis roster reconciliation must not select a dynamic shared domain as home")
	migration, err := s.GetAppV23MigrationState()
	require.NoError(t, err)
	require.Equal(t, "signed-genesis-manifest", migration.RootBootstrapDigest)
	require.Equal(t, 6, migration.AgentCount)

	require.NoError(t, s.EnsureAppV23Root("genesis-scope", 21))
	migrationAgain, err := s.GetAppV23MigrationState()
	require.NoError(t, err)
	require.Equal(t, migration, migrationAgain)
}

func TestAppV23HomeTransferCASPurgesGrantsAtomically(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	root := appV23Register(t, s, "transfer-root", "admin", 1, 0)
	require.NoError(t, s.EnsureAppV23Root("scope-transfer", 10))
	target := appV23Register(t, s, "mynah", "member", 11, DefaultSelfRegisteredAgentCapabilities)
	stale := appV23TestID("stale-grantee")
	require.NoError(t, s.RegisterDomain("voice-interface", root, "", 12))
	require.NoError(t, s.SetAccessGrant("voice-interface", stale, 2, 0, root))

	input := AppV23LocalEnrollment{
		AgentID: target, ApprovedBy: root, RootGeneration: 1,
		Profile: AppV23ProfileCompanion, HomeDomain: "voice-interface",
		ExpectedHomeDomainOwner: appV23TestID("wrong-owner"), TransferHomeDomain: true,
		Clearance: 0, Capabilities: 15, Active: true, UpdatedHeight: 13,
	}
	require.Error(t, s.ApproveAppV23LocalAgent(input, AppV23RoleMember, 0, 0))
	enrollment, err := s.GetAppV23Enrollment(target)
	require.NoError(t, err)
	require.Nil(t, enrollment)
	owner, err := s.GetDomainOwner("voice-interface")
	require.NoError(t, err)
	require.Equal(t, root, owner)
	_, _, _, err = s.GetAccessGrant("voice-interface", stale)
	require.NoError(t, err)

	input.ExpectedHomeDomainOwner = root
	require.NoError(t, s.ApproveAppV23LocalAgent(input, AppV23RoleMember, 0, 0))
	owner, err = s.GetDomainOwner("voice-interface")
	require.NoError(t, err)
	require.Equal(t, target, owner)
	_, _, _, err = s.GetAccessGrant("voice-interface", stale)
	require.ErrorIs(t, err, ErrAccessGrantNotFound)
	_, _, _, err = s.GetAccessGrant("voice-interface", target)
	require.ErrorIs(t, err, ErrAccessGrantNotFound,
		"home authority is ownership, not a duplicate synthetic grant")
	authorization, err := s.AuthorizeAppV23LocalDomain(
		target, "voice-interface", AppV23VerbWrite, false,
	)
	require.NoError(t, err)
	require.True(t, authorization.Allowed)
}

func TestAppV23HomeTransferCannotOrphanActiveLocalPrincipal(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	root := appV23Register(t, s, "protected-home-root", AppV23RoleAdmin, 1, 0)
	source := appV23Register(t, s, "protected-home-source", AppV23RoleMember, 2, 0)
	target := appV23Register(
		t, s, "protected-home-target", AppV23RoleMember, 3,
		DefaultSelfRegisteredAgentCapabilities,
	)
	require.NoError(t, s.EnsureAppV23Root("protected-home-scope", 10))
	sourceEnrollment, err := s.GetAppV23Enrollment(source)
	require.NoError(t, err)
	require.True(t, sourceEnrollment.Active)
	require.NotEmpty(t, sourceEnrollment.HomeDomain)
	targetEnrollment, err := s.GetAppV23Enrollment(target)
	require.NoError(t, err)
	targetRole, err := s.GetAppV23Role(target)
	require.NoError(t, err)

	approval := AppV23LocalEnrollment{
		AgentID: target, ApprovedBy: root, RootGeneration: 1,
		Profile: AppV23ProfileCompanion, HomeDomain: sourceEnrollment.HomeDomain,
		ExpectedHomeDomainOwner: source, TransferHomeDomain: true,
		Clearance: 0, Capabilities: 15, Active: true, UpdatedHeight: 11,
	}
	require.ErrorContains(t, s.ApproveAppV23LocalAgent(
		approval, AppV23RoleMember, targetEnrollment.Revision, targetRole.Revision,
	), "required home domain")
	owner, err := s.GetDomainOwner(sourceEnrollment.HomeDomain)
	require.NoError(t, err)
	require.Equal(t, source, owner)
	require.ErrorContains(t, s.TransferDomainAppV23(
		sourceEnrollment.HomeDomain, target, "", 12, false,
	), "required home domain")
	require.ErrorContains(t, s.TransferDomain(
		sourceEnrollment.HomeDomain, target, "", 12,
	), "required home domain")
	require.ErrorContains(t, s.TransferDomainAppV23(
		sourceEnrollment.HomeDomain, source, "", 12, true,
	), "required home domain")
	require.ErrorContains(t, s.SetSharedDomain(sourceEnrollment.HomeDomain), "required home domain")
	require.NoError(t, s.ValidateAppV23State())
}

func TestAppV23MigrationDoesNotSelectDynamicSharedDomainAsHome(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	appV23Register(t, s, "dynamic-shared-root", AppV23RoleAdmin, 1, 0)
	member := appV23Register(t, s, "dynamic-shared-member", AppV23RoleMember, 2, 0)
	require.NoError(t, s.RegisterDomain("open.shared", member, "", 3))
	require.NoError(t, s.SetSharedDomain("open.shared"))
	shared, err := s.IsAppV23SharedDomain("open.shared")
	require.NoError(t, err)
	require.True(t, shared)
	require.NoError(t, s.EnsureAppV23Root("dynamic-shared-scope", 10))

	enrollment, err := s.GetAppV23Enrollment(member)
	require.NoError(t, err)
	require.True(t, enrollment.Active)
	require.NotEqual(t, "open.shared", enrollment.HomeDomain)
	require.Equal(t, "local-"+member, enrollment.HomeDomain)
	require.NoError(t, s.ValidateAppV23State())
}

func TestAppV23ReadOnlyExitRequiresAtomicHomeEnrollment(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	root := appV23Register(t, s, "readonly-exit-root", AppV23RoleAdmin, 1, 0)
	observer := appV23Register(t, s, "readonly-exit-observer", "observer", 2, 0)
	require.NoError(t, s.EnsureAppV23Root("readonly-exit-scope", 10))
	enrollment, err := s.GetAppV23Enrollment(observer)
	require.NoError(t, err)
	role, err := s.GetAppV23Role(observer)
	require.NoError(t, err)
	require.Equal(t, AppV23ProfileReadOnly, enrollment.Profile)
	require.Empty(t, enrollment.HomeDomain)

	require.ErrorContains(t, s.SetAppV23Policy(
		root, observer, AppV23RoleMember,
		AppV23ProfileReadOnly, AppV23ProfileStandard,
		enrollment.Clearance, 0,
		role.Revision, enrollment.Revision, 11,
	), "owned non-shared home domain")
	require.NoError(t, s.ValidateAppV23State())

	require.NoError(t, s.ApproveAppV23LocalAgent(AppV23LocalEnrollment{
		AgentID: observer, ApprovedBy: root, RootGeneration: 1,
		Profile: AppV23ProfileStandard, HomeDomain: "observer-home",
		Clearance: enrollment.Clearance, Capabilities: 0,
		Active: true, UpdatedHeight: 12,
	}, AppV23RoleMember, enrollment.Revision, role.Revision))
	require.NoError(t, s.ValidateAppV23State())
	owner, err := s.GetDomainOwner("observer-home")
	require.NoError(t, err)
	require.Equal(t, observer, owner)
}

func TestAppV23ElevationReplayAndRootRotation(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	root := appV23Register(t, s, "rotation-root", "admin", 1, 0)
	admin := appV23Register(t, s, "rotation-admin", "admin", 2, 0)
	require.NoError(t, s.EnsureAppV23Root("scope-rotation", 10))
	adminEnrollment, err := s.GetAppV23Enrollment(admin)
	require.NoError(t, err)
	adminRole, err := s.GetAppV23Role(admin)
	require.NoError(t, err)
	require.NoError(t, s.SetAppV23Policy(
		root, admin, AppV23RoleAdmin,
		adminEnrollment.Profile, AppV23ProfileStandard,
		4, AgentCapabilityReadAllDomains,
		adminRole.Revision, adminEnrollment.Revision, 10,
	))
	require.NoError(t, s.RegisterDomain("root-owned", root, "", 10))
	adminBeforeRotation, err := s.AuthorizeAppV23LocalDomain(
		admin, "root-owned", AppV23VerbRead, false,
	)
	require.NoError(t, err)
	require.True(t, adminBeforeRotation.Allowed)
	use := &AppV23ElevationUse{
		AdminID: admin, RootGeneration: 1,
		ValidFromHeight: 10, ValidUntilHeight: 12,
		Nonce: "nonce_replay_0001",
	}
	require.NoError(t, s.ConsumeAppV23Elevation(use, 11))
	require.Error(t, s.ConsumeAppV23Elevation(use, 11))

	newCredential := appV23TestID("new-root-credential")
	require.NoError(t, s.RotateAppV23RootCredential(1, newCredential, 12))
	state, err := s.GetAppV23Root()
	require.NoError(t, err)
	require.Equal(t, root, state.PrincipalID)
	require.Equal(t, newCredential, state.CredentialID)
	require.Equal(t, uint64(2), state.Generation)
	require.NoError(t, s.ValidateAppV23State())
	staleAdmin, err := s.AuthorizeAppV23LocalDomain(
		admin, "root-owned", AppV23VerbRead, false,
	)
	require.NoError(t, err)
	require.False(t, staleAdmin.Allowed)
	require.True(t, staleAdmin.ExplicitDeny)
	for _, verb := range []AppV23DomainVerb{AppV23VerbRead, AppV23VerbWrite, AppV23VerbModify} {
		allowed, err := s.AuthorizeAppV23LocalDomain(newCredential, "root-owned", verb, false)
		require.NoError(t, err)
		require.True(t, allowed.Allowed, "rotated root credential must retain verb %d", verb)
		old, err := s.AuthorizeAppV23LocalDomain(root, "root-owned", verb, false)
		require.NoError(t, err)
		require.False(t, old.Allowed, "old root credential must lose verb %d", verb)
	}
	require.Error(t, s.ConsumeAppV23Elevation(&AppV23ElevationUse{
		AdminID: admin, RootGeneration: 1,
		ValidFromHeight: 12, ValidUntilHeight: 13, Nonce: "nonce_old_generation",
	}, 12))
}

func TestAppV23RootCredentialHistoryIsPermanentAndForwardOnly(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	root := appV23Register(t, s, "history-root", AppV23RoleAdmin, 1, 0)
	require.NoError(t, s.EnsureAppV23Root("history-scope", 10))
	generationTwo := appV23TestID("history-root-generation-two")
	generationThree := appV23TestID("history-root-generation-three")

	require.NoError(t, s.RotateAppV23RootCredential(1, generationTwo, 11))
	require.NoError(t, s.RotateAppV23RootCredential(2, generationThree, 12))
	require.NoError(t, s.ValidateAppV23State())

	for generation, id := range []string{root, generationTwo, generationThree} {
		wasRoot, markerErr := s.IsAppV23RootCredential(id)
		require.NoError(t, markerErr)
		require.True(t, wasRoot, "every Root credential generation stays permanently reserved")
		storedGeneration, found, generationErr :=
			s.GetAppV23RootCredentialGeneration(id)
		require.NoError(t, generationErr)
		require.True(t, found)
		require.Equal(t, uint64(generation+1), storedGeneration)
	}
	ordinary := appV23TestID("history-ordinary")
	wasRoot, err := s.IsAppV23RootCredential(ordinary)
	require.NoError(t, err)
	require.False(t, wasRoot)
	_, found, err := s.GetAppV23RootCredentialGeneration(ordinary)
	require.NoError(t, err)
	require.False(t, found)

	for _, retired := range []string{root, generationTwo} {
		require.ErrorContains(t,
			s.RotateAppV23RootCredential(3, retired, 13),
			"previously used",
			"tx39 handover must never reactivate a retired Root credential",
		)
		require.ErrorContains(t,
			s.RegisterAgentWithCapabilities(
				retired, "retired-root", AppV23RoleMember, "", "", "", 13, 0,
			),
			"cannot be registered as an agent",
		)
		decision, authErr := s.AuthorizeAppV23LocalDomain(
			retired, "irrelevant", AppV23VerbRead, false,
		)
		require.NoError(t, authErr)
		require.False(t, decision.Allowed)
		require.Equal(t, ErrAppV23NeedsApproval.Error(), decision.Reason)
	}

	state, err := s.GetAppV23Root()
	require.NoError(t, err)
	require.Equal(t, generationThree, state.CredentialID)
	require.Equal(t, uint64(3), state.Generation)
}

func TestAppV23ValidationRequiresEveryRootCredentialGenerationAndNoRetiredAgentCollision(t *testing.T) {
	path := t.TempDir()
	s, openErr := NewBadgerStore(path)
	require.NoError(t, openErr)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	appV23Register(t, s, "history-validation-root", AppV23RoleAdmin, 1, 0)
	require.NoError(t, s.EnsureAppV23Root("history-validation-scope", 10))
	generationTwo := appV23TestID("history-validation-generation-two")
	generationThree := appV23TestID("history-validation-generation-three")
	require.NoError(t, s.RotateAppV23RootCredential(1, generationTwo, 11))
	require.NoError(t, s.RotateAppV23RootCredential(2, generationThree, 12))
	require.NoError(t, s.ValidateAppV23State())

	var originalHistoryDigest string
	require.NoError(t, s.update(func(txn *badger.Txn) error {
		var root AppV23RootState
		if err := appV23ReadJSON(txn, appV23RootKey(), &root); err != nil {
			return err
		}
		originalHistoryDigest = root.HistoryDigest
		root.HistoryDigest = fmt.Sprintf("%064x", 1)
		data, err := appV23Marshal(root)
		if err != nil {
			return err
		}
		return s.txnSet(txn, appV23RootKey(), data)
	}))
	require.ErrorContains(t, s.ValidateAppV23State(), "root credential history digest mismatch")
	require.NoError(t, s.update(func(txn *badger.Txn) error {
		var root AppV23RootState
		if err := appV23ReadJSON(txn, appV23RootKey(), &root); err != nil {
			return err
		}
		root.HistoryDigest = originalHistoryDigest
		data, err := appV23Marshal(root)
		if err != nil {
			return err
		}
		return s.txnSet(txn, appV23RootKey(), data)
	}))
	require.NoError(t, s.ValidateAppV23State())

	retiredAgentData, marshalErr := appV23Marshal(OnChainAgent{
		AgentID: generationTwo, RegisteredName: "forged-retired-root-agent",
		Name: "forged-retired-root-agent", Role: AppV23RoleMember,
		RegisteredAt: 13,
	})
	require.NoError(t, marshalErr)
	require.NoError(t, s.update(func(txn *badger.Txn) error {
		return s.txnSet(txn, agentOnChainKey(generationTwo), retiredAgentData)
	}))
	require.ErrorContains(t, s.ValidateAppV23State(), "retired root credential collides")
	require.NoError(t, s.update(func(txn *badger.Txn) error {
		return s.txnDelete(txn, agentOnChainKey(generationTwo))
	}))
	require.NoError(t, s.ValidateAppV23State())

	forgedHistoryID := appV23TestID("history-validation-forged-generation-two")
	require.NoError(t, s.update(func(txn *badger.Txn) error {
		if err := s.txnDelete(txn, appV23RootCredentialKey(generationTwo)); err != nil {
			return err
		}
		return s.txnSet(
			txn,
			appV23RootCredentialKey(forgedHistoryID),
			appV23RootCredentialGenerationValue(2),
		)
	}))
	require.ErrorContains(t, s.ValidateAppV23State(), "root credential history digest",
		"an unrelated marker must not substitute for a missing retired generation")
	require.NoError(t, s.update(func(txn *badger.Txn) error {
		if err := s.txnDelete(txn, appV23RootCredentialKey(forgedHistoryID)); err != nil {
			return err
		}
		return s.txnSet(
			txn,
			appV23RootCredentialKey(generationTwo),
			appV23RootCredentialGenerationValue(2),
		)
	}))
	require.NoError(t, s.ValidateAppV23State())

	require.NoError(t, s.update(func(txn *badger.Txn) error {
		return s.txnDelete(txn, appV23RootCredentialKey(generationTwo))
	}))
	require.ErrorContains(t, s.ValidateAppV23State(), "root credential history count")

	require.NoError(t, s.CloseBadger())
	s, reopenErr := NewBadgerStore(path)
	require.NoError(t, reopenErr)
	require.ErrorContains(t, s.ValidateAppV23State(), "root credential history count",
		"reopening must not normalize or forget a missing historical Root marker")
}

func TestAppV23RootCredentialCannotCollideWithOrdinaryAgent(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	rootID := appV23Register(t, s, "collision-root", AppV23RoleAdmin, 1, 0)
	memberID := appV23Register(t, s, "collision-member", AppV23RoleMember, 2, 0)
	require.NoError(t, s.EnsureAppV23Root("collision-scope", 10))

	require.ErrorContains(t, s.RotateAppV23RootCredential(1, memberID, 11), "registered agent")
	root, err := s.GetAppV23Root()
	require.NoError(t, err)
	require.Equal(t, rootID, root.CredentialID)
	require.Equal(t, uint64(1), root.Generation)
	require.NoError(t, s.ValidateAppV23State())

	require.NoError(t, s.update(func(txn *badger.Txn) error {
		var corrupt AppV23RootState
		if err := appV23ReadJSON(txn, appV23RootKey(), &corrupt); err != nil {
			return err
		}
		corrupt.CredentialID = memberID
		data, err := appV23Marshal(corrupt)
		if err != nil {
			return err
		}
		return s.txnSet(txn, appV23RootKey(), data)
	}))
	require.ErrorContains(t, s.ValidateAppV23State(), "root credential collides")
}

func TestAppV23PolicyMatrixAndOwnerRead(t *testing.T) {
	require.NoError(t, ValidateAppV23Policy(AppV23RoleMember, AppV23ProfileStandard, 0, 0))
	require.NoError(t, ValidateAppV23Policy(AppV23RoleMember, AppV23ProfileStandard, AgentCapabilityDenyFederatedPipe, 0))
	require.Error(t, ValidateAppV23Policy(AppV23RoleMember, AppV23ProfileStandard, AgentCapabilityReadAllDomains, 0))
	require.NoError(t, ValidateAppV23Policy(AppV23RoleManager, AppV23ProfileStandard, 0, 2))
	require.NoError(t, ValidateAppV23Policy(AppV23RoleManager, AppV23ProfileStandard, AgentCapabilityDenyFederatedPipe, 2))
	require.Error(t, ValidateAppV23Policy(AppV23RoleManager, AppV23ProfileStandard, AgentCapabilityDenySharedDomainWrite, 2))
	require.NoError(t, ValidateAppV23Policy(AppV23RoleMember, AppV23ProfileCompanion, 15, 0))
	require.NoError(t, ValidateAppV23Policy(AppV23RoleMember, AppV23ProfileCompanion, 15|AgentCapabilityDenyFederatedPipe, 0))
	require.NoError(t, ValidateAppV23Policy(AppV23RoleMember, AppV23ProfileReadOnly, AgentCapabilityReadAllDomains, 0))
	require.NoError(t, ValidateAppV23Policy(AppV23RoleMember, AppV23ProfileReadOnly, AgentCapabilityReadAllDomains|AgentCapabilityDenyFederatedPipe, 0))
	require.Error(t, ValidateAppV23Policy(AppV23RoleMember, AppV23ProfileReadOnly, 0, 0))
	require.NoError(t, ValidateAppV23Policy(AppV23RoleAdmin, AppV23ProfileStandard, AgentCapabilityReadAllDomains, 4))
	require.Error(t, ValidateAppV23Policy(AppV23RoleAdmin, AppV23ProfileStandard, AgentCapabilityReadAllDomains, 3))
	require.NoError(t, ValidateAppV23Policy(AppV23RoleAdmin, AppV23ProfileStandard, AgentCapabilityReadAllDomains|AgentCapabilityDenyFederatedPipe, 4))
	require.Error(t, ValidateAppV23Policy(AppV23RoleAdmin, AppV23ProfileStandard, AgentCapabilityReadAllDomains|AgentCapabilityDenyDomainClaim, 4))
}

func TestAppV23ReadOnlyPolicyCannotTransitionWithoutOwnedHome(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	root := appV23Register(t, s, "profile-transition-root", AppV23RoleAdmin, 1, 0)
	observer := appV23Register(t, s, "profile-transition-observer", "observer", 2, 0)
	require.NoError(t, s.EnsureAppV23Root("profile-transition-scope", 10))
	enrollment, err := s.GetAppV23Enrollment(observer)
	require.NoError(t, err)
	role, err := s.GetAppV23Role(observer)
	require.NoError(t, err)
	require.Equal(t, AppV23ProfileReadOnly, enrollment.Profile)
	require.Empty(t, enrollment.HomeDomain)

	require.ErrorContains(t, s.SetAppV23Policy(
		root, observer, AppV23RoleMember,
		AppV23ProfileReadOnly, AppV23ProfileStandard,
		0, 0,
		role.Revision, enrollment.Revision, 11,
	), "requires an owned non-shared home domain")
	after, err := s.GetAppV23Enrollment(observer)
	require.NoError(t, err)
	require.Equal(t, AppV23ProfileReadOnly, after.Profile)
	require.Equal(t, enrollment.Revision, after.Revision)
	require.NoError(t, s.ValidateAppV23State())
}

func TestAppV23EnteringReadOnlyDropsHomeBindingAndRequiresFreshApprovalToLeave(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	root := appV23Register(t, s, "readonly-entry-root", AppV23RoleAdmin, 1, 0)
	member := appV23Register(t, s, "readonly-entry-member", AppV23RoleMember, 2, 0)
	require.NoError(t, s.EnsureAppV23Root("readonly-entry-scope", 10))
	enrollment, err := s.GetAppV23Enrollment(member)
	require.NoError(t, err)
	role, err := s.GetAppV23Role(member)
	require.NoError(t, err)
	home := enrollment.HomeDomain
	require.NotEmpty(t, home)

	require.NoError(t, s.SetAppV23Policy(
		root, member, AppV23RoleMember,
		AppV23ProfileStandard, AppV23ProfileReadOnly,
		enrollment.Clearance, AgentCapabilityReadAllDomains,
		role.Revision, enrollment.Revision, 11,
	))
	readOnly, err := s.GetAppV23Enrollment(member)
	require.NoError(t, err)
	require.Equal(t, AppV23ProfileReadOnly, readOnly.Profile)
	require.Empty(t, readOnly.HomeDomain,
		"entering Read-only must remove the home binding so role-only exit cannot bypass fresh target consent")
	owner, err := s.GetDomainOwner(home)
	require.NoError(t, err)
	require.Equal(t, member, owner,
		"changing profile must not silently transfer or relabel an existing domain")
	readOnlyRole, err := s.GetAppV23Role(member)
	require.NoError(t, err)
	require.ErrorContains(t, s.SetAppV23Policy(
		root, member, AppV23RoleMember,
		AppV23ProfileReadOnly, AppV23ProfileStandard,
		readOnly.Clearance, 0,
		readOnlyRole.Revision, readOnly.Revision, 12,
	), "owned non-shared home domain")
	require.NoError(t, s.ValidateAppV23State())
}

func TestAppV23ReadOnlyApprovalRejectsHomeBinding(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	root := appV23Register(t, s, "readonly-approval-root", AppV23RoleAdmin, 1, 0)
	target := appV23Register(t, s, "readonly-approval-target", AppV23RoleMember, 2, DefaultSelfRegisteredAgentCapabilities)
	require.NoError(t, s.EnsureAppV23Root("readonly-approval-scope", 10))
	enrollment, err := s.GetAppV23Enrollment(target)
	require.NoError(t, err)
	role, err := s.GetAppV23Role(target)
	require.NoError(t, err)

	err = s.ApproveAppV23LocalAgent(AppV23LocalEnrollment{
		AgentID: target, ApprovedBy: root, RootGeneration: 1,
		Profile: AppV23ProfileReadOnly, HomeDomain: "readonly-must-not-bind-home",
		Clearance: 0, Capabilities: AgentCapabilityReadAllDomains,
		Active: true, UpdatedHeight: 11,
	}, AppV23RoleMember, enrollment.Revision, role.Revision)
	require.ErrorContains(t, err, "must not retain a home domain")
}

func TestAppV23ApprovalCannotMutateRootEnrollment(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	root := appV23Register(t, s, "approval-root", AppV23RoleAdmin, 1, 0)
	require.NoError(t, s.EnsureAppV23Root("approval-root-scope", 10))
	enrollment, err := s.GetAppV23Enrollment(root)
	require.NoError(t, err)
	role, err := s.GetAppV23Role(root)
	require.NoError(t, err)

	require.ErrorContains(t, s.ApproveAppV23LocalAgent(AppV23LocalEnrollment{
		AgentID: root, ApprovedBy: root, RootGeneration: 1,
		Profile: AppV23ProfileStandard, Active: false, UpdatedHeight: 11,
	}, AppV23RoleMember, enrollment.Revision, role.Revision), "root enrollment is immutable")
	afterEnrollment, err := s.GetAppV23Enrollment(root)
	require.NoError(t, err)
	require.Equal(t, enrollment, afterEnrollment)
	afterRole, err := s.GetAppV23Role(root)
	require.NoError(t, err)
	require.Equal(t, role, afterRole)
	require.NoError(t, s.ValidateAppV23State())
}

func TestAppV23GroupMemberReadManagerWriteAndMultiGroupUnion(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	root := appV23Register(t, s, "group-root", "admin", 1, 0)
	ownerA := appV23Register(t, s, "group-owner-a", "member", 2, 0)
	ownerB := appV23Register(t, s, "group-owner-b", "member", 3, 0)
	member := appV23Register(t, s, "group-member", "member", 4, 0)
	manager := appV23Register(t, s, "group-manager", "member", 5, 0)
	outsider := appV23Register(t, s, "group-outsider", "member", 6, 0)
	require.NoError(t, s.EnsureAppV23Root("group-scope", 10))

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
	membersA := []string{ownerA, member, manager}
	membersB := []string{ownerB, manager}
	sort.Strings(membersA)
	sort.Strings(membersB)
	rootMembers := []string{root, manager}
	sort.Strings(rootMembers)
	require.ErrorContains(t, s.MutateAppV23AccessGroup(
		root, "root-scope", "Root scope", rootMembers, 0, false, 12,
	), "CEREBRUM root")
	require.NoError(t, s.MutateAppV23AccessGroup(root, "team-a", "Team A", membersA, 0, false, 12))
	require.NoError(t, s.MutateAppV23AccessGroup(root, "team-b", "Team B", membersB, 0, false, 12))

	ownerAEnrollment, err := s.GetAppV23Enrollment(ownerA)
	require.NoError(t, err)
	memberRead, err := s.AuthorizeAppV23LocalDomain(member, ownerAEnrollment.HomeDomain, AppV23VerbRead, false)
	require.NoError(t, err)
	require.True(t, memberRead.Allowed)
	memberWrite, err := s.AuthorizeAppV23LocalDomain(member, ownerAEnrollment.HomeDomain, AppV23VerbWrite, false)
	require.NoError(t, err)
	require.False(t, memberWrite.Allowed)

	managerWriteA, err := s.AuthorizeAppV23LocalDomain(manager, ownerAEnrollment.HomeDomain, AppV23VerbWrite, false)
	require.NoError(t, err)
	require.True(t, managerWriteA.Allowed)
	ownerBEnrollment, err := s.GetAppV23Enrollment(ownerB)
	require.NoError(t, err)
	managerWriteB, err := s.AuthorizeAppV23LocalDomain(manager, ownerBEnrollment.HomeDomain, AppV23VerbModify, false)
	require.NoError(t, err)
	require.True(t, managerWriteB.Allowed, "the union of multiple groups must grant manager authority")

	outsiderRead, err := s.AuthorizeAppV23LocalDomain(outsider, ownerAEnrollment.HomeDomain, AppV23VerbRead, false)
	require.NoError(t, err)
	require.False(t, outsiderRead.Allowed)

	// Removing a Member from the committed group must revoke only the derived
	// shared-domain relationship. The owner keeps its own domain authority; no
	// browser-side grouping can leave a stale read grant behind.
	teamA, err := s.GetAppV23AccessGroup("team-a")
	require.NoError(t, err)
	require.NotNil(t, teamA)
	remainingMembers := []string{ownerA, manager}
	sort.Strings(remainingMembers)
	require.NoError(t, s.MutateAppV23AccessGroup(
		root, "team-a", "Team A", remainingMembers, teamA.Revision, false, 13,
	))
	memberReadAfterRemoval, err := s.AuthorizeAppV23LocalDomain(member, ownerAEnrollment.HomeDomain, AppV23VerbRead, false)
	require.NoError(t, err)
	require.False(t, memberReadAfterRemoval.Allowed)
	ownerWriteAfterRemoval, err := s.AuthorizeAppV23LocalDomain(ownerA, ownerAEnrollment.HomeDomain, AppV23VerbWrite, false)
	require.NoError(t, err)
	require.True(t, ownerWriteAfterRemoval.Allowed)
}

func TestAppV23AccessGroupMutationPreservesGlobalStateBounds(t *testing.T) {
	t.Run("group count", func(t *testing.T) {
		s, err := NewBadgerStore(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

		root := appV23Register(t, s, "group-bound-root", AppV23RoleAdmin, 1, 0)
		require.NoError(t, s.EnsureAppV23Root("group-bound-scope", 10))
		for i := 0; i < AppV23MaxGroups; i++ {
			require.NoError(t, s.MutateAppV23AccessGroup(
				root, fmt.Sprintf("group-%03d", i), "", nil, 0, false, int64(11+i),
			))
		}
		require.NoError(t, s.ValidateAppV23State())
		require.ErrorContains(t, s.MutateAppV23AccessGroup(
			root, "group-overflow", "", nil, 0, false, 500,
		), "global access group limit")
		require.NoError(t, s.ValidateAppV23State())
	})

	t.Run("membership link count", func(t *testing.T) {
		s, err := NewBadgerStore(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

		root := appV23Register(t, s, "link-bound-root", AppV23RoleAdmin, 1, 0)
		members := make([]string, 257)
		for i := range members {
			members[i] = appV23Register(
				t, s, fmt.Sprintf("link-bound-member-%03d", i),
				AppV23RoleMember, int64(i+2), 0,
			)
		}
		require.NoError(t, s.EnsureAppV23Root("link-bound-scope", 300))
		for groupIndex := 0; groupIndex < AppV23MaxGroups; groupIndex++ {
			groupMembers := make([]string, 16)
			for memberIndex := range groupMembers {
				groupMembers[memberIndex] = members[(groupIndex+memberIndex)%256]
			}
			sort.Strings(groupMembers)
			require.NoError(t, s.MutateAppV23AccessGroup(
				root, fmt.Sprintf("links-%03d", groupIndex), "",
				groupMembers, 0, false, int64(301+groupIndex),
			))
		}
		require.NoError(t, s.ValidateAppV23State())

		group, err := s.GetAppV23AccessGroup("links-000")
		require.NoError(t, err)
		overflowMembers := append(append([]string(nil), group.Members...), members[256])
		sort.Strings(overflowMembers)
		require.ErrorContains(t, s.MutateAppV23AccessGroup(
			root, group.GroupID, group.Name, overflowMembers,
			group.Revision, false, 600,
		), "global membership link limit")
		require.NoError(t, s.ValidateAppV23State())
	})
}
