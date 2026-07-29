package abci

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/authzdenial"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

func TestAppV23MigratedLegacyMasksPreserveSignedRawDomainClaimAuthority(t *testing.T) {
	for mask := store.AgentCapabilities(0); mask <= store.KnownAgentCapabilities; mask++ {
		mask := mask
		t.Run(fmt.Sprintf("mask_%02d", mask), func(t *testing.T) {
			app := setupTestApp(t)
			app.appV22AppliedHeight = 1
			root := newAgentKey(t)
			agent := newAgentKey(t)
			registerAppV23Agent(t, app, root, store.AppV23RoleAdmin, 1, 0)
			registerAppV23Agent(t, app, agent, store.AppV23RoleMember, 2, mask)
			foreignDomain := fmt.Sprintf("legacy-foreign-%02d", mask)
			require.NoError(t, app.badgerStore.RegisterDomain(
				foreignDomain, root.id, "", 3,
			))

			// Directly execute the app-v22 shared write before migration. The
			// exact old authority was "allowed iff bit 2 is absent".
			beforeShared := app.processMemorySubmit(
				makeMemorySubmitTx(
					t, agent, "general",
					fmt.Sprintf("pre-v23 shared mask %02d", mask),
				),
				9,
				appV23BlockTime(),
			)
			wantShared := !mask.Has(store.AgentCapabilityDenySharedDomainWrite)
			require.Equal(t, wantShared, beforeShared.Code == 0, beforeShared.Log)

			require.NoError(t, app.badgerStore.EnsureAppV23Root("legacy-mask-claim", 10))
			require.NoError(t, app.badgerStore.ValidateAppV23State())
			app.appV23AppliedHeight = 10

			enrollment, err := app.badgerStore.GetAppV23Enrollment(agent.id)
			require.NoError(t, err)
			require.Equal(t, mask, enrollment.Capabilities)
			wantAllowed := !mask.Has(store.AgentCapabilityDenyDomainClaim)
			if mask == store.DefaultSelfRegisteredAgentCapabilities {
				require.False(t, enrollment.Active)
				wantAllowed = false
			} else {
				require.True(t, enrollment.Active)
			}

			// Execute the same shared-domain data-plane path after migration.
			// Grandfathering is migration-scoped, while the exact bit 2 hard
			// deny remains authoritative.
			afterShared := app.processMemorySubmit(
				makeMemorySubmitTx(
					t, agent, "general",
					fmt.Sprintf("post-v23 shared mask %02d", mask),
				),
				appV23MatrixRawHeight,
				appV23BlockTime(),
			)
			require.Equal(t, wantShared, afterShared.Code == 0, afterShared.Log)
			modifyAllowed, modifyCode, err := app.appV23DomainDecision(
				&tx.ParsedTx{}, agent.id, "general", store.AppV23VerbModify,
				appV23MatrixRawHeight, appV23BlockTime(),
			)
			require.NoError(t, err)
			require.False(t, modifyAllowed,
				"shared memory-submit grandfathering must not imply level-3 modify")
			if !enrollment.Active {
				require.Equal(t, authzdenial.CodePrincipalPendingReview, modifyCode)
			} else if mask.Has(store.AgentCapabilityDenySharedDomainWrite) {
				require.Equal(t, authzdenial.CodeSharedWriteRestricted, modifyCode)
			} else {
				require.Equal(t, authzdenial.CodeMissingWriteGrant, modifyCode)
			}

			readAllowed, readCode, err := app.appV23DomainDecision(
				&tx.ParsedTx{}, agent.id, foreignDomain, store.AppV23VerbRead,
				appV23MatrixRawHeight, appV23BlockTime(),
			)
			require.NoError(t, err)
			wantReadAll := enrollment.Active &&
				mask.Has(store.AgentCapabilityReadAllDomains)
			require.Equal(t, wantReadAll, readAllowed,
				"ReadAllDomains must still cover a foreign-owned domain")
			if enrollment.Active {
				require.Empty(t, readCode)
			} else {
				require.Equal(t, authzdenial.CodePrincipalPendingReview, readCode)
			}

			domain := fmt.Sprintf("legacy-claim-%02d", mask)
			allowed, code, err := app.appV23DomainDecision(
				&tx.ParsedTx{}, agent.id, domain, store.AppV23VerbWrite,
				appV23MatrixRawHeight, appV23BlockTime(),
			)
			require.NoError(t, err)
			require.Equal(t, wantAllowed, allowed)
			if wantAllowed {
				require.Empty(t, code)
			} else if mask == store.DefaultSelfRegisteredAgentCapabilities {
				require.Equal(t, authzdenial.CodePrincipalPendingReview, code)
			} else {
				require.Equal(t, authzdenial.CodeDomainClaimRestricted, code)
			}

			pub, sig, bodyHash, timestamp := signAgentProof(
				t, agent, []byte("legacy explicit claim "+domain),
			)
			parsed := &tx.ParsedTx{
				Type: tx.TxTypeDomainRegister,
				DomainRegister: &tx.DomainRegister{
					DomainName: domain, OwnerAgentID: agent.id,
				},
				AgentPubKey: pub, AgentSig: sig,
				AgentBodyHash: bodyHash, AgentTimestamp: timestamp,
			}
			result := appV23MatrixProcessRaw(
				t, app, parsed, agent, uint64(mask)+1, appV23MatrixRawHeight,
			)
			if wantAllowed {
				require.Zero(t, result.Code, result.Log)
				owner, err := app.badgerStore.GetDomainOwner(domain)
				require.NoError(t, err)
				require.Equal(t, agent.id, owner)
			} else {
				require.Equal(t, uint32(110), result.Code, result.Log)
			}
		})
	}
}

func TestAppV23SignedMutationsCannotMintLegacyRestrictedProfile(t *testing.T) {
	app := setupTestApp(t)
	root := newAgentKey(t)
	target := newAgentKey(t)
	registerAppV23Agent(t, app, root, store.AppV23RoleAdmin, 1, 0)
	registerAppV23Agent(
		t, app, target, store.AppV23RoleMember, 2,
		store.AgentCapabilityDenySharedDomainWrite,
	)
	require.NoError(t, app.badgerStore.RegisterDomain("legacy-target-home", target.id, "", 3))
	require.NoError(t, app.badgerStore.EnsureAppV23Root("legacy-mutation-scope", 10))
	app.appV23AppliedHeight = 10

	enrollment, err := app.badgerStore.GetAppV23Enrollment(target.id)
	require.NoError(t, err)
	role, err := app.badgerStore.GetAppV23Role(target.id)
	require.NoError(t, err)
	require.Equal(t, store.AppV23ProfileLegacyRestricted, enrollment.Profile)

	change := &tx.ParsedTx{
		Type: tx.TxTypeAgentRoleChange,
		AgentRoleChange: &tx.AgentRoleChange{
			AgentID: target.id, Role: store.AppV23RoleMember,
			ExpectedProfile:    enrollment.Profile,
			Profile:            store.AppV23ProfileLegacyRestricted,
			Clearance:          enrollment.Clearance,
			Capabilities:       uint32(enrollment.Capabilities),
			ExpectedRevision:   role.Revision,
			EnrollmentRevision: enrollment.Revision,
		},
	}
	result := appV23MatrixProcessRaw(
		t, app, change, root, 1, appV23MatrixRawHeight,
	)
	require.NotZero(t, result.Code, result.Log)
	afterEnrollment, err := app.badgerStore.GetAppV23Enrollment(target.id)
	require.NoError(t, err)
	require.Equal(t, enrollment, afterEnrollment)
	afterRole, err := app.badgerStore.GetAppV23Role(target.id)
	require.NoError(t, err)
	require.Equal(t, role, afterRole)
}

func TestAppV23MigratedSharedWriteGrandfatheringCoversCoCommitOnlyAtWriteLevel(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mask        store.AgentCapabilities
		wantAllowed bool
	}{
		{name: "legacy mask zero", mask: 0, wantAllowed: true},
		{
			name: "legacy shared-write hard deny",
			mask: store.AgentCapabilityDenySharedDomainWrite,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			app := setupTestApp(t)
			app.appV15AppliedHeight = 1
			app.appV22AppliedHeight = 1
			root := newAgentKey(t)
			agent := newAgentKey(t)
			registerAppV23Agent(t, app, root, store.AppV23RoleAdmin, 1, 0)
			registerAppV23Agent(t, app, agent, store.AppV23RoleMember, 2, tc.mask)
			require.NoError(t, app.badgerStore.EnsureAppV23Root(
				"legacy-co-commit-shared", 10,
			))
			app.appV23AppliedHeight = 10

			envelope, _ := buildCoCommitEnvelope(
				t, agent, "general",
				[]byte("app-v23 migrated shared co-commit "+tc.name),
				"sage-b",
			)
			result := app.processCoCommitSubmit(
				coCommitSubmitTx(t, agent, envelope),
				appV23MatrixRawHeight,
				appV23BlockTime(),
			)
			require.Equal(t, tc.wantAllowed, result.Code == 0, result.Log)
			if !tc.wantAllowed {
				require.Equal(t, uint32(110), result.Code, result.Log)
				require.Contains(t, result.Log,
					string(authzdenial.CodeSharedWriteRestricted))
			}

			allowed, code, err := app.appV23DomainDecision(
				&tx.ParsedTx{}, agent.id, "general",
				store.AppV23VerbModify,
				appV23MatrixRawHeight, appV23BlockTime(),
			)
			require.NoError(t, err)
			require.False(t, allowed)
			if tc.mask.Has(store.AgentCapabilityDenySharedDomainWrite) {
				require.Equal(t, authzdenial.CodeSharedWriteRestricted, code)
			} else {
				require.Equal(t, authzdenial.CodeMissingWriteGrant, code)
			}
		})
	}
}

func TestAppV23LegacyAdminRosterAboveCapPreservesReviewedMemberDataPlane(t *testing.T) {
	app := setupTestApp(t)
	app.appV22AppliedHeight = 1
	admins := make([]agentKey, 0, store.AppV23MaxAdmins+1)
	for i := 0; i < store.AppV23MaxAdmins+1; i++ {
		admin := newAgentKey(t)
		mask := store.AgentCapabilities(0)
		if i%2 == 1 {
			mask = store.DefaultSelfRegisteredAgentCapabilities
		}
		registerAppV23Agent(
			t, app, admin, store.AppV23RoleAdmin, int64(i)+1, mask,
		)
		admins = append(admins, admin)
	}
	require.NoError(t, app.badgerStore.EnsureAppV23Root(
		"legacy-admin-over-cap-raw", 100,
	))
	require.NoError(t, app.badgerStore.ValidateAppV23State())
	app.appV23AppliedHeight = 100

	var healthy, restricted *agentKey
	for i := range admins {
		role, err := app.badgerStore.GetAppV23Role(admins[i].id)
		require.NoError(t, err)
		if role.Role == store.AppV23RoleAdmin {
			continue
		}
		enrollment, err := app.badgerStore.GetAppV23Enrollment(admins[i].id)
		require.NoError(t, err)
		require.Equal(t, store.AppV23RoleMember, role.Role)
		require.Equal(t, store.AppV23ProfileLegacyRestricted, enrollment.Profile)
		if enrollment.Capabilities == 0 && healthy == nil {
			healthy = &admins[i]
		}
		if enrollment.Capabilities == store.DefaultSelfRegisteredAgentCapabilities &&
			restricted == nil {
			restricted = &admins[i]
		}
	}
	require.NotNil(t, healthy)
	require.NotNil(t, restricted)

	for _, tc := range []struct {
		name        string
		agent       agentKey
		wantAllowed bool
	}{
		{name: "reviewed healthy legacy Admin", agent: *healthy, wantAllowed: true},
		{name: "reviewed restricted legacy Admin", agent: *restricted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			domain := "legacy-admin-claim-" + tc.agent.id[:8]
			pub, sig, bodyHash, timestamp := signAgentProof(
				t, tc.agent, []byte("legacy Admin explicit claim "+domain),
			)
			result := appV23MatrixProcessRaw(t, app, &tx.ParsedTx{
				Type: tx.TxTypeDomainRegister,
				DomainRegister: &tx.DomainRegister{
					DomainName: domain, OwnerAgentID: tc.agent.id,
				},
				AgentPubKey: pub, AgentSig: sig,
				AgentBodyHash: bodyHash, AgentTimestamp: timestamp,
			}, tc.agent, 1, appV23MatrixRawHeight)
			require.Equal(t, tc.wantAllowed, result.Code == 0, result.Log)

			shared := app.processMemorySubmit(
				makeMemorySubmitTx(
					t, tc.agent, "general",
					"reviewed legacy Admin shared "+tc.name,
				),
				appV23MatrixRawHeight,
				appV23BlockTime(),
			)
			require.Equal(t, tc.wantAllowed, shared.Code == 0, shared.Log)
		})
	}
}
