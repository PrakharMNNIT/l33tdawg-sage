package store

import (
	"fmt"
	"testing"
	"time"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/require"
)

func TestAppV23BareMask30FingerprintUsesEveryExplicitReviewSignal(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, *BadgerStore, string, string)
	}{
		{name: "bare"},
		{name: "clearance", setup: func(t *testing.T, s *BadgerStore, _, id string) {
			require.NoError(t, s.SetAgentPermissionWithCapabilities(
				id, 2, "", "", "", "", DefaultSelfRegisteredAgentCapabilities,
			))
		}},
		{name: "domain policy", setup: func(t *testing.T, s *BadgerStore, _, id string) {
			require.NoError(t, s.SetAgentPermissionWithCapabilities(
				id, 1, `[{"domain":"reviewed","read":true}]`, "", "", "",
				DefaultSelfRegisteredAgentCapabilities,
			))
		}},
		{name: "visible policy", setup: func(t *testing.T, s *BadgerStore, _, id string) {
			require.NoError(t, s.SetAgentPermissionWithCapabilities(
				id, 1, "", `["peer"]`, "", "",
				DefaultSelfRegisteredAgentCapabilities,
			))
		}},
		{name: "legacy org slot", setup: func(t *testing.T, s *BadgerStore, _, id string) {
			require.NoError(t, s.SetAgentPermissionWithCapabilities(
				id, 1, "", "", "org-slot", "",
				DefaultSelfRegisteredAgentCapabilities,
			))
		}},
		{name: "legacy department slot", setup: func(t *testing.T, s *BadgerStore, _, id string) {
			require.NoError(t, s.SetAgentPermissionWithCapabilities(
				id, 1, "", "", "", "dept-slot",
				DefaultSelfRegisteredAgentCapabilities,
			))
		}},
		{name: "organization membership", setup: func(t *testing.T, s *BadgerStore, root, id string) {
			require.NoError(t, s.RegisterOrg("review-org", "Review", "", root, 3))
			require.NoError(t, s.AddOrgMember("review-org", id, 1, "member", 4))
		}},
		{name: "department membership", setup: func(t *testing.T, s *BadgerStore, root, id string) {
			require.NoError(t, s.RegisterOrg("dept-org", "Review", "", root, 3))
			require.NoError(t, s.RegisterDept("dept-org", "review-dept", "Review", "", "", 4))
			require.NoError(t, s.AddDeptMember("dept-org", "review-dept", id, 1, "member", 5))
		}},
		{name: "expired well formed grant", setup: func(t *testing.T, s *BadgerStore, root, id string) {
			require.NoError(t, s.RegisterDomain("expired-review", root, "", 3))
			require.NoError(t, s.SetAccessGrant("expired-review", id, 1, 1, root))
		}},
		{name: "historical admin role", setup: func(t *testing.T, s *BadgerStore, _, id string) {
			require.NoError(t, s.update(func(txn *badger.Txn) error {
				agent, err := s.GetRegisteredAgent(id)
				if err != nil {
					return err
				}
				agent.Role = AppV23RoleAdmin
				value, err := appV23Marshal(agent)
				if err != nil {
					return err
				}
				return s.txnSet(txn, agentOnChainKey(id), value)
			}))
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			s, err := NewBadgerStore(t.TempDir())
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
			root := appV23Register(t, s, "fingerprint-root-"+test.name, AppV23RoleAdmin, 1, 0)
			id := appV23Register(
				t, s, "fingerprint-target-"+test.name, AppV23RoleMember, 2,
				DefaultSelfRegisteredAgentCapabilities,
			)
			if test.setup != nil {
				test.setup(t, s, root, id)
			}
			require.NoError(t, s.EnsureAppV23Root("fingerprint-"+test.name, 100))
			enrollment, err := s.GetAppV23Enrollment(id)
			require.NoError(t, err)
			require.Equal(t, test.name != "bare", enrollment.Active)
			disposition, err := s.GetAppV23MigrationDisposition(id)
			require.NoError(t, err)
			switch test.name {
			case "bare":
				require.Equal(t, "pending_review", disposition.Disposition)
			case "historical admin role":
				require.Equal(t, "legacy_admin_review", disposition.Disposition)
			default:
				require.Equal(t, "legacy_restricted", disposition.Disposition)
			}
			require.NoError(t, s.ValidateAppV23State())
		})
	}
}

func TestAppV23MalformedReviewEvidenceFailsMigrationClosed(t *testing.T) {
	for _, kind := range []string{"grant", "membership"} {
		t.Run(kind, func(t *testing.T) {
			s, err := NewBadgerStore(t.TempDir())
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
			root := appV23Register(t, s, "malformed-root-"+kind, AppV23RoleAdmin, 1, 0)
			id := appV23Register(
				t, s, "malformed-target-"+kind, AppV23RoleMember, 2,
				DefaultSelfRegisteredAgentCapabilities,
			)
			require.NoError(t, s.update(func(txn *badger.Txn) error {
				if kind == "grant" {
					return s.txnSet(txn, grantKey("broken", id), []byte{1})
				}
				return s.txnSet(txn, orgMemberKey("broken", id), []byte{1})
			}))
			require.Error(t, s.EnsureAppV23Root("malformed-"+kind, 100))
			state, err := s.GetAppV23MigrationState()
			require.NoError(t, err)
			require.Nil(t, state)
			_ = root
		})
	}
}

func TestAppV23MigrationRosterFailsClosedOnMalformedIdentityRows(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(*testing.T, *BadgerStore, string)
	}{
		{
			name: "malformed json",
			corrupt: func(t *testing.T, s *BadgerStore, target string) {
				require.NoError(t, s.SetRawForTest(agentOnChainKey(target), []byte("{")))
			},
		},
		{
			name: "key value mismatch",
			corrupt: func(t *testing.T, s *BadgerStore, target string) {
				agent, err := s.GetRegisteredAgent(target)
				require.NoError(t, err)
				agent.AgentID = appV23TestID("mismatched-value-id")
				value, err := appV23Marshal(agent)
				require.NoError(t, err)
				require.NoError(t, s.SetRawForTest(agentOnChainKey(target), value))
			},
		},
		{
			name: "noncanonical key suffix",
			corrupt: func(t *testing.T, s *BadgerStore, _ string) {
				value, err := appV23Marshal(OnChainAgent{
					AgentID: appV23TestID("noncanonical-key-value"),
					Name:    "orphan", Role: AppV23RoleMember, RegisteredAt: 3,
				})
				require.NoError(t, err)
				require.NoError(t, s.SetRawForTest([]byte("agent:not-canonical"), value))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, err := NewBadgerStore(t.TempDir())
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
			appV23Register(t, s, "roster-root-"+test.name, AppV23RoleAdmin, 1, 0)
			target := appV23Register(
				t, s, "roster-target-"+test.name, AppV23RoleMember, 2, 0,
			)
			test.corrupt(t, s, target)

			require.Error(t, s.EnsureAppV23Root("roster-fail-closed", 100))
			root, err := s.GetAppV23Root()
			require.NoError(t, err)
			require.Nil(t, root)
			migration, err := s.GetAppV23MigrationState()
			require.NoError(t, err)
			require.Nil(t, migration)
		})
	}
}

func TestAppV23MigrationRosterReplayValidationRejectsRawCorruption(t *testing.T) {
	for _, test := range []struct {
		name    string
		corrupt func(*testing.T, *BadgerStore, string)
	}{
		{
			name: "malformed json",
			corrupt: func(t *testing.T, s *BadgerStore, target string) {
				require.NoError(t, s.SetRawForTest(agentOnChainKey(target), []byte("{")))
			},
		},
		{
			name: "key value mismatch",
			corrupt: func(t *testing.T, s *BadgerStore, target string) {
				agent, err := s.GetRegisteredAgent(target)
				require.NoError(t, err)
				agent.AgentID = appV23TestID("replay-mismatched-value-id")
				value, err := appV23Marshal(agent)
				require.NoError(t, err)
				require.NoError(t, s.SetRawForTest(agentOnChainKey(target), value))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, err := NewBadgerStore(t.TempDir())
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
			appV23Register(t, s, "replay-roster-root-"+test.name, AppV23RoleAdmin, 1, 0)
			target := appV23Register(
				t, s, "replay-roster-target-"+test.name, AppV23RoleMember, 2, 0,
			)
			require.NoError(t, s.EnsureAppV23Root("replay-roster", 100))
			require.NoError(t, s.ValidateAppV23State())

			test.corrupt(t, s, target)
			require.Error(t, s.ValidateAppV23State(),
				"state-sync validation must reject raw roster corruption")
			require.Error(t, s.EnsureAppV23Root("replay-roster", 101),
				"activation replay must reject raw roster corruption")
		})
	}
}

func TestAppV23LegacyReadBaselinePreservesExplicitPolicyAndReadAllBypass(t *testing.T) {
	for _, test := range []struct {
		name   string
		policy string
		caps   AgentCapabilities
	}{
		{name: "explicit", policy: `[{"domain":"allowed","read":true}]`},
		{name: "empty is deny", policy: `[]`},
		{name: "malformed is deny", policy: `{`},
		{
			name:   "read all bypasses explicit empty",
			policy: `[]`, caps: AgentCapabilityReadAllDomains,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			s, err := NewBadgerStore(t.TempDir())
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
			root := appV23Register(t, s, "policy-root-"+test.name, AppV23RoleAdmin, 1, 0)
			id := appV23Register(t, s, "policy-reader-"+test.name, AppV23RoleMember, 2, test.caps)
			require.NoError(t, s.SetAgentPermissionWithCapabilities(
				id, 1, test.policy, `["visible-peer"]`, "", "", test.caps,
			))
			require.NoError(t, s.RegisterDomain("allowed", root, "", 3))
			require.NoError(t, s.RegisterDomain("denied", root, "", 4))
			require.NoError(t, s.EnsureAppV23Root("policy-"+test.name, 100))

			allowed, err := s.AppV23LegacyReadCompatibility(
				id, "allowed", 1, time.Unix(1000, 0),
			)
			require.NoError(t, err)
			denied, err := s.AppV23LegacyReadCompatibility(
				id, "denied", 1, time.Unix(1000, 0),
			)
			require.NoError(t, err)
			if test.caps.Has(AgentCapabilityReadAllDomains) {
				require.True(t, allowed.Allowed)
				require.True(t, denied.Allowed)
				require.False(t, denied.ExplicitDomainRestriction)
			} else if test.name == "explicit" {
				require.True(t, allowed.Allowed)
				require.False(t, denied.Allowed)
				require.True(t, denied.ExplicitDomainRestriction)
			} else {
				require.False(t, allowed.Allowed)
				require.True(t, allowed.ExplicitDomainRestriction)
			}

			visible, restricted, err := s.AppV23LegacyVisibleAgents(id)
			require.NoError(t, err)
			if test.caps.Has(AgentCapabilityReadAllDomains) {
				require.False(t, restricted)
			} else {
				require.True(t, restricted)
				require.Equal(t, `["visible-peer"]`, visible)
			}
			require.NoError(t, s.ValidateAppV23State())

			if test.name == "explicit" {
				enrollment, err := s.GetAppV23Enrollment(id)
				require.NoError(t, err)
				role, err := s.GetAppV23Role(id)
				require.NoError(t, err)
				require.NoError(t, s.SetAppV23Policy(
					root, id, AppV23RoleMember,
					enrollment.Profile, AppV23ProfileStandard,
					enrollment.Clearance, 0,
					role.Revision, enrollment.Revision, 101,
				))
				afterReview, err := s.AppV23LegacyReadCompatibility(
					id, "allowed", 1, time.Unix(1000, 0),
				)
				require.NoError(t, err)
				require.False(t, afterReview.Eligible,
					"the first explicit app-v23 policy review ends compatibility")
			}
		})
	}
}

func TestAppV23LegacyExplicitDomainPolicyUsesHigherLiveOrgClearance(t *testing.T) {
	s, openErr := NewBadgerStore(t.TempDir())
	require.NoError(t, openErr)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
	root := appV23Register(t, s, "explicit-org-root", AppV23RoleAdmin, 1, 0)
	reader := appV23Register(t, s, "explicit-org-reader", AppV23RoleMember, 2, 0)
	require.NoError(t, s.SetAgentPermissionWithCapabilities(
		reader, 1,
		`[{"domain":"combined-domain","read":true}]`,
		"", "", "", 0,
	))
	require.NoError(t, s.RegisterDomain("combined-domain", root, "", 3))
	require.NoError(t, s.RegisterOrg("combined-org", "Combined", "", root, 4))
	require.NoError(t, s.AddOrgMember("combined-org", root, 3, "member", 5))
	require.NoError(t, s.AddOrgMember("combined-org", reader, 3, "member", 6))
	require.NoError(t, s.EnsureAppV23Root("combined-explicit-org", 100))

	decision, err := s.AppV23LegacyReadCompatibility(
		reader, "combined-domain", 3, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.True(t, decision.ExplicitDomainRestriction)
	require.True(t, decision.Allowed,
		"explicit domain scope must combine with the higher immutable-and-live org clearance")

	require.NoError(t, s.RemoveOrgMember("combined-org", reader))
	decision, err = s.AppV23LegacyReadCompatibility(
		reader, "combined-domain", 3, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.False(t, decision.Allowed,
		"removing the live org membership must immediately remove the compatibility ceiling")

	decision, err = s.AppV23LegacyReadCompatibility(
		reader, "outside-domain", 1, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.False(t, decision.Allowed,
		"the higher org clearance must never widen beyond the explicit domain allowlist")
}

func TestAppV23LegacyOrgReadBaselineSurvivesRootHandoverAndOwnerReview(t *testing.T) {
	s, openErr := NewBadgerStore(t.TempDir())
	require.NoError(t, openErr)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
	root := appV23Register(t, s, "org-root", AppV23RoleAdmin, 1, 0)
	owner := appV23Register(t, s, "org-owner", AppV23RoleMember, 2, 0)
	reader := appV23Register(t, s, "org-reader", AppV23RoleMember, 3, 0)
	require.NoError(t, s.RegisterDomain("root-history", root, "", 4))
	require.NoError(t, s.RegisterDomain("reviewed-owner", owner, "", 5))
	require.NoError(t, s.RegisterOrg("org-a", "Org A", "", root, 6))
	for _, id := range []string{root, owner, reader} {
		require.NoError(t, s.AddOrgMember("org-a", id, 2, "member", 7))
	}
	require.NoError(t, s.EnsureAppV23Root("org-continuity", 100))
	require.NoError(t, s.view(func(txn *badger.Txn) error {
		for _, id := range []string{root, owner, reader} {
			var baseline AppV23LegacyReadBaseline
			require.NoError(t, appV23ReadJSON(txn, appV23LegacyReadKey(id), &baseline))
			require.Len(t, baseline.OrgMemberships, 1)
			require.Equal(t, "org-a", baseline.OrgMemberships[0].OrgID)
		}
		return nil
	}))
	liveAllowed, accessErr := s.HasAccessMultiOrgWithFederationPolicy(
		"root-history", reader, 2, time.Unix(1000, 0), true, true,
	)
	require.NoError(t, accessErr)
	require.True(t, liveAllowed)

	assertAllowed := func(domain string, want bool) {
		t.Helper()
		decision, err := s.AppV23LegacyReadCompatibility(
			reader, domain, 2, time.Unix(1000, 0),
		)
		require.NoError(t, err)
		require.True(t, decision.Eligible)
		require.Equal(t, want, decision.Allowed)
	}
	assertAllowed("root-history", true)
	assertAllowed("reviewed-owner", true)

	newRootCredential := appV23TestID("org-root-generation-two")
	require.NoError(t, s.RotateAppV23RootCredential(1, newRootCredential, 101))
	assertAllowed("root-history", true)

	ownerEnrollment, err := s.GetAppV23Enrollment(owner)
	require.NoError(t, err)
	ownerRole, err := s.GetAppV23Role(owner)
	require.NoError(t, err)
	require.NoError(t, s.SetAppV23Policy(
		newRootCredential, owner, AppV23RoleMember,
		ownerEnrollment.Profile, AppV23ProfileStandard,
		ownerEnrollment.Clearance, 0,
		ownerRole.Revision, ownerEnrollment.Revision, 102,
	))
	assertAllowed("reviewed-owner", true)

	require.NoError(t, s.RemoveOrgMember("org-a", reader))
	assertAllowed("root-history", false)
	require.NoError(t, s.ValidateAppV23State())
}

func TestAppV23LegacyFederationReadIsBaselineIntersectLive(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
	root := appV23Register(t, s, "fed-root", AppV23RoleAdmin, 1, 0)
	reader := appV23Register(t, s, "fed-reader", AppV23RoleMember, 2, 0)
	require.NoError(t, s.RegisterDomain("federated.allowed", root, "", 3))
	require.NoError(t, s.RegisterOrg("org-owner", "Owner", "", root, 4))
	require.NoError(t, s.RegisterOrg("org-reader", "Reader", "", reader, 5))
	require.NoError(t, s.AddOrgMember("org-owner", root, 3, "member", 6))
	require.NoError(t, s.AddOrgMember("org-reader", reader, 3, "member", 7))
	require.NoError(t, s.RegisterDept("org-reader", "research", "Research", "", "", 8))
	require.NoError(t, s.AddDeptMember("org-reader", "research", reader, 3, "member", 9))
	require.NoError(t, s.SetFederation(
		"fed-a", "org-reader", "org-owner",
		[]string{"federated"}, 3, 0, false, "active",
		[]string{"research"},
	))
	require.NoError(t, s.EnsureAppV23Root("federation-baseline", 100))

	decision, err := s.AppV23LegacyReadCompatibility(
		reader, "federated.allowed", 2, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.True(t, decision.Allowed)
	require.NoError(t, s.UpdateFederationStatus("fed-a", "revoked"))
	decision, err = s.AppV23LegacyReadCompatibility(
		reader, "federated.allowed", 2, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.False(t, decision.Allowed)
}

func TestAppV23MigrationHomeAllocatorSkipsStaticDynamicAndSuffixCollisions(t *testing.T) {
	id := appV23TestID("allocator")
	base := "local-" + id
	home, err := appV23AllocateMigrationHome(
		id,
		map[string][]string{id: {"general", base}},
		map[string]string{base + "-1": appV23TestID("other-owner")},
		map[string]string{base + "-2": appV23TestID("new-owner")},
		map[string]struct{}{base: {}, base + "-3": {}},
	)
	require.NoError(t, err)
	require.Equal(t, base+"-4", home)
}

func TestAppV23LegacyBitEightStillAllowsGrantedModifyOnly(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
	root := appV23Register(t, s, "bit8-root", AppV23RoleAdmin, 1, 0)
	reader := appV23Register(
		t, s, "bit8-reader", AppV23RoleMember, 2,
		AgentCapabilityDenyForeignDomainWrite,
	)
	require.NoError(t, s.RegisterDomain("bit8-foreign", root, "", 3))
	require.NoError(t, s.SetAccessGrant("bit8-foreign", reader, 3, 0, root))
	require.NoError(t, s.EnsureAppV23Root("bit8", 100))

	write, err := s.AuthorizeAppV23LocalDomain(
		reader, "bit8-foreign", AppV23VerbWrite, false,
	)
	require.NoError(t, err)
	require.True(t, write.ExplicitDeny)
	modify, err := s.AuthorizeAppV23LocalDomain(
		reader, "bit8-foreign", AppV23VerbModify, false,
	)
	require.NoError(t, err)
	require.False(t, modify.ExplicitDeny)
	hasModify, err := s.HasAppV23AccessOrAncestor(
		"bit8-foreign", reader, 3, time.Unix(1000, 0), false,
	)
	require.NoError(t, err)
	require.True(t, hasModify)
}

func TestAppV23ObserverPreservesFederatedPipeDenyBit(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
	appV23Register(t, s, "observer-pipe-root", AppV23RoleAdmin, 1, 0)
	observer := appV23Register(
		t, s, "observer-pipe", "observer", 2,
		AgentCapabilityDenyFederatedPipe,
	)
	require.NoError(t, s.EnsureAppV23Root("observer-pipe", 100))
	enrollment, err := s.GetAppV23Enrollment(observer)
	require.NoError(t, err)
	require.Equal(t,
		AgentCapabilityReadAllDomains|AgentCapabilityDenyFederatedPipe,
		enrollment.Capabilities,
	)
}

func TestAppV23LegacyBaselineCorruptionInvalidatesConsensusState(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
	appV23Register(t, s, "baseline-corrupt-root", AppV23RoleAdmin, 1, 0)
	reader := appV23Register(t, s, "baseline-corrupt-reader", AppV23RoleMember, 2, 0)
	require.NoError(t, s.EnsureAppV23Root("baseline-corrupt", 100))
	require.NoError(t, s.ValidateAppV23State())
	require.NoError(t, s.update(func(txn *badger.Txn) error {
		return s.txnSet(txn, appV23LegacyReadKey(reader), []byte(`{"agent_id":"wrong"}`))
	}))
	require.ErrorContains(t, s.ValidateAppV23State(), "legacy read baseline identity")
}

func TestAppV23LegacyBaselineAppHashChangesWithPolicyEvidence(t *testing.T) {
	build := func(t *testing.T, policy string) string {
		t.Helper()
		s, err := NewBadgerStore(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
		appV23Register(t, s, "hash-root", AppV23RoleAdmin, 1, 0)
		id := appV23Register(t, s, "hash-reader", AppV23RoleMember, 2, 0)
		require.NoError(t, s.SetAgentPermissionWithCapabilities(
			id, 1, policy, "", "", "", 0,
		))
		require.NoError(t, s.EnsureAppV23Root("hash", 100))
		hash, err := s.ComputeAppHashExcludingBookkeeping()
		require.NoError(t, err)
		return fmt.Sprintf("%x", hash)
	}
	require.NotEqual(t,
		build(t, `[{"domain":"one","read":true}]`),
		build(t, `[{"domain":"two","read":true}]`),
	)
}
