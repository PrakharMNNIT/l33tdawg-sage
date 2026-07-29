package rest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/store"
)

func TestAppV23LegacyReadCompatibilityIsLocalOnlyAndRestrictive(t *testing.T) {
	srv, _, badger, _ := newRBACTestServer(t)
	srv.SetPostV22ForNextTxAccessor(func() bool { return true })
	srv.SetPostV23ForNextTxAccessor(func() bool { return true })

	root := fmt.Sprintf("%064x", 9001)
	reader := fmt.Sprintf("%064x", 9002)
	visible := fmt.Sprintf("%064x", 9003)
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		root, "root", store.AppV23RoleAdmin, "", "", "", 1, 0,
	))
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		reader, "reader", store.AppV23RoleMember, "", "", "", 2, 0,
	))
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		visible, "visible", store.AppV23RoleMember, "", "", "", 3, 0,
	))
	require.NoError(t, badger.SetAgentPermissionWithCapabilities(
		reader, 1,
		`[{"domain":"legacy-allowed","read":true}]`,
		`["`+visible+`"]`, "", "", 0,
	))
	require.NoError(t, badger.RegisterDomain("legacy-allowed", root, "", 4))
	require.NoError(t, badger.RegisterDomain("legacy-denied", root, "", 5))
	require.NoError(t, badger.EnsureAppV23Root("rest-legacy-read", 100))

	require.Error(t, checkAppV23DomainAccess(
		badger, reader, "legacy-allowed", "read",
	), "the generic/federated app-v23 resolver must not receive migration widening")
	require.NoError(t, srv.checkDomainAccess(
		context.Background(), reader, "legacy-allowed", "read",
	))
	allowed, err := srv.hasMemoryReadAccess(
		"legacy-allowed", reader, 1, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.True(t, allowed)

	require.NoError(t, badger.SetAccessGrant(
		"legacy-denied", reader, 1, 0, root,
	))
	require.Error(t, srv.checkDomainAccess(
		context.Background(), reader, "legacy-denied", "read",
	), "an immutable explicit legacy allowlist remains a restriction")
	allowed, err = srv.hasMemoryReadAccess(
		"legacy-denied", reader, 1, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.False(t, allowed)

	federated, clearance := srv.federationCallerCanRead(
		context.Background(), reader, "legacy-allowed",
	)
	require.False(t, federated)
	require.Equal(t, 1, clearance)

	agents, seeAll := srv.resolveVisibleAgents(reader)
	require.False(t, seeAll)
	require.ElementsMatch(t, []string{reader, visible}, agents)
	require.True(t, srv.appV23LegacyVisibilityRestricted(reader))
}

func TestAppV23LegacyOrgMembershipClearanceSurvivesLocalRESTOnly(t *testing.T) {
	srv, _, badger, _ := newRBACTestServer(t)
	srv.SetPostV22ForNextTxAccessor(func() bool { return true })
	srv.SetPostV23ForNextTxAccessor(func() bool { return true })

	root := fmt.Sprintf("%064x", 9101)
	reader := fmt.Sprintf("%064x", 9102)
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		root, "root", store.AppV23RoleAdmin, "", "", "", 1, 0,
	))
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		reader, "reader", store.AppV23RoleMember, "", "", "", 2, 0,
	))
	require.NoError(t, badger.RegisterDomain("org-domain", root, "", 3))
	require.NoError(t, badger.RegisterOrg("org-local", "Local", "", root, 4))
	require.NoError(t, badger.AddOrgMember("org-local", root, 3, "member", 5))
	require.NoError(t, badger.AddOrgMember("org-local", reader, 3, "member", 6))
	require.NoError(t, badger.EnsureAppV23Root("rest-legacy-org", 100))

	allowed, err := srv.hasMemoryReadAccess(
		"org-domain", reader, 3, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.True(t, allowed,
		"legacy membership clearance, not the lower global slot, is authoritative")
	allowed, err = srv.hasMemoryReadAccess(
		"org-domain", reader, 4, time.Unix(1000, 0),
	)
	require.NoError(t, err)
	require.False(t, allowed)

	federated, _ := srv.federationCallerCanRead(
		context.Background(), reader, "org-domain",
	)
	require.False(t, federated,
		"the local migration envelope must not widen a federated caller")
}
