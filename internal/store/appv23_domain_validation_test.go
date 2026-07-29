package store

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateAppV23DomainName(t *testing.T) {
	for _, valid := range []string{
		"technical/hardware",
		"singsearch-web-prototype",
		"research.eurorack",
		"voice_interface",
		"研发.笔记",
	} {
		t.Run("valid_"+valid, func(t *testing.T) {
			require.NoError(t, ValidateAppV23DomainName(valid))
		})
	}
	for _, invalid := range []string{
		"",
		".leading",
		"trailing.",
		"doubled..segment",
		"grant:alias",
		"has space",
		"has\ttab",
		"has\nnewline",
		strings.Repeat("a", appV23MaxDomainNameBytes+1),
		string([]byte{0xff}),
	} {
		t.Run("invalid", func(t *testing.T) {
			require.Error(t, ValidateAppV23DomainName(invalid))
		})
	}
}

func TestAppV23StoreMutationBoundariesRejectAmbiguousDomainComponents(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	root := appV23Register(t, s, "domain-validator-root", AppV23RoleAdmin, 1, 0)
	owner := appV23Register(t, s, "domain-validator-owner", AppV23RoleMember, 2, 0)
	target := appV23Register(t, s, "domain-validator-target", AppV23RoleMember, 3, 0)
	require.NoError(t, s.RegisterDomain("safe", owner, "", 4))
	require.NoError(t, s.RegisterDomain("safe:legacy", owner, "", 5))
	require.NoError(t, s.EnsureAppV23Root("domain-validator", 10))

	require.Error(t, s.SetAccessGrant("safe:legacy", target, 2, 0, root))
	require.Error(t, s.SetAccessGrant("safe", "prefix:"+target, 2, 0, root))
	require.Error(t, s.DeleteAccessGrant("safe", "prefix:"+target))
	require.Error(t, s.RegisterDomain("new:alias", owner, "", 11))
	require.Error(t, s.TransferDomainAppV23("safe:legacy", target, "", 11, false))
	require.Error(t, s.TransferDomain("safe:legacy", target, "", 11))
	require.Error(t, s.SetSharedDomain("safe:legacy"))

	currentOwner, err := s.GetDomainOwner("safe:legacy")
	require.NoError(t, err)
	require.Equal(t, owner, currentOwner)
}

func TestAppV23ExactDomainGrantPurgePreservesLegacyDelimitedChild(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	appV23Register(t, s, "grant-purge-root", AppV23RoleAdmin, 1, 0)
	owner := appV23Register(t, s, "grant-purge-owner", AppV23RoleMember, 2, 0)
	parentGrantee := appV23Register(t, s, "grant-purge-parent", AppV23RoleMember, 3, 0)
	childGrantee := appV23Register(t, s, "grant-purge-child", AppV23RoleMember, 4, 0)
	require.NoError(t, s.RegisterDomain("foo", owner, "", 5))
	require.NoError(t, s.RegisterDomain("foo:bar", owner, "", 6))
	require.NoError(t, s.SetAccessGrant("foo", parentGrantee, 2, 0, owner))
	require.NoError(t, s.SetAccessGrant("foo:bar", childGrantee, 2, 0, owner))
	require.NoError(t, s.EnsureAppV23Root("grant-purge-exact-domain", 10))

	count, exceeded, err := s.CountGrantsByDomainUpTo("foo", 256)
	require.NoError(t, err)
	require.False(t, exceeded)
	require.Equal(t, 1, count,
		"app-v23 preflight must not count a preserved legacy child key")
	purged, err := s.DeleteGrantsByDomain("foo")
	require.NoError(t, err)
	require.Equal(t, 1, purged)

	parentAccess, err := s.HasAccess("foo", parentGrantee, 2, time.Unix(1_000, 0))
	require.NoError(t, err)
	require.False(t, parentAccess)
	childAccess, err := s.HasAccess("foo:bar", childGrantee, 2, time.Unix(1_000, 0))
	require.NoError(t, err)
	require.True(t, childAccess,
		"exact-domain purge must preserve a legacy delimiter-bearing child grant")
}

func TestAppV23MigrationDoesNotBindHomeAuthorityToAmbiguousLegacyDomain(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })

	appV23Register(t, s, "invalid-home-root", AppV23RoleAdmin, 1, 0)
	member := appV23Register(t, s, "invalid-home-member", AppV23RoleMember, 2, 0)
	require.NoError(t, s.RegisterDomain("legacy:ambiguous", member, "", 3))
	require.NoError(t, s.EnsureAppV23Root("invalid-home-migration", 10))

	enrollment, err := s.GetAppV23Enrollment(member)
	require.NoError(t, err)
	require.NotEmpty(t, enrollment.HomeDomain)
	require.NotEqual(t, "legacy:ambiguous", enrollment.HomeDomain)
	require.NoError(t, ValidateAppV23DomainName(enrollment.HomeDomain))
	owner, err := s.GetDomainOwner("legacy:ambiguous")
	require.NoError(t, err)
	require.Equal(t, member, owner,
		"migration preserves historical ownership instead of rewriting chain history")
	require.NoError(t, s.ValidateAppV23State())
}
