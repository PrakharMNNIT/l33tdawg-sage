package rest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/store"
)

func TestAppV23MigratedLegacyMasksPreserveRESTReadSharedAndFederatedAuthority(t *testing.T) {
	srv, _, badger, _ := newRBACTestServer(t)
	srv.SetPostV22ForNextTxAccessor(func() bool { return true })
	srv.SetPostV23ForNextTxAccessor(func() bool { return true })

	rootID := fmt.Sprintf("%064x", 1)
	require.NoError(t, badger.RegisterAgentWithCapabilities(
		rootID, "legacy-root", store.AppV23RoleAdmin, "", "test", "", 1, 0,
	))
	require.NoError(t, badger.RegisterDomain("legacy-foreign-owned", rootID, "", 2))

	ids := make(map[store.AgentCapabilities]string, 32)
	for mask := store.AgentCapabilities(0); mask <= store.KnownAgentCapabilities; mask++ {
		id := fmt.Sprintf("%064x", uint64(mask)+100)
		ids[mask] = id
		require.NoError(t, badger.RegisterAgentWithCapabilities(
			id, fmt.Sprintf("legacy-mask-%02d", mask),
			store.AppV23RoleMember, "", "test", "", int64(mask)+3, mask,
		))
	}
	require.NoError(t, badger.EnsureAppV23Root("rest-legacy-mask-matrix", 100))
	require.NoError(t, badger.ValidateAppV23State())

	for mask := store.AgentCapabilities(0); mask <= store.KnownAgentCapabilities; mask++ {
		mask := mask
		t.Run(fmt.Sprintf("mask_%02d", mask), func(t *testing.T) {
			id := ids[mask]
			enrollment, err := badger.GetAppV23Enrollment(id)
			require.NoError(t, err)
			active := enrollment.Active

			sharedWriteErr := checkAppV23DomainAccess(
				badger, id, "general", "write",
			)
			require.Equal(t,
				active && !mask.Has(store.AgentCapabilityDenySharedDomainWrite),
				sharedWriteErr == nil,
				"REST preflight must preserve the migrated shared memory-submit path",
			)
			require.Error(t, checkAppV23DomainAccess(
				badger, id, "general", "modify",
			), "shared memory-submit grandfathering must not imply level-3 modify")

			wantReadAll := active &&
				mask.Has(store.AgentCapabilityReadAllDomains)
			readAllowed, err := srv.hasMemoryReadAccess(
				"legacy-foreign-owned", id, 1, time.Unix(1_700_000_000, 0),
			)
			require.NoError(t, err)
			require.Equal(t, wantReadAll, readAllowed,
				"ReadAllDomains must cover a foreign-owned domain")

			aboveClearance, err := srv.hasMemoryReadAccess(
				"legacy-foreign-owned", id, 2, time.Unix(1_700_000_000, 0),
			)
			require.NoError(t, err)
			require.False(t, aboveClearance,
				"ReadAllDomains must remain classification bounded")

			_, seeAll := srv.resolveVisibleAgents(id)
			require.Equal(t, active, seeAll,
				"app-v23 submitter filtering is domain-derived for every active principal")

			federatedRead, clearance := srv.federationCallerCanRead(
				context.Background(), id, "legacy-foreign-owned",
			)
			require.Equal(t, wantReadAll, federatedRead)
			wantClearance := 0
			if active {
				wantClearance = int(enrollment.Clearance)
			}
			require.Equal(t, wantClearance, clearance)

			require.Equal(t,
				active && !mask.Has(store.AgentCapabilityDenyFederatedPipe),
				srv.callerMayUseFederatedPipe(id),
				"DenyFederatedPipe must preserve recipient/contact eligibility exactly",
			)
		})
	}
}
