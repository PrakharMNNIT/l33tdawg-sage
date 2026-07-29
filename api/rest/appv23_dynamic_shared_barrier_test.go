package rest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAppV23RESTReadDoesNotCrossDynamicSharedDomainBarrier(t *testing.T) {
	srv, badger, _, ownerID, outsiderID := setupAppV23RESTAccess(t)

	require.NoError(t, badger.SetSharedDomain("owner.home.open"))
	require.NoError(t, badger.SetAccessGrant("owner.home", outsiderID, 1, 0, ownerID))

	require.NoError(t, srv.checkDomainAccess(
		context.Background(), outsiderID, "owner.home.private", "read",
	), "ordinary descendant still inherits its explicit ancestor grant")

	require.Error(t, srv.checkDomainAccess(
		context.Background(), outsiderID, "owner.home.open.notes", "read",
	), "REST read preflight must use the app-v23 dynamic shared barrier")

	allowed, err := srv.hasMemoryReadAccess(
		"owner.home.open.notes", outsiderID, 0, time.Unix(1_700_000_000, 0),
	)
	require.NoError(t, err)
	require.False(t, allowed,
		"record-level recall must not reopen the denial through the legacy org/grant evaluator")
}
