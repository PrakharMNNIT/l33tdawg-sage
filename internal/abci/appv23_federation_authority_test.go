package abci

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

func signedAppV23CrossFedSet(
	t *testing.T,
	signer agentKey,
	remote string,
	domains []string,
	nonce uint64,
) *tx.ParsedTx {
	t.Helper()
	parsed := crossFedSetTx(t, signer, termsFor(remote, domains))
	signAppV23Outer(t, parsed, signer, nonce)
	return parsed
}

func signedAppV23CrossFedRevoke(
	t *testing.T,
	signer agentKey,
	remote string,
	nonce uint64,
) *tx.ParsedTx {
	t.Helper()
	parsed := crossFedRevokeTx(t, signer, remote, "app-v23 authority test")
	signAppV23Outer(t, parsed, signer, nonce)
	return parsed
}

func TestAppV23CrossFedControlRequiresCurrentRootOrElevatedAdmin(t *testing.T) {
	app := setupTestApp(t)
	app.appV15AppliedHeight = 1
	root := newAgentKey(t)
	admin := newAgentKey(t)
	member := newAgentKey(t)
	registerAppV23Agent(t, app, root, store.AppV23RoleAdmin, 1, 0)
	registerAppV23Agent(t, app, admin, store.AppV23RoleAdmin, 2, 0)
	registerAppV23Agent(t, app, member, store.AppV23RoleMember, 3, 0)
	require.NoError(t, app.badgerStore.EnsureAppV23Root("federation-control-scope", 10))
	promoteAppV23TestAdmin(t, app, root, admin, 10)
	app.appV23AppliedHeight = 10

	memberEnrollment, err := app.badgerStore.GetAppV23Enrollment(member.id)
	require.NoError(t, err)
	require.NotEmpty(t, memberEnrollment.HomeDomain)
	memberSet := signedAppV23CrossFedSet(
		t, member, "peer-member-owned", []string{memberEnrollment.HomeDomain}, 1,
	)
	memberResult := app.processTx(memberSet, 11, appV23BlockTime())
	require.Equal(t, uint32(106), memberResult.Code, memberResult.Log)
	require.Contains(t, memberResult.Log, "not authorized")

	adminSet := crossFedSetTx(t, admin, termsFor("peer-admin", []string{"*"}))
	signAppV23Outer(t, adminSet, admin, 2)
	adminWithoutElevation := app.processTx(adminSet, 11, appV23BlockTime())
	require.Equal(t, uint32(110), adminWithoutElevation.Code, adminWithoutElevation.Log)

	adminSet = crossFedSetTx(t, admin, termsFor("peer-admin", []string{"*"}))
	attachAppV23Elevation(
		t, adminSet, root, admin, "federation-control-scope",
		"fed_admin_set_0001", 11,
	)
	signAppV23Outer(t, adminSet, admin, 3)
	adminWithElevation := app.processTx(adminSet, 11, appV23BlockTime())
	require.Zero(t, adminWithElevation.Code, adminWithElevation.Log)

	currentRootSet := signedAppV23CrossFedSet(
		t, root, "peer-current-root", []string{"*"}, 4,
	)
	currentRootResult := app.processTx(currentRootSet, 12, appV23BlockTime())
	require.Zero(t, currentRootResult.Code, currentRootResult.Log)

	replacementRoot := newAgentKey(t)
	require.NoError(t, app.badgerStore.RotateAppV23RootCredential(1, replacementRoot.id, 13))

	retiredRootSet := signedAppV23CrossFedSet(
		t, root, "peer-retired-root", []string{"*"}, 5,
	)
	retiredRootResult := app.processTx(retiredRootSet, 14, appV23BlockTime())
	require.Equal(t, uint32(110), retiredRootResult.Code, retiredRootResult.Log)

	replacementSet := signedAppV23CrossFedSet(
		t, replacementRoot, "peer-replacement-root", []string{"*"}, 6,
	)
	replacementResult := app.processTx(replacementSet, 14, appV23BlockTime())
	require.Zero(t, replacementResult.Code, replacementResult.Log)

	retiredRevoke := signedAppV23CrossFedRevoke(
		t, root, "peer-replacement-root", 7,
	)
	retiredRevokeResult := app.processTx(retiredRevoke, 15, appV23BlockTime())
	require.Equal(t, uint32(110), retiredRevokeResult.Code, retiredRevokeResult.Log)

	replacementRevoke := signedAppV23CrossFedRevoke(
		t, replacementRoot, "peer-replacement-root", 8,
	)
	replacementRevokeResult := app.processTx(replacementRevoke, 15, appV23BlockTime())
	require.Zero(t, replacementRevokeResult.Code, replacementRevokeResult.Log)
}
