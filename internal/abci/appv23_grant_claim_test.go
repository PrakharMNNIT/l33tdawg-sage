package abci

import (
	"context"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/authzdenial"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

func TestAppV23AccessRevokeRejectsGrantKeyComponentInjection(t *testing.T) {
	app := setupTestApp(t)
	activateV8(t, app, 1)
	root := newAgentKey(t)
	attacker := newAgentKey(t)
	victim := newAgentKey(t)
	registerAppV23Agent(t, app, root, store.AppV23RoleAdmin, 1, 0)
	registerAppV23Agent(t, app, attacker, store.AppV23RoleMember, 2, 0)
	registerAppV23Agent(t, app, victim, store.AppV23RoleMember, 3, 0)

	// Seed the pre-v23 state that makes the historical delimiter collision
	// observable: grant("foo:bar", victim) and revoke("foo", "bar:"+victim)
	// address the same raw Badger key.
	const victimDomain = "foo:bar"
	require.NoError(t, app.badgerStore.RegisterDomain("foo", attacker.id, "", 4))
	require.NoError(t, app.badgerStore.RegisterDomain(victimDomain, root.id, "", 5))
	require.NoError(t, app.badgerStore.SetAccessGrant(
		victimDomain, victim.id, 2, 0, root.id,
	))
	require.NoError(t, app.offchainStore.InsertAccessGrant(
		context.Background(),
		&store.AccessGrantEntry{
			Domain: victimDomain, GranteeID: victim.id, GranterID: root.id,
			Level: 2, CreatedHeight: 5, CreatedAt: appV23BlockTime(),
		},
	))

	require.NoError(t, app.badgerStore.EnsureAppV23Root("revoke-key-injection", 10))
	app.appV20AppliedHeight = 1
	app.appV23AppliedHeight = 10
	app.state.Height = 10

	parsed := makeAccessRevokeTx(t, attacker, "bar:"+victim.id, "foo")
	signAppV23Outer(t, parsed, attacker, 1)
	raw, err := tx.EncodeTx(parsed)
	require.NoError(t, err)
	response, err := app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{
		Height: 11,
		Time:   appV23BlockTime(),
		Txs:    [][]byte{raw},
	})
	require.NoError(t, err)
	require.Len(t, response.TxResults, 1)
	require.NotZero(t, response.TxResults[0].Code, response.TxResults[0].Log)
	require.Contains(t, response.TxResults[0].Log, "invalid revoke grantee")
	require.NotNil(t, app.pendingAppV20Finalize)
	require.Empty(t, app.pendingAppV20Finalize.app.pendingWrites)
	_, err = app.Commit(context.Background(), &abcitypes.RequestCommit{})
	require.NoError(t, err)

	hasVictimGrant, err := app.badgerStore.HasAccess(
		victimDomain, victim.id, 2, time.Unix(appV23BlockTime().Unix(), 0),
	)
	require.NoError(t, err)
	require.True(t, hasVictimGrant, "rejected alias revoke must preserve Badger grant")
	mirrorGrants, err := app.offchainStore.GetActiveGrants(context.Background(), victim.id)
	require.NoError(t, err)
	require.Len(t, mirrorGrants, 1)
	require.Equal(t, victimDomain, mirrorGrants[0].Domain,
		"rejected alias revoke must preserve mirrored grant")
}

func TestAppV23AccessRevokeRejectsMalformedKeyComponentsBeforeMutation(t *testing.T) {
	cases := []struct {
		name      string
		domain    string
		granteeID func(agentKey) string
	}{
		{
			name:      "empty domain",
			granteeID: func(key agentKey) string { return key.id },
		},
		{
			name: "delimiter domain", domain: "safe:alias",
			granteeID: func(key agentKey) string { return key.id },
		},
		{
			name: "empty dotted segment", domain: "safe..alias",
			granteeID: func(key agentKey) string { return key.id },
		},
		{
			name: "whitespace domain", domain: "safe alias",
			granteeID: func(key agentKey) string { return key.id },
		},
		{
			name: "empty grantee", domain: "safe-revoke",
			granteeID: func(agentKey) string { return "" },
		},
		{
			name: "malformed grantee", domain: "safe-revoke",
			granteeID: func(agentKey) string { return "not-a-canonical-agent-id" },
		},
		{
			name: "delimiter grantee", domain: "safe-revoke",
			granteeID: func(key agentKey) string { return "prefix:" + key.id },
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			app := setupTestApp(t)
			activateV8(t, app, 1)
			root := newAgentKey(t)
			owner := newAgentKey(t)
			victim := newAgentKey(t)
			registerAppV23Agent(t, app, root, store.AppV23RoleAdmin, 1, 0)
			registerAppV23Agent(t, app, owner, store.AppV23RoleMember, 2, 0)
			registerAppV23Agent(t, app, victim, store.AppV23RoleMember, 3, 0)
			require.NoError(t, app.badgerStore.RegisterDomain("safe-revoke", owner.id, "", 4))
			require.NoError(t, app.badgerStore.SetAccessGrant(
				"safe-revoke", victim.id, 2, 0, owner.id,
			))
			require.NoError(t, app.badgerStore.EnsureAppV23Root("invalid-revoke", 10))
			app.appV20AppliedHeight = 1
			app.appV23AppliedHeight = 10
			app.state.Height = 10

			parsed := makeAccessRevokeTx(
				t, owner, test.granteeID(victim), test.domain,
			)
			signAppV23Outer(t, parsed, owner, 1)
			raw, err := tx.EncodeTx(parsed)
			require.NoError(t, err)
			response, err := app.FinalizeBlock(
				context.Background(),
				&abcitypes.RequestFinalizeBlock{
					Height: 11, Time: appV23BlockTime(), Txs: [][]byte{raw},
				},
			)
			require.NoError(t, err)
			require.Len(t, response.TxResults, 1)
			require.NotZero(t, response.TxResults[0].Code, response.TxResults[0].Log)
			require.NotNil(t, app.pendingAppV20Finalize)
			require.Empty(t, app.pendingAppV20Finalize.app.pendingWrites)
			_, err = app.Commit(context.Background(), &abcitypes.RequestCommit{})
			require.NoError(t, err)

			level, _, _, err := app.badgerStore.GetAccessGrant(
				"safe-revoke", victim.id,
			)
			require.NoError(t, err)
			require.Equal(t, uint8(2), level)
		})
	}
}

func TestAppV23DomainReassignPurgesOnlyExactLegacyGrantDomain(t *testing.T) {
	app := setupTestApp(t)
	activateV8(t, app, 1)
	root := newAgentKey(t)
	owner := newAgentKey(t)
	newOwner := newAgentKey(t)
	parentGrantee := newAgentKey(t)
	childGrantee := newAgentKey(t)
	registerAppV23Agent(t, app, root, store.AppV23RoleAdmin, 1, 0)
	registerAppV23Agent(t, app, owner, store.AppV23RoleMember, 2, 0)
	registerAppV23Agent(t, app, newOwner, store.AppV23RoleMember, 3, 0)
	registerAppV23Agent(t, app, parentGrantee, store.AppV23RoleMember, 4, 0)
	registerAppV23Agent(t, app, childGrantee, store.AppV23RoleMember, 5, 0)

	require.NoError(t, app.badgerStore.RegisterDomain("aaa-owner-home", owner.id, "", 6))
	require.NoError(t, app.badgerStore.RegisterDomain("foo", owner.id, "", 7))
	require.NoError(t, app.badgerStore.RegisterDomain("foo:bar", owner.id, "", 8))
	require.NoError(t, app.badgerStore.SetAccessGrant(
		"foo", parentGrantee.id, 2, 0, owner.id,
	))
	require.NoError(t, app.badgerStore.SetAccessGrant(
		"foo:bar", childGrantee.id, 2, 0, owner.id,
	))
	require.NoError(t, app.badgerStore.EnsureAppV23Root("exact-reassign-purge", 10))
	app.appV20AppliedHeight = 1
	app.appV23AppliedHeight = 10

	body := tx.DomainReassign{Domain: "foo", NewOwnerID: newOwner.id}
	body.ProposalID = seedExecutedReassignProposal(t, app, root.id, body, 11)
	result := app.processDomainReassign(
		makeDomainReassignTx(t, root, &body, 1),
		12,
		appV23BlockTime(),
	)
	require.Zero(t, result.Code, result.Log)

	ownerAfter, err := app.badgerStore.GetDomainOwner("foo")
	require.NoError(t, err)
	require.Equal(t, newOwner.id, ownerAfter)
	parentAccess, err := app.badgerStore.HasAccess(
		"foo", parentGrantee.id, 2, appV23BlockTime(),
	)
	require.NoError(t, err)
	require.False(t, parentAccess)
	childAccess, err := app.badgerStore.HasAccess(
		"foo:bar", childGrantee.id, 2, appV23BlockTime(),
	)
	require.NoError(t, err)
	require.True(t, childAccess,
		"reassigning foo must not purge preserved legacy grants on foo:bar")
}

func TestAppV23InvalidGrantCannotPartiallyClaimOwnerlessDomain(t *testing.T) {
	blockTime := appV23BlockTime()
	cases := []struct {
		name      string
		domain    string
		grantee   func(agentKey) string
		level     uint8
		expiresAt int64
	}{
		{
			name: "level zero", domain: "invalid-level-zero",
			grantee: func(key agentKey) string { return key.id },
		},
		{
			name: "level four", domain: "invalid-level-four",
			grantee: func(key agentKey) string { return key.id }, level: 4,
		},
		{
			name: "empty grantee", domain: "invalid-empty-grantee",
			grantee: func(agentKey) string { return "" }, level: 1,
		},
		{
			name: "malformed grantee", domain: "invalid-malformed-grantee",
			grantee: func(agentKey) string { return "not-a-canonical-agent-id" }, level: 1,
		},
		{
			name:    "empty domain",
			grantee: func(key agentKey) string { return key.id }, level: 1,
		},
		{
			name: "delimiter domain", domain: "invalid:alias",
			grantee: func(key agentKey) string { return key.id }, level: 1,
		},
		{
			name: "empty dotted segment", domain: "invalid..alias",
			grantee: func(key agentKey) string { return key.id }, level: 1,
		},
		{
			name: "whitespace domain", domain: "invalid alias",
			grantee: func(key agentKey) string { return key.id }, level: 1,
		},
		{
			name: "negative expiry", domain: "invalid-negative-expiry",
			grantee: func(key agentKey) string { return key.id }, level: 1, expiresAt: -1,
		},
		{
			name: "non-future expiry", domain: "invalid-stale-expiry",
			grantee: func(key agentKey) string { return key.id }, level: 1, expiresAt: blockTime.Unix(),
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			app := setupTestApp(t)
			activateV8(t, app, 1)
			root := newAgentKey(t)
			registeredGrantee := newAgentKey(t)
			registerAppV23Agent(t, app, root, store.AppV23RoleAdmin, 1, 0)
			registerAppV23Agent(t, app, registeredGrantee, store.AppV23RoleMember, 2, 0)
			require.NoError(t, app.badgerStore.EnsureAppV23Root("invalid-grant-claim", 10))
			app.appV20AppliedHeight = 1
			app.appV23AppliedHeight = 10
			app.state.Height = 10

			granteeID := test.grantee(registeredGrantee)
			parsed := makeAccessGrantTx(t, root, granteeID, test.domain, test.level)
			parsed.AccessGrant.ExpiresAt = test.expiresAt
			signAppV23Outer(t, parsed, root, 1)
			raw, err := tx.EncodeTx(parsed)
			require.NoError(t, err)

			response, err := app.FinalizeBlock(context.Background(), &abcitypes.RequestFinalizeBlock{
				Height: 11,
				Time:   blockTime,
				Txs:    [][]byte{raw},
			})
			require.NoError(t, err)
			require.Len(t, response.TxResults, 1)
			require.NotZero(t, response.TxResults[0].Code, response.TxResults[0].Log)
			require.NotNil(t, app.pendingAppV20Finalize)
			require.Empty(t, app.pendingAppV20Finalize.app.pendingWrites,
				"invalid grant must not stage projection writes")

			_, err = app.Commit(context.Background(), &abcitypes.RequestCommit{})
			require.NoError(t, err)
			require.Empty(t, app.pendingWrites)

			_, err = app.badgerStore.GetDomainOwner(test.domain)
			require.Error(t, err, "invalid grant must not claim a domain")
			_, _, _, err = app.badgerStore.GetAccessGrant(test.domain, root.id)
			require.Error(t, err,
				"invalid grant must not create an owner self-grant")
			_, _, _, err = app.badgerStore.GetAccessGrant(test.domain, granteeID)
			require.Error(t, err,
				"invalid grant must not create a grantee grant")

			_, err = app.offchainStore.GetDomain(context.Background(), test.domain)
			require.Error(t, err, "invalid grant must not create a mirrored domain")
			for _, agentID := range []string{root.id, granteeID} {
				grants, listErr := app.offchainStore.GetActiveGrants(context.Background(), agentID)
				require.NoError(t, listErr)
				require.Empty(t, grants, "invalid grant must not create mirrored grants")
			}
		})
	}
}

func TestAppV23ManagerGrantControlOwnOwnerlessAndForeign(t *testing.T) {
	app := setupTestApp(t)
	activateV8(t, app, 1)
	root := newAgentKey(t)
	manager := newAgentKey(t)
	grantee := newAgentKey(t)
	registerAppV23Agent(t, app, root, store.AppV23RoleAdmin, 1, 0)
	registerAppV23Agent(t, app, manager, store.AppV23RoleMember, 2, 0)
	registerAppV23Agent(t, app, grantee, store.AppV23RoleMember, 3, 0)
	require.NoError(t, app.badgerStore.RegisterDomain("root-foreign", root.id, "", 4))
	require.NoError(t, app.badgerStore.EnsureAppV23Root("manager-grant", 10))
	app.appV23AppliedHeight = 10

	enrollment, err := app.badgerStore.GetAppV23Enrollment(manager.id)
	require.NoError(t, err)
	role, err := app.badgerStore.GetAppV23Role(manager.id)
	require.NoError(t, err)
	require.NoError(t, app.badgerStore.SetAppV23Policy(
		root.id, manager.id, store.AppV23RoleManager,
		enrollment.Profile, store.AppV23ProfileStandard,
		enrollment.Clearance, 0,
		role.Revision, enrollment.Revision, 11,
	))

	outcome, code, err := app.appV23GrantControlDecision(
		manager.id, enrollment.HomeDomain,
	)
	require.NoError(t, err)
	require.Equal(t, appV23GrantControlAllowed, outcome)
	require.Empty(t, code)

	const claimed = "manager-claimed"
	outcome, code, err = app.appV23GrantControlDecision(manager.id, claimed)
	require.NoError(t, err)
	require.Equal(t, appV23GrantControlClaimAndAllow, outcome)
	require.Empty(t, code)
	result := app.processAccessGrant(
		makeAccessGrantTx(t, manager, grantee.id, claimed, 2),
		12, appV23BlockTime(),
	)
	require.Zero(t, result.Code, result.Log)
	owner, err := app.badgerStore.GetDomainOwner(claimed)
	require.NoError(t, err)
	require.Equal(t, manager.id, owner)
	level, _, granter, err := app.badgerStore.GetAccessGrant(claimed, grantee.id)
	require.NoError(t, err)
	require.Equal(t, uint8(2), level)
	require.Equal(t, manager.id, granter)

	outcome, code, err = app.appV23GrantControlDecision(
		manager.id, "root-foreign",
	)
	require.NoError(t, err)
	require.Equal(t, appV23GrantControlDenied, outcome)
	require.Equal(t, authzdenial.CodeManagerScopeDenied, code)
}

func TestAppV23AdminOwnerlessGrantUsesAtomicClaimPath(t *testing.T) {
	app := setupTestApp(t)
	activateV8(t, app, 1)
	root := newAgentKey(t)
	grantee := newAgentKey(t)
	registerAppV23Agent(t, app, root, store.AppV23RoleAdmin, 1, 0)
	registerAppV23Agent(t, app, grantee, store.AppV23RoleMember, 2, 0)
	require.NoError(t, app.badgerStore.EnsureAppV23Root("admin-grant", 10))
	app.appV23AppliedHeight = 10

	const claimed = "admin-claimed"
	outcome, code, err := app.appV23GrantControlDecision(root.id, claimed)
	require.NoError(t, err)
	require.Equal(t, appV23GrantControlClaimAndAllow, outcome)
	require.Empty(t, code)
	result := app.processAccessGrant(
		makeAccessGrantTx(t, root, grantee.id, claimed, 1),
		11, appV23BlockTime(),
	)
	require.Zero(t, result.Code, result.Log)
	owner, err := app.badgerStore.GetDomainOwner(claimed)
	require.NoError(t, err)
	require.Equal(t, root.id, owner)
}

func TestAppV23LegacyBitEightDeniesWriteButNotGrantedModify(t *testing.T) {
	app := setupTestApp(t)
	root := newAgentKey(t)
	legacy := newAgentKey(t)
	registerAppV23Agent(t, app, root, store.AppV23RoleAdmin, 1, 0)
	registerAppV23Agent(
		t, app, legacy, store.AppV23RoleMember, 2,
		store.AgentCapabilityDenyForeignDomainWrite,
	)
	require.NoError(t, app.badgerStore.RegisterDomain("bit8-foreign", root.id, "", 3))
	require.NoError(t, app.badgerStore.SetAccessGrant(
		"bit8-foreign", legacy.id, 3, 0, root.id,
	))
	require.NoError(t, app.badgerStore.EnsureAppV23Root("bit8-decision", 10))
	app.appV23AppliedHeight = 10

	writeAllowed, writeCode, err := app.appV23DomainDecision(
		&tx.ParsedTx{}, legacy.id, "bit8-foreign", store.AppV23VerbWrite,
		11, appV23BlockTime(),
	)
	require.NoError(t, err)
	require.False(t, writeAllowed)
	require.Equal(t, authzdenial.CodeForeignWriteRestricted, writeCode)

	modifyAllowed, modifyCode, err := app.appV23DomainDecision(
		&tx.ParsedTx{}, legacy.id, "bit8-foreign", store.AppV23VerbModify,
		11, appV23BlockTime(),
	)
	require.NoError(t, err)
	require.True(t, modifyAllowed)
	require.Empty(t, modifyCode)
}
