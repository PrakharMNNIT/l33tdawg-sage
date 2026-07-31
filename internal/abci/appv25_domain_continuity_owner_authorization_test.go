package abci

import (
	"crypto/sha256"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/store"
)

func TestAppV25RecoveredOwnerTransferMatchesConsensusAuthorization(t *testing.T) {
	app := setupTestApp(t)
	root := newAgentKey(t)
	owner := newAgentKey(t)
	member := newAgentKey(t)
	newOwner := newAgentKey(t)
	registerAppV23Agent(t, app, root, store.AppV23RoleAdmin, 1, 0)
	registerAppV23Agent(t, app, owner, store.AppV23RoleMember, 2, store.DefaultSelfRegisteredAgentCapabilities)
	registerAppV23Agent(t, app, member, store.AppV23RoleMember, 2, store.DefaultSelfRegisteredAgentCapabilities)
	registerAppV23Agent(t, app, newOwner, store.AppV23RoleMember, 2, 0)
	const domain = "recovered-owner-abci"
	require.NoError(t, app.badgerStore.RegisterDomain(domain, root.id, "", 5))
	require.NoError(t, app.badgerStore.EnsureAppV23Root("recovered-owner-abci", 100))
	writers := []string{owner.id, member.id}
	sort.Strings(writers)
	plan := sha256.Sum256([]byte("recovered-owner-abci-plan"))
	require.NoError(t, app.badgerStore.ApplyAppV25DomainContinuityBatch(
		[]store.AppV25DomainContinuityBatchEntry{{
			Domain: domain, Owner: owner.id, Writers: writers,
		}},
		plan[:], 1, 120,
	))
	app.v8AppliedHeight = 1
	app.appV8AppliedHeight = 1
	app.appV15AppliedHeight = 1
	app.appV20AppliedHeight = 1
	app.appV21AppliedHeight = 1
	app.appV22AppliedHeight = 1
	app.appV23AppliedHeight = 1
	app.appV24AppliedHeight = 1
	app.appV25AppliedHeight = 1

	decide := func(agent agentKey, verb store.AppV23DomainVerb, want bool) {
		t.Helper()
		allowed, _, err := app.appV23DomainDecision(
			makeMemorySubmitTx(t, agent, domain, "owner parity"),
			agent.id, domain, verb, 121, appV23BlockTime(),
		)
		require.NoError(t, err)
		require.Equal(t, want, allowed)
	}
	decide(owner, store.AppV23VerbRead, true)
	decide(owner, store.AppV23VerbWrite, true)
	decide(owner, store.AppV23VerbModify, true)
	decide(member, store.AppV23VerbRead, true)
	decide(member, store.AppV23VerbWrite, true)
	decide(member, store.AppV23VerbModify, false)

	require.NoError(t, app.badgerStore.TransferDomainAppV23(
		domain, newOwner.id, "", 122, false,
	))
	decide(owner, store.AppV23VerbRead, true)
	decide(owner, store.AppV23VerbWrite, true)
	decide(owner, store.AppV23VerbModify, false)
	decide(newOwner, store.AppV23VerbRead, true)
	decide(newOwner, store.AppV23VerbWrite, true)
	decide(newOwner, store.AppV23VerbModify, true)
}
