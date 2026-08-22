package abci

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

// makeAccessGrantTx builds a signed ParsedTx for TxTypeAccessGrant from
// granter to grantee on domain. Mirrors makeMemorySubmitTx's signing
// pattern so verifyAgentIdentity passes.
func makeAccessGrantTx(t *testing.T, granter agentKey, granteeID, domain string, level uint8) *tx.ParsedTx {
	t.Helper()
	body := []byte(domain + granteeID)
	pubKey, sig, bodyHash, ts := signAgentProof(t, granter, body)
	return &tx.ParsedTx{
		Type: tx.TxTypeAccessGrant,
		AccessGrant: &tx.AccessGrant{
			GranterID: granter.id,
			GranteeID: granteeID,
			Domain:    domain,
			Level:     level,
		},
		AgentPubKey:    pubKey,
		AgentSig:       sig,
		AgentBodyHash:  bodyHash,
		AgentTimestamp: ts,
	}
}

// TestProcessAccessGrant_PreForkReplayParity asserts that on a pre-v8.0
// chain (v8AppliedHeight == 0), processAccessGrant continues to reject a
// grant on an unowned non-shared domain with Code 34 — byte-identical to
// v7.1.1. The fork gate must NOT relax authorization until the upgrade
// activates.
func TestProcessAccessGrant_PreForkReplayParity(t *testing.T) {
	app := setupTestApp(t)
	require.Equal(t, int64(0), app.v8AppliedHeight, "precondition: pre-fork")

	granter := newAgentKey(t)
	grantee := newAgentKey(t)

	ptx := makeAccessGrantTx(t, granter, grantee.id, "pipeline.failures.x", 2)
	res := app.processAccessGrant(ptx, 1, time.Now())
	assert.Equal(t, uint32(34), res.Code, "pre-fork must reject unowned-domain grant: %s", res.Log)

	// Domain must remain unregistered — pre-fork code path never auto-claims.
	_, err := app.badgerStore.GetDomainOwner("pipeline.failures.x")
	assert.Error(t, err, "pre-fork must not auto-register the domain")
}

// TestProcessAccessGrant_PostForkAutoRegister asserts the headline v8.0
// behaviour: on an unowned, non-shared domain, the granter auto-claims
// ownership and the grant proceeds with Code 0. After: the granter owns
// the domain in Badger, and the grantee has a live access grant.
func TestProcessAccessGrant_PostForkAutoRegister(t *testing.T) {
	app := setupTestApp(t)
	app.v8AppliedHeight = 100
	const height = int64(200)
	require.True(t, app.postV8Fork(height), "precondition: post-fork at height")

	granter := newAgentKey(t)
	grantee := newAgentKey(t)
	const domain = "pipeline.failures.x"
	blockTime := time.Unix(1700000000, 0)

	ptx := makeAccessGrantTx(t, granter, grantee.id, domain, 2)
	res := app.processAccessGrant(ptx, height, blockTime)
	require.Equal(t, uint32(0), res.Code, "post-fork unowned-domain grant must succeed: %s", res.Log)

	// Granter is the new owner.
	owner, err := app.badgerStore.GetDomainOwner(domain)
	require.NoError(t, err)
	assert.Equal(t, granter.id, owner, "granter must auto-claim ownership")

	// Grantee has the requested grant.
	level, _, gID, err := app.badgerStore.GetAccessGrant(domain, grantee.id)
	require.NoError(t, err)
	assert.Equal(t, uint8(2), level)
	assert.Equal(t, granter.id, gID, "granter recorded as authority")

	// Granter has their own owner grant (level 2).
	level, _, gID, err = app.badgerStore.GetAccessGrant(domain, granter.id)
	require.NoError(t, err)
	assert.Equal(t, uint8(2), level, "granter must have level-2 self-grant")
	assert.Equal(t, granter.id, gID)
}

// TestProcessAccessGrant_PostForkSharedExactReject asserts grants on
// exact-match shared domains (general/self/meta) are rejected with the
// new Code 50 — these are never ownable. No registration side effect.
func TestProcessAccessGrant_PostForkSharedExactReject(t *testing.T) {
	app := setupTestApp(t)
	app.v8AppliedHeight = 100
	const height = int64(200)

	granter := newAgentKey(t)
	grantee := newAgentKey(t)

	for _, domain := range []string{"general", "self", "meta"} {
		domain := domain
		t.Run(domain, func(t *testing.T) {
			ptx := makeAccessGrantTx(t, granter, grantee.id, domain, 1)
			res := app.processAccessGrant(ptx, height, time.Now())
			assert.Equal(t, uint32(50), res.Code, "shared domain %q must reject with Code 50: %s", domain, res.Log)
			assert.Contains(t, res.Log, "shared domain not ownable")

			_, err := app.badgerStore.GetDomainOwner(domain)
			assert.Error(t, err, "shared domain %q must remain unregistered", domain)
		})
	}
}

// TestProcessAccessGrant_PostForkSharedPrefixReject asserts the
// sage-* shared-prefix family also rejects with Code 50.
func TestProcessAccessGrant_PostForkSharedPrefixReject(t *testing.T) {
	app := setupTestApp(t)
	app.v8AppliedHeight = 100
	const height = int64(200)

	granter := newAgentKey(t)
	grantee := newAgentKey(t)

	ptx := makeAccessGrantTx(t, granter, grantee.id, "sage-debugging", 1)
	res := app.processAccessGrant(ptx, height, time.Now())
	assert.Equal(t, uint32(50), res.Code, "sage-* prefix must reject with Code 50: %s", res.Log)

	_, err := app.badgerStore.GetDomainOwner("sage-debugging")
	assert.Error(t, err, "sage-debugging must remain unregistered")
}

func TestProcessDomainRegister_PostForkSharedReject(t *testing.T) {
	app := setupTestApp(t)
	app.v8AppliedHeight = 100
	const height = int64(200)

	registrant := newAgentKey(t)
	require.NoError(t, app.badgerStore.SetSharedDomain("governed-open"))

	for _, domain := range []string{"general", "self", "meta", "sage-debugging", "governed-open"} {
		domain := domain
		t.Run(domain, func(t *testing.T) {
			parsed := makeDelegatedDomainRegisterTx(
				t, registrant, registrant, []byte("register "+domain),
				time.Unix(1_700_000_000, 0), domain, "", false,
			)
			result := app.processDomainRegister(parsed, height, time.Unix(1_700_000_000, 0))
			require.Equal(t, uint32(50), result.Code, result.Log)
			require.Contains(t, result.Log, "shared domain not ownable")

			_, err := app.badgerStore.GetDomainOwner(domain)
			require.Error(t, err, "shared domain %q must remain ownerless", domain)
		})
	}
}

// TestProcessAccessGrant_PostForkAncestorOwnedBlocksLeafClaim asserts
// that if any ancestor of the grant domain has an owner, a different
// agent CANNOT auto-claim the leaf — they would be writing under
// someone else's namespace. Returns Code 34 with no side effects.
func TestProcessAccessGrant_PostForkAncestorOwnedBlocksLeafClaim(t *testing.T) {
	app := setupTestApp(t)
	app.v8AppliedHeight = 100
	const height = int64(200)

	alice := newAgentKey(t)
	bob := newAgentKey(t)
	grantee := newAgentKey(t)

	// Alice owns "foo".
	require.NoError(t, app.badgerStore.RegisterDomain("foo", alice.id, "", 1))

	// Bob attempts to grant on "foo.bar" — Alice's ancestor blocks the claim.
	ptx := makeAccessGrantTx(t, bob, grantee.id, "foo.bar", 2)
	res := app.processAccessGrant(ptx, height, time.Now())
	assert.Equal(t, uint32(34), res.Code, "ancestor-owned must block leaf auto-claim: %s", res.Log)
	assert.Contains(t, res.Log, "access denied")

	// "foo.bar" must remain unregistered.
	_, err := app.badgerStore.GetDomainOwner("foo.bar")
	assert.Error(t, err, "leaf must not be auto-registered when ancestor is owned by another agent")
}

// TestProcessAccessGrant_PostForkPendingWritesCorrectness asserts the
// auto-register branch emits EXACTLY the right pendingWrites: a
// domain_register for the new domain, an access_grant for the granter's
// owner self-grant, AND the outer access_grant for the grantee. Three
// entries total, in that order.
func TestProcessAccessGrant_PostForkPendingWritesCorrectness(t *testing.T) {
	app := setupTestApp(t)
	app.v8AppliedHeight = 100
	const height = int64(200)
	blockTime := time.Unix(1700000000, 0)

	granter := newAgentKey(t)
	grantee := newAgentKey(t)
	const domain = "team.alpha.findings"

	ptx := makeAccessGrantTx(t, granter, grantee.id, domain, 1)
	res := app.processAccessGrant(ptx, height, blockTime)
	require.Equal(t, uint32(0), res.Code, "auto-register grant must succeed: %s", res.Log)

	require.Len(t, app.pendingWrites, 3, "expected exactly 3 pendingWrites: domain_register + owner self-grant + grantee grant")

	// First: domain_register for the auto-claimed domain.
	assert.Equal(t, "domain_register", app.pendingWrites[0].writeType)
	domainEntry, ok := app.pendingWrites[0].data.(*store.DomainEntry)
	require.True(t, ok, "first pending write must be *store.DomainEntry")
	assert.Equal(t, domain, domainEntry.DomainName)
	assert.Equal(t, granter.id, domainEntry.OwnerAgentID)
	assert.Equal(t, height, domainEntry.CreatedHeight)
	assert.Equal(t, blockTime, domainEntry.CreatedAt)

	// Second: granter's own level-2 owner grant.
	assert.Equal(t, "access_grant", app.pendingWrites[1].writeType)
	ownerGrant, ok := app.pendingWrites[1].data.(*store.AccessGrantEntry)
	require.True(t, ok)
	assert.Equal(t, domain, ownerGrant.Domain)
	assert.Equal(t, granter.id, ownerGrant.GranteeID, "owner self-grant: grantee == granter")
	assert.Equal(t, granter.id, ownerGrant.GranterID)
	assert.Equal(t, uint8(2), ownerGrant.Level, "owner self-grant must be level 2")

	// Third: the outer access_grant for the actual grantee.
	assert.Equal(t, "access_grant", app.pendingWrites[2].writeType)
	granteeGrant, ok := app.pendingWrites[2].data.(*store.AccessGrantEntry)
	require.True(t, ok)
	assert.Equal(t, domain, granteeGrant.Domain)
	assert.Equal(t, grantee.id, granteeGrant.GranteeID)
	assert.Equal(t, granter.id, granteeGrant.GranterID)
	assert.Equal(t, uint8(1), granteeGrant.Level, "grantee grant must match requested level")
}

// TestProcessAccessGrant_PostForkEmptyDomainGuard asserts the
// post-fork branch refuses to auto-register the empty-string domain.
// Without this guard, an empty-string grant would be treated as
// "non-shared, no ancestors" and silently capture the empty domain.
func TestProcessAccessGrant_PostForkEmptyDomainGuard(t *testing.T) {
	app := setupTestApp(t)
	app.v8AppliedHeight = 100
	const height = int64(200)

	granter := newAgentKey(t)
	grantee := newAgentKey(t)

	ptx := makeAccessGrantTx(t, granter, grantee.id, "", 2)
	res := app.processAccessGrant(ptx, height, time.Now())
	assert.Equal(t, uint32(33), res.Code, "empty-domain grant must be rejected: %s", res.Log)

	// No pending writes — auto-register must NOT have fired.
	assert.Empty(t, app.pendingWrites, "empty-domain grant must not emit any pendingWrites")
}

// TestProcessAccessGrant_PostForkSameBlockRaceLoss simulates the race
// where, between RegisterDomain returning ErrDomainAlreadyRegistered
// and our re-check, the domain ends up owned by SOMEONE ELSE. The
// loser tx must reject with Code 34 — grants depend on ownership, so
// we cannot fall through like processMemorySubmit can. No pendingWrites
// are emitted on the loser path.
//
// We simulate "the winner already registered" by pre-registering the
// domain to a third agent before invoking the grant. RegisterDomain
// will return ErrDomainAlreadyRegistered, the re-check will see a
// different owner, and the handler must reject with Code 34.
func TestProcessAccessGrant_PostForkSameBlockRaceLoss(t *testing.T) {
	app := setupTestApp(t)
	app.v8AppliedHeight = 100
	const height = int64(200)

	winner := newAgentKey(t)
	loser := newAgentKey(t)
	grantee := newAgentKey(t)
	const domain = "raced.grant.domain"

	// Winner already claimed the domain (simulating same-block race winner).
	// Note: IsDomainOwnerOrAncestor against `loser` returns false, so the
	// handler enters the auto-register branch. GetDomainOwner returns
	// `winner.id`, which under the spec's leafOwner != "" check would
	// actually go to the "owned by someone else" branch (Code 34). To
	// exercise the RACE path explicitly we need leafOwner=="" at the
	// GetDomainOwner check but RegisterDomain to fail. That window
	// doesn't exist in single-goroutine test land — so pre-registration
	// is the closest reachable analogue and exercises the same outcome:
	// loser is rejected, no pendingWrites emitted for loser.
	require.NoError(t, app.badgerStore.RegisterDomain(domain, winner.id, "", 1))
	preWrites := len(app.pendingWrites)

	ptx := makeAccessGrantTx(t, loser, grantee.id, domain, 2)
	res := app.processAccessGrant(ptx, height, time.Now())
	assert.Equal(t, uint32(34), res.Code, "loser must be rejected: %s", res.Log)

	// No spurious pendingWrites for the loser.
	assert.Len(t, app.pendingWrites, preWrites, "loser must not emit pendingWrites")

	// Winner still owns the domain.
	owner, err := app.badgerStore.GetDomainOwner(domain)
	require.NoError(t, err)
	assert.Equal(t, winner.id, owner, "winner's ownership survives the loser's attempt")
}
