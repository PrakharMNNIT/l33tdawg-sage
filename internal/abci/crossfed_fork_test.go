package abci

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/tx"
)

// ---------------------------------------------------------------------------
// Mode-1 EXCHANGE (v11 / app-v15): tx 33 CrossFedSet + tx 34 CrossFedRevoke.
// A unilateral local terms declaration for a remote chain, dual-gated on
// postAppV15Fork. Authority = local chain-admin OR owner of the scoped domains
// (NOT org-admin — solo/personal nodes must be able to use it).
// ---------------------------------------------------------------------------

func termsFor(remoteID string, domains []string) *tx.CrossFedTerms {
	return &tx.CrossFedTerms{
		RemoteChainID:  remoteID,
		Endpoint:       "https://peer.example:8443",
		PeerPubKey:     bytes.Repeat([]byte{9}, 32),
		MaxClearance:   tx.ClearanceConfidential,
		AllowedDomains: domains,
		AllowedDepts:   nil,
		ExpiresAt:      0,
		Status:         "active",
	}
}

func crossFedSetTx(t *testing.T, sender agentKey, terms *tx.CrossFedTerms) *tx.ParsedTx {
	t.Helper()
	pub, sig, bh, ts := signAgentProof(t, sender, []byte(terms.RemoteChainID+terms.Endpoint))
	return &tx.ParsedTx{
		Type: tx.TxTypeCrossFedSet, CrossFedTerms: terms,
		AgentPubKey: pub, AgentSig: sig, AgentBodyHash: bh, AgentTimestamp: ts,
	}
}

func crossFedRevokeTx(t *testing.T, sender agentKey, remoteID, reason string) *tx.ParsedTx {
	t.Helper()
	pub, sig, bh, ts := signAgentProof(t, sender, []byte(remoteID+reason))
	return &tx.ParsedTx{
		Type: tx.TxTypeCrossFedRevoke, CrossFedRevoke: &tx.CrossFedRevoke{RemoteChainID: remoteID, Reason: reason},
		AgentPubKey: pub, AgentSig: sig, AgentBodyHash: bh, AgentTimestamp: ts,
	}
}

// TestCrossFed_DualGatePreFork: pre-activation, both tx types are rejected Code 10
// and write nothing (byte-identical AppHash).
func TestCrossFed_DualGatePreFork(t *testing.T) {
	app := setupTestApp(t) // v15 dormant
	admin := newAgentKey(t)
	registerAgent(t, app, admin, "admin", "admin")

	before, err := ComputeAppHash(app.badgerStore)
	require.NoError(t, err)

	set := app.processCrossFedSet(crossFedSetTx(t, admin, termsFor("sage-b", []string{"*"})), 10, time.Now())
	assert.Equal(t, uint32(10), set.Code, "pre-fork set rejected as unknown tx")
	rev := app.processCrossFedRevoke(crossFedRevokeTx(t, admin, "sage-b", "x"), 10, time.Now())
	assert.Equal(t, uint32(10), rev.Code, "pre-fork revoke rejected as unknown tx")

	after, err := ComputeAppHash(app.badgerStore)
	require.NoError(t, err)
	assert.Equal(t, before, after, "pre-fork rejects write no key — AppHash byte-identical")
	_, _, _, _, _, _, _, gErr := app.badgerStore.GetCrossFed("sage-b")
	assert.Error(t, gErr, "no cross_fed record written pre-fork")
}

// TestCrossFed_SetAndRevoke: happy-path lifecycle by a chain-admin.
func TestCrossFed_SetAndRevoke(t *testing.T) {
	app := setupTestApp(t)
	app.appV15AppliedHeight = 5
	admin := newAgentKey(t)
	registerAgent(t, app, admin, "admin", "admin")

	set := app.processCrossFedSet(crossFedSetTx(t, admin, termsFor("sage-b", []string{"*"})), 10, time.Now())
	require.Equal(t, uint32(0), set.Code, "set: %s", set.Log)

	ep, pk, mc, ex, _, _, st, err := app.badgerStore.GetCrossFed("sage-b")
	require.NoError(t, err)
	assert.Equal(t, "https://peer.example:8443", ep)
	assert.Equal(t, bytes.Repeat([]byte{9}, 32), pk)
	assert.Equal(t, uint8(tx.ClearanceConfidential), mc)
	assert.Equal(t, int64(0), ex)
	assert.Equal(t, "active", st)

	rev := app.processCrossFedRevoke(crossFedRevokeTx(t, admin, "sage-b", "rotated"), 11, time.Now())
	require.Equal(t, uint32(0), rev.Code, "revoke: %s", rev.Log)
	_, _, _, _, _, _, st2, err := app.badgerStore.GetCrossFed("sage-b")
	require.NoError(t, err)
	assert.Equal(t, "revoked", st2, "revoke round-trips all fields, flips status")
	// The transport coords survive the status update (guards the truncation landmine).
	ep2, _, _, _, _, _, _, _ := app.badgerStore.GetCrossFed("sage-b")
	assert.Equal(t, "https://peer.example:8443", ep2)
}

func TestCrossFed_AppV22TermsValidationPreservesLegacyReplay(t *testing.T) {
	app := setupTestApp(t)
	app.appV15AppliedHeight = 5
	app.appV22AppliedHeight = 15
	admin := newAgentKey(t)
	registerAgent(t, app, admin, "admin", "admin")

	cases := []struct {
		name   string
		mutate func(*tx.CrossFedTerms)
		log    string
	}{
		{
			name: "clearance ceiling",
			mutate: func(terms *tx.CrossFedTerms) {
				terms.MaxClearance = tx.ClearanceLevel(255)
			},
			log: "max_clearance",
		},
		{
			name: "past expiry",
			mutate: func(terms *tx.CrossFedTerms) {
				terms.ExpiresAt = -1
			},
			log: "expires_at",
		},
		{
			name: "restrictive department",
			mutate: func(terms *tx.CrossFedTerms) {
				terms.AllowedDepts = []string{"voice"}
			},
			log: "allowed_depts",
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			legacy := termsFor(fmt.Sprintf("legacy-%d", i), []string{"*"})
			tc.mutate(legacy)
			legacyResult := app.processCrossFedSet(
				crossFedSetTx(t, admin, legacy),
				10,
				time.Unix(100, 0),
			)
			require.Equal(t, uint32(0), legacyResult.Code, legacyResult.Log)

			postV22 := termsFor(fmt.Sprintf("post-v22-%d", i), []string{"*"})
			tc.mutate(postV22)
			postResult := app.processCrossFedSet(
				crossFedSetTx(t, admin, postV22),
				16,
				time.Unix(100, 0),
			)
			require.Equal(t, uint32(105), postResult.Code, postResult.Log)
			require.Contains(t, postResult.Log, tc.log)
		})
	}
}

// TestCrossFed_Authz: chain-admin (wildcard) OK; domain-owner (scoped) OK;
// non-admin/non-owner denied; non-admin with wildcard denied.
func TestCrossFed_Authz(t *testing.T) {
	app := setupTestApp(t)
	app.appV15AppliedHeight = 5

	// chain-admin may set a wildcard treaty.
	admin := newAgentKey(t)
	registerAgent(t, app, admin, "admin", "admin")
	r1 := app.processCrossFedSet(crossFedSetTx(t, admin, termsFor("sage-b", []string{"*"})), 10, time.Now())
	assert.Equal(t, uint32(0), r1.Code, "chain-admin wildcard: %s", r1.Log)

	// domain-owner may set terms scoped to a domain they own.
	owner := newAgentKey(t)
	registerAgent(t, app, owner, "owner", "member")
	require.NoError(t, app.badgerStore.RegisterDomain("hr", owner.id, "", 1))
	r2 := app.processCrossFedSet(crossFedSetTx(t, owner, termsFor("sage-c", []string{"hr"})), 11, time.Now())
	assert.Equal(t, uint32(0), r2.Code, "domain-owner scoped: %s", r2.Log)

	// non-admin, non-owner: denied.
	stranger := newAgentKey(t)
	registerAgent(t, app, stranger, "stranger", "member")
	r3 := app.processCrossFedSet(crossFedSetTx(t, stranger, termsFor("sage-d", []string{"hr"})), 12, time.Now())
	assert.Equal(t, uint32(106), r3.Code, "non-owner of the scoped domain denied")

	// non-admin cannot set a wildcard (all-domains) treaty even if they own a domain.
	r4 := app.processCrossFedSet(crossFedSetTx(t, owner, termsFor("sage-e", []string{"*"})), 13, time.Now())
	assert.Equal(t, uint32(106), r4.Code, "wildcard treaty requires chain-admin")
}

// TestCrossFed_UpsertHijackRejected: the confused-deputy fix — a principal who
// owns only a throwaway domain cannot overwrite (hijack) an existing agreement
// (e.g. a chain-admin wildcard treaty) by re-scoping the slot to their domain.
func TestCrossFed_UpsertHijackRejected(t *testing.T) {
	app := setupTestApp(t)
	app.appV15AppliedHeight = 5

	// Chain-admin establishes the real trust anchor for "bank" (wildcard treaty).
	admin := newAgentKey(t)
	registerAgent(t, app, admin, "admin", "admin")
	real := termsFor("bank", []string{"*"})
	real.Endpoint = "https://bank.real:8443"
	real.PeerPubKey = bytes.Repeat([]byte{1}, 32)
	require.Equal(t, uint32(0), app.processCrossFedSet(crossFedSetTx(t, admin, real), 10, time.Now()).Code)

	// Attacker owns a throwaway domain and tries to overwrite cross_fed:bank.
	attacker := newAgentKey(t)
	registerAgent(t, app, attacker, "attacker", "member")
	require.NoError(t, app.badgerStore.RegisterDomain("alice", attacker.id, "", 1))
	evil := termsFor("bank", []string{"alice"})
	evil.Endpoint = "https://attacker:8443"
	evil.PeerPubKey = bytes.Repeat([]byte{0xEE}, 32)
	res := app.processCrossFedSet(crossFedSetTx(t, attacker, evil), 11, time.Now())
	assert.Equal(t, uint32(106), res.Code, "attacker cannot hijack an existing agreement via a throwaway domain")

	// The real trust anchor is intact (endpoint + pinned key unchanged).
	ep, pk, _, _, _, _, _, err := app.badgerStore.GetCrossFed("bank")
	require.NoError(t, err)
	assert.Equal(t, "https://bank.real:8443", ep, "endpoint not clobbered")
	assert.Equal(t, bytes.Repeat([]byte{1}, 32), pk, "pinned peer key not clobbered")
}

// TestCrossFed_OwnerCanUpdateOwnAgreement: the fix must not break a legitimate
// update by the same authorized party.
func TestCrossFed_OwnerCanUpdateOwnAgreement(t *testing.T) {
	app := setupTestApp(t)
	app.appV15AppliedHeight = 5
	owner := newAgentKey(t)
	registerAgent(t, app, owner, "owner", "member")
	require.NoError(t, app.badgerStore.RegisterDomain("hr", owner.id, "", 1))

	t1 := termsFor("sage-c", []string{"hr"})
	t1.Endpoint = "https://old:8443"
	require.Equal(t, uint32(0), app.processCrossFedSet(crossFedSetTx(t, owner, t1), 10, time.Now()).Code)
	t2 := termsFor("sage-c", []string{"hr"})
	t2.Endpoint = "https://new:8443"
	require.Equal(t, uint32(0), app.processCrossFedSet(crossFedSetTx(t, owner, t2), 11, time.Now()).Code, "owner may update their own agreement")
	ep, _, _, _, _, _, _, _ := app.badgerStore.GetCrossFed("sage-c")
	assert.Equal(t, "https://new:8443", ep, "the owner's update is applied")
}

// TestCrossFed_RevokeLifecycle: unknown-revoke rejects, revoke flips status,
// re-revoke of a revoked agreement rejects, and an authorized re-set reactivates.
func TestCrossFed_RevokeLifecycle(t *testing.T) {
	app := setupTestApp(t)
	app.appV15AppliedHeight = 5
	admin := newAgentKey(t)
	registerAgent(t, app, admin, "admin", "admin")

	unk := app.processCrossFedRevoke(crossFedRevokeTx(t, admin, "never-set", "x"), 10, time.Now())
	assert.Equal(t, uint32(108), unk.Code, "revoke of an unknown agreement rejected")

	require.Equal(t, uint32(0), app.processCrossFedSet(crossFedSetTx(t, admin, termsFor("sage-b", []string{"*"})), 11, time.Now()).Code)
	require.Equal(t, uint32(0), app.processCrossFedRevoke(crossFedRevokeTx(t, admin, "sage-b", "rotate"), 12, time.Now()).Code)
	again := app.processCrossFedRevoke(crossFedRevokeTx(t, admin, "sage-b", "again"), 13, time.Now())
	assert.Equal(t, uint32(108), again.Code, "revoke of an already-revoked agreement rejected")

	require.Equal(t, uint32(0), app.processCrossFedSet(crossFedSetTx(t, admin, termsFor("sage-b", []string{"*"})), 14, time.Now()).Code)
	_, _, _, _, _, _, st, err := app.badgerStore.GetCrossFed("sage-b")
	require.NoError(t, err)
	assert.Equal(t, "active", st, "an authorized re-set reactivates a revoked agreement")
}

// TestCrossFed_StoreBlobDeterministic: identical cross_fed writes hash identically
// (the blob is a pure function of its inputs → AppHash-deterministic across replicas).
func TestCrossFed_StoreBlobDeterministic(t *testing.T) {
	mk := func() []byte {
		bs := setupTestBadger(t)
		require.NoError(t, bs.SetCrossFed("sage-b", "https://p:8443", bytes.Repeat([]byte{9}, 32),
			2, 1_700_000_000, []string{"hr", "*"}, []string{"finance"}, "active"))
		h, err := ComputeAppHash(bs)
		require.NoError(t, err)
		return h
	}
	assert.Equal(t, mk(), mk(), "identical cross_fed writes produce identical AppHash")
}

// TestCrossFed_CheckTxDualGate (load-bearing mixed-binary guard).
func TestCrossFed_CheckTxDualGate(t *testing.T) {
	app := setupTestApp(t)
	admin := newAgentKey(t)
	registerAgent(t, app, admin, "admin", "admin")
	ptx := crossFedSetTx(t, admin, termsFor("sage-b", []string{"*"}))
	require.NoError(t, tx.SignTx(ptx, admin.priv))
	encoded, err := tx.EncodeTx(ptx)
	require.NoError(t, err)

	app.state.Height = 0
	resp, err := app.CheckTx(context.TODO(), &abcitypes.RequestCheckTx{Tx: encoded})
	require.NoError(t, err)
	assert.Equal(t, uint32(10), resp.Code, "pre-fork CheckTx rejects cross_fed Code 10")

	app.appV15AppliedHeight = 5
	app.state.Height = 100
	resp2, err := app.CheckTx(context.TODO(), &abcitypes.RequestCheckTx{Tx: encoded})
	require.NoError(t, err)
	assert.NotEqual(t, uint32(10), resp2.Code, "post-fork CheckTx admits cross_fed: %s", resp2.Log)
}
