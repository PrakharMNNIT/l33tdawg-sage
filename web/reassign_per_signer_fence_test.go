package web

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/tx"
)

// This file pins the GRANULARITY of the matrix save's signer-held
// short-circuit. The short-circuit itself is right — a row whose signing key
// is fenced parks for the whole backgroundSigningBudget before reporting
// not_sent_signer_held, so re-paying that budget per row would stall one save
// for minutes — but the superseded version keyed it on a single boolean for
// the WHOLE batch, and different domains resolve to DIFFERENT owning signers.
// One fenced owner therefore silently skipped every later row, including
// domains whose unfenced owner could have signed immediately: rows reported
// "signer held" about a signer that was never held.

// domainAccessBlob renders the persisted matrix blob granting read on each
// domain, the shape reconcileDomainGrants diffs against on-chain state.
func domainAccessBlob(t *testing.T, domains ...string) string {
	t.Helper()
	entries := make([]domainAccessEntry, 0, len(domains))
	for _, d := range domains {
		entries = append(entries, domainAccessEntry{Domain: d, Read: true})
	}
	blob, err := json.Marshal(entries)
	require.NoError(t, err)
	return string(blob)
}

// TestGrantAs_HeldSignerShortCircuitIsPerSigningIdentity is the structural
// half: the "already held" check must run AFTER owner resolution, against the
// identity of the key that would sign THIS row. A record naming signer A must
// stop A's rows without a broadcast, and must not touch B's.
func TestGrantAs_HeldSignerShortCircuitIsPerSigningIdentity(t *testing.T) {
	bs := newGrantTestBadger(t)
	_, keyA, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_, keyB, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	ownerA := agentIDForKey(keyA)
	ownerB := agentIDForKey(keyB)
	require.NoError(t, bs.RegisterDomain("fence.alpha", ownerA, "", 1))
	require.NoError(t, bs.RegisterDomain("fence.beta", ownerB, "", 1))

	var captured *tx.ParsedTx
	var calls atomic.Int32
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		raw := strings.TrimPrefix(r.URL.Query().Get("tx"), "0x")
		encoded, decErr := hex.DecodeString(raw)
		require.NoError(t, decErr)
		captured, decErr = tx.DecodeTx(encoded)
		require.NoError(t, decErr)
		writeCommitOK(w, r)
	}))
	t.Cleanup(rpc.Close)

	h := &DashboardHandler{
		BadgerStore: bs,
		CometBFTRPC: rpc.URL,
		ResolveAgentKeyFn: func(id string) (ed25519.PrivateKey, bool) {
			switch id {
			case ownerA:
				return keyA, true
			case ownerB:
				return keyB, true
			}
			return nil, false
		},
	}

	// Signer A hit a fence earlier in this save.
	heldSigners := map[string]bool{ownerA: true}

	// B's row must be attempted and succeed: B's key was never held.
	granted := h.grantAs("fence.beta", "agent-target", 1, nil, heldSigners)
	require.True(t, granted.OK, "a fence on owner A skipped a domain owned by unfenced owner B: %s", granted.Error)
	require.Equal(t, int32(1), calls.Load())
	require.NotNil(t, captured)
	assert.Equal(t, ownerB, captured.AccessGrant.GranterID,
		"the broadcast row must be signed by B, the resolved owner")

	// A's rows — grant AND revoke — must short-circuit without paying the
	// budget or touching the wire.
	skippedGrant := h.grantAs("fence.alpha", "agent-target", 1, nil, heldSigners)
	assert.False(t, skippedGrant.OK)
	assert.Equal(t, "not_sent_signer_held", skippedGrant.Code)
	skippedRevoke := h.revokeAs("fence.alpha", "agent-target", nil, heldSigners)
	assert.False(t, skippedRevoke.OK)
	assert.Equal(t, "not_sent_signer_held", skippedRevoke.Code)
	assert.Equal(t, int32(1), calls.Load(),
		"a short-circuited row must not broadcast; the whole point is not re-asking a held signer")
}

// TestReconcileDomainGrants_FenceOnOneOwnerDoesNotSkipOtherOwnersDomains is
// the end-to-end half, through the real batch loop with a REAL fence: owner
// A's key is genuinely fenced (indeterminate broadcast, reconciliation
// stonewalled), owner B's is not, and one matrix save touches domains of both.
// Every B-owned row must go on-chain; only A's row may report
// not_sent_signer_held.
//
// Two saves run back to back because the batch loop iterates a Go map: a
// single save could, by iteration-order luck, place A's domain last and mask
// the global-flag defect. Two consecutive saves make that masking vanishingly
// unlikely while still proving the map is rebuilt per save (a held marker for
// A must not leak between saves either — B keeps signing in round two).
func TestReconcileDomainGrants_FenceOnOneOwnerDoesNotSkipOtherOwnersDomains(t *testing.T) {
	// Shrink the signing budget so A's fenced row parks briefly instead of the
	// production 2x commit timeout. This changes only how long the fenced row
	// waits, never what any row concludes.
	t.Setenv("SAGE_TX_COMMIT_TIMEOUT_MS", "150")

	bs := newGrantTestBadger(t)
	_, keyA, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_, keyB, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	ownerA := agentIDForKey(keyA)
	ownerB := agentIDForKey(keyB)

	domainsB := []string{"held.beta", "held.gamma", "held.delta", "held.epsilon", "held.zeta"}
	require.NoError(t, bs.RegisterDomain("held.alpha", ownerA, "", 1))
	for _, d := range domainsB {
		require.NoError(t, bs.RegisterDomain(d, ownerB, "", 1))
	}

	// A's key gets a REAL fence, resolved with proof at teardown.
	fenceOneSigningKey(t, keyA)

	var mu sync.Mutex
	granters := map[string]string{} // domain -> signer who actually broadcast
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.URL.Query().Get("tx"), "0x")
		encoded, decErr := hex.DecodeString(raw)
		require.NoError(t, decErr)
		parsed, decErr := tx.DecodeTx(encoded)
		require.NoError(t, decErr)
		if parsed.AccessGrant != nil {
			mu.Lock()
			granters[parsed.AccessGrant.Domain] = parsed.AccessGrant.GranterID
			mu.Unlock()
		}
		writeCommitOK(w, r)
	}))
	t.Cleanup(rpc.Close)

	h := &DashboardHandler{
		BadgerStore: bs,
		CometBFTRPC: rpc.URL,
		ResolveAgentKeyFn: func(id string) (ed25519.PrivateKey, bool) {
			switch id {
			case ownerA:
				return keyA, true
			case ownerB:
				return keyB, true
			}
			return nil, false
		},
	}

	newBlob := domainAccessBlob(t, append([]string{"held.alpha"}, domainsB...)...)
	for round := 1; round <= 2; round++ {
		results := h.reconcileDomainGrants("agent-target", "", newBlob, nil)
		require.Len(t, results, len(domainsB)+1, "round %d: every row must get a result", round)

		byDomain := map[string]grantResult{}
		for _, res := range results {
			byDomain[res.Domain] = res
		}
		alpha, ok := byDomain["held.alpha"]
		require.True(t, ok, "round %d: the fenced owner's row vanished from the results", round)
		assert.False(t, alpha.OK, "round %d: a fenced signer's row cannot have been sent", round)
		assert.Equal(t, "not_sent_signer_held", alpha.Code,
			"round %d: the fenced row must be reported as not-sent, never as a rejection", round)

		for _, d := range domainsB {
			res, ok := byDomain[d]
			require.True(t, ok, "round %d: no result row for %s", round, d)
			assert.True(t, res.OK,
				"round %d: %s is owned by UNFENCED owner B but was not sent (%s: %s) — "+
					"a fence on one signer silently skipped another signer's domain",
				round, d, res.Code, res.Error)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	for _, d := range domainsB {
		assert.Equal(t, ownerB, granters[d], "%s must have been broadcast signed by owner B", d)
	}
	if got, found := granters["held.alpha"]; found {
		t.Fatalf("the fenced owner's row reached the wire signed by %s; a fenced key must not sign", got)
	}
}
