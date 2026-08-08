package web

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/tx"
)

// commitOKBody is what a single-validator node returns for an accepted
// commit-confirmed broadcast.
const commitOKBody = `{"result":{"check_tx":{"code":0},"tx_result":{"code":0},"hash":"ABC123","height":"42"}}`

// nonceFromBroadcast decodes the tx a CometBFT stub was just handed and returns
// its replay nonce and hex signer id. Reading them off the wire — rather than
// off the ParsedTx the caller still owns — is the point of these tests: the
// ordering that matters is the order transactions ARRIVE at consensus, under
// the identity consensus meters them by.
//
// It runs on the stub's HTTP goroutine, so it reports with assert rather than
// require: require's FailNow calls runtime.Goexit, which off the test goroutine
// would abandon the response mid-flight and surface as a transport error
// instead of the decode failure that actually happened.
func nonceFromBroadcast(t *testing.T, r *http.Request) (uint64, string) {
	t.Helper()
	raw := strings.TrimPrefix(r.URL.Query().Get("tx"), "0x")
	encoded, err := hex.DecodeString(raw)
	if !assert.NoError(t, err) {
		return 0, ""
	}
	decoded, err := tx.DecodeTx(encoded)
	if !assert.NoError(t, err) {
		return 0, ""
	}
	return decoded.Nonce, hex.EncodeToString(decoded.PublicKey)
}

// accessGrantTx builds a minimal non-governance RBAC transaction — the shape the
// dashboard fan-outs actually sign, and one that still carries the legacy
// same-key agent proof, so the signing work inside the lease is realistic.
func accessGrantTx(granter, grantee string) *tx.ParsedTx {
	return &tx.ParsedTx{
		Type: tx.TxTypeAccessGrant,
		AccessGrant: &tx.AccessGrant{
			GranterID: granter,
			GranteeID: grantee,
			Domain:    "sage-rbac",
			Level:     2,
		},
	}
}

// TestSignAndBroadcastCommitContextEmitsAscendingNoncesForOneKey is the
// end-to-end form of the v11.18.3 defect, at the layer that produced it.
//
// Clearing a Done column fires one HTTP request per card; every one lands in
// this helper with the SAME dashboard signing key. Before the lease, the nonce
// was stamped and the lock dropped, so the sign/encode/HTTP work that followed
// raced: transactions reached CometBFT in an order unrelated to their nonces,
// and app-v9's strictly-">" replay gate (internal/abci/app.go, consensus path)
// rejected every late-arriving lower nonce with Code 4 "nonce too low". The
// operator saw a random subset of the cards fail. Assert that what the node
// receives is monotonic, which is the property consensus actually checks.
func TestSignAndBroadcastCommitContextEmitsAscendingNoncesForOneKey(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	type arrival struct {
		nonce  uint64
		signer string
	}
	var (
		mu      sync.Mutex
		arrived []arrival
	)
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce, signer := nonceFromBroadcast(t, r)
		mu.Lock()
		arrived = append(arrived, arrival{nonce: nonce, signer: signer})
		mu.Unlock()
		_, _ = w.Write([]byte(commitOKBody))
	}))
	t.Cleanup(rpc.Close)

	h := &DashboardHandler{CometBFTRPC: rpc.URL}
	granter := agentIDForKey(key)

	const fanOut = 24
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < fanOut; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // every card leaves the browser at once
			_, _, _, broadcastErr := h.signAndBroadcastCommitContext(
				context.Background(), accessGrantTx(granter, fmt.Sprintf("agent-%d", i)), key)
			assert.NoError(t, broadcastErr)
		}(i)
	}
	close(start)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, arrived, fanOut)
	for i := 1; i < len(arrived); i++ {
		require.Greaterf(t, arrived[i].nonce, arrived[i-1].nonce,
			"transaction %d reached the node with nonce %d after %d: consensus rejects that Code 4 'nonce too low'",
			i, arrived[i].nonce, arrived[i-1].nonce)
	}
	// The lease serializes on the SIGNING key; app-v9's replay gate counts
	// nonces per PublicKeyToAgentID(tx.PublicKey). SignTx stamps that field from
	// the same private key, so the two identities coincide today — but if a
	// caller ever leased on one key and outer-signed with another, ordering
	// would still be enforced, just for an identity the gate does not track, and
	// the batch would fail exactly as it did before the fix.
	for i, got := range arrived {
		require.Equalf(t, granter, got.signer,
			"transaction %d was leased on one key and signed with another", i)
	}
}

// TestSignAndBroadcastCommitContextDoesNotSerializeDistinctKeys guards the fix
// against becoming a throughput cliff. Serializing every dashboard signer behind
// one lock would satisfy the ordering test above while turning unrelated
// operators, agents and federation peers into a single queue — each holding a
// commit-confirmed broadcast open for a full block. Prove overlap structurally:
// the stub does not answer either request until BOTH have arrived, so a global
// lock cannot get past the first one.
func TestSignAndBroadcastCommitContextDoesNotSerializeDistinctKeys(t *testing.T) {
	_, keyA, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	_, keyB, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	var (
		once     sync.Once
		mu       sync.Mutex
		inFlight int
		bothIn   = make(chan struct{})
		stalled  bool
	)
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		inFlight++
		reached := inFlight == 2
		mu.Unlock()
		if reached {
			once.Do(func() { close(bothIn) })
		}
		select {
		case <-bothIn:
		case <-time.After(10 * time.Second):
			// Release so the test reports the invariant rather than hanging
			// until the 60s commit timeout turns this into a transport error.
			mu.Lock()
			stalled = true
			mu.Unlock()
		}
		_, _ = w.Write([]byte(commitOKBody))
	}))
	t.Cleanup(rpc.Close)

	h := &DashboardHandler{CometBFTRPC: rpc.URL}
	var wg sync.WaitGroup
	for _, key := range []ed25519.PrivateKey{keyA, keyB} {
		wg.Add(1)
		go func(key ed25519.PrivateKey) {
			defer wg.Done()
			_, _, _, broadcastErr := h.signAndBroadcastCommitContext(
				context.Background(), accessGrantTx(agentIDForKey(key), "agent-b"), key)
			assert.NoError(t, broadcastErr)
		}(key)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	assert.False(t, stalled,
		"two different signing keys could not broadcast at the same time: the nonce lease is serializing unrelated signers")
}

// TestSignAndBroadcastCommitContextCancelledBeforeSigningNeverBroadcasts pins
// the "no change" contract for a request whose context is already dead: it must
// not consume a nonce (a burned nonce makes a later honest transaction look like
// a replay), must not reach the node, and must report a DEFINITIVE failure —
// deliberately not marked indeterminate, because nothing
// was signed or sent, so the caller must not go hunting for a change that cannot
// exist.
func TestSignAndBroadcastCommitContextCancelledBeforeSigningNeverBroadcasts(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	var broadcasts int
	var mu sync.Mutex
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		broadcasts++
		mu.Unlock()
		_, _ = w.Write([]byte(commitOKBody))
	}))
	t.Cleanup(rpc.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	h := &DashboardHandler{CometBFTRPC: rpc.URL}
	ptx := accessGrantTx(agentIDForKey(key), "agent-b")
	hash, height, txLog, err := h.signAndBroadcastCommitContext(ctx, ptx, key)

	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled))
	assert.Contains(t, err.Error(), "await signing slot for this key")
	assert.False(t, isIndeterminateCommitError(err),
		"nothing was signed or sent, so this must not be reported as a possibly-committed change")
	assert.Empty(t, hash)
	assert.Zero(t, height)
	assert.Empty(t, txLog)
	assert.Zero(t, ptx.Nonce, "a dead request must not consume a nonce from the key's sequence")
	assert.Empty(t, ptx.Signature, "a dead request must not have been signed")

	mu.Lock()
	defer mu.Unlock()
	assert.Zero(t, broadcasts, "a cancelled request reached CometBFT")
}

// TestSignAndBroadcastCommitContextCancelledWhileQueuedNeverBroadcasts is the
// same contract one step later, and the one that actually exercises the queue:
// the request wins nothing, waits behind a live holder of the same key, and its
// browser tab closes. It must abandon the queue without signing, and — the part
// a wrong release would break — must leave the key usable for the next caller.
func TestSignAndBroadcastCommitContextCancelledWhileQueuedNeverBroadcasts(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	var (
		mu      sync.Mutex
		granted []string
	)
	holderIn := make(chan struct{})
	releaseHolder := make(chan struct{})
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grantee := "unknown"
		raw := strings.TrimPrefix(r.URL.Query().Get("tx"), "0x")
		if encoded, decodeErr := hex.DecodeString(raw); decodeErr == nil {
			if decoded, txErr := tx.DecodeTx(encoded); txErr == nil && decoded.AccessGrant != nil {
				grantee = decoded.AccessGrant.GranteeID
			}
		}
		mu.Lock()
		granted = append(granted, grantee)
		mu.Unlock()
		if grantee == "holder" {
			close(holderIn)
			<-releaseHolder
		}
		_, _ = w.Write([]byte(commitOKBody))
	}))
	t.Cleanup(rpc.Close)

	h := &DashboardHandler{CometBFTRPC: rpc.URL}
	granter := agentIDForKey(key)

	holderDone := make(chan struct{})
	go func() {
		defer close(holderDone)
		_, _, _, holderErr := h.signAndBroadcastCommitContext(
			context.Background(), accessGrantTx(granter, "holder"), key)
		assert.NoError(t, holderErr)
	}()
	select {
	case <-holderIn:
	case <-time.After(10 * time.Second):
		t.Fatal("the holding request never reached the node")
	}

	queuedCtx, cancelQueued := context.WithCancel(context.Background())
	queuedTx := accessGrantTx(granter, "queued")
	queuedErr := make(chan error, 1)
	go func() {
		_, _, _, sendErr := h.signAndBroadcastCommitContext(queuedCtx, queuedTx, key)
		queuedErr <- sendErr
	}()
	// Let the second request actually reach the lease queue before killing it.
	time.Sleep(100 * time.Millisecond)
	cancelQueued()

	select {
	case abandonErr := <-queuedErr:
		require.Error(t, abandonErr)
		assert.True(t, errors.Is(abandonErr, context.Canceled))
		assert.Contains(t, abandonErr.Error(), "await signing slot for this key")
	case <-time.After(10 * time.Second):
		t.Fatal("a cancelled request stayed queued on the key")
	}
	assert.Zero(t, queuedTx.Nonce, "a request cancelled while queued must not consume a nonce")

	close(releaseHolder)
	<-holderDone

	// The key must still be usable: an abandoned waiter that drained the
	// semaphore it never acquired would have stranded the slot here.
	_, _, _, afterErr := h.signAndBroadcastCommitContext(
		context.Background(), accessGrantTx(granter, "after"), key)
	require.NoError(t, afterErr)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"holder", "after"}, granted,
		"only the holder and the follow-up may reach the node")
}
