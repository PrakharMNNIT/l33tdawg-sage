package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

type testAppV23RootReader struct {
	root *store.AppV23RootState
	err  error
}

func (r *testAppV23RootReader) GetAppV23Root() (*store.AppV23RootState, error) {
	return r.root, r.err
}

func testAgentKey(t *testing.T, seedByte byte) (ed25519.PrivateKey, string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	key := ed25519.NewKeyFromSeed(seed)
	return key, hex.EncodeToString(key.Public().(ed25519.PublicKey))
}

func writeTestAgentKey(t *testing.T, path string, key ed25519.PrivateKey) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, key, 0o600))
}

func TestParseKeyFileRejectsIncoherentExpandedEd25519Key(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.key")
	key, _ := testAgentKey(t, 0x10)
	require.NoError(t, os.WriteFile(path, key, 0o600))
	parsed, ok := parseKeyFile(path)
	require.True(t, ok)
	require.Equal(t, key, parsed)

	corrupt := append([]byte(nil), key...)
	corrupt[len(corrupt)-1] ^= 0xff
	require.NoError(t, os.WriteFile(path, corrupt, 0o600))
	parsed, ok = parseKeyFile(path)
	require.False(t, ok)
	require.Nil(t, parsed)
}

func TestLocalAgentKeyResolverCachesMissPerAgent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SAGE_HOME", home)
	nowAt := time.Unix(1_700_000_000, 0)
	resolver := localAgentKeyResolverWithOperatorCache(
		filepath.Join(home, "agent.key"),
		time.Second,
		func() time.Time { return nowAt },
	)

	keyA, agentA := testAgentKey(t, 0x11)
	_, agentB := testAgentKey(t, 0x22)
	require.False(t, keyFound(resolver(agentA)))

	// Adding the key does not defeat the negative-cache bound for agent A.
	writeTestAgentKey(t, filepath.Join(home, "agents", "a", "agent.key"), keyA)
	require.False(t, keyFound(resolver(agentA)))

	// Agent A's fresh miss must not globally rate-limit a distinct identity.
	keyB, _ := testAgentKey(t, 0x22)
	writeTestAgentKey(t, filepath.Join(home, "agents", "b", "agent.key"), keyB)
	require.True(t, keyFound(resolver(agentB)))

	nowAt = nowAt.Add(time.Second)
	require.True(t, keyFound(resolver(agentA)))
}

func TestLocalAgentKeyResolverFindsCEREBRUMBundleKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SAGE_HOME", home)
	operatorKey, _ := testAgentKey(t, 0x51)
	writeTestAgentKey(t, filepath.Join(home, "agent.key"), operatorKey)
	bundleKey, bundleID := testAgentKey(t, 0x52)
	writeTestAgentKey(t, filepath.Join(home, "bundles", bundleID, "agent.key"), bundleKey)

	resolver := localAgentKeyResolverWithOperator(filepath.Join(home, "agent.key"))
	resolved, ok := resolver(bundleID)
	require.True(t, ok)
	require.Equal(t, bundleKey, resolved)
}

func TestLocalAgentKeyResolverFindsSDKManagedIdentity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SAGE_HOME", home)
	operatorKey, _ := testAgentKey(t, 0x53)
	writeTestAgentKey(t, filepath.Join(home, "agent.key"), operatorKey)
	identityKey, identityID := testAgentKey(t, 0x54)
	writeTestAgentKey(
		t,
		filepath.Join(home, "identities", "agent-01.key"),
		identityKey,
	)

	resolver := localAgentKeyResolverWithOperator(filepath.Join(home, "agent.key"))
	resolved, ok := resolver(identityID)
	require.True(t, ok)
	require.Equal(t, identityKey, resolved)
}

func TestLocalAgentKeyResolverDoesNotFollowSDKIdentitySymlinks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SAGE_HOME", home)
	externalKey, externalID := testAgentKey(t, 0x55)
	externalPath := filepath.Join(t.TempDir(), "external.key")
	writeTestAgentKey(t, externalPath, externalKey)
	require.NoError(t, os.MkdirAll(filepath.Join(home, "identities"), 0o700))
	require.NoError(t, os.Symlink(
		externalPath,
		filepath.Join(home, "identities", "linked.key"),
	))

	resolver := localAgentKeyResolverWithOperator(filepath.Join(home, "agent.key"))
	_, ok := resolver(externalID)
	require.False(t, ok)
}

func TestLocalAgentKeyResolverExpiresRotatedPositive(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SAGE_HOME", home)
	path := filepath.Join(home, "agents", "rotating", "agent.key")
	oldKey, oldAgent := testAgentKey(t, 0x33)
	newKey, newAgent := testAgentKey(t, 0x44)
	writeTestAgentKey(t, path, oldKey)

	nowAt := time.Unix(1_700_000_000, 0)
	resolver := localAgentKeyResolverWithOperatorCache(
		filepath.Join(home, "agent.key"),
		time.Second,
		func() time.Time { return nowAt },
	)
	require.True(t, keyFound(resolver(oldAgent)))

	writeTestAgentKey(t, path, newKey)
	require.True(t, keyFound(resolver(oldAgent)), "positive answers may remain valid only for the bounded TTL")
	require.True(t, keyFound(resolver(newAgent)), "a different identity gets its own immediate freshness check")

	nowAt = nowAt.Add(time.Second)
	require.False(t, keyFound(resolver(oldAgent)), "rotated identity must disappear when its own cache entry expires")
}

func TestCurrentUpgradeSigningKeyTracksRotatedRootBundle(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SAGE_HOME", home)
	oldKey, oldID := testAgentKey(t, 0x61)
	newKey, newID := testAgentKey(t, 0x62)
	operatorPath := filepath.Join(home, "agent.key")
	writeTestAgentKey(t, operatorPath, oldKey)
	writeTestAgentKey(t, filepath.Join(home, "bundles", newID, "agent.key"), newKey)

	state := &testAppV23RootReader{root: &store.AppV23RootState{
		PrincipalID: oldID, CredentialID: oldID, Generation: 1,
	}}
	resolver := localAgentKeyResolverWithOperator(operatorPath)
	cfg := upgradeWatchdogConfig{
		ResolveSigningKey: func() (ed25519.PrivateKey, error) {
			return currentUpgradeSigningKey(state, func() bool { return true }, resolver, operatorPath, zerolog.Nop())
		},
	}

	before, err := buildUpgradeProposeTx(cfg, 23)
	require.NoError(t, err)
	require.Equal(t, oldID, before.UpgradePropose.ProposerID)
	beforeHeartbeatRaw, err := buildOperatorRegisterTx(cfg)
	require.NoError(t, err)
	beforeHeartbeat, err := tx.DecodeTx(beforeHeartbeatRaw)
	require.NoError(t, err)
	require.Equal(t, ed25519.PublicKey(oldKey.Public().(ed25519.PublicKey)), ed25519.PublicKey(beforeHeartbeat.AgentPubKey))
	require.Equal(t, ed25519.PublicKey(oldKey.Public().(ed25519.PublicKey)), ed25519.PublicKey(beforeHeartbeat.PublicKey))

	state.root = &store.AppV23RootState{
		PrincipalID: oldID, CredentialID: newID, Generation: 2,
	}
	after, err := buildUpgradeProposeTx(cfg, 24)
	require.NoError(t, err)
	require.Equal(t, newID, after.UpgradePropose.ProposerID)
	require.Equal(t, ed25519.PublicKey(newKey.Public().(ed25519.PublicKey)), ed25519.PublicKey(after.AgentPubKey))
	afterHeartbeatRaw, err := buildOperatorRegisterTx(cfg)
	require.NoError(t, err)
	afterHeartbeat, err := tx.DecodeTx(afterHeartbeatRaw)
	require.NoError(t, err)
	require.Equal(t, ed25519.PublicKey(newKey.Public().(ed25519.PublicKey)), ed25519.PublicKey(afterHeartbeat.AgentPubKey))
	require.Equal(t, ed25519.PublicKey(newKey.Public().(ed25519.PublicKey)), ed25519.PublicKey(afterHeartbeat.PublicKey))
}

func TestCurrentUpgradeSigningKeyFailsClosedAfterRootRotation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SAGE_HOME", home)
	oldKey, oldID := testAgentKey(t, 0x71)
	_, newID := testAgentKey(t, 0x72)
	operatorPath := filepath.Join(home, "agent.key")
	writeTestAgentKey(t, operatorPath, oldKey)

	state := &testAppV23RootReader{root: &store.AppV23RootState{
		PrincipalID: oldID, CredentialID: newID, Generation: 2,
	}}
	_, err := currentUpgradeSigningKey(
		state,
		func() bool { return true },
		localAgentKeyResolverWithOperator(operatorPath),
		operatorPath,
		zerolog.Nop(),
	)
	require.ErrorContains(t, err, "not held on this machine")
}

func TestCurrentUpgradeSigningKeyDoesNotFallbackWithoutV23Root(t *testing.T) {
	home := t.TempDir()
	oldKey, _ := testAgentKey(t, 0x73)
	operatorPath := filepath.Join(home, "agent.key")
	writeTestAgentKey(t, operatorPath, oldKey)

	_, err := currentUpgradeSigningKey(
		&testAppV23RootReader{},
		func() bool { return true },
		localAgentKeyResolverWithOperator(operatorPath),
		operatorPath,
		zerolog.Nop(),
	)
	require.ErrorContains(t, err, "no committed CEREBRUM Root")
}

func keyFound(_ ed25519.PrivateKey, ok bool) bool {
	return ok
}
