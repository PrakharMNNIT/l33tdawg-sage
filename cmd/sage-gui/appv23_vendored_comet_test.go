package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	cmtconfig "github.com/cometbft/cometbft/config"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	rpctypes "github.com/cometbft/cometbft/rpc/jsonrpc/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	sageabci "github.com/l33tdawg/sage/internal/abci"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
	"github.com/l33tdawg/sage/internal/vault"
)

const vendoredFirstMemoryContent = "Mynah real-Comet first memory"

type recordingGenesisApplication struct {
	abcitypes.Application

	mu            sync.Mutex
	infoVersions  []uint64
	initResponses []*abcitypes.ResponseInitChain
}

func (r *recordingGenesisApplication) Info(
	ctx context.Context,
	request *abcitypes.RequestInfo,
) (*abcitypes.ResponseInfo, error) {
	response, err := r.Application.Info(ctx, request)
	if response != nil {
		r.mu.Lock()
		r.infoVersions = append(r.infoVersions, response.AppVersion)
		r.mu.Unlock()
	}
	return response, err
}

func (r *recordingGenesisApplication) InitChain(
	ctx context.Context,
	request *abcitypes.RequestInitChain,
) (*abcitypes.ResponseInitChain, error) {
	response, err := r.Application.InitChain(ctx, request)
	if response != nil {
		r.mu.Lock()
		r.initResponses = append(r.initResponses, response)
		r.mu.Unlock()
	}
	return response, err
}

func (r *recordingGenesisApplication) snapshot() (
	[]uint64,
	[]*abcitypes.ResponseInitChain,
) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]uint64(nil), r.infoVersions...),
		append([]*abcitypes.ResponseInitChain(nil), r.initResponses...)
}

func vendoredCometConfig(cometHome string) *cmtconfig.Config {
	cfg := cmtconfig.DefaultConfig()
	cfg.SetRoot(cometHome)
	cfg.Moniker = "app-v23-genesis-test"
	cfg.RPC.ListenAddress = ""
	cfg.P2P.ListenAddress = "tcp://127.0.0.1:0"
	cfg.P2P.PexReactor = false
	cfg.P2P.AddrBookStrict = false
	cfg.Consensus.CreateEmptyBlocks = false
	// The KV transaction indexer owns a separate DB handle that CometBFT does
	// not close in Node.OnStop. It is irrelevant to this handshake test and
	// would make the same-process restart fail on its file lock.
	cfg.TxIndex.Indexer = "null"
	return cfg
}

func startVendoredCometTestNode(
	t *testing.T,
	cometHome, dataDir string,
	application abcitypes.Application,
) *SageNodeController {
	t.Helper()
	cfg := vendoredCometConfig(cometHome)
	pv := privval.LoadFilePV(
		cfg.PrivValidatorKeyFile(),
		cfg.PrivValidatorStateFile(),
	)
	nodeKey, err := p2p.LoadNodeKey(cfg.NodeKeyFile())
	require.NoError(t, err)
	controller := NewSageNodeController(
		cfg,
		application,
		pv,
		nodeKey,
		cmtlog.NewNopLogger(),
		zerolog.Nop(),
		dataDir,
	)
	require.NoError(t, controller.StartChain())
	return controller
}

func vendoredFirstMemoryRaw(
	t *testing.T,
	bootstrap *VendoredAgentBootstrapConfig,
) []byte {
	t.Helper()
	agentKey, ok := parseKeyFile(bootstrap.AgentKeyFile)
	require.True(t, ok)
	return vendoredMemoryRaw(
		t,
		agentKey,
		bootstrap.HomeDomain,
		vendoredFirstMemoryContent,
		1,
	)
}

func vendoredMemoryRaw(
	t *testing.T,
	agentKey ed25519.PrivateKey,
	domain, content string,
	nonce uint64,
) []byte {
	t.Helper()
	contentHash := sha256.Sum256([]byte(content))
	proofHash := sha256.Sum256([]byte(content + domain))
	proofTime := time.Now().Unix()
	var proofTimeBytes [8]byte
	binary.BigEndian.PutUint64(proofTimeBytes[:], uint64(proofTime))
	proofMessage := append(append([]byte(nil), proofHash[:]...), proofTimeBytes[:]...)
	parsed := &tx.ParsedTx{
		Type: tx.TxTypeMemorySubmit,
		MemorySubmit: &tx.MemorySubmit{
			ContentHash: contentHash[:], MemoryType: tx.MemoryTypeObservation,
			DomainTag: domain, ConfidenceScore: 0.9,
			Content: content, Classification: tx.ClearanceInternal,
		},
		AgentPubKey: agentKey.Public().(ed25519.PublicKey),
		AgentSig:    ed25519.Sign(agentKey, proofMessage), AgentBodyHash: proofHash[:],
		AgentTimestamp: proofTime, Nonce: nonce,
	}
	require.NoError(t, tx.SignTx(parsed, agentKey))
	raw, err := tx.EncodeTx(parsed)
	require.NoError(t, err)
	return raw
}

func vendoredRootRotationRaw(
	t *testing.T,
	oldRoot, newRoot ed25519.PrivateKey,
	scope string,
	expectedGeneration, nonce uint64,
) []byte {
	t.Helper()
	oldRootID := appV23AgentIDForKey(oldRoot)
	rotation := &tx.RootCredentialRotate{
		ExpectedGeneration: expectedGeneration,
		NewCredentialID:    appV23AgentIDForKey(newRoot),
		Scope:              scope,
	}
	rotation.NewCredentialSignature = ed25519.Sign(
		newRoot,
		tx.RootCredentialRotationSignBytes(oldRootID, rotation),
	)
	proofHash := sha256.Sum256([]byte("vendored real-Comet Root handover"))
	proofTime := time.Now().Unix()
	var proofTimeBytes [8]byte
	binary.BigEndian.PutUint64(proofTimeBytes[:], uint64(proofTime))
	proofMessage := append(append([]byte(nil), proofHash[:]...), proofTimeBytes[:]...)
	parsed := &tx.ParsedTx{
		Type:                 tx.TxTypeRootCredentialRotate,
		RootCredentialRotate: rotation,
		AgentPubKey:          oldRoot.Public().(ed25519.PublicKey),
		AgentSig:             ed25519.Sign(oldRoot, proofMessage),
		AgentBodyHash:        proofHash[:],
		AgentTimestamp:       proofTime,
		Nonce:                nonce,
	}
	require.NoError(t, tx.SignTx(parsed, oldRoot))
	raw, err := tx.EncodeTx(parsed)
	require.NoError(t, err)
	return raw
}

func TestVendoredAgentRealCometHandshakeStartsAtAppV23AndRestartsCleanly(t *testing.T) {
	runVendoredAgentRealCometHandshake(t, false)
}

func TestVendoredAgentRealCometEncryptedFirstMemoryAndRestart(t *testing.T) {
	runVendoredAgentRealCometHandshake(t, true)
}

func runVendoredAgentRealCometHandshake(t *testing.T, encrypted bool) {
	cometHome := t.TempDir()
	sageHome := t.TempDir()
	t.Setenv("SAGE_HOME", sageHome)
	rootKeyPath := filepath.Join(sageHome, "agent.key")
	bootstrap := &VendoredAgentBootstrapConfig{
		AgentKeyFile: filepath.Join(sageHome, "agents", "mynah", "agent.key"),
		HomeDomain:   "voice-interface",
		Clearance:    1,
	}
	require.NoError(t, initCometBFTConfigWithBootstrap(
		cometHome,
		rootKeyPath,
		bootstrap,
	))
	genesis, err := cmttypes.GenesisDocFromFile(
		filepath.Join(cometHome, "config", "genesis.json"),
	)
	require.NoError(t, err)

	badgerPath := filepath.Join(t.TempDir(), "badger")
	projectionPath := filepath.Join(t.TempDir(), "projection.db")
	app, badgerStore, projection := openVendoredTestApp(
		t,
		badgerPath,
		projectionPath,
	)
	var vaultKeyPath string
	if encrypted {
		vaultKeyPath = filepath.Join(t.TempDir(), "vault.key")
		require.NoError(t, vault.Init(vaultKeyPath, "vendored-comet-test"))
		unlocked, unlockErr := vault.Open(vaultKeyPath, "vendored-comet-test")
		require.NoError(t, unlockErr)
		projection.SetVaultExpected(true)
		require.True(t, projection.VaultLocked())
		lockedStatus := scopedProjectionReadinessStatus(0, projection.VaultLocked())
		require.True(t, lockedStatus.Required)
		require.False(t, lockedStatus.OK)
		projection.SetVault(unlocked)
		require.False(t, projection.VaultLocked())
		unlockedStatus := scopedProjectionReadinessStatus(0, projection.VaultLocked())
		require.False(t, unlockedStatus.Required)
		require.True(t, unlockedStatus.OK)
	}
	require.NoError(t, app.SetExpectedGovernanceDelegationDomain(genesis.ChainID))
	firstRecorder := &recordingGenesisApplication{Application: app}
	firstController := startVendoredCometTestNode(
		t,
		cometHome,
		filepath.Dir(badgerPath),
		firstRecorder,
	)
	t.Cleanup(func() { _ = firstController.StopChain() })
	firstInfo, firstInit := firstRecorder.snapshot()
	require.NotEmpty(t, firstInfo)
	require.Equal(t, uint64(1), firstInfo[0],
		"the fresh application constructor must honestly report its pre-Init version")
	require.Len(t, firstInit, 1)
	require.NotNil(t, firstInit[0].ConsensusParams)
	require.NotNil(t, firstInit[0].ConsensusParams.Version)
	require.Equal(t, sageabci.AppV23GenesisAppVersion, firstInit[0].ConsensusParams.Version.App)
	require.NotEmpty(t, firstInit[0].AppHash)
	rpcEnvironment, err := firstController.GetCometNode().ConfigureRPC()
	require.NoError(t, err)
	status, err := rpcEnvironment.Status(nil)
	require.NoError(t, err)
	require.Equal(t, sageabci.AppV23GenesisAppVersion, status.NodeInfo.ProtocolVersion.App)
	require.NoError(t, verifyAppV23VendoredAgentReadiness(
		bootstrap,
		exactVendoredKeyResolver(rootKeyPath),
		badgerStore,
	))
	rootKey, ok := parseKeyFile(rootKeyPath)
	require.True(t, ok)
	// Model the already-governed single-validator app-v24 plan. A
	// production-built current-Root heartbeat enters the mempool at activation
	// height H, fails execution because Root is never an ordinary agent, and
	// still advances the protocol to app-v24. The Companion transaction at H+1
	// is then the first safe write.
	require.NoError(t, badgerStore.SetUpgradePlan(&store.UpgradePlanRecord{
		Name: tx.CanonicalUpgradeName(24), TargetAppVersion: 24,
		ActivationHeight: 1, ProposedAt: 0,
	}))
	rawMemory := vendoredFirstMemoryRaw(t, bootstrap)
	heartbeatRaw, err := buildOperatorRegisterTx(upgradeWatchdogConfig{
		ResolveSigningKey: func() (ed25519.PrivateKey, error) {
			return rootKey, nil
		},
	})
	require.NoError(t, err)
	activation, err := rpcEnvironment.BroadcastTxCommit(
		&rpctypes.Context{},
		cmttypes.Tx(heartbeatRaw),
	)
	require.NoError(t, err)
	require.Zero(t, activation.CheckTx.Code, activation.CheckTx.Log)
	require.Equal(t, uint32(110), activation.TxResult.Code)
	require.Equal(t, "access denied", activation.TxResult.Log)
	status, err = rpcEnvironment.Status(nil)
	require.NoError(t, err)
	require.Equal(t, sageabci.AppV23GenesisAppVersion, status.NodeInfo.ProtocolVersion.App,
		"Comet advertises its handshake version until restart")
	activatedInfo, err := app.Info(context.Background(), &abcitypes.RequestInfo{})
	require.NoError(t, err)
	require.Equal(t, uint64(24), activatedInfo.AppVersion)

	broadcast, err := rpcEnvironment.BroadcastTxCommit(
		&rpctypes.Context{},
		cmttypes.Tx(rawMemory),
	)
	require.NoError(t, err)
	require.Zero(t, broadcast.CheckTx.Code, broadcast.CheckTx.Log)
	require.Zero(t, broadcast.TxResult.Code, broadcast.TxResult.Log)
	memoryID := string(broadcast.TxResult.Data)
	require.NotEmpty(t, memoryID)
	projected, err := projection.GetMemory(context.Background(), memoryID)
	require.NoError(t, err)
	require.Equal(t, bootstrap.HomeDomain, projected.DomainTag)
	_, _, err = badgerStore.GetMemoryHash(memoryID)
	require.NoError(t, err)
	originalTransportBytes, err := os.ReadFile(rootKeyPath)
	require.NoError(t, err)
	rootState, err := badgerStore.GetAppV23Root()
	require.NoError(t, err)
	preRotationRaw := vendoredMemoryRaw(
		t,
		rootKey,
		bootstrap.HomeDomain,
		"generation-one Root memory",
		1,
	)
	preRotationBroadcast, err := rpcEnvironment.BroadcastTxCommit(
		&rpctypes.Context{},
		cmttypes.Tx(preRotationRaw),
	)
	require.NoError(t, err)
	require.Zero(t, preRotationBroadcast.CheckTx.Code, preRotationBroadcast.CheckTx.Log)
	require.Zero(t, preRotationBroadcast.TxResult.Code, preRotationBroadcast.TxResult.Log)
	preRotationMemoryID := string(preRotationBroadcast.TxResult.Data)
	require.NotEmpty(t, preRotationMemoryID)

	replacementSeed := sha256.Sum256([]byte("vendored real-Comet replacement Root"))
	replacementRoot := ed25519.NewKeyFromSeed(replacementSeed[:])
	replacementID := appV23AgentIDForKey(replacementRoot)
	replacementPath := filepath.Join(sageHome, "bundles", replacementID, "agent.key")
	require.NoError(t, os.MkdirAll(filepath.Dir(replacementPath), 0o700))
	require.NoError(t, os.WriteFile(replacementPath, replacementSeed[:], 0o600))
	rotationRaw := vendoredRootRotationRaw(
		t,
		rootKey,
		replacementRoot,
		rootState.Scope,
		rootState.Generation,
		2,
	)
	rotationBroadcast, err := rpcEnvironment.BroadcastTxCommit(
		&rpctypes.Context{},
		cmttypes.Tx(rotationRaw),
	)
	require.NoError(t, err)
	require.Zero(t, rotationBroadcast.CheckTx.Code, rotationBroadcast.CheckTx.Log)
	require.Zero(t, rotationBroadcast.TxResult.Code, rotationBroadcast.TxResult.Log)
	require.NoError(t, verifyAppV23VendoredAgentReadiness(
		bootstrap,
		localAgentKeyResolverWithOperator(rootKeyPath),
		badgerStore,
	))
	transportAfterRotation, err := os.ReadFile(rootKeyPath)
	require.NoError(t, err)
	require.Equal(t, originalTransportBytes, transportAfterRotation)

	postRotationRaw := vendoredMemoryRaw(
		t,
		replacementRoot,
		bootstrap.HomeDomain,
		"generation-two Root memory",
		1,
	)
	postRotationBroadcast, err := rpcEnvironment.BroadcastTxCommit(
		&rpctypes.Context{},
		cmttypes.Tx(postRotationRaw),
	)
	require.NoError(t, err)
	require.Zero(t, postRotationBroadcast.CheckTx.Code, postRotationBroadcast.CheckTx.Log)
	require.Zero(t, postRotationBroadcast.TxResult.Code, postRotationBroadcast.TxResult.Log)
	postRotationMemoryID := string(postRotationBroadcast.TxResult.Data)
	require.NotEmpty(t, postRotationMemoryID)
	retiredRaw := vendoredMemoryRaw(
		t,
		rootKey,
		bootstrap.HomeDomain,
		"retired Root must not write",
		3,
	)
	retiredBroadcast, err := rpcEnvironment.BroadcastTxCommit(
		&rpctypes.Context{},
		cmttypes.Tx(retiredRaw),
	)
	require.NoError(t, err)
	require.Zero(t, retiredBroadcast.CheckTx.Code, retiredBroadcast.CheckTx.Log)
	require.NotZero(t, retiredBroadcast.TxResult.Code, retiredBroadcast.TxResult.Log)

	preRotationAuthor, err := badgerStore.GetMemoryAuthor(preRotationMemoryID)
	require.NoError(t, err)
	require.Equal(t, appV23AgentIDForKey(rootKey), preRotationAuthor)
	postRotationAuthor, err := badgerStore.GetMemoryAuthor(postRotationMemoryID)
	require.NoError(t, err)
	require.Equal(t, replacementID, postRotationAuthor)
	owner, err := badgerStore.GetDomainOwner(bootstrap.HomeDomain)
	require.NoError(t, err)
	require.Equal(t, appV23AgentIDForKey(agentKeyFromBootstrap(t, bootstrap)), owner)
	status, err = rpcEnvironment.Status(nil)
	require.NoError(t, err)
	require.GreaterOrEqual(t, status.SyncInfo.LatestBlockHeight, int64(1))
	require.NoError(t, firstController.StopChain())
	require.NoError(t, projection.Close())
	require.NoError(t, badgerStore.CloseBadger())
	if encrypted {
		projectionBytes, readErr := os.ReadFile(projectionPath)
		require.NoError(t, readErr)
		require.False(
			t,
			strings.Contains(string(projectionBytes), vendoredFirstMemoryContent),
			"encrypted projection must not retain the first memory as plaintext",
		)
	}

	// Restart through a new application and a new Comet node wrapper. The
	// dedicated marker and positive-height state must be loaded before Comet's
	// first Info. InitChain must not replay after the committed first memory.
	app, badgerStore, projection = openVendoredTestApp(
		t,
		badgerPath,
		projectionPath,
	)
	if encrypted {
		unlocked, unlockErr := vault.Open(vaultKeyPath, "vendored-comet-test")
		require.NoError(t, unlockErr)
		projection.SetVaultExpected(true)
		projection.SetVault(unlocked)
	}
	t.Cleanup(func() {
		require.NoError(t, projection.Close())
		require.NoError(t, badgerStore.CloseBadger())
	})
	require.NoError(t, app.SetExpectedGovernanceDelegationDomain(genesis.ChainID))
	secondRecorder := &recordingGenesisApplication{Application: app}
	secondController := startVendoredCometTestNode(
		t,
		cometHome,
		filepath.Dir(badgerPath),
		secondRecorder,
	)
	t.Cleanup(func() { require.NoError(t, secondController.StopChain()) })
	secondInfo, secondInit := secondRecorder.snapshot()
	require.NotEmpty(t, secondInfo)
	require.Equal(t, uint64(24), secondInfo[0])
	require.Empty(t, secondInit)
	secondRPC, err := secondController.GetCometNode().ConfigureRPC()
	require.NoError(t, err)
	secondStatus, err := secondRPC.Status(nil)
	require.NoError(t, err)
	require.Equal(t, uint64(24), secondStatus.NodeInfo.ProtocolVersion.App)
	require.GreaterOrEqual(t, secondStatus.SyncInfo.LatestBlockHeight, int64(1))
	projected, err = projection.GetMemory(context.Background(), memoryID)
	require.NoError(t, err)
	require.Equal(t, bootstrap.HomeDomain, projected.DomainTag)
	projected, err = projection.GetMemory(context.Background(), preRotationMemoryID)
	require.NoError(t, err)
	require.Equal(t, appV23AgentIDForKey(rootKey), projected.SubmittingAgent)
	projected, err = projection.GetMemory(context.Background(), postRotationMemoryID)
	require.NoError(t, err)
	require.Equal(t, replacementID, projected.SubmittingAgent)
	_, _, err = badgerStore.GetMemoryHash(memoryID)
	require.NoError(t, err)
	require.NoError(t, verifyAppV23VendoredAgentReadiness(
		bootstrap,
		localAgentKeyResolverWithOperator(rootKeyPath),
		badgerStore,
	))
	rootAfterRestart, err := badgerStore.GetAppV23Root()
	require.NoError(t, err)
	require.Equal(t, appV23AgentIDForKey(rootKey), rootAfterRestart.PrincipalID)
	require.Equal(t, replacementID, rootAfterRestart.CredentialID)
	require.Equal(t, uint64(2), rootAfterRestart.Generation)
	transportAfterRestart, err := os.ReadFile(rootKeyPath)
	require.NoError(t, err)
	require.Equal(t, originalTransportBytes, transportAfterRestart)
}

func agentKeyFromBootstrap(
	t *testing.T,
	bootstrap *VendoredAgentBootstrapConfig,
) ed25519.PrivateKey {
	t.Helper()
	key, ok := parseKeyFile(bootstrap.AgentKeyFile)
	require.True(t, ok)
	return key
}
