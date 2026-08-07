package mcp

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/api/rest"
	"github.com/l33tdawg/sage/internal/auth"
	"github.com/l33tdawg/sage/internal/embedding"
	"github.com/l33tdawg/sage/internal/federation"
	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/metrics"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tlsca"
)

type mcpE2ENode struct {
	chainID  string
	certs    string
	caPEM    []byte
	manager  *federation.Manager
	badger   *store.BadgerStore
	sqlite   *store.SQLiteStore
	pub      ed25519.PublicKey
	private  ed25519.PrivateKey
	resolver mcpE2EGuestResolver
}

type mcpE2EGuestResolver map[string]map[string]bool

func (r mcpE2EGuestResolver) FederatedGuestGroupAllowsDomain(
	_ context.Context, groupID, domain string,
) (bool, error) {
	return r[groupID][domain], nil
}

func newMCPE2ENode(t *testing.T, chainID string) *mcpE2ENode {
	t.Helper()
	dir := t.TempDir()
	certs := filepath.Join(dir, "certs")
	caCert, caKey, err := tlsca.LoadOrGenerateCA(certs, chainID)
	require.NoError(t, err)
	nodeCert, nodeKey, err := tlsca.GenerateNodeCert(caCert, caKey, "node-"+chainID, nil)
	require.NoError(t, err)
	require.NoError(t, tlsca.WriteCert(filepath.Join(certs, tlsca.NodeCertFile), nodeCert))
	require.NoError(t, tlsca.WriteKey(filepath.Join(certs, tlsca.NodeKeyFile), nodeKey))
	badger, err := store.NewBadgerStore(filepath.Join(dir, "badger"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = badger.CloseBadger() })
	sqlite, err := store.NewSQLiteStore(context.Background(), filepath.Join(dir, "memory.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlite.Close() })
	pub, private, err := auth.GenerateKeypair()
	require.NoError(t, err)
	companion, _, err := auth.GenerateKeypair()
	require.NoError(t, err)
	require.NoError(t, badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: hex.EncodeToString(pub), Scope: "mcp-" + chainID,
		AgentID: hex.EncodeToString(companion), Profile: store.AppV23ProfileStandard,
		HomeDomain: "local-" + chainID, Clearance: 1, Capabilities: 0,
		Height: 1, BootstrapDigest: strings.Repeat("99", 32),
	}))
	resolver := mcpE2EGuestResolver{"mcp-linked-readers": {}}
	manager := federation.NewManager(federation.Config{
		LocalChainID:        chainID,
		CertsDir:            certs,
		AgentKey:            private,
		Badger:              badger,
		MemStore:            sqlite,
		FederatedGuestStore: sqlite,
		LocalGroupResolver:  resolver,
		QueryChallengeStore: sqlite,
		PostV23ForNextTx:    func() bool { return true },
		Logger:              zerolog.Nop(),
	})
	return &mcpE2ENode{
		chainID: chainID, certs: certs, caPEM: []byte(tlsca.EncodeCertPEM(caCert)),
		manager: manager, badger: badger, sqlite: sqlite, pub: pub,
		private: private, resolver: resolver,
	}
}

func setMCPE2EAgreement(t *testing.T, local, remote *mcpE2ENode, endpoint string, domains []string) {
	t.Helper()
	pin, err := local.manager.StoreRemoteCA(remote.chainID, remote.caPEM)
	require.NoError(t, err)
	require.NoError(t, local.badger.SetCrossFed(remote.chainID, endpoint, pin, 4, 0, domains, nil, "active"))
}

func startMCPE2EFederation(t *testing.T, node *mcpE2ENode) *httptest.Server {
	t.Helper()
	tlsConfig, err := node.manager.ServerTLSConfig()
	require.NoError(t, err)
	server := httptest.NewUnstartedServer(node.manager.Router())
	server.TLS = tlsConfig
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func enableMCPE2EV23Pair(t *testing.T, left, right *mcpE2ENode, domain string) {
	t.Helper()
	pair := []string{left.chainID, right.chainID}
	sort.Strings(pair)
	seed := sha256.Sum256([]byte(pair[0] + "\x00" + pair[1]))
	epoch := "mcp-v23-" + pair[0] + "-" + pair[1]
	for _, direction := range [][2]*mcpE2ENode{{left, right}, {right, left}} {
		local, remote := direction[0], direction[1]
		_, pin, _, _, _, _, _, err := local.badger.GetCrossFed(remote.chainID)
		require.NoError(t, err)
		require.NoError(t, local.sqlite.PrepareSyncControl(context.Background(), store.SyncControl{
			RemoteChainID: remote.chainID, Role: "host",
			ControllerChainID: local.chainID, ControllerAgentID: hex.EncodeToString(local.pub),
			PeerAgentID: hex.EncodeToString(remote.pub), PolicyEpoch: epoch,
			RemoteCAPin: hex.EncodeToString(pin), PolicyVersion: 3,
		}))
		require.NoError(t, local.sqlite.ActivateSyncControl(context.Background(), remote.chainID, epoch))
		_, err = local.sqlite.ReplaceBoundPeerRBACPolicy(context.Background(), store.PeerRBACPolicy{
			RemoteChainID: remote.chainID, PeerAgentID: hex.EncodeToString(remote.pub),
			PolicyEpoch: epoch, RemoteCAPin: hex.EncodeToString(pin),
			PolicyVersion: store.CurrentPeerRBACPolicyVersion,
			Domains:       []store.PeerRBACDomainPermission{{Domain: domain, Read: true}},
		})
		require.NoError(t, err)
		seedDir := filepath.Join(local.certs, "federation", remote.chainID)
		require.NoError(t, os.MkdirAll(seedDir, 0o700))
		envelope, err := json.Marshal(federation.TOTPSeedEnvelope{
			V: 1, Epoch: 1, SeedEstablished: true, BoundPinPair: seed[:],
			ChainID: remote.chainID, CreatedAt: time.Now().Unix(),
			Body: base64.StdEncoding.EncodeToString(seed[:]),
		})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(seedDir, "totp.seed.json"), envelope, 0o600))
		require.Equal(t, 1, local.manager.LoadSeedsIntoCache())
	}
}

func addMCPE2ELinkedReader(
	t *testing.T, destination, source *mcpE2ENode, agentID, domain string,
) {
	t.Helper()
	status, err := source.manager.PeerStatus(context.Background(), destination.chainID)
	require.NoError(t, err)
	require.Equal(t, 23, status.FederationProtocolVersion)
	destination.resolver["mcp-linked-readers"][domain] = true
	guest := store.FederatedGroupGuest{
		GroupID: "mcp-linked-readers", RemoteChainID: source.chainID,
		RemoteAgentID:          agentID,
		AgreementBindingDigest: status.QueryAgreementBindingDigest,
		MaxClassification:      4, Revision: 1, State: store.FederatedGuestStateActive,
	}
	require.NoError(t, store.SignFederatedGroupGuest(&guest, destination.private))
	require.NoError(t, destination.sqlite.PutFederatedGroupGuest(context.Background(), guest))
}

func enrollMCPE2EOrdinaryMember(
	t *testing.T, node *mcpE2ENode, name string, clearance uint8, active bool, domainAccess string,
) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, private, err := auth.GenerateKeypair()
	require.NoError(t, err)
	agentID := auth.PublicKeyToAgentID(pub)
	require.NoError(t, node.badger.RegisterAgentWithCapabilities(
		agentID, name, store.AppV23RoleMember, domainAccess, "codex", "", 2,
		0,
	))
	root, err := node.badger.GetAppV23Root()
	require.NoError(t, err)
	require.NotNil(t, root)
	require.NoError(t, node.badger.ApproveAppV23LocalAgent(store.AppV23LocalEnrollment{
		AgentID: agentID, ApprovedBy: root.CredentialID,
		RootGeneration: root.Generation, Profile: store.AppV23ProfileStandard,
		HomeDomain: "local-" + name, Clearance: clearance,
		Capabilities: 0,
		Active:       active, UpdatedHeight: 3,
	}, store.AppV23RoleMember, 0, 0))
	return agentID, private
}

func TestMCPOrdinaryAgentFederatedRecallTwoNodesEndToEnd(t *testing.T) {
	t.Setenv("SAGE_RECALL_HYBRID", "0")
	nodeA := newMCPE2ENode(t, "chain-a")
	nodeB := newMCPE2ENode(t, "chain-b")
	const benchmarkDomain = "sage-autoresearch-benchmark"
	setMCPE2EAgreement(t, nodeA, nodeB, "https://unused.invalid", []string{benchmarkDomain})
	aListener := startMCPE2EFederation(t, nodeA)
	setMCPE2EAgreement(t, nodeB, nodeA, aListener.URL, []string{benchmarkDomain})
	enableMCPE2EV23Pair(t, nodeA, nodeB, benchmarkDomain)

	content := "benchmark federation works end to end"
	contentHash := sha256.Sum256([]byte(content))
	require.NoError(t, nodeA.sqlite.InsertMemory(context.Background(), &memory.MemoryRecord{
		MemoryID:        "benchmark-a",
		SubmittingAgent: hex.EncodeToString(nodeA.pub),
		Content:         content,
		ContentHash:     contentHash[:],
		MemoryType:      memory.TypeFact,
		DomainTag:       benchmarkDomain,
		ConfidenceScore: .95,
		Status:          memory.StatusCommitted,
		CreatedAt:       time.Now(),
	}))
	require.NoError(t, nodeA.badger.SetMemoryHash(
		"benchmark-a", contentHash[:], string(memory.StatusCommitted),
	))
	require.NoError(t, nodeA.badger.SetMemoryDomain("benchmark-a", benchmarkDomain))
	require.NoError(t, nodeA.badger.SetMemoryAuthor(
		"benchmark-a", hex.EncodeToString(nodeA.pub),
	))
	require.NoError(t, nodeA.badger.SetMemoryClassification("benchmark-a", 2))
	localSecret := "same-name local secret must never ride a federation-only read"
	localSecretHash := sha256.Sum256([]byte(localSecret))
	require.NoError(t, nodeB.sqlite.InsertMemory(context.Background(), &memory.MemoryRecord{
		MemoryID: "local-secret-b", SubmittingAgent: hex.EncodeToString(nodeB.pub),
		Content: localSecret, ContentHash: localSecretHash[:], MemoryType: memory.TypeFact,
		DomainTag: benchmarkDomain, ConfidenceScore: .95, Status: memory.StatusCommitted,
		CreatedAt: time.Now(),
	}))
	require.NoError(t, nodeB.badger.SetMemoryHash(
		"local-secret-b", localSecretHash[:], string(memory.StatusCommitted),
	))
	require.NoError(t, nodeB.badger.SetMemoryDomain("local-secret-b", benchmarkDomain))
	require.NoError(t, nodeB.badger.SetMemoryAuthor("local-secret-b", hex.EncodeToString(nodeB.pub)))
	require.NoError(t, nodeB.badger.SetMemoryClassification("local-secret-b", 1))

	health := metrics.NewHealthChecker()
	// Keep the end-to-end federation gate hermetic: the MCP recall path probes
	// /v1/embed and must not depend on a developer or CI runner having Ollama.
	bREST := rest.NewServer("", nodeB.sqlite, nodeB.sqlite, nodeB.badger, health, zerolog.Nop(), embedding.NewHashProvider(768))
	bREST.SetFederation(nodeB.manager)
	bREST.SetNodeOperatorID(hex.EncodeToString(nodeB.pub))
	bREST.SetPostV23ForNextTxAccessor(func() bool { return true })
	bHTTP := httptest.NewServer(bREST.Router())
	t.Cleanup(bHTTP.Close)

	// Plain Standard Member: no ReadAll, no same-named local domain/grant, no
	// local Access Group, and no destination linked-reader row.
	ordinaryID, ordinaryKey := enrollMCPE2EOrdinaryMember(t, nodeB, "ordinary-b", 4, true, "")
	mcpB := NewServer(bHTTP.URL, ordinaryKey)
	discovery, err := mcpB.toolFederation(context.Background(), nil)
	require.NoError(t, err)
	connections := discovery.(map[string]any)["connections"].([]map[string]any)
	require.Len(t, connections, 1)
	assert.Equal(t, []any{benchmarkDomain}, connections[0]["shared_read_domains"])
	result, err := mcpB.toolRecall(context.Background(), map[string]any{
		"query":  "benchmark federation",
		"domain": benchmarkDomain,
		"scope":  "auto",
		"top_k":  float64(5),
	})
	require.NoError(t, err)
	memories := result.(map[string]any)["memories"].([]map[string]any)
	federationResult := result.(map[string]any)["federation"]
	require.Len(t, memories, 1, "recall result: %+v federation: %+v", result, federationResult)
	assert.Equal(t, "benchmark-a", memories[0]["memory_id"])
	assert.Equal(t, "chain-a", memories[0]["source_chain_id"])
	assert.Equal(t, "federated_live", memories[0]["source_kind"])
	assert.Equal(t, "external_untrusted", memories[0]["trust"])
	assert.NotEqual(t, "local-secret-b", memories[0]["memory_id"],
		"federation-only authority leaked a same-name local row")

	// Requester-side restrictions are local exceptions to the default read
	// contract. They must affect both discovery and the recall planner without
	// requiring the exporting peer to mirror any state.
	restriction, err := nodeB.manager.SetFederatedReaderRestriction(
		context.Background(), nodeA.chainID, ordinaryID,
		store.FederatedReaderRestrictionStateActive, false,
		[]string{benchmarkDomain}, 0,
	)
	require.NoError(t, err)
	require.Equal(t, int64(1), restriction.Revision)
	restrictedDiscovery, err := mcpB.toolFederation(context.Background(), nil)
	require.NoError(t, err)
	restrictedConnections := restrictedDiscovery.(map[string]any)["connections"].([]map[string]any)
	require.Len(t, restrictedConnections, 1)
	assert.Empty(t, restrictedConnections[0]["shared_read_domains"],
		"a denied domain must be filtered from discovery")
	_, err = mcpB.toolRecall(context.Background(), map[string]any{
		"query": "benchmark federation", "domain": benchmarkDomain, "scope": "auto",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no authorized v23 federation destination")
	assert.Contains(t, err.Error(), "local federation access controls deny this peer domain")

	revoked, err := nodeB.manager.SetFederatedReaderRestriction(
		context.Background(), nodeA.chainID, ordinaryID,
		store.FederatedReaderRestrictionStateRevoked, false, nil, 1,
	)
	require.NoError(t, err)
	require.Equal(t, int64(2), revoked.Revision)
	restoredDiscovery, err := mcpB.toolFederation(context.Background(), nil)
	require.NoError(t, err)
	restoredConnections := restoredDiscovery.(map[string]any)["connections"].([]map[string]any)
	require.Len(t, restoredConnections, 1)
	assert.Equal(t, []any{benchmarkDomain}, restoredConnections[0]["shared_read_domains"],
		"revoking the local exception must restore default read access")
	restoredResult, err := mcpB.toolRecall(context.Background(), map[string]any{
		"query": "benchmark federation", "domain": benchmarkDomain, "scope": "auto",
	})
	require.NoError(t, err)
	require.Len(t, restoredResult.(map[string]any)["memories"], 1)

	// A second ordinary Member gets the same peer export by default. No group is
	// mirrored onto this SAGE and no per-agent link is created at the destination.
	_, unlinkedKey := enrollMCPE2EOrdinaryMember(t, nodeB, "ordinary-b-2", 4, true, "")
	unlinkedMCP := NewServer(bHTTP.URL, unlinkedKey)
	unlinkedDiscovery, err := unlinkedMCP.toolFederation(context.Background(), nil)
	require.NoError(t, err)
	unlinkedConnections := unlinkedDiscovery.(map[string]any)["connections"].([]map[string]any)
	require.Len(t, unlinkedConnections, 1)
	assert.Equal(t, []any{benchmarkDomain}, unlinkedConnections[0]["read_candidate_domains"])
	assert.Equal(t, []any{benchmarkDomain}, unlinkedConnections[0]["shared_read_domains"],
		"ordinary peer agents inherit the directional export by default")
	assert.Equal(t, "verified", unlinkedConnections[0]["read_authorization"])
	unlinkedResult, err := unlinkedMCP.toolRecall(context.Background(), map[string]any{
		"query": "benchmark federation", "domain": benchmarkDomain, "scope": "auto",
	})
	require.NoError(t, err)
	require.Len(t, unlinkedResult.(map[string]any)["memories"], 1)

	// Source attestation carries the actual classification ceiling. A low-
	// clearance Member discovers the export but cannot receive its class-2 row.
	_, lowKey := enrollMCPE2EOrdinaryMember(t, nodeB, "ordinary-low", 1, true, "")
	lowMCP := NewServer(bHTTP.URL, lowKey)
	lowDiscovery, err := lowMCP.toolFederation(context.Background(), nil)
	require.NoError(t, err)
	lowConnections := lowDiscovery.(map[string]any)["connections"].([]map[string]any)
	require.Len(t, lowConnections, 1)
	assert.Equal(t, []any{benchmarkDomain}, lowConnections[0]["shared_read_domains"])
	lowResult, err := lowMCP.toolRecall(context.Background(), map[string]any{
		"query":  "benchmark federation",
		"domain": benchmarkDomain,
		"scope":  "auto",
	})
	require.NoError(t, err)
	assert.Empty(t, lowResult.(map[string]any)["memories"],
		"classification above the attested source clearance leaked")

	_, inactiveKey := enrollMCPE2EOrdinaryMember(t, nodeB, "ordinary-inactive", 4, false, "")
	inactiveMCP := NewServer(bHTTP.URL, inactiveKey)
	_, err = inactiveMCP.toolRecall(context.Background(), map[string]any{
		"query": "benchmark federation", "domain": benchmarkDomain, "scope": "auto",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "active ordinary agent")
}
