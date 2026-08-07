package federation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/auth"
	"github.com/l33tdawg/sage/internal/store"
)

func enableV23Pair(t *testing.T, left, right *testChain, domains []string) {
	t.Helper()
	for _, node := range []*testChain{left, right} {
		companion, _, _ := ed25519.GenerateKey(nil)
		if err := node.badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
			RootID: hex.EncodeToString(node.agentPub), Scope: "test-" + node.chainID,
			AgentID: hex.EncodeToString(companion), Profile: store.AppV23ProfileStandard,
			HomeDomain: "local-" + node.chainID, Clearance: 1, Capabilities: 0,
			Height: 1, BootstrapDigest: strings.Repeat("88", 32),
		}); err != nil {
			t.Fatal(err)
		}
		sqlite := node.mem.(*store.SQLiteStore)
		node.mgr.federatedGuestStore = sqlite
		node.mgr.queryChallengeStore = sqlite
		node.mgr.localGroupResolver = v23GroupResolverFake{"v23-test-readers": {}}
		node.mgr.postV23ForNextTx = func() bool { return true }
	}
	pair := []string{left.chainID, right.chainID}
	sort.Strings(pair)
	seed := sha256.Sum256([]byte(pair[0] + "\x00" + pair[1]))
	epoch := "v23-" + pair[0] + "-" + pair[1]
	for _, direction := range [][2]*testChain{{left, right}, {right, left}} {
		local, remote := direction[0], direction[1]
		agreement, agreementErr := local.mgr.ActiveAgreement(remote.chainID)
		if agreementErr != nil {
			t.Fatal(agreementErr)
		}
		sqlite := local.mem.(*store.SQLiteStore)
		if err := sqlite.PrepareSyncControl(context.Background(), store.SyncControl{
			RemoteChainID: remote.chainID, Role: "host",
			ControllerChainID: local.chainID,
			ControllerAgentID: hex.EncodeToString(local.agentPub),
			PeerAgentID:       hex.EncodeToString(remote.agentPub),
			PolicyEpoch:       epoch, RemoteCAPin: hex.EncodeToString(agreement.PeerPubKey),
			PolicyVersion: SyncPolicyVersionPeerRBAC,
		}); err != nil {
			t.Fatal(err)
		}
		if err := sqlite.ActivateSyncControl(context.Background(), remote.chainID, epoch); err != nil {
			t.Fatal(err)
		}
		grants := make([]store.PeerRBACDomainPermission, 0, len(domains))
		for _, domain := range domains {
			grants = append(grants, store.PeerRBACDomainPermission{Domain: domain, Read: true})
		}
		if _, err := sqlite.ReplaceBoundPeerRBACPolicy(context.Background(), store.PeerRBACPolicy{
			RemoteChainID: remote.chainID, PeerAgentID: hex.EncodeToString(remote.agentPub),
			PolicyEpoch: epoch, RemoteCAPin: hex.EncodeToString(agreement.PeerPubKey),
			PolicyVersion: store.CurrentPeerRBACPolicyVersion, Domains: grants,
		}); err != nil {
			t.Fatal(err)
		}
		commit, rollback, stageErr := local.mgr.stageSeed(
			remote.chainID, seed[:], seed[:], time.Now().Unix(),
		)
		if stageErr != nil {
			t.Fatal(stageErr)
		}
		t.Cleanup(rollback)
		if err := commit(); err != nil {
			t.Fatal(err)
		}
	}
}

func addV23TestGuest(
	t *testing.T,
	destination, source *testChain,
	agentID, domain string,
	maxClassification uint8,
) {
	t.Helper()
	agreement, err := destination.mgr.ActiveAgreement(source.chainID)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := destination.mgr.agreementBindingDigestV23(
		context.Background(), agreement, hex.EncodeToString(source.agentPub),
	)
	if err != nil {
		t.Fatal(err)
	}
	resolver := destination.mgr.localGroupResolver.(v23GroupResolverFake)
	resolver["v23-test-readers"][domain] = true
	guest := store.FederatedGroupGuest{
		GroupID: "v23-test-readers", RemoteChainID: source.chainID,
		RemoteAgentID: agentID, AgreementBindingDigest: digest,
		MaxClassification: maxClassification, Revision: 1,
		State: store.FederatedGuestStateActive,
	}
	if err := store.SignFederatedGroupGuest(&guest, destination.agentKey); err != nil {
		t.Fatal(err)
	}
	if err := destination.mem.(*store.SQLiteStore).PutFederatedGroupGuest(
		context.Background(), guest,
	); err != nil {
		t.Fatal(err)
	}
}

func planAndSignV23Query(
	t *testing.T,
	source, destination *testChain,
	request *QueryRequest,
) *QueryRequest {
	t.Helper()
	callerPub, callerKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	callerID := hex.EncodeToString(callerPub)
	enrollV23SourceReadAllAdmin(t, source, "federated-query-caller", callerPub, 20)
	addV23TestGuest(t, destination, source, callerID, request.DomainTag, 4)
	plan, err := source.mgr.PlanRecall(
		context.Background(), []string{destination.chainID}, callerID, request.DomainTag,
	)
	if err != nil || len(plan.Destinations) != 1 {
		t.Fatalf("plan recall: plan=%+v err=%v", plan, err)
	}
	path := "/v1/memory/search"
	switch request.Mode {
	case ModeSemantic:
		path = "/v1/memory/query"
	case ModeHybrid:
		path = "/v1/memory/hybrid"
	}
	signedBody := map[string]any{
		"query": request.Query, "embedding": request.Embedding,
		"domain_tag": request.DomainTag, "provider": request.Provider,
		"min_confidence": request.MinConfidence, "top_k": request.TopK,
		"tags": request.Tags, "federated": true,
		"federate_chains": plan.Destinations,
		"federation_context": map[string]any{
			"source_chain_id":    plan.SourceChainID,
			"agreement_bindings": plan.AgreementBindings,
			"query_challenges":   plan.QueryChallenges,
		},
	}
	if request.EmbeddingProvider != "" {
		signedBody["embedding_provider"] = request.EmbeddingProvider
	}
	body, err := json.Marshal(signedBody)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	nonce := []byte("0123456789abcdef")
	request.AgentProof = &QueryAgentProof{
		AgentID: callerID,
		Signature: auth.SignRequestWithNonce(
			callerKey, "POST", path, body, now, nonce,
		),
		Timestamp: now, Nonce: nonce,
		CanonicalRequest: append([]byte("POST "+path+"\n"), body...),
	}
	request.PlanAgreementBindings = plan.AgreementBindings
	request.PlanChallenges = plan.QueryChallenges
	return request
}
