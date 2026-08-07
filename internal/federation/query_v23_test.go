package federation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/l33tdawg/sage/internal/auth"
	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
)

type v23GuestStoreFake struct {
	guests []store.FederatedGroupGuest
}

func (f v23GuestStoreFake) ListFederatedGroupGuests(context.Context, string, string) ([]store.FederatedGroupGuest, error) {
	return append([]store.FederatedGroupGuest(nil), f.guests...), nil
}

type v23GroupResolverFake map[string]map[string]bool

func (f v23GroupResolverFake) FederatedGuestGroupAllowsDomain(_ context.Context, groupID, domain string) (bool, error) {
	return f[groupID][domain], nil
}

func makeV23QueryFixture(t *testing.T) (*Manager, *peerIdentity, *store.CrossFedRecord, *QueryRequest) {
	return makeV23QueryFixtureWithAuthorizationTuple(t, true)
}

func makeV23QueryFixtureWithAuthorizationTuple(
	t *testing.T, includeAuthorizationTuple bool,
) (*Manager, *peerIdentity, *store.CrossFedRecord, *QueryRequest) {
	t.Helper()
	localPub, localKey, localKeyErr := ed25519.GenerateKey(rand.Reader)
	if localKeyErr != nil {
		t.Fatal(localKeyErr)
	}
	peerPub, _, peerKeyErr := ed25519.GenerateKey(rand.Reader)
	if peerKeyErr != nil {
		t.Fatal(peerKeyErr)
	}
	agentPub, agentKey, agentKeyErr := ed25519.GenerateKey(rand.Reader)
	if agentKeyErr != nil {
		t.Fatal(agentKeyErr)
	}
	companionPub, _, _ := ed25519.GenerateKey(rand.Reader)
	badger, badgerErr := store.NewBadgerStore(filepath.Join(t.TempDir(), "badger"))
	if badgerErr != nil {
		t.Fatal(badgerErr)
	}
	t.Cleanup(func() { _ = badger.CloseBadger() })
	if err := badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: hex.EncodeToString(localPub), Scope: "test-scope",
		AgentID: hex.EncodeToString(companionPub), Profile: store.AppV23ProfileStandard,
		HomeDomain: "local-companion", Clearance: 1, Capabilities: 0,
		Height: 1, BootstrapDigest: strings.Repeat("01", 32),
	}); err != nil {
		t.Fatal(err)
	}
	sqlite, sqliteErr := store.NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "federation.db"))
	if sqliteErr != nil {
		t.Fatal(sqliteErr)
	}
	t.Cleanup(func() { _ = sqlite.Close() })
	guestStore := v23GuestStoreFake{}
	resolver := v23GroupResolverFake{"g-research": {"research": true}}
	m := NewManager(Config{
		LocalChainID: "chain-b", CertsDir: t.TempDir(),
		AgentKey: localKey, Badger: badger, MemStore: sqlite,
		FederatedGuestStore: guestStore, LocalGroupResolver: resolver,
		QueryChallengeStore: sqlite, PostV23ForNextTx: func() bool { return true },
		Logger: zerolog.Nop(),
	})
	peer := &peerIdentity{ChainID: "chain-a", AgentID: hex.EncodeToString(peerPub)}
	agreement := &store.CrossFedRecord{
		RemoteChainID:  "chain-a",
		Endpoint:       "https://peer.example:8444",
		PeerPubKey:     append([]byte(nil), peerPub...),
		MaxClearance:   4,
		AllowedDomains: []string{"*"},
		Status:         "active",
	}
	if err := badger.SetCrossFed(
		agreement.RemoteChainID, agreement.Endpoint, agreement.PeerPubKey,
		agreement.MaxClearance, agreement.ExpiresAt, agreement.AllowedDomains,
		agreement.AllowedDepts, agreement.Status,
	); err != nil {
		t.Fatal(err)
	}
	peer.Agreement = agreement
	pin := hex.EncodeToString(agreement.PeerPubKey)
	if err := sqlite.PrepareSyncControl(context.Background(), store.SyncControl{
		RemoteChainID: "chain-a", Role: "host", ControllerChainID: "chain-b",
		ControllerAgentID: hex.EncodeToString(localPub), PeerAgentID: peer.AgentID,
		PolicyEpoch: "epoch-v23", RemoteCAPin: pin, PolicyVersion: SyncPolicyVersionPeerRBAC,
	}); err != nil {
		t.Fatal(err)
	}
	if err := sqlite.ActivateSyncControl(context.Background(), "chain-a", "epoch-v23"); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlite.ReplaceBoundPeerRBACPolicy(context.Background(), store.PeerRBACPolicy{
		RemoteChainID: "chain-a", PeerAgentID: peer.AgentID, PolicyEpoch: "epoch-v23",
		RemoteCAPin: pin, PolicyVersion: store.CurrentPeerRBACPolicyVersion,
		Domains: []store.PeerRBACDomainPermission{{Domain: "research", Read: true}},
	}); err != nil {
		t.Fatal(err)
	}
	commitSeed, rollbackSeed, stageErr := m.stageSeed("chain-a", []byte("0123456789abcdef0123456789abcdef"),
		[]byte("0123456789abcdef0123456789abcdef"), time.Now().Unix())
	if stageErr != nil {
		t.Fatal(stageErr)
	}
	t.Cleanup(rollbackSeed)
	if err := commitSeed(); err != nil {
		t.Fatal(err)
	}
	digest, digestErr := m.agreementBindingDigestV23(context.Background(), agreement, peer.AgentID)
	if digestErr != nil {
		t.Fatal(digestErr)
	}
	challenge := strings.Repeat("66", 32)
	if err := sqlite.IssueFederatedQueryChallenge(context.Background(), store.FederatedQueryChallenge{
		ChallengeID: challenge, RemoteChainID: "chain-a", PeerAgentID: peer.AgentID,
		RequestedAgentID: hex.EncodeToString(agentPub), DomainTag: "research",
		AgreementBindingDigest: digest, ExpiresAt: time.Now().Add(time.Minute).Unix(),
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	federationContext := map[string]any{
		"source_chain_id":    "chain-a",
		"agreement_bindings": map[string]string{"chain-b": digest},
		"query_challenges":   map[string]string{"chain-b": challenge},
	}
	if includeAuthorizationTuple {
		federationContext["authorization_models"] = map[string]string{"chain-b": ""}
		federationContext["authorization_attestations"] =
			map[string]SourceAuthorizationAttestation{"chain-b": {}}
	}
	signedBody, signedBodyErr := json.Marshal(map[string]any{
		"query":              "needle",
		"domain_tag":         "research",
		"top_k":              7,
		"tags":               []string{"reviewed"},
		"federated":          true,
		"federate_chains":    []string{"chain-b"},
		"federation_context": federationContext,
	})
	if signedBodyErr != nil {
		t.Fatal(signedBodyErr)
	}
	now := time.Now().Unix()
	nonce := []byte("0123456789abcdef")
	sig := auth.SignRequestWithNonce(agentKey, "POST", "/v1/memory/search", signedBody, now, nonce)
	req := &QueryRequest{
		ProtocolVersion:        FederationProtocolV23,
		SourceChainID:          "chain-a",
		DestinationChainID:     "chain-b",
		AgreementBindingDigest: digest,
		QueryChallenge:         challenge,
		AgentProof: &QueryAgentProof{
			AgentID:          hex.EncodeToString(agentPub),
			Signature:        sig,
			Timestamp:        now,
			Nonce:            nonce,
			CanonicalRequest: append([]byte("POST /v1/memory/search\n"), signedBody...),
		},
		Mode:      ModeText,
		Query:     "needle",
		DomainTag: "research",
		TopK:      7,
		Tags:      []string{"reviewed"},
	}
	guest := store.FederatedGroupGuest{
		GroupID:                "g-research",
		RemoteChainID:          "chain-a",
		RemoteAgentID:          req.AgentProof.AgentID,
		AgreementBindingDigest: digest,
		MaxClassification:      2,
		Revision:               1,
		State:                  store.FederatedGuestStateActive,
	}
	if err := store.SignFederatedGroupGuest(&guest, localKey); err != nil {
		t.Fatal(err)
	}
	if guest.AuthorizedBy != hex.EncodeToString(localPub) {
		t.Fatal("guest signer mismatch")
	}
	m.federatedGuestStore = v23GuestStoreFake{guests: []store.FederatedGroupGuest{guest}}
	return m, peer, agreement, req
}

func TestValidateQueryEnvelopeV23AndReplay(t *testing.T) {
	m, peer, agreement, req := makeV23QueryFixture(t)
	ceiling, err := m.validateQueryEnvelopeV23(context.Background(), peer, agreement, req)
	if err != nil || ceiling != 2 {
		t.Fatalf("valid query: ceiling=%d err=%v", ceiling, err)
	}
	if _, err := m.validateQueryEnvelopeV23(context.Background(), peer, agreement, req); err == nil ||
		!strings.Contains(err.Error(), "already consumed") {
		t.Fatalf("nested proof replay was not rejected: %v", err)
	}
}

func TestVerifyQueryAgentProofV23BindsEmbeddingProvider(t *testing.T) {
	for _, test := range []struct {
		name  string
		mode  string
		path  string
		query string
	}{
		{name: "semantic", mode: ModeSemantic, path: "/v1/memory/query"},
		{name: "hybrid", mode: ModeHybrid, path: "/v1/memory/hybrid", query: "needle"},
	} {
		t.Run(test.name, func(t *testing.T) {
			agentPub, agentKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			agentID := hex.EncodeToString(agentPub)
			const vectorSpace = "ollama:model-a:3"
			makeRequest := func(includeProvider bool) *QueryRequest {
				body := map[string]any{
					"query":           test.query,
					"embedding":       []float32{0.1, 0.2, 0.3},
					"domain_tag":      "research",
					"provider":        "caller-provider",
					"min_confidence":  0.4,
					"top_k":           7,
					"tags":            []string{"reviewed"},
					"federated":       true,
					"federate_chains": []string{"chain-b"},
					"federation_context": map[string]any{
						"source_chain_id":            "chain-a",
						"agreement_bindings":         map[string]string{"chain-b": "binding-v23"},
						"query_challenges":           map[string]string{"chain-b": "challenge-v23"},
						"authorization_models":       map[string]string{"chain-b": ""},
						"authorization_attestations": map[string]SourceAuthorizationAttestation{"chain-b": {}},
					},
				}
				embeddingProvider := ""
				if includeProvider {
					body["embedding_provider"] = vectorSpace
					embeddingProvider = vectorSpace
				}
				canonicalBody, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now().Unix()
				nonce := []byte("0123456789abcdef")
				return &QueryRequest{
					SourceChainID:          "chain-a",
					DestinationChainID:     "chain-b",
					AgreementBindingDigest: "binding-v23",
					QueryChallenge:         "challenge-v23",
					Mode:                   test.mode,
					Query:                  test.query,
					Embedding:              []float32{0.1, 0.2, 0.3},
					EmbeddingProvider:      embeddingProvider,
					Provider:               "caller-provider",
					DomainTag:              "research",
					MinConfidence:          0.4,
					TopK:                   7,
					Tags:                   []string{"reviewed"},
					AgentProof: &QueryAgentProof{
						AgentID: agentID,
						Signature: auth.SignRequestWithNonce(
							agentKey, http.MethodPost, test.path, canonicalBody, now, nonce,
						),
						Timestamp:        now,
						Nonce:            nonce,
						CanonicalRequest: append([]byte("POST "+test.path+"\n"), canonicalBody...),
					},
				}
			}

			manager := &Manager{}
			exact := makeRequest(true)
			if _, err := manager.verifyQueryAgentProofV23(time.Now(), exact); err != nil {
				t.Fatalf("exact signed embedding provider denied: %v", err)
			}

			tampered := makeRequest(true)
			tampered.EmbeddingProvider = "ollama:operator-substitution:3"
			if _, err := manager.verifyQueryAgentProofV23(time.Now(), tampered); err == nil ||
				!strings.Contains(err.Error(), "does not match") {
				t.Fatalf("unsigned embedding-provider substitution was not rejected: %v", err)
			}

			omitted := makeRequest(false)
			if _, err := manager.verifyQueryAgentProofV23(time.Now(), omitted); err == nil ||
				!strings.Contains(err.Error(), "omits embedding_provider") {
				t.Fatalf("signed embedding-provider omission was not rejected: %v", err)
			}
		})
	}
}

func TestValidateQueryEnvelopeV23RejectsWrongChainAndGeneration(t *testing.T) {
	t.Run("wrong destination", func(t *testing.T) {
		m, peer, agreement, req := makeV23QueryFixture(t)
		req.DestinationChainID = "chain-c"
		if _, err := m.validateQueryEnvelopeV23(context.Background(), peer, agreement, req); err == nil ||
			!strings.Contains(err.Error(), "chain binding") {
			t.Fatalf("wrong destination was not rejected: %v", err)
		}
	})
	t.Run("wrong generation", func(t *testing.T) {
		m, peer, agreement, req := makeV23QueryFixture(t)
		req.AgreementBindingDigest = strings.Repeat("00", 32)
		if _, err := m.validateQueryEnvelopeV23(context.Background(), peer, agreement, req); err == nil ||
			!strings.Contains(err.Error(), "generation") {
			t.Fatalf("wrong generation was not rejected: %v", err)
		}
	})
	t.Run("tampered query", func(t *testing.T) {
		m, peer, agreement, req := makeV23QueryFixture(t)
		req.Query = "different"
		if _, err := m.validateQueryEnvelopeV23(context.Background(), peer, agreement, req); err == nil ||
			!strings.Contains(err.Error(), "does not match") {
			t.Fatalf("tampered query was not rejected: %v", err)
		}
		// Authorization failures must not burn the destination challenge. The
		// correctly signed envelope can still consume it exactly once.
		req.Query = "needle"
		if _, err := m.validateQueryEnvelopeV23(context.Background(), peer, agreement, req); err != nil {
			t.Fatalf("failed envelope consumed challenge before authorization completed: %v", err)
		}
	})
	t.Run("tampered provider constraint", func(t *testing.T) {
		m, peer, agreement, req := makeV23QueryFixture(t)
		req.Provider = "substituted-provider"
		if _, err := m.validateQueryEnvelopeV23(context.Background(), peer, agreement, req); err == nil ||
			!strings.Contains(err.Error(), "does not match") {
			t.Fatalf("tampered provider was not rejected: %v", err)
		}
	})
}

func TestValidatePeerV23StatusRejectsLegacyAndIncompletePeers(t *testing.T) {
	valid := &StatusResponse{
		FederationProtocolVersion:   FederationProtocolV23,
		QueryAgreementBindingDigest: strings.Repeat("ab", 32),
		Capabilities: []string{
			CapabilityFederationV23,
			CapabilityQueryAgentProofV2,
		},
	}
	if err := validatePeerV23Status(valid); err != nil {
		t.Fatalf("valid v23 status: %v", err)
	}
	legacy := *valid
	legacy.FederationProtocolVersion = 0
	if err := validatePeerV23Status(&legacy); err == nil {
		t.Fatal("legacy peer status was accepted")
	}
	incomplete := *valid
	incomplete.Capabilities = []string{CapabilityFederationV23}
	if err := validatePeerV23Status(&incomplete); err == nil {
		t.Fatal("peer without nested-agent-proof capability was accepted")
	}
}

func TestFederatedGuestIsExactReadOnlyCapability(t *testing.T) {
	m, peer, agreement, req := makeV23QueryFixture(t)
	if ceiling, err := m.authorizeFederatedGuestRead(
		context.Background(), peer, agreement, req.AgentProof.AgentID, "research",
	); err != nil || ceiling != 2 {
		t.Fatalf("exact linked reader denied: ceiling=%d err=%v", ceiling, err)
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := m.authorizeFederatedGuestRead(
		context.Background(), peer, agreement, hex.EncodeToString(otherPub), "research",
	); err == nil {
		t.Fatal("unlinked foreign agent inherited another agent's linked-reader capability")
	}
	if _, err := m.authorizeFederatedGuestRead(
		context.Background(), peer, agreement, peer.AgentID, "research",
	); err == nil {
		t.Fatal("peer operator inherited the linked original agent's reader capability")
	}
	if _, err := m.authorizeFederatedGuestRead(
		context.Background(), peer, agreement, req.AgentProof.AgentID, "governance",
	); err == nil {
		t.Fatal("linked reader escaped its local group/domain intersection")
	}
	guestType := reflect.TypeOf(store.FederatedGroupGuest{})
	for _, forbidden := range []string{"Write", "Copy", "Modify", "Claim", "Govern"} {
		if _, exists := guestType.FieldByName(forbidden); exists {
			t.Fatalf("federated guest schema unexpectedly grants %s", forbidden)
		}
	}
}

func TestFederatedGuestSignedByHistoricalRootSurvivesRotation(t *testing.T) {
	m, peer, agreement, req := makeV23QueryFixture(t)
	if _, err := m.authorizeFederatedGuestRead(
		context.Background(), peer, agreement, req.AgentProof.AgentID, "research",
	); err != nil {
		t.Fatalf("current root-signed guest denied before rotation: %v", err)
	}

	newRootPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := m.badger.RotateAppV23RootCredential(
		1, hex.EncodeToString(newRootPub), 10,
	); err != nil {
		t.Fatal(err)
	}
	if ceiling, err := m.authorizeFederatedGuestRead(
		context.Background(), peer, agreement, req.AgentProof.AgentID, "research",
	); err != nil || ceiling != 2 {
		t.Fatalf("historical Root-signed guest lost authority after handover: ceiling=%d err=%v",
			ceiling, err)
	}
}

func TestFederatedDisclosureLeaseLinearizesRootRotationAndPreservesFrozenAuthority(t *testing.T) {
	m, peer, agreement, req := makeV23QueryFixture(t)
	if _, err := m.authorizeFederatedGuestRead(
		context.Background(), peer, agreement, req.AgentProof.AgentID, "research",
	); err != nil {
		t.Fatalf("current root-signed guest denied before rotation: %v", err)
	}

	// A disclosure holds the published-state read lease from authorization
	// through response serialization. Root rotation must take the matching
	// writer lease so it cannot commit while an old-root authorization is in
	// flight.
	unlockDisclosure := m.badger.LockDomainOwnershipRead()
	unlocked := false
	t.Cleanup(func() {
		if !unlocked {
			unlockDisclosure()
		}
	})

	newRootPub, _, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	rotationStarted := make(chan struct{})
	rotationDone := make(chan error, 1)
	go func() {
		close(rotationStarted)
		rotationDone <- m.badger.RotateAppV23RootCredential(
			1, hex.EncodeToString(newRootPub), 10,
		)
	}()
	<-rotationStarted

	select {
	case rotationErr := <-rotationDone:
		t.Fatalf("root rotation escaped the active disclosure lease: %v", rotationErr)
	case <-time.After(100 * time.Millisecond):
	}
	rootBeforeRelease, rootErr := m.badger.GetAppV23Root()
	if rootErr != nil {
		t.Fatal(rootErr)
	}
	if rootBeforeRelease.Generation != 1 {
		t.Fatalf("root rotation committed under disclosure lease: generation=%d", rootBeforeRelease.Generation)
	}

	unlockDisclosure()
	unlocked = true
	if rotationErr := <-rotationDone; rotationErr != nil {
		t.Fatal(rotationErr)
	}
	if ceiling, err := m.authorizeFederatedGuestRead(
		context.Background(), peer, agreement, req.AgentProof.AgentID, "research",
	); err != nil || ceiling != 2 {
		t.Fatalf("frozen Root authority did not survive completed handover: ceiling=%d err=%v",
			ceiling, err)
	}
}

func TestFederatedRecallAfterRootHandoverPreservesOldAndNewAuthorProvenance(t *testing.T) {
	m, peer, _, req := makeV23QueryFixture(t)
	rootBefore, rootErr := m.badger.GetAppV23Root()
	if rootErr != nil {
		t.Fatal(rootErr)
	}
	newRootPub, newRootKey, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	newRootID := hex.EncodeToString(newRootPub)
	if err := m.badger.RotateAppV23RootCredential(1, newRootID, 10); err != nil {
		t.Fatal(err)
	}

	// The old Root signature is immutable authority provenance. Handover must
	// not require rewriting the linked-reader row with the new Root key.
	_ = newRootKey

	sqlite := m.memStore.(*store.SQLiteStore)
	for _, record := range []*memory.MemoryRecord{
		{
			MemoryID: "before-root-handover", SubmittingAgent: rootBefore.CredentialID,
			Content:    "needle old root memory",
			MemoryType: memory.TypeFact, DomainTag: "research",
			ConfidenceScore: 0.9, Status: memory.StatusCommitted, CreatedAt: time.Now().UTC(),
		},
		{
			MemoryID: "after-root-handover", SubmittingAgent: newRootID,
			Content:    "needle new root memory",
			MemoryType: memory.TypeFact, DomainTag: "research",
			ConfidenceScore: 0.9, Status: memory.StatusCommitted, CreatedAt: time.Now().UTC(),
		},
	} {
		record.ContentHash = memory.ComputeContentHash(record.Content)
		if err := sqlite.InsertMemory(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		if err := sqlite.SetTags(context.Background(), record.MemoryID, []string{"reviewed"}); err != nil {
			t.Fatal(err)
		}
		publishFederationTestRecord(t, m.badger, record, 0)
		if err := m.badger.SetMemoryAuthorPrincipal(
			record.MemoryID, rootBefore.PrincipalID,
		); err != nil {
			t.Fatal(err)
		}
	}

	body, bodyErr := json.Marshal(req)
	if bodyErr != nil {
		t.Fatal(bodyErr)
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/fed/v1/query", bytes.NewReader(body))
	httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), peerCtxKey{}, peer))
	recorder := httptest.NewRecorder()
	m.handleQuery(recorder, httpReq)
	if recorder.Code != http.StatusOK {
		t.Fatalf("post-handover federated recall status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response QueryResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	authors := make(map[string]string, len(response.Results))
	for _, result := range response.Results {
		authors[result.MemoryID] = result.SubmittingAgent
	}
	if authors["before-root-handover"] != rootBefore.CredentialID {
		t.Fatalf("old author was rewritten: got %q want %q",
			authors["before-root-handover"], rootBefore.CredentialID)
	}
	if authors["after-root-handover"] != newRootID {
		t.Fatalf("new author lost current credential provenance: got %q want %q",
			authors["after-root-handover"], newRootID)
	}
}

func TestFederatedQueryRequiresLivePeerReadAndUnpausedPolicy(t *testing.T) {
	t.Run("active Read", func(t *testing.T) {
		m, peer, _, req := makeV23QueryFixture(t)
		body, _ := json.Marshal(req)
		httpReq := httptest.NewRequest(http.MethodPost, "/fed/v1/query", bytes.NewReader(body))
		httpReq = httpReq.WithContext(context.WithValue(
			httpReq.Context(), peerCtxKey{}, peer,
		))
		recorder := httptest.NewRecorder()
		m.handleQuery(recorder, httpReq)
		if recorder.Code != http.StatusOK {
			t.Fatalf("active Read status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})
	t.Run("paused", func(t *testing.T) {
		m, peer, _, req := makeV23QueryFixture(t)
		if _, err := m.SetPeerRBACPaused(context.Background(), "chain-a", true); err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(req)
		httpReq := httptest.NewRequest(http.MethodPost, "/fed/v1/query", bytes.NewReader(body))
		httpReq = httpReq.WithContext(context.WithValue(
			httpReq.Context(), peerCtxKey{}, peer,
		))
		recorder := httptest.NewRecorder()
		m.handleQuery(recorder, httpReq)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("paused status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})
	t.Run("Read removed", func(t *testing.T) {
		m, peer, _, req := makeV23QueryFixture(t)
		if _, err := m.ReplacePeerRBACPolicy(context.Background(), "chain-a", nil); err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(req)
		httpReq := httptest.NewRequest(http.MethodPost, "/fed/v1/query", bytes.NewReader(body))
		httpReq = httpReq.WithContext(context.WithValue(
			httpReq.Context(), peerCtxKey{}, peer,
		))
		recorder := httptest.NewRecorder()
		m.handleQuery(recorder, httpReq)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("removed Read status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})
}

func TestFederatedQueryRejectsOmittedLegacyAuthorizationTuple(t *testing.T) {
	m, peer, _, req := makeV23QueryFixtureWithAuthorizationTuple(t, false)
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/fed/v1/query", bytes.NewReader(body))
	httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), peerCtxKey{}, peer))
	recorder := httptest.NewRecorder()
	m.handleQuery(recorder, httpReq)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("omitted legacy authorization tuple status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "signed recall body does not authorize") {
		t.Fatalf("omitted legacy authorization tuple returned the wrong error: %s", recorder.Body.String())
	}
}
