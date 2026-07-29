package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/l33tdawg/sage/internal/auth"
	"github.com/l33tdawg/sage/internal/store"
)

const queryAgentProofMaxSkew = 5 * time.Minute

type signedRecallBody struct {
	Query             string                   `json:"query"`
	Embedding         []float32                `json:"embedding"`
	EmbeddingProvider string                   `json:"embedding_provider"`
	DomainTag         string                   `json:"domain_tag"`
	MinConfidence     float64                  `json:"min_confidence"`
	TopK              int                      `json:"top_k"`
	Tags              []string                 `json:"tags"`
	Provider          string                   `json:"provider"`
	Federated         bool                     `json:"federated"`
	FederateChains    []string                 `json:"federate_chains"`
	FederationContext *signedFederationContext `json:"federation_context"`
}

type signedFederationContext struct {
	SourceChainID     string            `json:"source_chain_id"`
	AgreementBindings map[string]string `json:"agreement_bindings"`
	QueryChallenges   map[string]string `json:"query_challenges"`
}

func splitCanonicalAgentRequest(canonical []byte) (method, path string, body []byte, err error) {
	lineEnd := bytes.IndexByte(canonical, '\n')
	if lineEnd <= 0 {
		return "", "", nil, errors.New("agent canonical request is malformed")
	}
	requestLine := string(canonical[:lineEnd])
	parts := strings.Split(requestLine, " ")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", nil, errors.New("agent canonical request line is malformed")
	}
	return parts[0], parts[1], canonical[lineEnd+1:], nil
}

func containsExactChain(chains []string, destination string) bool {
	if len(chains) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(chains))
	for _, chain := range chains {
		if chain == "*" || chain == "" || chain != strings.TrimSpace(chain) {
			return false
		}
		if _, duplicate := seen[chain]; duplicate {
			return false
		}
		seen[chain] = struct{}{}
	}
	_, ok := seen[destination]
	return ok
}

func queryModeForSignedPath(path string, body signedRecallBody) (string, error) {
	switch path {
	case "/v1/memory/query":
		if body.Query != "" {
			return ModeHybrid, nil
		}
		return ModeSemantic, nil
	case "/v1/memory/search":
		return ModeText, nil
	case "/v1/memory/hybrid":
		return ModeHybrid, nil
	default:
		return "", errors.New("agent proof is not for a recall endpoint")
	}
}

func (m *Manager) verifyQueryAgentProofV23(now time.Time, req *QueryRequest) (string, error) {
	if req == nil || req.AgentProof == nil {
		return "", errors.New("v23 agent proof is required")
	}
	proof := req.AgentProof
	// SAGE's authenticated REST contract uses an 8-byte random X-Nonce. Keep
	// v23 proof verification aligned with that canonical client contract: the
	// destination-issued 32-byte query challenge supplies the stronger
	// single-use authorization primitive for a federated disclosure.
	if len(proof.Nonce) < 8 || len(proof.Nonce) > 64 {
		return "", errors.New("v23 agent proof nonce must be 8 to 64 bytes")
	}
	if len(proof.Signature) != 64 {
		return "", errors.New("v23 agent proof signature is invalid")
	}
	if delta := now.Sub(time.Unix(proof.Timestamp, 0)); delta > queryAgentProofMaxSkew || delta < -queryAgentProofMaxSkew {
		return "", errors.New("v23 agent proof timestamp is outside the freshness window")
	}
	pub, err := auth.AgentIDToPublicKey(proof.AgentID)
	if err != nil || proof.AgentID != strings.ToLower(proof.AgentID) {
		return "", errors.New("v23 agent id is invalid")
	}
	method, path, body, err := splitCanonicalAgentRequest(proof.CanonicalRequest)
	if err != nil {
		return "", err
	}
	if method != http.MethodPost || strings.Contains(path, "?") {
		return "", errors.New("v23 agent proof must be an exact POST recall request")
	}
	if !auth.VerifyRequestWithNonce(pub, method, path, body, proof.Timestamp, proof.Nonce, proof.Signature) {
		return "", errors.New("v23 agent proof signature verification failed")
	}
	var signed signedRecallBody
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decodeErr := decoder.Decode(&signed); decodeErr != nil {
		return "", errors.New("v23 signed recall body is invalid")
	}
	if trailingErr := decoder.Decode(&struct{}{}); !errors.Is(trailingErr, io.EOF) {
		return "", errors.New("v23 signed recall body contains trailing JSON")
	}
	if !signed.Federated || !containsExactChain(signed.FederateChains, req.DestinationChainID) {
		return "", errors.New("v23 signed recall body does not authorize this exact destination")
	}
	if signed.FederationContext == nil ||
		signed.FederationContext.SourceChainID != req.SourceChainID ||
		signed.FederationContext.AgreementBindings[req.DestinationChainID] != req.AgreementBindingDigest ||
		signed.FederationContext.QueryChallenges[req.DestinationChainID] != req.QueryChallenge {
		return "", errors.New("v23 signed recall body does not authorize this source, agreement generation, and challenge")
	}
	mode, err := queryModeForSignedPath(path, signed)
	if err != nil {
		return "", err
	}
	if mode != req.Mode || signed.Query != req.Query || signed.DomainTag != req.DomainTag ||
		signed.Provider != req.Provider ||
		signed.EmbeddingProvider != req.EmbeddingProvider ||
		signed.MinConfidence != req.MinConfidence || signed.TopK != req.TopK ||
		!reflect.DeepEqual(signed.Embedding, req.Embedding) ||
		!reflect.DeepEqual(signed.Tags, req.Tags) {
		return "", errors.New("v23 query envelope does not match the signed recall body")
	}
	if len(req.Embedding) > 0 && signed.EmbeddingProvider == "" {
		return "", errors.New("v23 signed recall body omits embedding_provider")
	}
	return proof.AgentID, nil
}

func (m *Manager) validateQueryEnvelopeV23(ctx context.Context, peer *peerIdentity, agreement *store.CrossFedRecord, req *QueryRequest) (uint8, error) {
	if req.ProtocolVersion != FederationProtocolV23 {
		return 0, errors.New("federation protocol v23 is required")
	}
	if req.SourceChainID != peer.ChainID || req.DestinationChainID != m.localChainID {
		return 0, errors.New("v23 query chain binding mismatch")
	}
	expectedDigest, err := m.agreementBindingDigestV23(ctx, agreement, peer.AgentID)
	if err != nil {
		return 0, err
	}
	if req.AgreementBindingDigest == "" || req.AgreementBindingDigest != expectedDigest {
		return 0, errors.New("v23 query agreement generation mismatch")
	}
	requestedAgentID, err := m.verifyQueryAgentProofV23(time.Now(), req)
	if err != nil {
		return 0, err
	}
	ceiling, err := m.authorizeFederatedGuestRead(ctx, peer, agreement, req.AgentProof.AgentID, req.DomainTag)
	if err != nil {
		return 0, err
	}
	if m.queryChallengeStore == nil {
		return 0, errors.New("v23 durable query challenge store is unavailable")
	}
	if err := m.queryChallengeStore.ConsumeFederatedQueryChallenge(ctx, store.FederatedQueryChallenge{
		ChallengeID:            req.QueryChallenge,
		RemoteChainID:          peer.ChainID,
		PeerAgentID:            peer.AgentID,
		RequestedAgentID:       requestedAgentID,
		DomainTag:              req.DomainTag,
		AgreementBindingDigest: req.AgreementBindingDigest,
		ExpiresAt:              1, // validated from the durable row by the atomic UPDATE.
	}, time.Now()); err != nil {
		return 0, err
	}
	return ceiling, nil
}

func cloneQueryRequest(req *QueryRequest) (*QueryRequest, error) {
	if req == nil {
		return nil, errors.New("query request is required")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode query request: %w", err)
	}
	var clone QueryRequest
	if err := json.Unmarshal(body, &clone); err != nil {
		return nil, fmt.Errorf("clone query request: %w", err)
	}
	return &clone, nil
}
