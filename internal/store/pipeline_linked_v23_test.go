package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLinkedV23PipelineAuthorizationRoundTripsAndBindsReplay(t *testing.T) {
	ctx := context.Background()
	s, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "linked-pipes.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	now := time.Now().UTC().Truncate(time.Second)
	relation := []byte(`{"version":1,"purpose":"test-byte-exact-relation"}`)
	proof := testPipelineTransportProof(t)
	outbound := &PipelineMessage{
		PipeID: "pipe-linked-outbound", FromAgent: proof.AgentID,
		ToAgent: strings.Repeat("b", 64), Intent: "linked",
		Payload: "payload", Status: "pending", CreatedAt: now,
		ExpiresAt: now.Add(time.Hour), DestinationChainID: "chain-peer",
		FederationPolicyEpoch:       "epoch-linked",
		FederationAgreementID:       strings.Repeat("c", 64),
		FederationContactID:         strings.Repeat("d", 64),
		FederationContactRevision:   strings.Repeat("e", 64),
		FederationAuthorizationMode: "linked-v23",
		FederationLinkedRelation:    append([]byte(nil), relation...),
	}
	outbox := &PipelineTransportOutbox{
		EventID: "event-linked-outbound", PipeID: outbound.PipeID,
		RemoteChainID: outbound.DestinationChainID, EventKind: "send",
		PolicyEpoch:       outbound.FederationPolicyEpoch,
		AgreementID:       outbound.FederationAgreementID,
		ContactID:         outbound.FederationContactID,
		ContactRevision:   outbound.FederationContactRevision,
		AuthorizationMode: outbound.FederationAuthorizationMode,
		LinkedRelation:    append([]byte(nil), relation...),
		SourceAgentID:     outbound.FromAgent, TargetAgentID: outbound.ToAgent,
		Proof: proof, CreatedAt: now, ExpiresAt: outbound.ExpiresAt,
	}
	require.NoError(t, s.InsertPipelineWithTransport(ctx, outbound, outbox))

	storedMessage, err := s.GetPipeline(ctx, outbound.PipeID)
	require.NoError(t, err)
	require.Equal(t, "linked-v23", storedMessage.FederationAuthorizationMode)
	require.True(t, bytes.Equal(relation, storedMessage.FederationLinkedRelation))
	storedOutbox, err := s.GetPipelineTransport(ctx, outbox.EventID)
	require.NoError(t, err)
	require.Equal(t, "linked-v23", storedOutbox.AuthorizationMode)
	require.True(t, bytes.Equal(relation, storedOutbox.LinkedRelation))

	// app-v23 columns are additive. Ordinary/pre-v23 rows still use byte-empty
	// defaults and remain on the original contact authorization path.
	ordinaryProof := testPipelineTransportProof(t)
	ordinary := &PipelineMessage{
		PipeID: "pipe-ordinary-compatible", FromAgent: ordinaryProof.AgentID,
		ToAgent: strings.Repeat("9", 64), Intent: "ordinary",
		Payload: "payload", Status: "pending", CreatedAt: now,
		ExpiresAt: now.Add(time.Hour), DestinationChainID: "chain-peer",
		FederationPolicyEpoch:     "epoch-ordinary",
		FederationAgreementID:     strings.Repeat("8", 64),
		FederationContactID:       strings.Repeat("7", 64),
		FederationContactRevision: strings.Repeat("6", 64),
	}
	ordinaryOutbox := &PipelineTransportOutbox{
		EventID: "event-ordinary-compatible", PipeID: ordinary.PipeID,
		RemoteChainID: ordinary.DestinationChainID, EventKind: "send",
		PolicyEpoch:     ordinary.FederationPolicyEpoch,
		AgreementID:     ordinary.FederationAgreementID,
		ContactID:       ordinary.FederationContactID,
		ContactRevision: ordinary.FederationContactRevision,
		SourceAgentID:   ordinary.FromAgent, TargetAgentID: ordinary.ToAgent,
		Proof: ordinaryProof, CreatedAt: now, ExpiresAt: ordinary.ExpiresAt,
	}
	require.NoError(t, s.InsertPipelineWithTransport(
		ctx, ordinary, ordinaryOutbox,
	))
	storedOrdinary, err := s.GetPipeline(ctx, ordinary.PipeID)
	require.NoError(t, err)
	require.Empty(t, storedOrdinary.FederationAuthorizationMode)
	require.Empty(t, storedOrdinary.FederationLinkedRelation)
	storedOrdinaryOutbox, err := s.GetPipelineTransport(
		ctx, ordinaryOutbox.EventID,
	)
	require.NoError(t, err)
	require.Empty(t, storedOrdinaryOutbox.AuthorizationMode)
	require.Empty(t, storedOrdinaryOutbox.LinkedRelation)

	contentHash := sha256.Sum256([]byte("linked inbound content"))
	proofHash := sha256.Sum256([]byte("linked inbound proof"))
	imported := &PipelineMessage{
		PipeID: "pipe-linked-inbound", FromAgent: strings.Repeat("a", 64),
		ToAgent: strings.Repeat("f", 64), Intent: "linked",
		Payload: "payload", Status: "pending", CreatedAt: now,
		ExpiresAt: now.Add(time.Hour), SourceChainID: "chain-peer",
		SourcePipeID:                "remote-linked-event",
		FederationPolicyEpoch:       "epoch-linked",
		FederationAgreementID:       strings.Repeat("c", 64),
		FederationContactID:         strings.Repeat("d", 64),
		FederationContactRevision:   strings.Repeat("e", 64),
		FederationAuthorizationMode: "linked-v23",
		FederationLinkedRelation:    append([]byte(nil), relation...),
	}
	dedup := &PipelineTransportDedup{
		RemoteChainID:        imported.SourceChainID,
		PolicyEpoch:          imported.FederationPolicyEpoch,
		AgreementID:          imported.FederationAgreementID,
		ContactID:            imported.FederationContactID,
		ContactRevision:      imported.FederationContactRevision,
		AuthorizationMode:    imported.FederationAuthorizationMode,
		LinkedRelationDigest: pipelineLinkedRelationDigest(relation),
		SourceAgentID:        imported.FromAgent, TargetAgentID: imported.ToAgent,
		EventKind: "send", RemotePipeID: imported.SourcePipeID,
		ContentHash: contentHash[:], ProofHash: proofHash[:],
		LocalPipeID: imported.PipeID, Outcome: "accepted",
		ExpiresAt: now.Add(2 * time.Hour),
	}
	_, duplicate, err := s.AdmitFederatedPipeline(ctx, imported, dedup)
	require.NoError(t, err)
	require.False(t, duplicate)
	storedImported, err := s.GetPipeline(ctx, imported.PipeID)
	require.NoError(t, err)
	require.Equal(t, "linked-v23", storedImported.FederationAuthorizationMode)
	require.True(t, bytes.Equal(relation, storedImported.FederationLinkedRelation))

	rewrapped := *imported
	rewrapped.PipeID = "pipe-linked-rewrapped"
	rewrapped.SourcePipeID = "remote-linked-rewrapped"
	rewrapped.FederationLinkedRelation = []byte(`{"version":1,"purpose":"different-relation"}`)
	rewrappedDedup := *dedup
	rewrappedDedup.RemotePipeID = rewrapped.SourcePipeID
	rewrappedDedup.LocalPipeID = rewrapped.PipeID
	rewrappedDedup.LinkedRelationDigest =
		pipelineLinkedRelationDigest(rewrapped.FederationLinkedRelation)
	_, _, err = s.AdmitFederatedPipeline(ctx, &rewrapped, &rewrappedDedup)
	require.ErrorIs(t, err, ErrPipelineTransportReplay,
		"one signed request cannot be rebound to a different linked relation")
}
