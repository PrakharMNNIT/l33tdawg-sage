package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func linkedConsentPolicy(t *testing.T, s *SQLiteStore) *PeerRBACPolicy {
	t.Helper()
	ctx := context.Background()
	epoch, caPin := testPeerRBACBinding()
	policy := PeerRBACPolicy{
		RemoteChainID: "chain-peer", PeerAgentID: testPeerAgentID(t),
		PolicyEpoch: epoch, RemoteCAPin: caPin,
		PolicyVersion: CurrentPeerRBACPolicyVersion,
		Domains:       []PeerRBACDomainPermission{{Domain: "research", Read: true}},
	}
	require.NoError(t, s.PrepareSyncControl(ctx, testLegacyPeerRBACControl(policy)))
	require.NoError(t, s.ActivateSyncControl(ctx, policy.RemoteChainID, policy.PolicyEpoch))
	stored, err := s.ReplaceBoundPeerRBACPolicy(ctx, policy)
	require.NoError(t, err)
	return stored
}

func TestLinkedMessageConsentDefaultOffCASAndGenerationBinding(t *testing.T) {
	ctx := context.Background()
	s := newSyncTestStore(t)
	policy := linkedConsentPolicy(t, s)
	remoteAgentID := testPeerAgentID(t)
	localAgentID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	consent, err := s.GetBoundFederatedLinkedMessageConsent(
		ctx, *policy, remoteAgentID, localAgentID,
	)
	require.NoError(t, err)
	require.Nil(t, consent)

	revision, err := s.SetBoundFederatedLinkedMessageConsentCAS(
		ctx, *policy, remoteAgentID, localAgentID, 0, true,
	)
	require.NoError(t, err)
	require.EqualValues(t, 1, revision)
	consent, err = s.GetBoundFederatedLinkedMessageConsent(
		ctx, *policy, remoteAgentID, localAgentID,
	)
	require.NoError(t, err)
	require.True(t, consent.Accepting)
	require.EqualValues(t, 1, consent.Revision)

	_, err = s.SetBoundFederatedLinkedMessageConsentCAS(
		ctx, *policy, remoteAgentID, localAgentID, 0, false,
	)
	require.ErrorIs(t, err, ErrLinkedMessageConsentConflict)
	revision, err = s.SetBoundFederatedLinkedMessageConsentCAS(
		ctx, *policy, remoteAgentID, localAgentID, 1, false,
	)
	require.NoError(t, err)
	require.EqualValues(t, 2, revision)
	consent, err = s.GetBoundFederatedLinkedMessageConsent(
		ctx, *policy, remoteAgentID, localAgentID,
	)
	require.NoError(t, err)
	require.False(t, consent.Accepting)
	require.EqualValues(t, 2, consent.Revision)

	replaced, err := s.ReplaceBoundPeerRBACPolicy(ctx, PeerRBACPolicy{
		RemoteChainID: policy.RemoteChainID, PeerAgentID: policy.PeerAgentID,
		PolicyEpoch: policy.PolicyEpoch, RemoteCAPin: policy.RemoteCAPin,
		PolicyVersion: CurrentPeerRBACPolicyVersion,
		Domains:       []PeerRBACDomainPermission{{Domain: "research", Read: true}},
	})
	require.NoError(t, err)
	consent, err = s.GetBoundFederatedLinkedMessageConsent(
		ctx, *replaced, remoteAgentID, localAgentID,
	)
	require.NoError(t, err)
	require.Nil(t, consent)
	revision, err = s.SetBoundFederatedLinkedMessageConsentCAS(
		ctx, *replaced, remoteAgentID, localAgentID, 0, true,
	)
	require.NoError(t, err)
	require.EqualValues(t, 3, revision)
}

func TestLinkedMessageConsentPauseDeniesEnableButAllowsDisable(t *testing.T) {
	ctx := context.Background()
	s := newSyncTestStore(t)
	policy := linkedConsentPolicy(t, s)
	remoteAgentID := testPeerAgentID(t)
	localAgentID := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	revision, err := s.SetBoundFederatedLinkedMessageConsentCAS(
		ctx, *policy, remoteAgentID, localAgentID, 0, true,
	)
	require.NoError(t, err)

	paused, err := s.SetBoundPeerRBACPaused(ctx, *policy, true)
	require.NoError(t, err)
	_, err = s.SetBoundFederatedLinkedMessageConsentCAS(
		ctx, *paused, remoteAgentID, localAgentID, revision, true,
	)
	require.ErrorIs(t, err, ErrPeerRBACBindingMismatch)
	next, err := s.SetBoundFederatedLinkedMessageConsentCAS(
		ctx, *paused, remoteAgentID, localAgentID, revision, false,
	)
	require.NoError(t, err)
	require.EqualValues(t, revision+1, next)
	consent, err := s.GetBoundFederatedLinkedMessageConsent(
		ctx, *paused, remoteAgentID, localAgentID,
	)
	require.NoError(t, err)
	require.NotNil(t, consent)
	require.False(t, consent.Accepting)
}

func TestFederationV23MalformedSecuritySchemaFailsStartup(t *testing.T) {
	for _, tc := range []struct {
		name, ddl string
	}{
		{
			name: "linked consent",
			ddl: `CREATE TABLE fed_linked_message_consent (
				remote_chain_id TEXT PRIMARY KEY
			)`,
		},
		{
			name: "pipeline outbox",
			ddl: `CREATE TABLE pipeline_transport_outbox (
				event_id TEXT PRIMARY KEY
			)`,
		},
		{
			name: "group guest",
			ddl: `CREATE TABLE federated_group_guest (
				group_id TEXT PRIMARY KEY
			)`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "malformed.db")
			db, err := sql.Open("sqlite", path)
			require.NoError(t, err)
			_, err = db.Exec(tc.ddl)
			require.NoError(t, err)
			require.NoError(t, db.Close())

			store, err := NewSQLiteStore(context.Background(), path)
			if store != nil {
				_ = store.Close()
			}
			require.Error(t, err)
			require.False(t, errors.Is(err, context.Canceled))
		})
	}
}
