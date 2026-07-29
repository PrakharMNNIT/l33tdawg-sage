package tx

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppV23GenericElevationTrailerPreservesLegacyEncoding(t *testing.T) {
	base := &ParsedTx{
		Type: TxTypeAgentSetPermission,
		AgentSetPermission: &AgentSetPermission{
			AgentID: "agent-a", Clearance: 1,
			DomainAccess: "{}", VisibleAgents: "[]",
		},
	}
	legacy, err := EncodeTx(base)
	require.NoError(t, err)
	decodedLegacy, err := DecodeTx(legacy)
	require.NoError(t, err)
	require.Nil(t, decodedLegacy.LocalElevation)
	legacyAgain, err := EncodeTx(decodedLegacy)
	require.NoError(t, err)
	require.Equal(t, legacy, legacyAgain)
	malformedHistoricalTail := append(append([]byte(nil), legacy...), 0, 0, 0, 2, 0xff)
	tolerated, err := DecodeTx(malformedHistoricalTail)
	require.NoError(t, err, "pre-v15 malformed optional tails remain decode-tolerant for replay")
	require.Nil(t, tolerated.LocalElevation)

	withElevation := *base
	withElevation.LocalElevation = &LocalElevationProof{
		RootGeneration:   3,
		ValidFromHeight:  100,
		ValidUntilHeight: 110,
		Nonce:            "elevation_nonce_0001",
		Signature:        bytes.Repeat([]byte{0x5a}, 64),
	}
	encoded, err := EncodeTx(&withElevation)
	require.NoError(t, err)
	require.Greater(t, len(encoded), len(legacy))
	decoded, err := DecodeTx(encoded)
	require.NoError(t, err)
	require.Equal(t, withElevation.LocalElevation, decoded.LocalElevation)
	encodedAgain, err := EncodeTx(decoded)
	require.NoError(t, err)
	require.Equal(t, encoded, encodedAgain)
}

func TestAppV23ControlPayloadsAndRootRotationRoundTrip(t *testing.T) {
	cases := []*ParsedTx{
		{
			Type: TxTypeLocalAgentApprove,
			LocalAgentApprove: &LocalAgentApprove{
				AgentID: "agent", ExpectedRevision: 2, ExpectedRoleRevision: 3,
				Active: true, Role: "member", Profile: "companion",
				HomeDomain: "voice-interface", ExpectedHomeDomainOwner: "root",
				TransferHomeDomain: true, Clearance: 0, Capabilities: 15,
				Scope: "scope", TargetSignature: bytes.Repeat([]byte{1}, 64),
			},
		},
		{
			Type: TxTypeAgentRoleChange,
			AgentRoleChange: &AgentRoleChange{
				AgentID: "agent", ExpectedRevision: 4, EnrollmentRevision: 5,
				Role: "admin", ExpectedProfile: "standard", Profile: "standard",
				Clearance: 4, Capabilities: 1,
			},
		},
		{
			Type: TxTypeAccessGroupMutate,
			AccessGroupMutate: &AccessGroupMutate{
				GroupID: "team", Name: "Team", ExpectedRevision: 6,
				Members: []string{"a", "b"},
			},
		},
		{
			Type: TxTypeRootCredentialRotate,
			RootCredentialRotate: &RootCredentialRotate{
				ExpectedGeneration: 7, NewCredentialID: "new-root", Scope: "scope",
				NewCredentialSignature: bytes.Repeat([]byte{2}, 64),
			},
		},
	}
	for _, original := range cases {
		encoded, err := EncodeTx(original)
		require.NoError(t, err)
		decoded, err := DecodeTx(encoded)
		require.NoError(t, err)
		again, err := EncodeTx(decoded)
		require.NoError(t, err)
		require.Equal(t, encoded, again, "type %d must be canonical", original.Type)
	}
}
