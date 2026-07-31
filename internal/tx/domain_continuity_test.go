package tx

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDomainContinuityPayloadCanonicalRoundTripAndTargetBinding(t *testing.T) {
	plan := sha256.Sum256([]byte("continuity-plan"))
	payload := DomainContinuityPayload{
		Version: DomainContinuityPayloadVersion, RootCredentialID: "root",
		RootGeneration: 2, PlanDigest: plan[:],
		Entries: []DomainContinuityEntry{{
			Domain: "technical/hardware", Owner: "agent-a",
			Writers: []string{"agent-a", "agent-b"},
		}},
	}
	encoded, err := EncodeDomainContinuityPayload(payload)
	require.NoError(t, err)
	decoded, err := DecodeDomainContinuityPayload(encoded)
	require.NoError(t, err)
	require.Equal(t, payload, *decoded)
	target, err := DomainContinuityTargetID(encoded)
	require.NoError(t, err)
	require.Len(t, target, sha256.Size*2)

	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-1] ^= 1
	otherTarget, err := DomainContinuityTargetID(tampered)
	require.NoError(t, err)
	require.NotEqual(t, target, otherTarget)
}

func TestDomainContinuityPayloadRejectsUnsortedDuplicateAndTrailingData(t *testing.T) {
	plan := sha256.Sum256([]byte("continuity-plan"))
	base := DomainContinuityPayload{
		Version: DomainContinuityPayloadVersion, RootCredentialID: "root",
		RootGeneration: 1, PlanDigest: plan[:],
	}
	base.Entries = []DomainContinuityEntry{{Domain: "domain", Owner: "a", Writers: []string{"b", "a"}}}
	_, err := EncodeDomainContinuityPayload(base)
	require.Error(t, err)
	base.Entries[0].Writers = []string{"a", "a"}
	_, err = EncodeDomainContinuityPayload(base)
	require.Error(t, err)
	base.Entries[0].Writers = []string{"a"}
	encoded, err := EncodeDomainContinuityPayload(base)
	require.NoError(t, err)
	_, err = DecodeDomainContinuityPayload(append(encoded, 0))
	require.Error(t, err)
}

func TestDomainContinuityPayloadV1ByteCompatibleAndNormalizes(t *testing.T) {
	plan := sha256.Sum256([]byte("legacy-plan"))
	payload := DomainContinuityPayload{
		Version: DomainContinuityPayloadLegacyVersion, RootCredentialID: "root",
		RootGeneration: 7, PlanDigest: plan[:], Domain: "legacy-domain",
		Writers: []string{"agent-a", "agent-b"},
	}
	encoded, err := EncodeDomainContinuityPayload(payload)
	require.NoError(t, err)
	require.Equal(t,
		"0100000004726f6f740000000000000007"+
			"8d946e4ec4479631d8f2441ee3ebbd936c374060325a70fb55b3682f67f3d89a"+
			"0000000d6c65676163792d646f6d61696e"+
			"00000002000000076167656e742d61000000076167656e742d62",
		hex.EncodeToString(encoded),
		"v1 bytes and therefore its target ID must remain replay-compatible",
	)
	decoded, err := DecodeDomainContinuityPayload(encoded)
	require.NoError(t, err)
	require.Equal(t, payload, *decoded)
	require.Equal(t, []DomainContinuityEntry{{
		Domain: "legacy-domain", Writers: []string{"agent-a", "agent-b"},
	}}, DomainContinuityEntries(decoded))
}

func TestDomainContinuityPayloadV2RequiresStrictEntryOrderAndBounds(t *testing.T) {
	plan := sha256.Sum256([]byte("batch-plan"))
	base := DomainContinuityPayload{
		Version: DomainContinuityPayloadVersion, RootCredentialID: "root",
		RootGeneration: 1, PlanDigest: plan[:],
		Entries: []DomainContinuityEntry{
			{Domain: "a", Owner: "agent", Writers: []string{"agent"}},
			{Domain: "b", Owner: "agent", Writers: []string{"agent"}},
		},
	}
	_, err := EncodeDomainContinuityPayload(base)
	require.NoError(t, err)
	base.Entries[0], base.Entries[1] = base.Entries[1], base.Entries[0]
	_, err = EncodeDomainContinuityPayload(base)
	require.ErrorContains(t, err, "strictly sorted")
	base.Entries = make([]DomainContinuityEntry, MaxDomainContinuityEntries+1)
	for i := range base.Entries {
		base.Entries[i] = DomainContinuityEntry{
			Domain: fmt.Sprintf("domain-%03d", i), Owner: "agent", Writers: []string{"agent"},
		}
	}
	_, err = EncodeDomainContinuityPayload(base)
	require.ErrorContains(t, err, "entry count")
}

func TestDomainContinuityPayloadV2BindsOwnerAndRequiresNonemptyIdentity(t *testing.T) {
	plan := sha256.Sum256([]byte("owner-plan"))
	base := DomainContinuityPayload{
		Version: DomainContinuityPayloadVersion, RootCredentialID: "root",
		RootGeneration: 1, PlanDigest: plan[:],
		Entries: []DomainContinuityEntry{{
			Domain: "shared", Owner: "agent-a", Writers: []string{"agent-a", "agent-b"},
		}},
	}
	encoded, err := EncodeDomainContinuityPayload(base)
	require.NoError(t, err)

	base.Entries[0].Owner = "agent-b"
	other, err := EncodeDomainContinuityPayload(base)
	require.NoError(t, err)
	require.NotEqual(t, encoded, other, "owner must be consensus-bound in v2 bytes")

	base.Entries[0].Owner = ""
	_, err = EncodeDomainContinuityPayload(base)
	require.ErrorContains(t, err, "invalid owner length")
}
