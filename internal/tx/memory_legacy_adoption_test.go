package tx

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func testMemoryLegacyAdoptionPayload() MemoryLegacyAdoptionPayload {
	return MemoryLegacyAdoptionPayload{
		Version:          MemoryLegacyAdoptionPayloadVersion,
		RootCredentialID: "root-credential",
		RootGeneration:   3,
		PlanDigest:       bytes.Repeat([]byte{0x91}, sha256.Size),
		Entries: []MemoryLegacyAdoptionEntry{
			{
				MemoryID:        "memory-a",
				Status:          "proposed",
				ContentHash:     bytes.Repeat([]byte{0x11}, sha256.Size),
				Domain:          "engineering",
				Author:          "author-a",
				AuthorPrincipal: "agent:author-a",
				Classification:  2,
			},
			{
				MemoryID:        "memory-b",
				Status:          "deprecated",
				ContentHash:     bytes.Repeat([]byte{0x22}, sha256.Size),
				Domain:          "research",
				Author:          "author-b",
				AuthorPrincipal: "agent:author-b",
				Classification:  1,
			},
		},
	}
}

func TestMemoryLegacyAdoptionPayloadCanonicalRoundTrip(t *testing.T) {
	payload := testMemoryLegacyAdoptionPayload()
	encoded, err := EncodeMemoryLegacyAdoptionPayload(payload)
	require.NoError(t, err)
	require.LessOrEqual(t, len(encoded), MaxMemoryLegacyAdoptionPayloadBytes)

	decoded, err := DecodeMemoryLegacyAdoptionPayload(encoded)
	require.NoError(t, err)
	require.Equal(t, payload, *decoded)

	reencoded, err := EncodeMemoryLegacyAdoptionPayload(*decoded)
	require.NoError(t, err)
	require.Equal(t, encoded, reencoded)
}

func TestMemoryLegacyAdoptionTargetBindsEveryAttestedField(t *testing.T) {
	payload := testMemoryLegacyAdoptionPayload()
	encoded, err := EncodeMemoryLegacyAdoptionPayload(payload)
	require.NoError(t, err)
	original, err := MemoryLegacyAdoptionTargetID(encoded)
	require.NoError(t, err)

	mutations := []func(*MemoryLegacyAdoptionPayload){
		func(p *MemoryLegacyAdoptionPayload) { p.RootGeneration++ },
		func(p *MemoryLegacyAdoptionPayload) { p.PlanDigest[0] ^= 0xff },
		func(p *MemoryLegacyAdoptionPayload) { p.Entries[0].ContentHash[0] ^= 0xff },
		func(p *MemoryLegacyAdoptionPayload) { p.Entries[0].Status = "deprecated" },
		func(p *MemoryLegacyAdoptionPayload) { p.Entries[0].Domain = "different" },
		func(p *MemoryLegacyAdoptionPayload) { p.Entries[0].Author = "different" },
		func(p *MemoryLegacyAdoptionPayload) { p.Entries[0].AuthorPrincipal = "different" },
		func(p *MemoryLegacyAdoptionPayload) { p.Entries[0].Classification++ },
	}
	for i, mutate := range mutations {
		changed := testMemoryLegacyAdoptionPayload()
		changed.PlanDigest = append([]byte(nil), changed.PlanDigest...)
		changed.Entries = append([]MemoryLegacyAdoptionEntry(nil), changed.Entries...)
		for j := range changed.Entries {
			changed.Entries[j].ContentHash = append([]byte(nil), changed.Entries[j].ContentHash...)
		}
		mutate(&changed)
		raw, encodeErr := EncodeMemoryLegacyAdoptionPayload(changed)
		require.NoError(t, encodeErr, "mutation %d", i)
		target, targetErr := MemoryLegacyAdoptionTargetID(raw)
		require.NoError(t, targetErr, "mutation %d", i)
		require.NotEqual(t, original, target, "mutation %d", i)
	}
}

func TestMemoryLegacyAdoptionPayloadRejectsUnsafeShapes(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*MemoryLegacyAdoptionPayload)
	}{
		{"unknown version", func(p *MemoryLegacyAdoptionPayload) { p.Version++ }},
		{"zero Root generation", func(p *MemoryLegacyAdoptionPayload) { p.RootGeneration = 0 }},
		{"bad plan digest", func(p *MemoryLegacyAdoptionPayload) { p.PlanDigest = p.PlanDigest[:31] }},
		{"empty entries", func(p *MemoryLegacyAdoptionPayload) { p.Entries = nil }},
		{"unsorted", func(p *MemoryLegacyAdoptionPayload) {
			p.Entries[0], p.Entries[1] = p.Entries[1], p.Entries[0]
		}},
		{"duplicate", func(p *MemoryLegacyAdoptionPayload) { p.Entries[1].MemoryID = p.Entries[0].MemoryID }},
		{"unknown status", func(p *MemoryLegacyAdoptionPayload) { p.Entries[0].Status = "challenged" }},
		{"empty domain", func(p *MemoryLegacyAdoptionPayload) { p.Entries[0].Domain = "" }},
		{"empty author", func(p *MemoryLegacyAdoptionPayload) { p.Entries[0].Author = "" }},
		{"bad classification", func(p *MemoryLegacyAdoptionPayload) { p.Entries[0].Classification = 5 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := testMemoryLegacyAdoptionPayload()
			tt.mutate(&payload)
			_, err := EncodeMemoryLegacyAdoptionPayload(payload)
			require.Error(t, err)
		})
	}
}

func TestMemoryLegacyAdoptionPayloadRejectsMalformedEncoding(t *testing.T) {
	encoded, err := EncodeMemoryLegacyAdoptionPayload(testMemoryLegacyAdoptionPayload())
	require.NoError(t, err)
	for cut := 0; cut < len(encoded); cut++ {
		_, decodeErr := DecodeMemoryLegacyAdoptionPayload(encoded[:cut])
		require.Error(t, decodeErr, "cut=%d", cut)
	}
	trailing := append(append([]byte(nil), encoded...), 0)
	_, err = DecodeMemoryLegacyAdoptionPayload(trailing)
	require.Error(t, err)
}
