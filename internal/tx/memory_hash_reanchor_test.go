package tx

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testMemoryHashReanchorPayload() MemoryHashReanchorPayload {
	first := sha256.Sum256([]byte("first memory content"))
	second := sha256.Sum256([]byte("second memory content"))
	return MemoryHashReanchorPayload{
		Version:          MemoryHashReanchorPayloadVersion,
		RootCredentialID: strings.Repeat("a", 64),
		RootGeneration:   7,
		Entries: []MemoryHashReanchorEntry{
			{MemoryID: "memory-a", ExpectedStatus: "committed", ContentHash: first[:]},
			{MemoryID: "memory-b", ExpectedStatus: "deprecated", ContentHash: second[:]},
		},
	}
}

func TestMemoryHashReanchorPayloadCanonicalRoundTripAndTarget(t *testing.T) {
	payload := testMemoryHashReanchorPayload()
	encoded, err := EncodeMemoryHashReanchorPayload(payload)
	require.NoError(t, err)

	decoded, err := DecodeMemoryHashReanchorPayload(encoded)
	require.NoError(t, err)
	assert.Equal(t, &payload, decoded)

	reencoded, err := EncodeMemoryHashReanchorPayload(*decoded)
	require.NoError(t, err)
	assert.Equal(t, encoded, reencoded)

	target, err := MemoryHashReanchorTargetID(encoded)
	require.NoError(t, err)
	expected := sha256.Sum256(append(
		[]byte("sage/memory-hash-reanchor/v1\x00"),
		encoded...,
	))
	assert.Equal(t, hex.EncodeToString(expected[:]), target)
	assert.Len(t, target, 64)
	assert.Equal(t, strings.ToLower(target), target)
}

func TestMemoryHashReanchorPayloadWireLayoutIsStable(t *testing.T) {
	hash := bytes.Repeat([]byte{0x5a}, sha256.Size)
	payload := MemoryHashReanchorPayload{
		Version:          1,
		RootCredentialID: "root",
		RootGeneration:   9,
		Entries: []MemoryHashReanchorEntry{{
			MemoryID: "m", ExpectedStatus: "committed", ContentHash: hash,
		}},
	}
	encoded, err := EncodeMemoryHashReanchorPayload(payload)
	require.NoError(t, err)

	expected := []byte{1}
	expected = appendReanchorBytes(expected, []byte("root"))
	expected = appendReanchorUint64(expected, 9)
	expected = appendReanchorUint32(expected, 1)
	expected = appendReanchorBytes(expected, []byte("m"))
	expected = append(expected, memoryHashReanchorStatusCommitted)
	expected = append(expected, hash...)
	assert.Equal(t, expected, encoded)
}

func TestMemoryHashReanchorPayloadAcceptsExactBoundaries(t *testing.T) {
	entries := make([]MemoryHashReanchorEntry, MaxMemoryHashReanchorEntries)
	for i := range entries {
		hash := sha256.Sum256([]byte(fmt.Sprintf("boundary content %03d", i)))
		entries[i] = MemoryHashReanchorEntry{
			MemoryID:       fmt.Sprintf("%03d", i),
			ExpectedStatus: "committed",
			ContentHash:    hash[:],
		}
	}
	entries[len(entries)-1].MemoryID = strings.Repeat("z", MaxMemoryHashReanchorIDBytes)
	payload := MemoryHashReanchorPayload{
		Version:          MemoryHashReanchorPayloadVersion,
		RootCredentialID: strings.Repeat("r", MaxMemoryHashReanchorIDBytes),
		RootGeneration:   1,
		Entries:          entries,
	}
	encoded, err := EncodeMemoryHashReanchorPayload(payload)
	require.NoError(t, err)
	require.LessOrEqual(t, len(encoded), MaxMemoryHashReanchorPayloadBytes)
	decoded, err := DecodeMemoryHashReanchorPayload(encoded)
	require.NoError(t, err)
	assert.Equal(t, &payload, decoded)
}

func TestEncodeMemoryHashReanchorPayloadRejectsNonCanonicalValues(t *testing.T) {
	base := testMemoryHashReanchorPayload()
	tests := []struct {
		name   string
		mutate func(*MemoryHashReanchorPayload)
	}{
		{"unknown version", func(p *MemoryHashReanchorPayload) { p.Version = 2 }},
		{"empty Root credential", func(p *MemoryHashReanchorPayload) { p.RootCredentialID = "" }},
		{"oversized Root credential", func(p *MemoryHashReanchorPayload) {
			p.RootCredentialID = strings.Repeat("r", MaxMemoryHashReanchorIDBytes+1)
		}},
		{"zero Root generation", func(p *MemoryHashReanchorPayload) { p.RootGeneration = 0 }},
		{"zero entries", func(p *MemoryHashReanchorPayload) { p.Entries = nil }},
		{"too many entries", func(p *MemoryHashReanchorPayload) {
			entry := p.Entries[0]
			p.Entries = make([]MemoryHashReanchorEntry, MaxMemoryHashReanchorEntries+1)
			for i := range p.Entries {
				p.Entries[i] = entry
				p.Entries[i].MemoryID = strings.Repeat("x", i/256+1) + string(rune(i%256))
			}
		}},
		{"empty memory ID", func(p *MemoryHashReanchorPayload) { p.Entries[0].MemoryID = "" }},
		{"oversized memory ID", func(p *MemoryHashReanchorPayload) {
			p.Entries[0].MemoryID = strings.Repeat("m", MaxMemoryHashReanchorIDBytes+1)
		}},
		{"unsorted entries", func(p *MemoryHashReanchorPayload) {
			p.Entries[0], p.Entries[1] = p.Entries[1], p.Entries[0]
		}},
		{"duplicate entries", func(p *MemoryHashReanchorPayload) {
			p.Entries[1].MemoryID = p.Entries[0].MemoryID
		}},
		{"invalid status", func(p *MemoryHashReanchorPayload) {
			p.Entries[0].ExpectedStatus = "proposed"
		}},
		{"short hash", func(p *MemoryHashReanchorPayload) {
			p.Entries[0].ContentHash = p.Entries[0].ContentHash[:sha256.Size-1]
		}},
		{"long hash", func(p *MemoryHashReanchorPayload) {
			p.Entries[0].ContentHash = append(p.Entries[0].ContentHash, 0)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := base
			payload.Entries = append([]MemoryHashReanchorEntry(nil), base.Entries...)
			for i := range payload.Entries {
				payload.Entries[i].ContentHash = append([]byte(nil), base.Entries[i].ContentHash...)
			}
			test.mutate(&payload)
			_, err := EncodeMemoryHashReanchorPayload(payload)
			require.Error(t, err)
		})
	}
}

func TestDecodeMemoryHashReanchorPayloadRejectsMalformedBytes(t *testing.T) {
	encoded, err := EncodeMemoryHashReanchorPayload(testMemoryHashReanchorPayload())
	require.NoError(t, err)

	for cut := 0; cut < len(encoded); cut++ {
		_, decodeErr := DecodeMemoryHashReanchorPayload(encoded[:cut])
		require.Error(t, decodeErr, "cut at byte %d", cut)
	}

	unknownVersion := append([]byte(nil), encoded...)
	unknownVersion[0] = 2
	_, err = DecodeMemoryHashReanchorPayload(unknownVersion)
	require.ErrorContains(t, err, "unsupported version")

	trailing := append(append([]byte(nil), encoded...), 0)
	_, err = DecodeMemoryHashReanchorPayload(trailing)
	require.ErrorContains(t, err, "trailing")

	oversized := make([]byte, MaxMemoryHashReanchorPayloadBytes+1)
	oversized[0] = MemoryHashReanchorPayloadVersion
	_, err = DecodeMemoryHashReanchorPayload(oversized)
	require.ErrorContains(t, err, "exceeds")
}

func TestDecodeMemoryHashReanchorPayloadRejectsFieldMutations(t *testing.T) {
	payload := MemoryHashReanchorPayload{
		Version:          1,
		RootCredentialID: "root",
		RootGeneration:   1,
		Entries: []MemoryHashReanchorEntry{
			{MemoryID: "a", ExpectedStatus: "committed", ContentHash: bytes.Repeat([]byte{1}, sha256.Size)},
			{MemoryID: "b", ExpectedStatus: "deprecated", ContentHash: bytes.Repeat([]byte{2}, sha256.Size)},
		},
	}
	encoded, err := EncodeMemoryHashReanchorPayload(payload)
	require.NoError(t, err)

	rootLenOffset := 1
	rootOffset := rootLenOffset + 4
	generationOffset := rootOffset + len(payload.RootCredentialID)
	countOffset := generationOffset + 8
	firstIDLenOffset := countOffset + 4
	firstIDOffset := firstIDLenOffset + 4
	firstStatusOffset := firstIDOffset + len(payload.Entries[0].MemoryID)
	firstHashOffset := firstStatusOffset + 1
	secondIDLenOffset := firstHashOffset + sha256.Size
	secondIDOffset := secondIDLenOffset + 4

	mutations := []struct {
		name   string
		mutate func([]byte)
	}{
		{"zero root length", func(raw []byte) { binary.BigEndian.PutUint32(raw[rootLenOffset:], 0) }},
		{"oversized root length", func(raw []byte) {
			binary.BigEndian.PutUint32(raw[rootLenOffset:], MaxMemoryHashReanchorIDBytes+1)
		}},
		{"zero generation", func(raw []byte) {
			for i := 0; i < 8; i++ {
				raw[generationOffset+i] = 0
			}
		}},
		{"zero count", func(raw []byte) { binary.BigEndian.PutUint32(raw[countOffset:], 0) }},
		{"count over limit", func(raw []byte) {
			binary.BigEndian.PutUint32(raw[countOffset:], MaxMemoryHashReanchorEntries+1)
		}},
		{"zero memory ID length", func(raw []byte) {
			binary.BigEndian.PutUint32(raw[firstIDLenOffset:], 0)
		}},
		{"unknown status", func(raw []byte) { raw[firstStatusOffset] = 0xff }},
		{"duplicate raw ID", func(raw []byte) { raw[secondIDOffset] = raw[firstIDOffset] }},
		{"descending raw ID", func(raw []byte) {
			raw[firstIDOffset] = 'z'
			raw[secondIDOffset] = 'a'
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			mutated := append([]byte(nil), encoded...)
			test.mutate(mutated)
			_, decodeErr := DecodeMemoryHashReanchorPayload(mutated)
			require.Error(t, decodeErr)
			_, targetErr := MemoryHashReanchorTargetID(mutated)
			require.Error(t, targetErr)
		})
	}
}

func TestMemoryHashReanchorTargetChangesForCanonicalEvidenceMutations(t *testing.T) {
	payload := testMemoryHashReanchorPayload()
	encoded, err := EncodeMemoryHashReanchorPayload(payload)
	require.NoError(t, err)
	originalTarget, err := MemoryHashReanchorTargetID(encoded)
	require.NoError(t, err)

	mutations := []func(*MemoryHashReanchorPayload){
		func(p *MemoryHashReanchorPayload) { p.RootGeneration++ },
		func(p *MemoryHashReanchorPayload) { p.RootCredentialID = strings.Repeat("b", 64) },
		func(p *MemoryHashReanchorPayload) { p.Entries[0].ExpectedStatus = "deprecated" },
		func(p *MemoryHashReanchorPayload) { p.Entries[0].ContentHash[0] ^= 0xff },
	}
	for i, mutate := range mutations {
		changed := payload
		changed.Entries = append([]MemoryHashReanchorEntry(nil), payload.Entries...)
		for entryIndex := range changed.Entries {
			changed.Entries[entryIndex].ContentHash =
				append([]byte(nil), payload.Entries[entryIndex].ContentHash...)
		}
		mutate(&changed)
		changedBytes, encodeErr := EncodeMemoryHashReanchorPayload(changed)
		require.NoError(t, encodeErr, "mutation %d", i)
		changedTarget, targetErr := MemoryHashReanchorTargetID(changedBytes)
		require.NoError(t, targetErr, "mutation %d", i)
		assert.NotEqual(t, originalTarget, changedTarget, "mutation %d", i)
	}
}

func FuzzDecodeMemoryHashReanchorPayload(f *testing.F) {
	seed, err := EncodeMemoryHashReanchorPayload(testMemoryHashReanchorPayload())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{MemoryHashReanchorPayloadVersion})
	f.Add(bytes.Repeat([]byte{0xff}, MaxMemoryHashReanchorPayloadBytes+1))

	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, decodeErr := DecodeMemoryHashReanchorPayload(raw)
		if decodeErr != nil {
			return
		}
		reencoded, encodeErr := EncodeMemoryHashReanchorPayload(*decoded)
		require.NoError(t, encodeErr)
		require.Equal(t, raw, reencoded)
	})
}
