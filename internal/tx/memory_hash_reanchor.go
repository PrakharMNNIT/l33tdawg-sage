package tx

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// MemoryHashReanchorPayloadVersion is the only payload version understood
	// by app-v24.
	MemoryHashReanchorPayloadVersion uint8 = 1

	// MaxMemoryHashReanchorPayloadBytes bounds the complete inner governance
	// payload before any field parsing or allocation.
	MaxMemoryHashReanchorPayloadBytes = 192 << 10

	// MaxMemoryHashReanchorEntries bounds both consensus work and the Badger
	// write set for one governance operation.
	MaxMemoryHashReanchorEntries = 256

	// MaxMemoryHashReanchorIDBytes applies to both Root credential and memory
	// identifiers. Current IDs are substantially smaller; this preserves room
	// for future canonical identifiers without permitting unbounded fields.
	MaxMemoryHashReanchorIDBytes = 512
)

const memoryHashReanchorTargetDomain = "sage/memory-hash-reanchor/v1\x00"

const (
	memoryHashReanchorStatusCommitted  uint8 = 1
	memoryHashReanchorStatusDeprecated uint8 = 2
)

var errMemoryHashReanchorPayload = errors.New("invalid memory hash reanchor payload")

// EncodeMemoryHashReanchorPayload returns the one canonical binary encoding:
//
//	version(1)
//	root credential ID length(4) + bytes
//	root generation(8)
//	entry count(4)
//	repeated memory ID length(4) + bytes + expected status(1) + SHA-256(32)
//
// Entries must already be strictly sorted by raw memory-ID bytes. The encoder
// never sorts on the caller's behalf because doing so could make a differently
// ordered, already-signed body appear canonical.
func EncodeMemoryHashReanchorPayload(payload MemoryHashReanchorPayload) ([]byte, error) {
	if err := validateMemoryHashReanchorPayload(payload); err != nil {
		return nil, err
	}

	encoded := make([]byte, 0, 1+4+len(payload.RootCredentialID)+8+4+
		len(payload.Entries)*(4+sha256.Size+1))
	encoded = append(encoded, payload.Version)
	encoded = appendReanchorBytes(encoded, []byte(payload.RootCredentialID))
	encoded = appendReanchorUint64(encoded, payload.RootGeneration)
	encoded = appendReanchorUint32(encoded, uint32(len(payload.Entries))) // #nosec G115 -- capped at 256
	for _, entry := range payload.Entries {
		encoded = appendReanchorBytes(encoded, []byte(entry.MemoryID))
		status, _ := encodeMemoryHashReanchorStatus(entry.ExpectedStatus)
		encoded = append(encoded, status)
		encoded = append(encoded, entry.ContentHash...)
	}
	if len(encoded) > MaxMemoryHashReanchorPayloadBytes {
		return nil, fmt.Errorf(
			"%w: encoded size %d exceeds %d bytes",
			errMemoryHashReanchorPayload, len(encoded), MaxMemoryHashReanchorPayloadBytes,
		)
	}
	return encoded, nil
}

// DecodeMemoryHashReanchorPayload accepts only the canonical v1 encoding. It
// rejects unknown versions, oversized input, truncation, trailing bytes,
// invalid fields, and non-canonical entry ordering before returning a value.
func DecodeMemoryHashReanchorPayload(encoded []byte) (*MemoryHashReanchorPayload, error) {
	if len(encoded) == 0 {
		return nil, fmt.Errorf("%w: empty payload", errMemoryHashReanchorPayload)
	}
	if len(encoded) > MaxMemoryHashReanchorPayloadBytes {
		return nil, fmt.Errorf(
			"%w: encoded size %d exceeds %d bytes",
			errMemoryHashReanchorPayload, len(encoded), MaxMemoryHashReanchorPayloadBytes,
		)
	}

	offset := 0
	version := encoded[offset]
	offset++
	if version != MemoryHashReanchorPayloadVersion {
		return nil, fmt.Errorf(
			"%w: unsupported version %d", errMemoryHashReanchorPayload, version,
		)
	}

	rootID, next, err := readReanchorBytes(encoded, offset, MaxMemoryHashReanchorIDBytes, "Root credential ID")
	if err != nil {
		return nil, err
	}
	offset = next

	rootGeneration, next, err := readReanchorUint64(encoded, offset, "Root generation")
	if err != nil {
		return nil, err
	}
	offset = next

	entryCount, next, err := readReanchorUint32(encoded, offset, "entry count")
	if err != nil {
		return nil, err
	}
	offset = next
	if entryCount == 0 || entryCount > MaxMemoryHashReanchorEntries {
		return nil, fmt.Errorf(
			"%w: entry count %d is outside 1..%d",
			errMemoryHashReanchorPayload, entryCount, MaxMemoryHashReanchorEntries,
		)
	}

	payload := &MemoryHashReanchorPayload{
		Version:          version,
		RootCredentialID: string(rootID),
		RootGeneration:   rootGeneration,
		Entries:          make([]MemoryHashReanchorEntry, 0, int(entryCount)),
	}
	for i := uint32(0); i < entryCount; i++ {
		memoryID, afterID, readErr := readReanchorBytes(
			encoded, offset, MaxMemoryHashReanchorIDBytes, fmt.Sprintf("entry %d memory ID", i),
		)
		if readErr != nil {
			return nil, readErr
		}
		offset = afterID
		if offset >= len(encoded) {
			return nil, fmt.Errorf(
				"%w: truncated entry %d status", errMemoryHashReanchorPayload, i,
			)
		}
		status, statusErr := decodeMemoryHashReanchorStatus(encoded[offset])
		if statusErr != nil {
			return nil, fmt.Errorf("%w: entry %d: %v", errMemoryHashReanchorPayload, i, statusErr)
		}
		offset++
		if len(encoded)-offset < sha256.Size {
			return nil, fmt.Errorf(
				"%w: truncated entry %d content hash", errMemoryHashReanchorPayload, i,
			)
		}
		contentHash := append([]byte(nil), encoded[offset:offset+sha256.Size]...)
		offset += sha256.Size
		payload.Entries = append(payload.Entries, MemoryHashReanchorEntry{
			MemoryID:       string(memoryID),
			ExpectedStatus: status,
			ContentHash:    contentHash,
		})
	}
	if offset != len(encoded) {
		return nil, fmt.Errorf(
			"%w: %d trailing bytes", errMemoryHashReanchorPayload, len(encoded)-offset,
		)
	}
	if err := validateMemoryHashReanchorPayload(*payload); err != nil {
		return nil, err
	}

	// The parser above is intentionally strict; this equality is a final
	// defense against future decoder drift accidentally accepting a second
	// representation of the same attested payload.
	canonical, err := EncodeMemoryHashReanchorPayload(*payload)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, encoded) {
		return nil, fmt.Errorf("%w: non-canonical encoding", errMemoryHashReanchorPayload)
	}
	return payload, nil
}

// MemoryHashReanchorTargetID validates payload and returns the lowercase
// domain-separated SHA-256 digest required in GovPropose.TargetID.
func MemoryHashReanchorTargetID(payload []byte) (string, error) {
	if _, err := DecodeMemoryHashReanchorPayload(payload); err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(memoryHashReanchorTargetDomain))
	_, _ = digest.Write(payload)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func validateMemoryHashReanchorPayload(payload MemoryHashReanchorPayload) error {
	if payload.Version != MemoryHashReanchorPayloadVersion {
		return fmt.Errorf(
			"%w: unsupported version %d", errMemoryHashReanchorPayload, payload.Version,
		)
	}
	if len(payload.RootCredentialID) == 0 ||
		len(payload.RootCredentialID) > MaxMemoryHashReanchorIDBytes {
		return fmt.Errorf(
			"%w: Root credential ID length %d is outside 1..%d",
			errMemoryHashReanchorPayload,
			len(payload.RootCredentialID),
			MaxMemoryHashReanchorIDBytes,
		)
	}
	if payload.RootGeneration == 0 {
		return fmt.Errorf("%w: Root generation must be positive", errMemoryHashReanchorPayload)
	}
	if len(payload.Entries) == 0 || len(payload.Entries) > MaxMemoryHashReanchorEntries {
		return fmt.Errorf(
			"%w: entry count %d is outside 1..%d",
			errMemoryHashReanchorPayload, len(payload.Entries), MaxMemoryHashReanchorEntries,
		)
	}

	var previous []byte
	for i, entry := range payload.Entries {
		memoryID := []byte(entry.MemoryID)
		if len(memoryID) == 0 || len(memoryID) > MaxMemoryHashReanchorIDBytes {
			return fmt.Errorf(
				"%w: entry %d memory ID length %d is outside 1..%d",
				errMemoryHashReanchorPayload, i, len(memoryID), MaxMemoryHashReanchorIDBytes,
			)
		}
		if i > 0 && bytes.Compare(previous, memoryID) >= 0 {
			return fmt.Errorf(
				"%w: entry %d memory ID is not strictly raw-byte sorted and unique",
				errMemoryHashReanchorPayload, i,
			)
		}
		if _, err := encodeMemoryHashReanchorStatus(entry.ExpectedStatus); err != nil {
			return fmt.Errorf("%w: entry %d: %v", errMemoryHashReanchorPayload, i, err)
		}
		if len(entry.ContentHash) != sha256.Size {
			return fmt.Errorf(
				"%w: entry %d content hash length %d, want %d",
				errMemoryHashReanchorPayload, i, len(entry.ContentHash), sha256.Size,
			)
		}
		previous = memoryID
	}
	return nil
}

func encodeMemoryHashReanchorStatus(status string) (uint8, error) {
	switch status {
	case "committed":
		return memoryHashReanchorStatusCommitted, nil
	case "deprecated":
		return memoryHashReanchorStatusDeprecated, nil
	default:
		return 0, fmt.Errorf("expected status %q is not committed or deprecated", status)
	}
}

func decodeMemoryHashReanchorStatus(status uint8) (string, error) {
	switch status {
	case memoryHashReanchorStatusCommitted:
		return "committed", nil
	case memoryHashReanchorStatusDeprecated:
		return "deprecated", nil
	default:
		return "", fmt.Errorf("unknown expected status code %d", status)
	}
}

func appendReanchorBytes(dst, value []byte) []byte {
	dst = appendReanchorUint32(dst, uint32(len(value))) // #nosec G115 -- validated <= 512
	return append(dst, value...)
}

func appendReanchorUint32(dst []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(dst, encoded[:]...)
}

func appendReanchorUint64(dst []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(dst, encoded[:]...)
}

func readReanchorBytes(
	data []byte,
	offset int,
	max int,
	field string,
) ([]byte, int, error) {
	length, next, err := readReanchorUint32(data, offset, field+" length")
	if err != nil {
		return nil, offset, err
	}
	if length == 0 || length > uint32(max) {
		return nil, offset, fmt.Errorf(
			"%w: %s %d is outside 1..%d",
			errMemoryHashReanchorPayload, field+" length", length, max,
		)
	}
	if uint64(length) > uint64(len(data)-next) {
		return nil, offset, fmt.Errorf(
			"%w: truncated %s", errMemoryHashReanchorPayload, field,
		)
	}
	end := next + int(length) // #nosec G115 -- bounded by the remaining slice
	return data[next:end], end, nil
}

func readReanchorUint32(data []byte, offset int, field string) (uint32, int, error) {
	if offset < 0 || len(data)-offset < 4 {
		return 0, offset, fmt.Errorf(
			"%w: truncated %s", errMemoryHashReanchorPayload, field,
		)
	}
	return binary.BigEndian.Uint32(data[offset : offset+4]), offset + 4, nil
}

func readReanchorUint64(data []byte, offset int, field string) (uint64, int, error) {
	if offset < 0 || len(data)-offset < 8 {
		return 0, offset, fmt.Errorf(
			"%w: truncated %s", errMemoryHashReanchorPayload, field,
		)
	}
	return binary.BigEndian.Uint64(data[offset : offset+8]), offset + 8, nil
}
