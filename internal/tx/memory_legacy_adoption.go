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
	MemoryLegacyAdoptionPayloadVersion  uint8 = 1
	MaxMemoryLegacyAdoptionPayloadBytes       = 256 << 10
	MaxMemoryLegacyAdoptionEntries            = 256
	MaxMemoryLegacyAdoptionIDBytes            = 512
)

const memoryLegacyAdoptionTargetDomain = "sage/memory-legacy-adoption/v1\x00"

const (
	memoryLegacyAdoptionStatusCommitted  uint8 = 1
	memoryLegacyAdoptionStatusDeprecated uint8 = 2
	memoryLegacyAdoptionStatusProposed   uint8 = 3
)

var errMemoryLegacyAdoptionPayload = errors.New("invalid memory legacy adoption payload")

// EncodeMemoryLegacyAdoptionPayload emits the sole accepted binary encoding.
// Entries must already be strictly sorted by raw memory-ID bytes.
func EncodeMemoryLegacyAdoptionPayload(payload MemoryLegacyAdoptionPayload) ([]byte, error) {
	if err := validateMemoryLegacyAdoptionPayload(payload); err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, 1+4+len(payload.RootCredentialID)+8+sha256.Size+4+
		len(payload.Entries)*(4+sha256.Size+1+4*3+1))
	encoded = append(encoded, payload.Version)
	encoded = appendLegacyAdoptionBytes(encoded, []byte(payload.RootCredentialID))
	encoded = appendLegacyAdoptionUint64(encoded, payload.RootGeneration)
	encoded = append(encoded, payload.PlanDigest...)
	encoded = appendLegacyAdoptionUint32(encoded, uint32(len(payload.Entries))) // #nosec G115 -- capped
	for _, entry := range payload.Entries {
		encoded = appendLegacyAdoptionBytes(encoded, []byte(entry.MemoryID))
		status, _ := encodeMemoryLegacyAdoptionStatus(entry.Status)
		encoded = append(encoded, status)
		encoded = append(encoded, entry.ContentHash...)
		encoded = appendLegacyAdoptionBytes(encoded, []byte(entry.Domain))
		encoded = appendLegacyAdoptionBytes(encoded, []byte(entry.Author))
		encoded = appendLegacyAdoptionBytes(encoded, []byte(entry.AuthorPrincipal))
		encoded = append(encoded, entry.Classification)
	}
	if len(encoded) > MaxMemoryLegacyAdoptionPayloadBytes {
		return nil, fmt.Errorf(
			"%w: encoded size %d exceeds %d bytes",
			errMemoryLegacyAdoptionPayload, len(encoded), MaxMemoryLegacyAdoptionPayloadBytes,
		)
	}
	return encoded, nil
}

// DecodeMemoryLegacyAdoptionPayload accepts only the canonical v1 encoding.
func DecodeMemoryLegacyAdoptionPayload(encoded []byte) (*MemoryLegacyAdoptionPayload, error) {
	if len(encoded) == 0 {
		return nil, fmt.Errorf("%w: empty payload", errMemoryLegacyAdoptionPayload)
	}
	if len(encoded) > MaxMemoryLegacyAdoptionPayloadBytes {
		return nil, fmt.Errorf(
			"%w: encoded size %d exceeds %d bytes",
			errMemoryLegacyAdoptionPayload, len(encoded), MaxMemoryLegacyAdoptionPayloadBytes,
		)
	}
	offset := 0
	version := encoded[offset]
	offset++
	if version != MemoryLegacyAdoptionPayloadVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", errMemoryLegacyAdoptionPayload, version)
	}
	root, next, err := readLegacyAdoptionBytes(encoded, offset, MaxMemoryLegacyAdoptionIDBytes, "Root credential ID")
	if err != nil {
		return nil, err
	}
	offset = next
	rootGeneration, next, err := readLegacyAdoptionUint64(encoded, offset, "Root generation")
	if err != nil {
		return nil, err
	}
	offset = next
	if len(encoded)-offset < sha256.Size {
		return nil, fmt.Errorf("%w: truncated plan digest", errMemoryLegacyAdoptionPayload)
	}
	planDigest := append([]byte(nil), encoded[offset:offset+sha256.Size]...)
	offset += sha256.Size
	count, next, err := readLegacyAdoptionUint32(encoded, offset, "entry count")
	if err != nil {
		return nil, err
	}
	offset = next
	if count == 0 || count > MaxMemoryLegacyAdoptionEntries {
		return nil, fmt.Errorf(
			"%w: entry count %d is outside 1..%d",
			errMemoryLegacyAdoptionPayload, count, MaxMemoryLegacyAdoptionEntries,
		)
	}
	payload := &MemoryLegacyAdoptionPayload{
		Version:          version,
		RootCredentialID: string(root),
		RootGeneration:   rootGeneration,
		PlanDigest:       planDigest,
		Entries:          make([]MemoryLegacyAdoptionEntry, 0, int(count)),
	}
	for i := uint32(0); i < count; i++ {
		memoryID, afterID, readErr := readLegacyAdoptionBytes(
			encoded, offset, MaxMemoryLegacyAdoptionIDBytes, fmt.Sprintf("entry %d memory ID", i),
		)
		if readErr != nil {
			return nil, readErr
		}
		offset = afterID
		if offset >= len(encoded) {
			return nil, fmt.Errorf("%w: truncated entry %d status", errMemoryLegacyAdoptionPayload, i)
		}
		status, statusErr := decodeMemoryLegacyAdoptionStatus(encoded[offset])
		if statusErr != nil {
			return nil, fmt.Errorf("%w: entry %d: %v", errMemoryLegacyAdoptionPayload, i, statusErr)
		}
		offset++
		if len(encoded)-offset < sha256.Size {
			return nil, fmt.Errorf("%w: truncated entry %d content hash", errMemoryLegacyAdoptionPayload, i)
		}
		contentHash := append([]byte(nil), encoded[offset:offset+sha256.Size]...)
		offset += sha256.Size
		domain, afterDomain, readErr := readLegacyAdoptionBytes(
			encoded, offset, MaxMemoryLegacyAdoptionIDBytes, fmt.Sprintf("entry %d domain", i),
		)
		if readErr != nil {
			return nil, readErr
		}
		offset = afterDomain
		author, afterAuthor, readErr := readLegacyAdoptionBytes(
			encoded, offset, MaxMemoryLegacyAdoptionIDBytes, fmt.Sprintf("entry %d author", i),
		)
		if readErr != nil {
			return nil, readErr
		}
		offset = afterAuthor
		principal, afterPrincipal, readErr := readLegacyAdoptionBytes(
			encoded, offset, MaxMemoryLegacyAdoptionIDBytes, fmt.Sprintf("entry %d author principal", i),
		)
		if readErr != nil {
			return nil, readErr
		}
		offset = afterPrincipal
		if offset >= len(encoded) {
			return nil, fmt.Errorf("%w: truncated entry %d classification", errMemoryLegacyAdoptionPayload, i)
		}
		classification := encoded[offset]
		offset++
		payload.Entries = append(payload.Entries, MemoryLegacyAdoptionEntry{
			MemoryID:        string(memoryID),
			Status:          status,
			ContentHash:     contentHash,
			Domain:          string(domain),
			Author:          string(author),
			AuthorPrincipal: string(principal),
			Classification:  classification,
		})
	}
	if offset != len(encoded) {
		return nil, fmt.Errorf(
			"%w: %d trailing bytes", errMemoryLegacyAdoptionPayload, len(encoded)-offset,
		)
	}
	if validationErr := validateMemoryLegacyAdoptionPayload(*payload); validationErr != nil {
		return nil, validationErr
	}
	canonical, err := EncodeMemoryLegacyAdoptionPayload(*payload)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, encoded) {
		return nil, fmt.Errorf("%w: non-canonical encoding", errMemoryLegacyAdoptionPayload)
	}
	return payload, nil
}

// MemoryLegacyAdoptionTargetID binds the complete attested evidence.
func MemoryLegacyAdoptionTargetID(payload []byte) (string, error) {
	if _, err := DecodeMemoryLegacyAdoptionPayload(payload); err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(memoryLegacyAdoptionTargetDomain))
	_, _ = digest.Write(payload)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// ValidateMemoryLegacyAdoptionEntry applies the exact per-entry wire bounds
// before an off-consensus planner appends a row to its candidate queue. This
// lets one oversized historical field be isolated for recovery instead of
// making every later valid row unencodable.
func ValidateMemoryLegacyAdoptionEntry(entry MemoryLegacyAdoptionEntry) error {
	return validateMemoryLegacyAdoptionEntry(0, entry)
}

func validateMemoryLegacyAdoptionPayload(payload MemoryLegacyAdoptionPayload) error {
	if payload.Version != MemoryLegacyAdoptionPayloadVersion {
		return fmt.Errorf("%w: unsupported version %d", errMemoryLegacyAdoptionPayload, payload.Version)
	}
	if len(payload.RootCredentialID) == 0 || len(payload.RootCredentialID) > MaxMemoryLegacyAdoptionIDBytes {
		return fmt.Errorf("%w: invalid Root credential ID length %d", errMemoryLegacyAdoptionPayload, len(payload.RootCredentialID))
	}
	if payload.RootGeneration == 0 {
		return fmt.Errorf("%w: Root generation must be positive", errMemoryLegacyAdoptionPayload)
	}
	if len(payload.PlanDigest) != sha256.Size {
		return fmt.Errorf("%w: plan digest length %d, want %d", errMemoryLegacyAdoptionPayload, len(payload.PlanDigest), sha256.Size)
	}
	if len(payload.Entries) == 0 || len(payload.Entries) > MaxMemoryLegacyAdoptionEntries {
		return fmt.Errorf(
			"%w: entry count %d is outside 1..%d",
			errMemoryLegacyAdoptionPayload, len(payload.Entries), MaxMemoryLegacyAdoptionEntries,
		)
	}
	var previous []byte
	for i, entry := range payload.Entries {
		if err := validateMemoryLegacyAdoptionEntry(i, entry); err != nil {
			return err
		}
		memoryID := []byte(entry.MemoryID)
		if i > 0 && bytes.Compare(previous, memoryID) >= 0 {
			return fmt.Errorf("%w: entry %d memory ID is not strictly raw-byte sorted and unique", errMemoryLegacyAdoptionPayload, i)
		}
		previous = append(previous[:0], memoryID...)
	}
	return nil
}

func validateMemoryLegacyAdoptionEntry(index int, entry MemoryLegacyAdoptionEntry) error {
	if len(entry.MemoryID) == 0 || len(entry.MemoryID) > MaxMemoryLegacyAdoptionIDBytes {
		return fmt.Errorf("%w: entry %d has invalid memory ID length %d", errMemoryLegacyAdoptionPayload, index, len(entry.MemoryID))
	}
	if _, err := encodeMemoryLegacyAdoptionStatus(entry.Status); err != nil {
		return fmt.Errorf("%w: entry %d: %v", errMemoryLegacyAdoptionPayload, index, err)
	}
	if len(entry.ContentHash) != sha256.Size {
		return fmt.Errorf("%w: entry %d content hash length %d, want %d", errMemoryLegacyAdoptionPayload, index, len(entry.ContentHash), sha256.Size)
	}
	if len(entry.Domain) == 0 || len(entry.Domain) > MaxMemoryLegacyAdoptionIDBytes {
		return fmt.Errorf("%w: entry %d has invalid domain length %d", errMemoryLegacyAdoptionPayload, index, len(entry.Domain))
	}
	if len(entry.Author) == 0 || len(entry.Author) > MaxMemoryLegacyAdoptionIDBytes {
		return fmt.Errorf("%w: entry %d has invalid author length %d", errMemoryLegacyAdoptionPayload, index, len(entry.Author))
	}
	if len(entry.AuthorPrincipal) == 0 || len(entry.AuthorPrincipal) > MaxMemoryLegacyAdoptionIDBytes {
		return fmt.Errorf("%w: entry %d has invalid author principal length %d", errMemoryLegacyAdoptionPayload, index, len(entry.AuthorPrincipal))
	}
	if entry.Classification > 4 {
		return fmt.Errorf("%w: entry %d classification %d is outside 0..4", errMemoryLegacyAdoptionPayload, index, entry.Classification)
	}
	return nil
}

func encodeMemoryLegacyAdoptionStatus(status string) (uint8, error) {
	switch status {
	case "proposed":
		return memoryLegacyAdoptionStatusProposed, nil
	case "committed":
		return memoryLegacyAdoptionStatusCommitted, nil
	case "deprecated":
		return memoryLegacyAdoptionStatusDeprecated, nil
	default:
		return 0, fmt.Errorf("status %q is not terminal", status)
	}
}

func decodeMemoryLegacyAdoptionStatus(status uint8) (string, error) {
	switch status {
	case memoryLegacyAdoptionStatusProposed:
		return "proposed", nil
	case memoryLegacyAdoptionStatusCommitted:
		return "committed", nil
	case memoryLegacyAdoptionStatusDeprecated:
		return "deprecated", nil
	default:
		return "", fmt.Errorf("unknown status %d", status)
	}
}

func appendLegacyAdoptionBytes(dst, value []byte) []byte {
	dst = appendLegacyAdoptionUint32(dst, uint32(len(value))) // #nosec G115 -- validated
	return append(dst, value...)
}

func appendLegacyAdoptionUint32(dst []byte, value uint32) []byte {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return append(dst, raw[:]...)
}

func appendLegacyAdoptionUint64(dst []byte, value uint64) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	return append(dst, raw[:]...)
}

func readLegacyAdoptionBytes(raw []byte, offset, max int, field string) ([]byte, int, error) {
	length, next, err := readLegacyAdoptionUint32(raw, offset, field+" length")
	if err != nil {
		return nil, 0, err
	}
	if length > uint32(max) {
		return nil, 0, fmt.Errorf("%w: %s length %d exceeds %d", errMemoryLegacyAdoptionPayload, field, length, max)
	}
	if uint64(length) > uint64(len(raw)-next) {
		return nil, 0, fmt.Errorf("%w: truncated %s", errMemoryLegacyAdoptionPayload, field)
	}
	end := next + int(length)
	return append([]byte(nil), raw[next:end]...), end, nil
}

func readLegacyAdoptionUint32(raw []byte, offset int, field string) (uint32, int, error) {
	if offset < 0 || len(raw)-offset < 4 {
		return 0, 0, fmt.Errorf("%w: truncated %s", errMemoryLegacyAdoptionPayload, field)
	}
	return binary.BigEndian.Uint32(raw[offset : offset+4]), offset + 4, nil
}

func readLegacyAdoptionUint64(raw []byte, offset int, field string) (uint64, int, error) {
	if offset < 0 || len(raw)-offset < 8 {
		return 0, 0, fmt.Errorf("%w: truncated %s", errMemoryLegacyAdoptionPayload, field)
	}
	return binary.BigEndian.Uint64(raw[offset : offset+8]), offset + 8, nil
}
