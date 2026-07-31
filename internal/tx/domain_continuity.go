package tx

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

const (
	DomainContinuityPayloadLegacyVersion uint8 = 1
	DomainContinuityPayloadVersion       uint8 = 2
	MaxDomainContinuityPayloadBytes            = 64 << 10
	MaxDomainContinuityEntries                 = 128
	MaxDomainContinuityWriters                 = 64
	MaxDomainContinuityStringBytes             = 512
)

const domainContinuityTargetDomain = "sage/domain-continuity/v1\x00"

var errDomainContinuityPayload = errors.New("invalid domain continuity payload")

type DomainContinuityEntry struct {
	Domain  string
	Owner   string
	Writers []string
}

// DomainContinuityPayload is a validator-attested restoration manifest.
// Version 1 carries Domain/Writers for already-created singleton proposals.
// Version 2 carries a bounded batch whose entries are strictly domain-sorted.
type DomainContinuityPayload struct {
	Version          uint8
	RootCredentialID string
	RootGeneration   uint64
	PlanDigest       []byte
	Domain           string
	Writers          []string
	Entries          []DomainContinuityEntry
}

func EncodeDomainContinuityPayload(payload DomainContinuityPayload) ([]byte, error) {
	if err := validateDomainContinuityPayload(payload); err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, 1+4+len(payload.RootCredentialID)+8+sha256.Size+256)
	encoded = append(encoded, payload.Version)
	encoded = appendDomainContinuityBytes(encoded, []byte(payload.RootCredentialID))
	encoded = appendDomainContinuityUint64(encoded, payload.RootGeneration)
	encoded = append(encoded, payload.PlanDigest...)
	switch payload.Version {
	case DomainContinuityPayloadLegacyVersion:
		encoded = appendDomainContinuityLegacyEntry(encoded, DomainContinuityEntry{
			Domain: payload.Domain, Writers: payload.Writers,
		})
	case DomainContinuityPayloadVersion:
		encoded = appendDomainContinuityUint32(encoded, uint32(len(payload.Entries))) // #nosec G115 -- bounded
		for _, entry := range payload.Entries {
			encoded = appendDomainContinuityV2Entry(encoded, entry)
		}
	}
	if len(encoded) > MaxDomainContinuityPayloadBytes {
		return nil, fmt.Errorf("%w: encoded payload exceeds %d bytes", errDomainContinuityPayload, MaxDomainContinuityPayloadBytes)
	}
	return encoded, nil
}

func DecodeDomainContinuityPayload(encoded []byte) (*DomainContinuityPayload, error) {
	if len(encoded) == 0 || len(encoded) > MaxDomainContinuityPayloadBytes {
		return nil, fmt.Errorf("%w: invalid encoded size %d", errDomainContinuityPayload, len(encoded))
	}
	offset := 0
	version := encoded[offset]
	offset++
	root, next, err := readDomainContinuityBytes(encoded, offset, MaxDomainContinuityStringBytes, "Root credential ID")
	if err != nil {
		return nil, err
	}
	offset = next
	generation, next, err := readDomainContinuityUint64(encoded, offset, "Root generation")
	if err != nil {
		return nil, err
	}
	offset = next
	if len(encoded)-offset < sha256.Size {
		return nil, fmt.Errorf("%w: truncated plan digest", errDomainContinuityPayload)
	}
	planDigest := append([]byte(nil), encoded[offset:offset+sha256.Size]...)
	offset += sha256.Size
	payload := &DomainContinuityPayload{
		Version: version, RootCredentialID: string(root), RootGeneration: generation,
		PlanDigest: planDigest,
	}
	switch version {
	case DomainContinuityPayloadLegacyVersion:
		entry, after, readErr := readDomainContinuityLegacyEntry(encoded, offset, 0)
		if readErr != nil {
			return nil, readErr
		}
		offset = after
		payload.Domain = entry.Domain
		payload.Writers = entry.Writers
	case DomainContinuityPayloadVersion:
		count, after, readErr := readDomainContinuityUint32(encoded, offset, "entry count")
		if readErr != nil {
			return nil, readErr
		}
		offset = after
		if count == 0 || count > MaxDomainContinuityEntries {
			return nil, fmt.Errorf("%w: entry count %d outside 1..%d", errDomainContinuityPayload, count, MaxDomainContinuityEntries)
		}
		payload.Entries = make([]DomainContinuityEntry, 0, int(count))
		for i := uint32(0); i < count; i++ {
			entry, after, entryErr := readDomainContinuityV2Entry(encoded, offset, int(i))
			if entryErr != nil {
				return nil, entryErr
			}
			offset = after
			payload.Entries = append(payload.Entries, entry)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported version %d", errDomainContinuityPayload, version)
	}
	if offset != len(encoded) {
		return nil, fmt.Errorf("%w: %d trailing bytes", errDomainContinuityPayload, len(encoded)-offset)
	}
	if err := validateDomainContinuityPayload(*payload); err != nil {
		return nil, err
	}
	canonical, err := EncodeDomainContinuityPayload(*payload)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, encoded) {
		return nil, fmt.Errorf("%w: non-canonical encoding", errDomainContinuityPayload)
	}
	return payload, nil
}

func DomainContinuityTargetID(encoded []byte) (string, error) {
	if _, err := DecodeDomainContinuityPayload(encoded); err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(domainContinuityTargetDomain))
	_, _ = digest.Write(encoded)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func validateDomainContinuityPayload(payload DomainContinuityPayload) error {
	if payload.Version != DomainContinuityPayloadLegacyVersion &&
		payload.Version != DomainContinuityPayloadVersion {
		return fmt.Errorf("%w: unsupported version %d", errDomainContinuityPayload, payload.Version)
	}
	if len(payload.RootCredentialID) == 0 || len(payload.RootCredentialID) > MaxDomainContinuityStringBytes {
		return fmt.Errorf("%w: invalid Root credential ID length", errDomainContinuityPayload)
	}
	if payload.RootGeneration == 0 || len(payload.PlanDigest) != sha256.Size {
		return fmt.Errorf("%w: invalid Root generation or plan digest", errDomainContinuityPayload)
	}
	switch payload.Version {
	case DomainContinuityPayloadLegacyVersion:
		if len(payload.Entries) != 0 {
			return fmt.Errorf("%w: legacy payload cannot contain batch entries", errDomainContinuityPayload)
		}
		return validateDomainContinuityLegacyEntry(DomainContinuityEntry{
			Domain: payload.Domain, Writers: payload.Writers,
		})
	case DomainContinuityPayloadVersion:
		if payload.Domain != "" || len(payload.Writers) != 0 {
			return fmt.Errorf("%w: batch payload cannot contain legacy fields", errDomainContinuityPayload)
		}
		if len(payload.Entries) == 0 || len(payload.Entries) > MaxDomainContinuityEntries {
			return fmt.Errorf("%w: invalid entry count", errDomainContinuityPayload)
		}
		for i, entry := range payload.Entries {
			if err := validateDomainContinuityV2Entry(entry); err != nil {
				return fmt.Errorf("entry %d: %w", i, err)
			}
			if i > 0 && payload.Entries[i-1].Domain >= entry.Domain {
				return fmt.Errorf("%w: domains are not strictly sorted", errDomainContinuityPayload)
			}
		}
		return nil
	}
	return fmt.Errorf("%w: unsupported version %d", errDomainContinuityPayload, payload.Version)
}

func validateDomainContinuityLegacyEntry(entry DomainContinuityEntry) error {
	if entry.Owner != "" {
		return fmt.Errorf("%w: legacy entry cannot contain an owner", errDomainContinuityPayload)
	}
	return validateDomainContinuityEntryFields(entry)
}

func validateDomainContinuityV2Entry(entry DomainContinuityEntry) error {
	if len(entry.Owner) == 0 || len(entry.Owner) > MaxDomainContinuityStringBytes {
		return fmt.Errorf("%w: invalid owner length", errDomainContinuityPayload)
	}
	return validateDomainContinuityEntryFields(entry)
}

func validateDomainContinuityEntryFields(entry DomainContinuityEntry) error {
	if len(entry.Domain) == 0 || len(entry.Domain) > MaxDomainContinuityStringBytes {
		return fmt.Errorf("%w: invalid domain length", errDomainContinuityPayload)
	}
	if len(entry.Writers) == 0 || len(entry.Writers) > MaxDomainContinuityWriters {
		return fmt.Errorf("%w: invalid writer count", errDomainContinuityPayload)
	}
	if !sort.StringsAreSorted(entry.Writers) {
		return fmt.Errorf("%w: writers are not sorted", errDomainContinuityPayload)
	}
	for i, writer := range entry.Writers {
		if len(writer) == 0 || len(writer) > MaxDomainContinuityStringBytes {
			return fmt.Errorf("%w: invalid writer %d length", errDomainContinuityPayload, i)
		}
		if i > 0 && entry.Writers[i-1] == writer {
			return fmt.Errorf("%w: duplicate writer", errDomainContinuityPayload)
		}
	}
	return nil
}

// DomainContinuityEntries normalizes both wire versions to the batch model.
func DomainContinuityEntries(payload *DomainContinuityPayload) []DomainContinuityEntry {
	if payload == nil {
		return nil
	}
	if payload.Version == DomainContinuityPayloadLegacyVersion {
		return []DomainContinuityEntry{{
			Domain: payload.Domain, Writers: append([]string(nil), payload.Writers...),
		}}
	}
	entries := make([]DomainContinuityEntry, len(payload.Entries))
	for i := range payload.Entries {
		entries[i] = DomainContinuityEntry{
			Domain:  payload.Entries[i].Domain,
			Owner:   payload.Entries[i].Owner,
			Writers: append([]string(nil), payload.Entries[i].Writers...),
		}
	}
	return entries
}

func appendDomainContinuityLegacyEntry(dst []byte, entry DomainContinuityEntry) []byte {
	dst = appendDomainContinuityBytes(dst, []byte(entry.Domain))
	return appendDomainContinuityWriters(dst, entry.Writers)
}

func appendDomainContinuityV2Entry(dst []byte, entry DomainContinuityEntry) []byte {
	dst = appendDomainContinuityBytes(dst, []byte(entry.Domain))
	dst = appendDomainContinuityBytes(dst, []byte(entry.Owner))
	return appendDomainContinuityWriters(dst, entry.Writers)
}

func appendDomainContinuityWriters(dst []byte, writers []string) []byte {
	dst = appendDomainContinuityUint32(dst, uint32(len(writers))) // #nosec G115 -- bounded
	for _, writer := range writers {
		dst = appendDomainContinuityBytes(dst, []byte(writer))
	}
	return dst
}

func readDomainContinuityLegacyEntry(data []byte, offset, index int) (DomainContinuityEntry, int, error) {
	domain, next, err := readDomainContinuityBytes(
		data, offset, MaxDomainContinuityStringBytes, fmt.Sprintf("entry %d domain", index),
	)
	if err != nil {
		return DomainContinuityEntry{}, offset, err
	}
	return readDomainContinuityWriters(data, next, index, DomainContinuityEntry{Domain: string(domain)})
}

func readDomainContinuityV2Entry(data []byte, offset, index int) (DomainContinuityEntry, int, error) {
	domain, next, err := readDomainContinuityBytes(
		data, offset, MaxDomainContinuityStringBytes, fmt.Sprintf("entry %d domain", index),
	)
	if err != nil {
		return DomainContinuityEntry{}, offset, err
	}
	owner, next, err := readDomainContinuityBytes(
		data, next, MaxDomainContinuityStringBytes, fmt.Sprintf("entry %d owner", index),
	)
	if err != nil {
		return DomainContinuityEntry{}, offset, err
	}
	return readDomainContinuityWriters(data, next, index, DomainContinuityEntry{
		Domain: string(domain), Owner: string(owner),
	})
}

func readDomainContinuityWriters(data []byte, offset, index int, entry DomainContinuityEntry) (DomainContinuityEntry, int, error) {
	count, next, err := readDomainContinuityUint32(data, offset, fmt.Sprintf("entry %d writer count", index))
	if err != nil {
		return DomainContinuityEntry{}, offset, err
	}
	if count == 0 || count > MaxDomainContinuityWriters {
		return DomainContinuityEntry{}, offset, fmt.Errorf(
			"%w: writer count %d outside 1..%d", errDomainContinuityPayload, count, MaxDomainContinuityWriters,
		)
	}
	entry.Writers = make([]string, 0, int(count))
	for i := uint32(0); i < count; i++ {
		writer, after, readErr := readDomainContinuityBytes(
			data, next, MaxDomainContinuityStringBytes, fmt.Sprintf("entry %d writer %d", index, i),
		)
		if readErr != nil {
			return DomainContinuityEntry{}, offset, readErr
		}
		next = after
		entry.Writers = append(entry.Writers, string(writer))
	}
	return entry, next, nil
}

func appendDomainContinuityBytes(dst, value []byte) []byte {
	dst = appendDomainContinuityUint32(dst, uint32(len(value))) // #nosec G115 -- bounded by validation
	return append(dst, value...)
}

func appendDomainContinuityUint32(dst []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(dst, encoded[:]...)
}

func appendDomainContinuityUint64(dst []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(dst, encoded[:]...)
}

func readDomainContinuityBytes(data []byte, offset, max int, field string) ([]byte, int, error) {
	length, next, err := readDomainContinuityUint32(data, offset, field+" length")
	if err != nil {
		return nil, offset, err
	}
	if length == 0 || length > uint32(max) {
		return nil, offset, fmt.Errorf("%w: %s length %d outside 1..%d", errDomainContinuityPayload, field, length, max)
	}
	if uint64(next)+uint64(length) > uint64(len(data)) {
		return nil, offset, fmt.Errorf("%w: truncated %s", errDomainContinuityPayload, field)
	}
	end := next + int(length)
	return data[next:end], end, nil
}

func readDomainContinuityUint32(data []byte, offset int, field string) (uint32, int, error) {
	if offset < 0 || len(data)-offset < 4 {
		return 0, offset, fmt.Errorf("%w: truncated %s", errDomainContinuityPayload, field)
	}
	return binary.BigEndian.Uint32(data[offset : offset+4]), offset + 4, nil
}

func readDomainContinuityUint64(data []byte, offset int, field string) (uint64, int, error) {
	if offset < 0 || len(data)-offset < 8 {
		return 0, offset, fmt.Errorf("%w: truncated %s", errDomainContinuityPayload, field)
	}
	return binary.BigEndian.Uint64(data[offset : offset+8]), offset + 8, nil
}
