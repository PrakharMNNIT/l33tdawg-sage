// Package idfmt provides bounded, panic-free formatting for identifiers that
// may come from legacy state or untrusted request data.
package idfmt

const humanPrefixBytes = 16

// Prefix returns at most the first 16 bytes of id. Canonical SAGE agent IDs are
// lowercase ASCII hex, so this preserves their historical human-readable log
// representation exactly while remaining safe for empty and legacy short IDs.
func Prefix(id string) string {
	if len(id) > humanPrefixBytes {
		return id[:humanPrefixBytes]
	}
	return id
}
