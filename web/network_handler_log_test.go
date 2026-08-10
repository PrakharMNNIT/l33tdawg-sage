package web

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryReassignLogFingerprintIsBoundedAndControlSafe(t *testing.T) {
	inputs := []string{
		"source\r\nFORGED log entry\x00\x01\x1f",
		"target\nsecond line\r\x02\x03",
		strings.Repeat("agent-id-", 1<<17),
	}
	safeHex := regexp.MustCompile(`^[0-9a-f]{24}$`)

	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		fingerprint := memoryReassignLogFingerprint(input)
		require.True(t, safeHex.MatchString(fingerprint), "fingerprint must be fixed-size lowercase hex: %q", fingerprint)
		assert.NotContains(t, fingerprint, "\r")
		assert.NotContains(t, fingerprint, "\n")
		for _, control := range []byte{0x00, 0x01, 0x02, 0x03, 0x1f} {
			assert.NotContains(t, []byte(fingerprint), control)
		}
		seen[fingerprint] = struct{}{}
	}
	assert.Len(t, seen, len(inputs), "distinct agent IDs should retain distinct diagnostic correlation values")
	assert.Equal(t, memoryReassignLogFingerprint(inputs[0]), memoryReassignLogFingerprint(inputs[0]),
		"the same agent ID must retain a stable diagnostic correlation value")
}
