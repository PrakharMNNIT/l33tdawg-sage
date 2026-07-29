package taskidempotency

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/tx"
)

func TestTaskIdentityAndPayloadDigestAreStableAndExact(t *testing.T) {
	principal := strings.Repeat("a1", 32)
	assignee := strings.Repeat("b2", 32)
	contentHash := sha256.Sum256([]byte("[TASK] Inspect HDMI port"))
	submit := &tx.MemorySubmit{
		ContentHash:     contentHash[:],
		MemoryType:      tx.MemoryTypeTask,
		DomainTag:       "technical.hardware",
		ConfidenceScore: 0.9,
		Content:         "[TASK] Inspect HDMI port",
		Classification:  tx.ClearanceInternal,
		TaskStatus:      "planned",
		Tags:            []string{"hardware", "urgent"},
	}
	var err error
	submit.MemoryID, err = MemoryID(principal, "request-1")
	require.NoError(t, err)
	require.Equal(t, "4", submit.MemoryID[14:15], "stable identifier remains UUID-shaped")

	first, err := PayloadDigest(principal, assignee, submit)
	require.NoError(t, err)
	second, err := PayloadDigest(principal, assignee, submit)
	require.NoError(t, err)
	require.Equal(t, first, second)

	changed := *submit
	changed.Tags = []string{"hardware", "urgent", "onsite"}
	other, err := PayloadDigest(principal, assignee, &changed)
	require.NoError(t, err)
	require.NotEqual(t, first, other, "every canonical task field must affect the receipt")

	otherID, err := MemoryID(principal, "request-2")
	require.NoError(t, err)
	require.NotEqual(t, submit.MemoryID, otherID)
}

func TestTaskIdempotencyKeyValidationIsCanonicalAndBounded(t *testing.T) {
	require.NoError(t, ValidateKey("mcp-deadbeef"))
	require.Error(t, ValidateKey(""))
	require.Error(t, ValidateKey("contains spaces"))
	require.Error(t, ValidateKey(strings.Repeat("x", MaxKeyBytes+1)))
}

func TestSemanticKeyIsStableAndCallerDomainContentBound(t *testing.T) {
	agent := strings.Repeat("ab", 32)
	first, err := SemanticKey(agent, "technical.hardware", "[TASK] Check HDMI")
	require.NoError(t, err)
	second, err := SemanticKey(agent, "technical.hardware", "[TASK] Check HDMI")
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.NoError(t, ValidateKey(first))

	otherDomain, err := SemanticKey(agent, "technical.audio", "[TASK] Check HDMI")
	require.NoError(t, err)
	require.NotEqual(t, first, otherDomain)
	otherContent, err := SemanticKey(agent, "technical.hardware", "[TASK] Check cable")
	require.NoError(t, err)
	require.NotEqual(t, first, otherContent)
	otherAgent, err := SemanticKey(strings.Repeat("cd", 32), "technical.hardware", "[TASK] Check HDMI")
	require.NoError(t, err)
	require.NotEqual(t, first, otherAgent)
}
