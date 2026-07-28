package mcp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatPipelineInboxItemLegacyShortSenderNoPanic(t *testing.T) {
	short := formatPipelineInboxItem(pipelineInboxWireItem{FromAgent: "x"})
	require.Equal(t, "x", short["from"])

	canonicalID := strings.Repeat("ab", 32)
	canonical := formatPipelineInboxItem(pipelineInboxWireItem{FromAgent: canonicalID})
	require.Equal(t, canonicalID[:16]+"...", canonical["from"])
}
