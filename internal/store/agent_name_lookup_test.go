package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeAgentNameLookupFoldsASCIIOnlyAndEscapesWildcards(t *testing.T) {
	exact, pattern, limit, ok := normalizeAgentNameLookup("  MYNAH-Ü%_\\  ", 200, maxAgentNameLookupResults)
	require.True(t, ok)
	assert.Equal(t, `mynah-Ü\%\_\\`, exact)
	assert.Equal(t, `%mynah-Ü\%\_\\%`, pattern)
	assert.Equal(t, maxAgentNameLookupResults, limit)
	assert.NotContains(t, exact, "ü", "non-ASCII code points must retain registered casing")
}
