package web

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppV23AddAgentWizardCollectsIdentityNotDiscardedPolicyIntent(t *testing.T) {
	appBytes, err := os.ReadFile("static/js/app.js")
	require.NoError(t, err)
	app := string(appBytes)
	start := strings.Index(app, "function AddAgentWizard")
	require.NotEqual(t, -1, start)
	endOffset := strings.Index(app[start:], "\nfunction shellQuote")
	require.NotEqual(t, -1, endOffset)
	wizard := app[start : start+endOffset]

	assert.Contains(t, wizard, "Access review")
	assert.Contains(t, wizard, "This wizard creates the agent identity and connection material only")
	assert.Contains(t, wizard, "It does not stage or remember a requested role, clearance, or domain list")
	assert.Contains(t, wizard, "Open Access Controls")
	assert.Contains(t, wizard, "name, avatar, boot_bio: bio")

	assert.NotContains(t, wizard, "Requested role after approval")
	assert.NotContains(t, wizard, "<label>Domain Access</label>")
	assert.NotContains(t, wizard, "Clearance Level")
	assert.NotContains(t, wizard, "Approval intent")
	assert.NotContains(t, wizard, "Requested domains")
	assert.NotContains(t, wizard, "domain_access: JSON.stringify")
	assert.NotContains(t, wizard, "role: 'member'")
}
