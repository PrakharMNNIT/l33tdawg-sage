package web

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppV23LinkedMessageUIIsSeparateExactConsentWithoutCheckboxWall(t *testing.T) {
	appBytes, err := os.ReadFile("static/js/app.js")
	require.NoError(t, err)
	app := string(appBytes)
	start := strings.Index(app, `<div class="v23-linked-messages">`)
	require.NotEqual(t, -1, start)
	endOffset := strings.Index(app[start:], "\n        </section>")
	require.NotEqual(t, -1, endOffset)
	card := app[start : start+endOffset]

	assert.Contains(t, card, "A read link does not open an inbox")
	assert.Contains(t, card, "Remote sender")
	assert.Contains(t, card, "Local receiver")
	assert.Contains(t, card, "Block messages")
	assert.Contains(t, card, "Allow exact pair")
	assert.Contains(t, card, "Remote → local only")
	assert.Contains(t, card, "Directory visibility is never used as authority")
	assert.Contains(t, card, "v23-message-principal federated")
	assert.Contains(t, card, "v23-message-principal local")
	assert.NotContains(t, card, `type="checkbox"`)
	assert.NotContains(t, card, "domain_access")
}

func TestAppV23LinkedMessageUIUsesCyanRemoteAndGreenLocalCues(t *testing.T) {
	cssBytes, err := os.ReadFile("static/css/sage.css")
	require.NoError(t, err)
	css := string(cssBytes)

	assert.Contains(t, css, ".v23-message-principal.federated")
	assert.Contains(t, css, "border-color: rgba(6, 182, 212, .55)")
	assert.Contains(t, css, ".v23-message-principal.local")
	assert.Contains(t, css, "border-color: rgba(16, 185, 129, .55)")
	assert.Contains(t, css, ".v23-consent-choice.allowed.selected")
	assert.Contains(t, css, ".v23-consent-choice.blocked.selected")
}
