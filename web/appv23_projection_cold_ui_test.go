package web

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppV23ColdProjectionDoesNotBecomeUnavailableOrEmptyBrain(t *testing.T) {
	appBytes, err := os.ReadFile("static/js/app.js")
	require.NoError(t, err)
	app := string(appBytes)

	inventoryStart := strings.Index(app, "function BrainDomainInventory")
	require.NotEqual(t, -1, inventoryStart)
	inventoryEnd := strings.Index(app[inventoryStart:], "\nfunction MriView")
	require.NotEqual(t, -1, inventoryEnd)
	inventory := app[inventoryStart : inventoryStart+inventoryEnd]
	assert.Contains(t, inventory, "const projectionChecking")
	assert.Contains(t, inventory, "onAvailability('partial')")
	assert.Contains(t, inventory, "let retryDelay = 2000")
	assert.Contains(t, inventory, "retryDelay = Math.min(retryDelay * 2, 30000)")
	assert.Contains(t, inventory, "retryTimer = setTimeout(load, delay)")
	assert.GreaterOrEqual(t, strings.Count(inventory, "scheduleRetry()"), 2,
		"both checking and real stats failures should recover without a reload storm")
	assert.Contains(t, inventory, "if (projectionChecking)")

	brainStart := strings.Index(app, "function BrainView")
	require.NotEqual(t, -1, brainStart)
	brainEnd := strings.Index(app[brainStart:], "\nfunction ")
	require.NotEqual(t, -1, brainEnd)
	brain := app[brainStart : brainStart+brainEnd]
	assert.Contains(t, brain, "typeof data?.total_memories === 'number'")
	assert.Contains(t, brain, "projection?.complete === true")
	assert.Contains(t, brain, "graphNodeCount === 0")
	assert.Contains(t, brain, "stats.projection?.stale !== true")
	assert.NotContains(t, brain, "(stats.total_memories || 0) === 0")
}

func TestMRIGraphFailureIsUnavailableAndNeverSyntheticEmptyData(t *testing.T) {
	mriBytes, err := os.ReadFile("static/js/mri-brain.js")
	require.NoError(t, err)
	mri := string(mriBytes)

	assert.Contains(t, mri, "throw err;")
	assert.Contains(t, mri, "sage:mri-graph-availability")
	assert.Contains(t, mri, "reportGraphAvailability('unavailable')")
	assert.Contains(t, mri, "let graphRetryDelay = 2000")
	assert.Contains(t, mri, "graphRetryDelay = Math.min(graphRetryDelay * 2, 30000)")
	assert.Contains(t, mri, "scheduleGraphRetry(acquireInitialGraph)")
	assert.Contains(t, mri, "scheduleGraphRetry(load)")
	assert.Contains(t, mri, "connectomeReloadIntent.requestTick()")
	assert.NotContains(t, mri,
		"return { live: false, nodes: [], links: [], total: 0",
		"a transport failure must not masquerade as a successful empty graph")
}

func TestMRIRefreshFailureKeepsSameModeVerifiedSnapshotVisible(t *testing.T) {
	mriBytes, err := os.ReadFile("static/js/mri-brain.js")
	require.NoError(t, err)
	mri := string(mriBytes)

	assert.Contains(t, mri, "let renderedMode = null")
	assert.Contains(t, mri, "renderedMode = request.mode")
	assert.Contains(t, mri, "renderedMode = mode")
	assert.Contains(t, mri, "graphAvailabilityAfterFailure(")
}

func TestMRIPostRenderInitializationFailureKeepsVerifiedGraphVisible(t *testing.T) {
	mriBytes, err := os.ReadFile("static/js/mri-brain.js")
	require.NoError(t, err)
	mri := string(mriBytes)

	coreReady := strings.Index(mri, "Graph.graphData(data);\n    refreshCounts(data);\n    reportGraphAvailability('ready')")
	require.NotEqual(t, -1, coreReady,
		"readiness must be published only after the core graph and truthful HUD exist")
	forceGraph := strings.Index(mri, "Graph = ForceGraph3D({ controlType:'orbit' })($('.mrib-graph'));")
	require.NotEqual(t, -1, forceGraph)
	assert.Greater(t, coreReady, forceGraph)
	optionalChain := strings.Index(mri, "Graph.backgroundColor(mriBgColor())")
	require.NotEqual(t, -1, optionalChain)
	assert.Greater(t, optionalChain, coreReady,
		"optional fluent setters must not run before the verified core is published")

	assert.Contains(t, mri,
		"!!Graph && !!rendered, renderedMode, request.mode")
	assert.Contains(t, mri, "if (availability === 'ready')")
	assert.Contains(t, mri,
		"optional initial graph setup incomplete; keeping verified graph")
	assert.Contains(t, mri,
		"if (typeof Graph.clickAfterDrag === 'function') Graph.clickAfterDrag(true)",
		"optional ForceGraph APIs must be feature-gated so renderer setup can continue")
	assert.NotContains(t, mri, ".onLinkHover(showLinkTip)\n      .clickAfterDrag(true)",
		"an unavailable optional API must not remain in the required fluent chain")
}

func TestMRIOverlayAuthorityDoesNotFollowDomainInventoryFailure(t *testing.T) {
	appBytes, err := os.ReadFile("static/js/app.js")
	require.NoError(t, err)
	app := string(appBytes)

	mriStart := strings.Index(app, "function MriView")
	require.NotEqual(t, -1, mriStart)
	mriEnd := strings.Index(app[mriStart:], "\n// Global tooltips state")
	require.NotEqual(t, -1, mriEnd)
	mri := app[mriStart : mriStart+mriEnd]

	assert.Contains(t, mri,
		"const memoryViewUnavailable = graphAvailability === 'unavailable'")
	assert.NotContains(t, mri,
		"const memoryViewUnavailable = projectionAvailability === 'unavailable'")
}

func TestMemoryListClientCarriesOpaqueContinuation(t *testing.T) {
	apiBytes, err := os.ReadFile("static/js/api.js")
	require.NoError(t, err)
	api := string(apiBytes)

	assert.Contains(t, api, "if (params.cursor) q.set('cursor', params.cursor)")
}
