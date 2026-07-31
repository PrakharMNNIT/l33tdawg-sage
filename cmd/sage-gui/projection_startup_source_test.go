package main

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultUnlockDispatchesCanonicalProjectionAuditOffCallbackPath(t *testing.T) {
	nodeBytes, err := os.ReadFile("node.go")
	require.NoError(t, err)
	node := string(nodeBytes)

	start := strings.Index(node, "dashboard.OnVaultUnlocked = func")
	require.NotEqual(t, -1, start)
	end := strings.Index(node[start:], "\n\t}")
	require.NotEqual(t, -1, end)
	callback := node[start : start+end]

	assert.Contains(t, callback, "bootRuntime.SetLocalTxAdmissionBlocked(false)")
	assert.Contains(t, callback, "requestProjectionAudit()")
	assert.NotContains(t, callback, "dashboard.AuditAppV23CanonicalMemoryProjection(",
		"vault unlock must enter the single coalesced full-audit lane")
	assert.Less(t,
		strings.Index(callback, "bootRuntime.SetLocalTxAdmissionBlocked(false)"),
		strings.Index(callback, "requestProjectionAudit()"),
		"vault publication/admission ordering must complete before the audit is dispatched")
}
