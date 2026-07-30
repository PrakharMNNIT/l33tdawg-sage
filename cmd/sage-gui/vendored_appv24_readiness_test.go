package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVendoredAgentProtocolStatusRequiresAppV24ForNextTx(t *testing.T) {
	waiting := vendoredAgentProtocolStatus(false)
	require.True(t, waiting.Required)
	require.False(t, waiting.OK)
	require.Equal(t, "waiting_for_app_v24", waiting.State)

	ready := vendoredAgentProtocolStatus(true)
	require.True(t, ready.Required)
	require.True(t, ready.OK)
	require.Equal(t, "ready", ready.State)
}
