package store

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAgentCapabilityPersistenceRejectsUnknownBits(t *testing.T) {
	bs := newTestBadger(t)
	const agentID = "capability-validation-agent"
	require.NoError(t, bs.RegisterAgent(agentID, "Capability Agent", "member", "", "", "", 1))

	unknown := AgentCapabilities(1 << 31)
	err := bs.SetAgentPermissionWithCapabilities(agentID, 1, "", "*", "", "", unknown)
	require.ErrorContains(t, err, "unknown agent capability bits")

	agent, err := bs.GetRegisteredAgent(agentID)
	require.NoError(t, err)
	require.Zero(t, agent.Capabilities, "rejected masks must not mutate the stored permission record")

	agent.Capabilities = unknown
	rawAgent, err := json.Marshal(agent)
	require.NoError(t, err)
	require.NoError(t, bs.SetRawForTest(agentOnChainKey(agentID), rawAgent))

	capabilities, registered, err := bs.GetRegisteredAgentCapabilities(agentID)
	require.ErrorContains(t, err, "unknown agent capability bits")
	require.True(t, registered, "a malformed mask must remain distinguishable from an unknown agent")
	require.Zero(t, capabilities, "callers must never receive a partially trusted malformed mask")
}
