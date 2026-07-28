package store

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seedSQLiteAgentClaim(t *testing.T, s *SQLiteStore, token string, expiresAt *time.Time) *AgentEntry {
	t.Helper()
	agent := &AgentEntry{
		AgentID:        "claim-agent-" + token[:8],
		Name:           "Claim Agent",
		Role:           "member",
		Status:         "active",
		ClaimToken:     token,
		ClaimExpiresAt: expiresAt,
		CreatedAt:      time.Now().UTC(),
	}
	require.NoError(t, s.CreateAgent(context.Background(), agent))
	return agent
}

func TestSQLiteRedeemAgentClaimConcurrentSingleUse(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	expiresAt := now.Add(time.Hour)
	const token = "sqlite-concurrent-claim-token"
	agent := seedSQLiteAgentClaim(t, s, token, &expiresAt)

	const contenders = 32
	var successes atomic.Int32
	var invalid atomic.Int32
	var wg sync.WaitGroup
	wg.Add(contenders)
	for range contenders {
		go func() {
			defer wg.Done()
			agentID, err := s.RedeemAgentClaim(context.Background(), token, now)
			switch {
			case err == nil:
				assert.Equal(t, agent.AgentID, agentID)
				successes.Add(1)
			case errors.Is(err, ErrAgentClaimInvalid):
				invalid.Add(1)
			default:
				assert.NoError(t, err)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), successes.Load())
	assert.Equal(t, int32(contenders-1), invalid.Load())
	got, err := s.GetAgent(context.Background(), agent.AgentID)
	require.NoError(t, err)
	assert.Empty(t, got.ClaimToken)
	assert.Nil(t, got.ClaimExpiresAt)
}

func TestSQLiteRedeemAgentClaimExpiresAndRetiresToken(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	expiresAt := now.Add(-time.Second)
	const token = "sqlite-expired-claim-token"
	agent := seedSQLiteAgentClaim(t, s, token, &expiresAt)

	_, err := s.RedeemAgentClaim(context.Background(), token, now)
	require.ErrorIs(t, err, ErrAgentClaimExpired)
	_, err = s.RedeemAgentClaim(context.Background(), token, now)
	require.ErrorIs(t, err, ErrAgentClaimInvalid)

	got, err := s.GetAgent(context.Background(), agent.AgentID)
	require.NoError(t, err)
	assert.Empty(t, got.ClaimToken)
	assert.Nil(t, got.ClaimExpiresAt)
}

func TestSQLiteRedeemAgentClaimMalformedExpiryFailsClosed(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	const token = "sqlite-malformed-expiry-token"
	agent := seedSQLiteAgentClaim(t, s, token, nil)
	_, err := s.writeExecContext(context.Background(),
		`UPDATE network_agents SET claim_expires_at = ? WHERE agent_id = ?`,
		"not-a-time", agent.AgentID)
	require.NoError(t, err)

	_, err = s.RedeemAgentClaim(context.Background(), token, now)
	require.ErrorIs(t, err, ErrAgentClaimExpired)
	_, err = s.RedeemAgentClaim(context.Background(), token, now)
	require.ErrorIs(t, err, ErrAgentClaimInvalid)
}
