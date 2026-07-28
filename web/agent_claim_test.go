package web

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/store"
)

func canonicalClaimToken(fill byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, agentClaimTokenBytes))
}

func seedWebAgentClaim(t *testing.T, s *store.SQLiteStore, token string, expiresAt time.Time, writeKey bool) *store.AgentEntry {
	t.Helper()
	agent := &store.AgentEntry{
		AgentID:         "claim-web-agent-" + token[:8],
		Name:            "Web Claim Agent",
		Role:            "member",
		Status:          "active",
		Clearance:       2,
		DomainAccess:    "project.docs",
		BundlePath:      "/must/not/leak/bundle.zip",
		ClaimToken:      token,
		ClaimExpiresAt:  &expiresAt,
		ValidatorPubkey: "validator-public",
		CreatedAt:       time.Now().UTC(),
	}
	require.NoError(t, s.CreateAgent(context.Background(), agent))
	if writeKey {
		dir := filepath.Join(sageHome(), "bundles", agent.AgentID)
		require.NoError(t, os.MkdirAll(dir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "agent.key"), bytes.Repeat([]byte{0x42}, ed25519.SeedSize), 0o600))
	}
	return agent
}

func claimRequest(token, remoteAddr string) *http.Request {
	body, _ := json.Marshal(map[string]string{"token": token})
	req := httptest.NewRequest(http.MethodPost, "/v1/dashboard/network/claim", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	return req
}

func TestEncryptedRemoteAgentClaimUsesTokenAsSoleAuthority(t *testing.T) {
	t.Setenv("SAGE_HOME", t.TempDir())
	h, s := newTestHandler(t)
	h.Encrypted.Store(true)
	h.VaultLocked.Store(true)
	token := canonicalClaimToken(0x31)
	agent := seedWebAgentClaim(t, s, token, time.Now().Add(time.Hour), true)

	rr := httptest.NewRecorder()
	testRouter(h).ServeHTTP(rr, claimRequest(token, "198.51.100.12:43210"))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	var response map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	assert.Equal(t, agent.AgentID, response["agent_id"])
	assert.Len(t, response["key_seed"], ed25519.SeedSize*2)
	assert.NotContains(t, response, "claim_token")
	assert.NotContains(t, response, "claim_expires_at")
	assert.NotContains(t, response, "bundle_path")
	safeAgent, ok := response["agent"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, agent.Name, safeAgent["name"])
	assert.Equal(t, agent.Role, safeAgent["role"])
	assert.NotContains(t, safeAgent, "claim_token")
	assert.NotContains(t, safeAgent, "claim_expires_at")
	assert.NotContains(t, safeAgent, "bundle_path")
	assert.NotContains(t, rr.Body.String(), token)
	assert.NotContains(t, rr.Body.String(), agent.BundlePath)
}

func TestAgentClaimConcurrentRedemptionExactlyOneSuccess(t *testing.T) {
	t.Setenv("SAGE_HOME", t.TempDir())
	h, s := newTestHandler(t)
	token := canonicalClaimToken(0x32)
	seedWebAgentClaim(t, s, token, time.Now().Add(time.Hour), true)
	router := testRouter(h)

	const contenders = 24
	var successes atomic.Int32
	var rejected atomic.Int32
	var wg sync.WaitGroup
	wg.Add(contenders)
	for i := range contenders {
		go func(i int) {
			defer wg.Done()
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, claimRequest(token, fmt.Sprintf("198.51.100.%d:43210", i+1)))
			switch rr.Code {
			case http.StatusOK:
				successes.Add(1)
			case http.StatusNotFound:
				rejected.Add(1)
			default:
				assert.Failf(t, "unexpected claim response", "status=%d body=%s", rr.Code, rr.Body.String())
			}
		}(i)
	}
	wg.Wait()
	assert.Equal(t, int32(1), successes.Load())
	assert.Equal(t, int32(contenders-1), rejected.Load())
}

func TestAgentClaimExpiryIsRetired(t *testing.T) {
	t.Setenv("SAGE_HOME", t.TempDir())
	h, s := newTestHandler(t)
	token := canonicalClaimToken(0x33)
	agent := seedWebAgentClaim(t, s, token, time.Now().Add(-time.Minute), true)
	router := testRouter(h)

	first := httptest.NewRecorder()
	router.ServeHTTP(first, claimRequest(token, "203.0.113.4:1234"))
	require.Equal(t, http.StatusGone, first.Code, first.Body.String())

	second := httptest.NewRecorder()
	router.ServeHTTP(second, claimRequest(token, "203.0.113.5:1234"))
	require.Equal(t, http.StatusNotFound, second.Code, second.Body.String())
	got, err := s.GetAgent(context.Background(), agent.AgentID)
	require.NoError(t, err)
	assert.Empty(t, got.ClaimToken)
	assert.Nil(t, got.ClaimExpiresAt)
}

func TestAgentClaimDownstreamFailureStillBurnsToken(t *testing.T) {
	t.Setenv("SAGE_HOME", t.TempDir())
	h, s := newTestHandler(t)
	token := canonicalClaimToken(0x34)
	seedWebAgentClaim(t, s, token, time.Now().Add(time.Hour), false)
	router := testRouter(h)

	first := httptest.NewRecorder()
	router.ServeHTTP(first, claimRequest(token, "203.0.113.6:1234"))
	require.Equal(t, http.StatusInternalServerError, first.Code, first.Body.String())

	second := httptest.NewRecorder()
	router.ServeHTTP(second, claimRequest(token, "203.0.113.7:1234"))
	require.Equal(t, http.StatusNotFound, second.Code, second.Body.String())
}

func TestAgentClaimRateLimitUsesRemoteIPNotForwardedHeader(t *testing.T) {
	h, _ := newTestHandler(t)
	router := testRouter(h)
	token := canonicalClaimToken(0x35)
	for i := 0; i < redeemMaxAttempts; i++ {
		req := claimRequest(token, "192.0.2.44:9876")
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i+1))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		require.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())
	}

	req := claimRequest(token, "192.0.2.44:1234")
	req.Header.Set("X-Forwarded-For", "198.51.100.250")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusTooManyRequests, rr.Code, rr.Body.String())
	assert.Equal(t, "60", rr.Header().Get("Retry-After"))
}

func TestAgentClaimRejectsShortLegacyAndOversizedTokens(t *testing.T) {
	h, _ := newTestHandler(t)
	router := testRouter(h)

	legacy := httptest.NewRecorder()
	router.ServeHTTP(legacy, claimRequest("ABC234", "192.0.2.55:1234"))
	require.Equal(t, http.StatusNotFound, legacy.Code, legacy.Body.String())

	body := []byte(`{"token":"` + string(bytes.Repeat([]byte{'A'}, agentClaimRequestMaxBytes)) + `"}`)
	oversized := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/dashboard/network/claim", bytes.NewReader(body))
	req.RemoteAddr = "192.0.2.56:1234"
	router.ServeHTTP(oversized, req)
	require.Equal(t, http.StatusBadRequest, oversized.Code, oversized.Body.String())
}

func TestGenerateAgentClaimTokenIsCanonical256Bit(t *testing.T) {
	token, err := generateClaimToken()
	require.NoError(t, err)
	raw, err := base64.RawURLEncoding.DecodeString(token)
	require.NoError(t, err)
	assert.Len(t, raw, agentClaimTokenBytes)
	assert.True(t, validAgentClaimToken(token))
	assert.False(t, validAgentClaimToken(token+"="))
}
