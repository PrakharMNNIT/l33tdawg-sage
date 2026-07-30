package rest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/auth"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/vault"
)

func appV23LookupVaultKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("app-v23-agent-lookup-vault:" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func appV23LookupVaultID(key ed25519.PrivateKey) string {
	return auth.PublicKeyToAgentID(key.Public().(ed25519.PublicKey))
}

func signedAgentLookupRequest(
	t *testing.T,
	key ed25519.PrivateKey,
	agentID, path string,
) *http.Request {
	t.Helper()
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	require.NoError(t, err)
	timestamp := time.Now().Unix()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-Agent-ID", agentID)
	req.Header.Set("X-Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set("X-Nonce", hex.EncodeToString(nonce))
	req.Header.Set("X-Signature", hex.EncodeToString(
		auth.SignRequestWithNonce(key, http.MethodGet, path, nil, timestamp, nonce),
	))
	return req
}

func TestAppV23AgentLookupLiveNamesMatchAcrossUnlockedVaultModes(t *testing.T) {
	keys := map[string]ed25519.PrivateKey{}
	ids := map[string]string{}
	names := []string{
		"root", "caller", "claude", "mynah", "unrelated",
		"claude-pending", "claude-inactive",
	}
	for i := 0; i < 21; i++ {
		names = append(
			names,
			fmt.Sprintf("claude-page-pending-%02d", i),
			fmt.Sprintf("mynah-page-pending-%02d", i),
		)
	}
	for _, name := range names {
		keys[name] = appV23LookupVaultKey(name)
		ids[name] = appV23LookupVaultID(keys[name])
	}

	type lookupResult struct {
		Query     string
		AgentID   string
		Name      string
		MatchKind string
	}
	var baseline []lookupResult

	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "unencrypted", true: "encrypted-unlocked"}[encrypted], func(t *testing.T) {
			srv, _, badger, _ := newRBACTestServer(t)
			agents, err := store.NewSQLiteStore(
				t.Context(), filepath.Join(t.TempDir(), "agents.db"),
			)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, agents.Close()) })
			srv.agentStore = agents

			if encrypted {
				keyPath := filepath.Join(t.TempDir(), "vault.key")
				require.NoError(t, vault.Init(keyPath, "agent-lookup-passphrase"))
				unlocked, openErr := vault.Open(keyPath, "agent-lookup-passphrase")
				require.NoError(t, openErr)
				agents.SetVault(unlocked)
				agents.SetVaultExpected(true)
				require.True(t, agents.VaultActive())
			} else {
				require.False(t, agents.VaultActive())
			}

			require.NoError(t, badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
				RootID: ids["root"], Scope: "agent-lookup-vault",
				AgentID: ids["caller"], Profile: store.AppV23ProfileStandard,
				HomeDomain: "caller.home", Clearance: 1, Capabilities: 0,
				Height: 1, BootstrapDigest: "agent-lookup-vault-bootstrap",
			}))
			require.NoError(t, agents.CreateAgent(t.Context(), &store.AgentEntry{
				AgentID: ids["root"], Name: "claude-root",
				Role: store.AppV23RoleAdmin, Status: "active", Clearance: 4,
			}))
			require.NoError(t, agents.CreateAgent(t.Context(), &store.AgentEntry{
				AgentID: ids["caller"], Name: "ordinary-caller",
				Role: store.AppV23RoleMember, Status: "active", Clearance: 1,
			}))

			addAgent := func(
				name, displayName, registeredName, provider string,
				clearance uint8, active *bool,
			) {
				t.Helper()
				require.NoError(t, badger.RegisterAgentWithCapabilities(
					ids[name], displayName, store.AppV23RoleMember, "",
					provider, "", int64(clearance), 0,
				))
				if active != nil {
					require.NoError(t, badger.ApproveAppV23LocalAgent(
						store.AppV23LocalEnrollment{
							AgentID: ids[name], ApprovedBy: ids["root"],
							RootGeneration: 1, Profile: store.AppV23ProfileStandard,
							HomeDomain: name + ".home", Clearance: clearance,
							Capabilities: 0, Active: *active, UpdatedHeight: 2,
						},
						store.AppV23RoleMember, 0, 0,
					))
				}
				require.NoError(t, agents.CreateAgent(t.Context(), &store.AgentEntry{
					AgentID: ids[name], Name: displayName,
					RegisteredName: registeredName, Provider: provider,
					Role: store.AppV23RoleMember, Status: "active",
					Clearance: int(clearance),
				}))
			}
			active, inactive := true, false
			addAgent(
				"claude", "claude-code/sage", "claude-code/sage",
				"claude-code", 4, &active,
			)
			addAgent(
				"mynah", "Mynah - Sage Voice Bridge", "agent-mynah",
				"mynah-appliance", 3, &active,
			)
			addAgent(
				"unrelated", "Perplexity Research", "perplexity/research",
				"perplexity", 1, &active,
			)
			addAgent(
				"claude-pending", "claude pending", "claude/pending",
				"claude-code", 1, nil,
			)
			addAgent(
				"claude-inactive", "claude inactive", "claude/inactive",
				"claude-code", 1, &inactive,
			)
			// SQL status alone is not canonical enrollment. More than one
			// complete candidate page of matching self-registrations must not
			// starve the later active claude/mynah recipient.
			for i := 0; i < 21; i++ {
				addAgent(
					fmt.Sprintf("claude-page-pending-%02d", i),
					fmt.Sprintf("claude !%02d pending", i),
					fmt.Sprintf("claude/pending/%02d", i),
					"claude-code", 1, nil,
				)
				addAgent(
					fmt.Sprintf("mynah-page-pending-%02d", i),
					fmt.Sprintf("mynah !%02d pending", i),
					fmt.Sprintf("mynah/pending/%02d", i),
					"mynah-pending", 1, nil,
				)
			}
			srv.SetPostV23ForNextTxAccessor(func() bool { return true })

			results := make([]lookupResult, 0, 2)
			requestCase := "unencrypted"
			if encrypted {
				requestCase = "encrypted-unlocked"
			}
			for _, tc := range []struct {
				query, wantName, wantID string
			}{
				{query: "claude", wantName: "claude-code/sage", wantID: ids["claude"]},
				{query: "mynah", wantName: "Mynah - Sage Voice Bridge", wantID: ids["mynah"]},
			} {
				req := signedRequestAs(
					t, keys["caller"], ids["caller"], http.MethodGet,
					"/v1/agents/lookup?name="+tc.query+"&limit=20&case="+requestCase, nil,
				)
				rec := httptest.NewRecorder()
				srv.Router().ServeHTTP(rec, req)
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				response := decodeAgentLookup(t, rec)
				require.Equal(t, 1, response.Total, rec.Body.String())
				require.Len(t, response.Agents, 1)
				require.Equal(t, tc.wantID, response.Agents[0].AgentID)
				require.Equal(t, tc.wantName, response.Agents[0].Name)
				require.Equal(t, "substring", response.Agents[0].MatchKind)
				require.NotEqual(t, ids["root"], response.Agents[0].AgentID)
				require.NotEqual(t, ids["claude-pending"], response.Agents[0].AgentID)
				require.NotEqual(t, ids["claude-inactive"], response.Agents[0].AgentID)
				require.NotEqual(t, ids["unrelated"], response.Agents[0].AgentID)
				results = append(results, lookupResult{
					Query: tc.query, AgentID: response.Agents[0].AgentID,
					Name:      response.Agents[0].Name,
					MatchKind: response.Agents[0].MatchKind,
				})
			}

			if !encrypted {
				baseline = results
			} else {
				require.Equal(t, baseline, results,
					"unlocked encryption must not change caller-scoped agent discovery")
			}
		})
	}
}

func TestAppV23AgentLookupMigratesLegacyRosterAcrossUnlockedVaultModes(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "unencrypted", true: "encrypted-unlocked"}[encrypted], func(t *testing.T) {
			srv, _, badger, _ := newRBACTestServer(t)
			agents, err := store.NewSQLiteStore(
				t.Context(), filepath.Join(t.TempDir(), "legacy-agents.db"),
			)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, agents.Close()) })
			srv.agentStore = agents

			if encrypted {
				keyPath := filepath.Join(t.TempDir(), "legacy-vault.key")
				require.NoError(t, vault.Init(keyPath, "legacy-agent-lookup-passphrase"))
				unlocked, openErr := vault.Open(keyPath, "legacy-agent-lookup-passphrase")
				require.NoError(t, openErr)
				agents.SetVault(unlocked)
				agents.SetVaultExpected(true)
				require.True(t, agents.VaultActive())
			} else {
				require.False(t, agents.VaultActive())
			}

			keys := map[string]ed25519.PrivateKey{}
			ids := map[string]string{}
			for _, name := range []string{"root", "caller", "claude", "mynah"} {
				keys[name] = appV23LookupVaultKey("legacy-" + name)
				ids[name] = appV23LookupVaultID(keys[name])
			}
			legacy := []struct {
				name, displayName, registeredName, provider, role string
				capabilities                                      store.AgentCapabilities
			}{
				{
					name: "root", displayName: "Legacy CEREBRUM operator",
					registeredName: "legacy-root", provider: "cerebrum",
					role: store.AppV23RoleAdmin,
				},
				{
					name: "caller", displayName: "codex/release",
					registeredName: "codex/release", provider: "codex",
					role: store.AppV23RoleMember,
				},
				{
					name: "claude", displayName: "claude-code/sage",
					registeredName: "claude-code/sage", provider: "claude-code",
					role: store.AppV23RoleMember,
				},
				{
					name: "mynah", displayName: "MYNAH (SAGE Voice Bridge Agent)",
					registeredName: "SAGE Voice Bridge", provider: "mynah-appliance",
					role: store.AppV23RoleMember, capabilities: 15,
				},
			}
			for i, item := range legacy {
				require.NoError(t, badger.RegisterAgentWithCapabilities(
					ids[item.name], item.displayName, item.role, "", item.provider, "",
					int64(i+1), item.capabilities,
				))
				require.NoError(t, agents.CreateAgent(t.Context(), &store.AgentEntry{
					AgentID: ids[item.name], Name: item.displayName,
					RegisteredName: item.registeredName, Provider: item.provider,
					Role: item.role, Status: "active", Clearance: 1,
					Capabilities: item.capabilities,
				}))
			}

			for _, name := range []string{"caller", "claude", "mynah"} {
				enrollment, enrollmentErr := badger.GetAppV23Enrollment(ids[name])
				require.NoError(t, enrollmentErr)
				require.Nil(t, enrollment,
					"fixture must begin as a real pre-v23 roster without local enrollment")
			}

			require.NoError(t, badger.EnsureAppV23Root("legacy-agent-lookup", 100))
			require.NoError(t, badger.ValidateAppV23State())
			for _, tc := range []struct {
				name, profile string
			}{
				{name: "caller", profile: store.AppV23ProfileStandard},
				{name: "claude", profile: store.AppV23ProfileStandard},
				{name: "mynah", profile: store.AppV23ProfileCompanion},
			} {
				enrollment, enrollmentErr := badger.GetAppV23Enrollment(ids[tc.name])
				require.NoError(t, enrollmentErr)
				require.NotNil(t, enrollment)
				require.True(t, enrollment.Active)
				require.Equal(t, tc.profile, enrollment.Profile)
			}

			// App-v24 retains app-v23's local-enrollment authority. The REST gate
			// therefore switches on at v23 and remains the production lookup path
			// after the v24 lifecycle upgrade.
			srv.SetPostV23ForNextTxAccessor(func() bool { return true })
			for _, tc := range []struct {
				query, wantName, wantID string
			}{
				{query: "claude", wantName: "claude-code/sage", wantID: ids["claude"]},
				{
					query: "mynah", wantName: "MYNAH (SAGE Voice Bridge Agent)",
					wantID: ids["mynah"],
				},
			} {
				req := signedAgentLookupRequest(
					t, keys["caller"], ids["caller"],
					"/v1/agents/lookup?name="+tc.query+"&limit=20",
				)
				rec := httptest.NewRecorder()
				srv.Router().ServeHTTP(rec, req)
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				response := decodeAgentLookup(t, rec)
				require.Equal(t, 1, response.Total, rec.Body.String())
				require.Len(t, response.Agents, 1)
				require.Equal(t, tc.wantID, response.Agents[0].AgentID)
				require.Equal(t, tc.wantName, response.Agents[0].Name)
				require.Equal(t, "substring", response.Agents[0].MatchKind)
			}
		})
	}
}
