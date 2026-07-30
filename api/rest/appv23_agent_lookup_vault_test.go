package rest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

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

func TestAppV23AgentLookupLiveNamesMatchAcrossUnlockedVaultModes(t *testing.T) {
	keys := map[string]ed25519.PrivateKey{}
	ids := map[string]string{}
	for _, name := range []string{
		"root", "caller", "claude", "mynah", "unrelated",
		"claude-pending", "claude-inactive",
	} {
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
