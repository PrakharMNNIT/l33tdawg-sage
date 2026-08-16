package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadOrGenerateKeyConcurrentFirstLaunchUsesOneIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.key")
	const callers = 24
	ids := make(chan string, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, err := loadOrGenerateKey(path)
			if err == nil {
				ids <- hex.EncodeToString(key.Public().(ed25519.PublicKey))
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	unique := map[string]bool{}
	for id := range ids {
		unique[id] = true
	}
	require.Len(t, unique, 1)
}

func TestCanonicalWorkspaceRootCollapsesLinkedWorktree(t *testing.T) {
	root := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", output)
	}
	run("init")
	require.NoError(t, os.WriteFile(filepath.Join(root, "README.md"), []byte("workspace\n"), 0o600))
	run("add", "README.md")
	run("-c", "user.name=SAGE Test", "-c", "user.email=sage@example.invalid", "commit", "-m", "init")
	worktree := filepath.Join(t.TempDir(), "scratchpad-agent")
	run("worktree", "add", "-b", "scratch-test", worktree)

	got, err := canonicalWorkspaceRoot(worktree)
	require.NoError(t, err)
	require.True(t, sameFilesystemPath(root, got), "linked worktrees must reuse the primary repository boundary")

	key := filepath.Join(t.TempDir(), "primary-agent.key")
	config := map[string]any{"mcpServers": map[string]any{"sage": map[string]any{"env": map[string]any{
		"SAGE_PROVIDER": "claude-code", "SAGE_PROJECT": "workspace", "SAGE_IDENTITY_PATH": key,
	}}}}
	raw, err := json.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, ".mcp.json"), raw, 0o600))
	rootKey, _, _, err := resolveImplicitWorkspaceIdentity(t.TempDir(), root, "claude-code", "")
	require.NoError(t, err)
	worktreeKey, _, _, err := resolveImplicitWorkspaceIdentity(t.TempDir(), worktree, "claude-code", "")
	require.NoError(t, err)
	require.Equal(t, rootKey, worktreeKey)
	require.Equal(t, key, worktreeKey, "managed worktrees must use the primary repository's established signer")
}

func TestPrimaryWorkspaceMCPEnvPreservesPinnedProviderIdentity(t *testing.T) {
	root := t.TempDir()
	key := filepath.Join(t.TempDir(), "agent.key")
	config := map[string]any{"mcpServers": map[string]any{"sage": map[string]any{"env": map[string]any{
		"SAGE_PROVIDER": "claude-code", "SAGE_PROJECT": "sage", "SAGE_IDENTITY_PATH": key,
	}}}}
	raw, err := json.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, ".mcp.json"), raw, 0o600))

	env, found, err := primaryWorkspaceMCPEnv(root)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "claude-code", env["SAGE_PROVIDER"])
	require.Equal(t, "sage", env["SAGE_PROJECT"])
	require.Equal(t, key, env["SAGE_IDENTITY_PATH"])

	home := t.TempDir()
	inherited, provider, project, err := resolveImplicitWorkspaceIdentity(home, root, "", "")
	require.NoError(t, err)
	require.Equal(t, key, inherited)
	require.Equal(t, "claude-code", provider)
	require.Equal(t, "sage", project)

	codexKey, codexProvider, _, err := resolveImplicitWorkspaceIdentity(home, root, "codex", "")
	require.NoError(t, err)
	require.Equal(t, "codex", codexProvider)
	require.NotEqual(t, key, codexKey, "Claude Code and Codex must remain separate signers")
}

func TestProviderProjectAgentDirSeparatesProvidersInOneCheckout(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(t.TempDir(), "tii-sage")
	claudePath := providerProjectAgentDir(home, project, "claude-code")
	codexPath := providerProjectAgentDir(home, project, "codex")

	require.NotEqual(t, claudePath, codexPath, "Claude Code and Codex must never share a project identity path")
	require.Contains(t, claudePath, "tii-sage-claude-code-")
	require.Contains(t, codexPath, "tii-sage-codex-")
	require.Equal(t, claudePath, providerProjectAgentDir(home, project, "CLAUDE-CODE"), "provider spelling must not fork an identity")
}
