package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteChatGPTDesktopConfig_AppWideAndPreservesOtherServers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configPath := filepath.Join(home, ".codex", "config.toml")
	require.NoError(t, os.MkdirAll(filepath.Dir(configPath), 0755))
	require.NoError(t, os.WriteFile(configPath, []byte("[mcp_servers.other]\ncommand = \"other\"\n"), 0600))

	files, err := writeChatGPTDesktopConfig("/tmp/sage-home", "/Applications/SAGE/sage-gui")
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.Equal(t, configPath, files[0].Path)
	assert.Equal(t, "merged", files[0].Action)

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	config := string(data)
	assert.Contains(t, config, "[mcp_servers.other]")
	assert.Contains(t, config, "[mcp_servers.sage]")
	assert.Contains(t, config, `command = "/Applications/SAGE/sage-gui"`)
	assert.Contains(t, config, `SAGE_HOME = "/tmp/sage-home"`)
	assert.Contains(t, config, `SAGE_PROVIDER = "codex"`)
	assert.NotContains(t, config, "SAGE_IDENTITY_PATH",
		"the user-level Codex config must let the MCP process derive identity from each workspace")
	assert.Contains(t, config, `SAGE_IDENTITY_MODE = "workspace"`,
		"workspace mode must neutralize inherited shell identity variables")
}

func TestGlobalCodexConfigDerivesDistinctIdentityPerProject(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	sageHome := filepath.Join(home, ".sage")
	globalConfig := filepath.Join(home, ".codex", "config.toml")
	projectA := filepath.Join(home, "work", "project-a")
	projectB := filepath.Join(home, "work", "project-b")

	block := codexSageConfigBlock(globalConfig, "/bin/sage-gui", sageHome, "codex")
	assert.NotContains(t, block, "SAGE_IDENTITY_PATH")
	assert.Contains(t, block, `SAGE_IDENTITY_MODE = "workspace"`)
	assert.Contains(t, block, `SAGE_PROJECT = ""`)

	identityA := implicitMCPIdentityPath(sageHome, projectA, "codex", "")
	identityB := implicitMCPIdentityPath(sageHome, projectB, "codex", "")
	require.NotEqual(t, identityA, identityB)
	assert.Contains(t, identityA, "project-a-agent-")
	assert.Contains(t, identityB, "project-b-agent-")
	assert.Equal(t,
		filepath.Join(providerProjectAgentDir(sageHome, projectA, ""), "agent.key"),
		identityA,
		"global Codex MCP and its provider-neutral workspace hook must resolve the same key",
	)
}

func TestWorkspaceIdentityModeIgnoresInheritedShellPins(t *testing.T) {
	t.Setenv("SAGE_IDENTITY_MODE", "workspace")
	t.Setenv("SAGE_IDENTITY_PATH", "/tmp/foreign-project.key")
	t.Setenv("SAGE_AGENT_KEY", "/tmp/operator.key")

	path, workspace := configuredMCPIdentityEnv()

	assert.True(t, workspace)
	assert.Empty(t, path)
}

func TestGlobalCodexConfigMigratesGeneratedSharedIdentityButPreservesCustomKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	sageHome := filepath.Join(home, ".sage")
	globalConfig := filepath.Join(home, ".codex", "config.toml")
	require.NoError(t, os.MkdirAll(filepath.Dir(globalConfig), 0755))
	generated := filepath.Join(sageHome, "agents", "global-codex", "agent.key")
	require.NoError(t, os.WriteFile(globalConfig, []byte(codexSageConfigBlockWithIdentity(
		globalConfig, "/old/sage-gui", sageHome, "codex", generated,
	)), 0600))

	_, err := mergeCodexConfigForProvider(globalConfig, "/new/sage-gui", sageHome, "codex")
	require.NoError(t, err)
	updated, err := os.ReadFile(globalConfig)
	require.NoError(t, err)
	assert.NotContains(t, string(updated), "SAGE_IDENTITY_PATH")

	custom := filepath.Join(home, "keys", "pinned-agent.key")
	require.NoError(t, os.WriteFile(globalConfig, []byte(codexSageConfigBlockWithIdentity(
		globalConfig, "/old/sage-gui", sageHome, "codex", custom,
	)), 0600))
	_, err = mergeCodexConfigForProvider(globalConfig, "/new/sage-gui", sageHome, "codex")
	require.NoError(t, err)
	updated, err = os.ReadFile(globalConfig)
	require.NoError(t, err)
	assert.Contains(t, string(updated), `SAGE_IDENTITY_PATH = "`+custom+`"`)
	assert.Contains(t, string(updated), `SAGE_IDENTITY_MODE = "pinned"`)

	legacy := filepath.Join(home, "keys", "legacy-agent.key")
	legacyConfig := strings.Replace(
		codexSageConfigBlockWithIdentity(globalConfig, "/old/sage-gui", sageHome, "codex", ""),
		`SAGE_IDENTITY_MODE = "workspace"`,
		`SAGE_IDENTITY_MODE = "pinned"`+"\n"+`SAGE_AGENT_KEY = "`+legacy+`"`,
		1,
	)
	require.NoError(t, os.WriteFile(globalConfig, []byte(legacyConfig), 0600))
	_, err = mergeCodexConfigForProvider(globalConfig, "/new/sage-gui", sageHome, "codex")
	require.NoError(t, err)
	updated, err = os.ReadFile(globalConfig)
	require.NoError(t, err)
	assert.Contains(t, string(updated), `SAGE_IDENTITY_PATH = "`+legacy+`"`)
	assert.Contains(t, string(updated), `SAGE_IDENTITY_MODE = "pinned"`)
	assert.NotContains(t, string(updated), "SAGE_AGENT_KEY")
}

func TestMergeCodexConfig_PreservesComplexTOMLAndReplacesQuotedSage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	existing := `title = "kept"
literal = '''
[mcp_servers.sage]
this is multiline content, not a table
'''

[[catalog.entries]]
name = "first"

[mcp_servers."other"] # preserve this comment
command = "other"

[mcp_servers . "sage"]
command = "stale"

[mcp_servers.'sage'.env]
SAGE_PROVIDER = "stale"
`
	require.NoError(t, os.WriteFile(path, []byte(existing), 0600))
	action, err := mergeCodexConfigForProvider(path, `/Applications/SAGE "beta"/sage-gui`, "/Users/me/SAGE\\home", "codex")
	require.NoError(t, err)
	assert.Equal(t, "merged", action)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	config := string(data)
	assert.Contains(t, config, "this is multiline content, not a table")
	assert.Contains(t, config, `[[catalog.entries]]`)
	assert.Contains(t, config, `[mcp_servers."other"] # preserve this comment`)
	assert.NotContains(t, config, `command = "stale"`)
	var parsed any
	require.NoError(t, toml.Unmarshal(data, &parsed))
	root := parsed.(map[string]any)
	mcp := root["mcp_servers"].(map[string]any)
	sage := mcp["sage"].(map[string]any)
	assert.Equal(t, `/Applications/SAGE "beta"/sage-gui`, sage["command"])
}

func TestMergeCodexConfig_RejectsOversizedWithoutChangingOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	original := []byte("#" + strings.Repeat("x", (1<<20)+1))
	require.NoError(t, os.WriteFile(path, original, 0600))
	_, err := mergeCodexConfig(path, "/bin/sage", "/tmp/sage")
	require.Error(t, err)
	after, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, original, after)
}

func TestSafeWriteFile_RejectsFinalSymlinkAndReplacesHardlinkAtomically(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(target, []byte("original"), 0600))
	require.NoError(t, os.Symlink(target, link))
	require.Error(t, safeWriteFile(link, []byte("new"), 0600))
	targetData, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "original", string(targetData))

	require.NoError(t, os.Remove(link))
	if linkErr := os.Link(target, link); linkErr != nil {
		t.Skipf("hardlinks unavailable: %v", linkErr)
	}
	require.NoError(t, safeWriteFile(link, []byte("replacement"), 0600))
	linkedData, err := os.ReadFile(link)
	require.NoError(t, err)
	assert.Equal(t, "replacement", string(linkedData))
	targetData, err = os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "original", string(targetData), "atomic replacement must not mutate another hardlink")
}

func TestWriteChatGPTDesktopConfig_RejectsSymlinkedConfigDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	realDir := t.TempDir()
	require.NoError(t, os.Symlink(realDir, filepath.Join(home, ".codex")))
	_, err := writeChatGPTDesktopConfig("/tmp/sage-home", "/bin/sage-gui")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symlinked ChatGPT config directory")
}

func TestWriteChatGPTDesktopConfig_CreatesUserConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	files, err := writeChatGPTDesktopConfig("/tmp/sage-home", "/usr/local/bin/sage-gui")
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.Equal(t, "created", files[0].Action)
	assert.FileExists(t, filepath.Join(home, ".codex", "config.toml"))
}

func TestProjectMCPConfigsUseDistinctStableIdentityAndProjectName(t *testing.T) {
	home := t.TempDir()
	sageHome := filepath.Join(home, ".sage")
	projectA := filepath.Join(home, "work", "synth-lab")
	projectB := filepath.Join(home, "friends", "synth-lab")
	configA := filepath.Join(projectA, ".codex", "config.toml")
	configB := filepath.Join(projectB, ".codex", "config.toml")

	identityA := mcpIdentityPath(configA, sageHome, "codex")
	identityB := mcpIdentityPath(configB, sageHome, "codex")
	claudeIdentityA := mcpIdentityPath(configA, sageHome, "claude-code")
	require.NotEqual(t, identityA, identityB, "same folder name in different projects must not share a key")
	require.NotEqual(t, identityA, claudeIdentityA, "Codex and Claude Code in one project must not share a key")
	require.Equal(t, "synth-lab", mcpProjectName(configA, sageHome, "codex"))
	require.Equal(t, "synth-lab", mcpProjectName(configB, sageHome, "codex"))

	block := codexSageConfigBlock(configA, "/Applications/SAGE.app/Contents/MacOS/sage-gui", sageHome, "codex")
	assert.Contains(t, block, `SAGE_IDENTITY_PATH = "`+identityA+`"`)
	assert.Contains(t, block, `SAGE_PROJECT = "synth-lab"`)
}

func TestLegacyClaudeIdentityIsPreservedWhileCodexSplitsDuringMCPConfigRefresh(t *testing.T) {
	sageHome := t.TempDir()
	project := filepath.Join(t.TempDir(), "tii-sage")
	mcpPath := filepath.Join(project, ".mcp.json")
	require.NoError(t, os.MkdirAll(project, 0755))
	legacyPath := legacyProjectAgentPath(sageHome, project)
	require.NoError(t, os.MkdirAll(filepath.Dir(legacyPath), 0700))
	require.NoError(t, os.WriteFile(legacyPath, []byte("legacy-key"), 0600))
	require.NoError(t, os.WriteFile(mcpPath, []byte(`{"mcpServers":{"sage":{"command":"old"}}}`), 0600))

	_, err := mergeMCPServerConfig(mcpPath, "/bin/sage-gui", sageHome, "claude-code")
	require.NoError(t, err)
	data, err := os.ReadFile(mcpPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), legacyPath)

	codexPath := filepath.Join(project, ".codex", "config.toml")
	require.NoError(t, os.MkdirAll(filepath.Dir(codexPath), 0755))
	require.NoError(t, os.WriteFile(codexPath, []byte("[mcp_servers.sage]\ncommand = \"old\"\n"), 0600))
	_, err = mergeCodexConfigForProvider(codexPath, "/bin/sage-gui", sageHome, "codex")
	require.NoError(t, err)
	data, err = os.ReadFile(codexPath)
	require.NoError(t, err)
	codexPathAfterRefresh := mcpIdentityPath(codexPath, sageHome, "codex")
	assert.NotEqual(t, legacyPath, codexPathAfterRefresh)
	assert.Contains(t, string(data), codexPathAfterRefresh)
}

func TestSelfHealKnownMCPConfigs_IsolatedNodeCannotTouchGlobalCodexEndpoint(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	globalConfig := filepath.Join(home, ".codex", "config.toml")
	require.NoError(t, os.MkdirAll(filepath.Dir(globalConfig), 0755))
	original := []byte(`[mcp_servers.sage]
command = "/Applications/SAGE.app/Contents/MacOS/sage-gui"
args = ["mcp"]

[mcp_servers.sage.env]
SAGE_HOME = "` + filepath.Join(home, ".sage") + `"
SAGE_API_URL = "http://127.0.0.1:8080"
`)
	require.NoError(t, os.WriteFile(globalConfig, original, 0600))

	isolatedSageHome := filepath.Join(t.TempDir(), "acceptance-node")
	errs := selfHealKnownMCPConfigs(isolatedSageHome, "/tmp/acceptance/sage-gui")
	require.Empty(t, errs)
	after, err := os.ReadFile(globalConfig)
	require.NoError(t, err)
	assert.Equal(t, original, after,
		"an acceptance node must leave the global Codex endpoint byte-identical")
}

func TestSelfHealKnownMCPConfigs_DefaultNodeStillRefreshesGlobalCodexEndpoint(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	defaultSageHome := filepath.Join(home, ".sage")
	globalConfig := filepath.Join(home, ".codex", "config.toml")
	require.NoError(t, os.MkdirAll(filepath.Dir(globalConfig), 0755))
	require.NoError(t, os.WriteFile(globalConfig, []byte(`[mcp_servers.sage]
command = "/old/sage-gui"
args = ["mcp"]
`), 0600))

	errs := selfHealKnownMCPConfigs(defaultSageHome, "/Applications/SAGE.app/Contents/MacOS/sage-gui")
	require.Empty(t, errs)
	after, err := os.ReadFile(globalConfig)
	require.NoError(t, err)
	assert.Contains(t, string(after), `command = "/Applications/SAGE.app/Contents/MacOS/sage-gui"`)
	assert.Contains(t, string(after), `SAGE_API_URL = "http://127.0.0.1:8080"`)
}
