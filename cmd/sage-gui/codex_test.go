package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withCodexInstallEnv flips CWD to a temp dir and points SAGE_HOME at
// another temp dir so runCodexInstall() writes into an isolated fixture.
func withCodexInstallEnv(t *testing.T) (projectDir, sageHome string) {
	t.Helper()
	projectDir = t.TempDir()
	sageHome = t.TempDir()

	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(projectDir))
	t.Cleanup(func() { _ = os.Chdir(orig) })

	t.Setenv("SAGE_HOME", sageHome)
	t.Setenv("HOME", sageHome) // so any ~ expansion stays sandboxed
	return projectDir, sageHome
}

func TestRunCodexInstall_WritesAllArtifacts(t *testing.T) {
	projectDir, sageHome := withCodexInstallEnv(t)

	require.NoError(t, runCodexInstall())

	// config.toml
	configData, err := os.ReadFile(filepath.Join(projectDir, ".codex", "config.toml"))
	require.NoError(t, err)
	config := string(configData)
	assert.Contains(t, config, "[mcp_servers.sage]")
	assert.Contains(t, config, `args = ["mcp"]`)
	assert.Contains(t, config, "[mcp_servers.sage.env]")
	assert.Contains(t, config, sageHome)
	assert.Contains(t, config, `SAGE_PROVIDER = "codex"`)
	assert.NotContains(t, config, "__SAGE_GUI_BIN__", "placeholder must be substituted")
	assert.NotContains(t, config, "__SAGE_HOME__", "placeholder must be substituted")

	// hooks.json
	hooksData, err := os.ReadFile(filepath.Join(projectDir, ".codex", "hooks.json"))
	require.NoError(t, err)
	var hooksDoc map[string]any
	require.NoError(t, json.Unmarshal(hooksData, &hooksDoc))
	hooks, ok := hooksDoc["hooks"].(map[string]any)
	require.True(t, ok, "hooks.json must have top-level hooks map")
	for _, k := range []string{"SessionStart", "SessionEnd", "PreCompact", "UserPromptSubmit", "Stop", "SubagentStop"} {
		assert.Contains(t, hooks, k, "hooks.%s must be wired", k)
	}
	// Hook commands must use absolute paths (Codex doesn't expand env vars).
	assert.Contains(t, string(hooksData), filepath.Join(projectDir, ".codex", "hooks"))
	expectedShell := resolveCodexBash("")
	assert.Contains(t, hookCommand(t, hooks, "SessionStart"), expectedShell, "Codex hooks must use the resolved shell")
	if filepath.IsAbs(expectedShell) {
		assert.NotContains(t, string(hooksData), `"command": "bash `, "Codex hooks must not depend on launcher PATH")
	}
	assert.NotContains(t, string(hooksData), "${CLAUDE_PROJECT_DIR}")

	// 5 hook scripts present and templated.
	for name := range hookScriptSet() {
		path := filepath.Join(projectDir, ".codex", "hooks", name)
		data, readErr := os.ReadFile(path)
		require.NoError(t, readErr, "hook script %s must exist", name)
		assert.NotContains(t, string(data), "__SAGE_GUI_BIN__", "script %s placeholder must be substituted", name)
		if hookUsesDirectWriteIdentity(name) {
			assert.Contains(t, string(data), `SAGE_PROVIDER="codex"`, "script %s must use the Codex identity", name)
			assert.Contains(t, string(data), codexConfigIdentityPath(filepath.Join(projectDir, ".codex", "config.toml"), sageHome, "codex"), "script %s must use the configured identity", name)
		}
	}

	// AGENTS.md
	mdData, err := os.ReadFile(filepath.Join(projectDir, "AGENTS.md"))
	require.NoError(t, err)
	md := string(mdData)
	assert.Contains(t, md, "# AGENTS.md")
	assert.Contains(t, md, sageClaudeMDMarker)
	assert.Contains(t, md, ".codex/config.toml", "AGENTS.md should point to codex config")

	// memory_mode flag created in SAGE_HOME.
	_, err = os.Stat(filepath.Join(sageHome, "memory_mode"))
	assert.NoError(t, err)
}

func TestRunCodexInstall_AgentsMDPatchesExisting(t *testing.T) {
	projectDir, _ := withCodexInstallEnv(t)

	// Plant an existing AGENTS.md with an old SAGE block.
	mdPath := filepath.Join(projectDir, "AGENTS.md")
	pre := "# AGENTS.md\n\n## SAGE — Persistent Memory\n\nOld instructions.\n\n## Other Section\n\nKeep this.\n"
	require.NoError(t, os.WriteFile(mdPath, []byte(pre), 0644))

	require.NoError(t, runCodexInstall())

	data, err := os.ReadFile(mdPath)
	require.NoError(t, err)
	content := string(data)
	assert.NotContains(t, content, "Old instructions.")
	assert.Contains(t, content, ".codex/config.toml")
	assert.Contains(t, content, "## Other Section")
	assert.Contains(t, content, "Keep this.")
}

func TestRunCodexInstall_AgentsMDAppendsWhenNoSageBlock(t *testing.T) {
	projectDir, _ := withCodexInstallEnv(t)

	mdPath := filepath.Join(projectDir, "AGENTS.md")
	require.NoError(t, os.WriteFile(mdPath, []byte("# AGENTS.md\n\nProject notes here.\n"), 0644))

	require.NoError(t, runCodexInstall())

	data, err := os.ReadFile(mdPath)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, "Project notes here.")
	assert.Contains(t, content, sageClaudeMDMarker)
	assert.Contains(t, content, ".codex/config.toml")
}

func TestRunCodexInstall_Idempotent(t *testing.T) {
	projectDir, _ := withCodexInstallEnv(t)

	require.NoError(t, runCodexInstall())
	require.NoError(t, runCodexInstall())

	md, err := os.ReadFile(filepath.Join(projectDir, "AGENTS.md"))
	require.NoError(t, err)
	count := strings.Count(string(md), sageClaudeMDMarker)
	assert.Equal(t, 1, count, "AGENTS.md SAGE section should appear exactly once after double install")
}

func TestSelfHealCodex_RewritesStaleBinaryPath(t *testing.T) {
	projectDir, sageHome := withCodexInstallEnv(t)
	require.NoError(t, runCodexInstall())

	// Plant a stale binary path in the config and one hook.
	configPath := filepath.Join(projectDir, ".codex", "config.toml")
	configData, _ := os.ReadFile(configPath)
	staleConfig := strings.ReplaceAll(string(configData), expectExecutable(t), "/old/path/to/sage-gui")
	require.NoError(t, os.WriteFile(configPath, []byte(staleConfig), 0600))

	startPath := filepath.Join(projectDir, ".codex", "hooks", "sage-session-start.sh")
	startData, _ := os.ReadFile(startPath)
	staleStart := strings.ReplaceAll(string(startData), expectExecutable(t), "/old/path/to/sage-gui")
	require.NoError(t, os.WriteFile(startPath, []byte(staleStart), 0755))

	selfHealCodex(projectDir, sageHome)

	configAfter, _ := os.ReadFile(configPath)
	assert.NotContains(t, string(configAfter), "/old/path/to/sage-gui")
	startAfter, _ := os.ReadFile(startPath)
	assert.NotContains(t, string(startAfter), "/old/path/to/sage-gui")
}

func TestSelfHealCodex_RewritesStaleHookBytesWithCurrentPaths(t *testing.T) {
	projectDir, sageHome := withCodexInstallEnv(t)
	require.NoError(t, runCodexInstall())

	// Reproduce the v11.18.17 field failure: the hook directory and all five
	// filenames exist, other hooks still mention the current binary and identity,
	// but Stop is an older installer-owned no-op. Presence/path checks alone
	// incorrectly accepted this mixed generation as current.
	stopPath := filepath.Join(projectDir, ".codex", "hooks", "sage-stop.sh")
	require.NoError(t, os.WriteFile(stopPath, []byte("#!/bin/bash\n# reserved for future checks\nexit 0\n"), 0755))

	selfHealCodex(projectDir, sageHome)

	binPath := expectExecutable(t)
	identityPath := codexConfigIdentityPath(filepath.Join(projectDir, ".codex", "config.toml"), sageHome, "codex")
	for name, tpl := range hookScriptSet() {
		got, err := os.ReadFile(filepath.Join(projectDir, ".codex", "hooks", name))
		require.NoError(t, err, "read refreshed %s", name)
		assert.Equal(t, renderHookScript(tpl, binPath, "codex", identityPath), string(got),
			"self-heal must restore the complete rendered hook set when any one script is stale")
	}
}

func TestSelfHealCodex_NoOpWhenNoCodexDir(t *testing.T) {
	projectDir, sageHome := withCodexInstallEnv(t)

	// .codex/ doesn't exist — self-heal should be a no-op (not create the dir uninvited).
	selfHealCodex(projectDir, sageHome)

	_, err := os.Stat(filepath.Join(projectDir, ".codex"))
	assert.True(t, os.IsNotExist(err), "self-heal must not create .codex/ when it doesn't exist")
}

func TestSelfHealCodex_NeverCreatesGlobalHooksUnderUserHome(t *testing.T) {
	userHome := t.TempDir()
	sageHome := t.TempDir()
	t.Setenv("HOME", userHome)

	// A normal global Codex installation already has ~/.codex/config.toml.
	// Its presence must not be mistaken for evidence of a project-local SAGE
	// install, because ~/.codex/hooks.json is loaded by every unrelated task.
	codexDir := filepath.Join(userHome, ".codex")
	require.NoError(t, os.MkdirAll(codexDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(codexDir, "config.toml"),
		[]byte("[mcp_servers.sage]\ncommand = \"sage-gui\"\n"), 0600))

	selfHealCodex(userHome, sageHome)

	_, hooksErr := os.Stat(filepath.Join(codexDir, "hooks.json"))
	assert.True(t, os.IsNotExist(hooksErr), "self-heal must never create global Codex hooks")
	_, scriptsErr := os.Stat(filepath.Join(codexDir, "hooks"))
	assert.True(t, os.IsNotExist(scriptsErr), "self-heal must never create global hook scripts")
}

func TestSelfHealCodex_RepairsMissingHooksJSON(t *testing.T) {
	projectDir, sageHome := withCodexInstallEnv(t)
	require.NoError(t, runCodexInstall())

	// Simulate legacy install that predates hooks.json (Dhillon's first manual setup)
	hooksJSONPath := filepath.Join(projectDir, ".codex", "hooks.json")
	require.NoError(t, os.Remove(hooksJSONPath))

	selfHealCodex(projectDir, sageHome)

	_, err := os.Stat(hooksJSONPath)
	assert.NoError(t, err, "self-heal should repair missing hooks.json")
}

func TestSelfHealCodex_RewritesPathDependentHooksJSON(t *testing.T) {
	projectDir, sageHome := withCodexInstallEnv(t)
	require.NoError(t, runCodexInstall())

	hooksJSONPath := filepath.Join(projectDir, ".codex", "hooks.json")
	hooksData, err := os.ReadFile(hooksJSONPath)
	require.NoError(t, err)
	var document map[string]any
	require.NoError(t, json.Unmarshal(hooksData, &document))
	hooks := document["hooks"].(map[string]any)
	for _, event := range hooks {
		entries, ok := event.([]any)
		if !ok {
			continue
		}
		for _, entryValue := range entries {
			entry := entryValue.(map[string]any)
			for _, hookValue := range entry["hooks"].([]any) {
				hook := hookValue.(map[string]any)
				command := hook["command"].(string)
				if isInstalledSageHookCommand(command, filepath.Join(projectDir, ".codex", "hooks")) {
					hook["command"] = "bash" + command[strings.Index(command, " "):]
				}
			}
		}
	}
	customStop := map[string]any{"hooks": []any{map[string]any{"type": "command", "command": "custom-tool", "timeout": float64(9)}}}
	hooks["Stop"] = append(hooks["Stop"].([]any), customStop)
	hooks["Notification"] = []any{map[string]any{"hooks": []any{map[string]any{"type": "command", "command": "notify-tool"}}}}
	document["customSetting"] = "keep-me"
	legacy, err := json.MarshalIndent(document, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(hooksJSONPath, append(legacy, '\n'), 0600))

	selfHealCodex(projectDir, sageHome)

	healed, err := os.ReadFile(hooksJSONPath)
	require.NoError(t, err)
	var healedDocument map[string]any
	require.NoError(t, json.Unmarshal(healed, &healedDocument))
	healedHooks := healedDocument["hooks"].(map[string]any)
	assert.Equal(t, "keep-me", healedDocument["customSetting"])
	assert.Contains(t, healedHooks, "Notification", "custom hook events must survive self-heal")
	assert.Contains(t, string(healed), "custom-tool", "custom hooks under SAGE events must survive self-heal")
	assert.Contains(t, hookCommand(t, healedHooks, "SessionStart"), resolveCodexBash(""))
}

func TestRunCodexInstall_PreservesExistingCustomHooks(t *testing.T) {
	projectDir, _ := withCodexInstallEnv(t)
	codexDir := filepath.Join(projectDir, ".codex")
	require.NoError(t, os.MkdirAll(codexDir, 0755))
	existing := `{"customSetting":true,"hooks":{"Stop":[{"hooks":[{"type":"command","command":"custom-tool"}]}],"Notification":[{"hooks":[{"type":"command","command":"notify-tool"}]}]}}`
	require.NoError(t, os.WriteFile(filepath.Join(codexDir, "hooks.json"), []byte(existing), 0600))

	require.NoError(t, runCodexInstall())

	data, err := os.ReadFile(filepath.Join(codexDir, "hooks.json"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "custom-tool")
	assert.Contains(t, string(data), "notify-tool")
	assert.Contains(t, string(data), `"customSetting": true`)
}

func TestCodexHookCommandRunsWithEmptyPATH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell command execution assertion is Unix-specific")
	}
	shell := resolveCodexBash("")
	if !filepath.IsAbs(shell) {
		t.Skip("bash was not resolvable to an absolute path")
	}
	hookDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "ran")
	script := filepath.Join(hookDir, "sage-session-start.sh")
	require.NoError(t, os.WriteFile(script, []byte("printf ok > \""+marker+"\"\n"), 0755))
	hooks := sageHooksConfigWithShell(hookDir, shell)
	command := hookCommand(t, hooks, "SessionStart")
	cmd := exec.Command("/bin/sh", "-c", command) //nolint:gosec // generated fixture command
	cmd.Env = []string{"PATH="}
	require.NoError(t, cmd.Run())
	data, err := os.ReadFile(marker)
	require.NoError(t, err)
	assert.Equal(t, "ok", string(data))
}

func TestCodexHookCommandQuotesShellPathsWithSpaces(t *testing.T) {
	hooks := sageHooksConfigWithShell("C:/tmp/hooks", "C:/Program Files/Git/bin/bash.exe")
	assert.Equal(t, `"C:/Program Files/Git/bin/bash.exe" "C:/tmp/hooks/sage-session-start.sh"`, hookCommand(t, hooks, "SessionStart"))
}

func TestRenderMergedCodexHooksRejectsInvalidJSON(t *testing.T) {
	_, err := renderMergedCodexHooks([]byte(`{"hooks":`), t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON")
}

func hookCommand(t *testing.T, hooks map[string]any, event string) string {
	t.Helper()
	entries, ok := hooks[event].([]any)
	require.True(t, ok)
	require.NotEmpty(t, entries)
	entry, ok := entries[0].(map[string]any)
	require.True(t, ok)
	commands, ok := entry["hooks"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, commands)
	hook, ok := commands[0].(map[string]any)
	require.True(t, ok)
	command, ok := hook["command"].(string)
	require.True(t, ok)
	return command
}

// expectExecutable returns the cleaned, symlink-resolved path of the test
// binary, matching what runCodexInstall writes into the artifacts.
func expectExecutable(t *testing.T) string {
	t.Helper()
	binPath, err := os.Executable()
	require.NoError(t, err)
	if resolved, symErr := filepath.EvalSymlinks(binPath); symErr == nil {
		binPath = resolved
	}
	return binPath
}
