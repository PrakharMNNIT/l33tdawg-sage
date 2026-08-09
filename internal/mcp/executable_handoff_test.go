package mcp

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMCPExecutableSnapshotDetectsAtomicReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sage-gui")
	require.NoError(t, os.WriteFile(path, []byte("old-runtime"), 0o700))
	initial, err := os.Stat(path)
	require.NoError(t, err)
	snapshot := &mcpExecutableSnapshot{path: path, info: initial}
	require.Equal(t, mcpExecutableUnchanged, snapshot.state())

	replacement := filepath.Join(dir, "sage-gui.new")
	require.NoError(t, os.WriteFile(replacement, []byte("new-runtime-with-new-schema"), 0o700))
	require.NoError(t, os.Rename(replacement, path))
	require.Equal(t, mcpExecutableReplaced, snapshot.state(), "an atomically replaced app binary must retire the stale MCP runtime")
}

func TestCaptureMCPExecutableSnapshotFailsClosedWithoutExactRegularPath(t *testing.T) {
	_, err := captureMCPExecutableSnapshotAt("")
	require.ErrorContains(t, err, "path is empty")

	_, err = captureMCPExecutableSnapshotAt(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)

	_, err = captureMCPExecutableSnapshotAt(t.TempDir())
	require.ErrorContains(t, err, "not a regular file")
}

func TestMCPExecutableSnapshotFailsClosedWhenInstalledPathIsUnavailable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sage-gui")
	require.NoError(t, os.WriteFile(path, []byte("runtime"), 0o700))
	initial, err := os.Stat(path)
	require.NoError(t, err)
	snapshot := &mcpExecutableSnapshot{path: path, info: initial}
	require.NoError(t, os.Remove(path))
	require.Equal(t, mcpExecutableUnavailable, snapshot.state(), "an absent installed path must never permit stale dispatch")
}

func TestMCPHandoffHelperProcess(t *testing.T) {
	if os.Getenv("SAGE_MCP_HANDOFF_HELPER") != "1" {
		return
	}
	_, _ = io.Copy(os.Stdout, os.Stdin)
	if os.Getenv("SAGE_MCP_HANDOFF_FAIL_AFTER_READ") == "1" {
		os.Exit(23)
	}
	os.Exit(0)
}

func TestHandoffMCPProcessReplaysConsumedFrameBeforeRemainingInput(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)
	first := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	remaining := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call"}` + "\n")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	environ := append(os.Environ(), "SAGE_MCP_HANDOFF_HELPER=1")

	started, err := handoffMCPProcess(
		context.Background(),
		executable,
		[]string{"-test.run=^TestMCPHandoffHelperProcess$"},
		first,
		bytes.NewReader(remaining),
		&stdout,
		&stderr,
		environ,
		true,
	)
	require.NoError(t, err, stderr.String())
	require.True(t, started)
	require.Equal(t, append(append(append([]byte(nil), first...), '\n'), remaining...), stdout.Bytes())
}

func TestHandoffMCPProcessPreservesFramesAlreadyBufferedPastConsumedFrame(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)
	first := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	second := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call"}` + "\n")
	input := bufio.NewReaderSize(bytes.NewReader(append(append(append([]byte(nil), first...), '\n'), second...)), 4096)
	consumed, err := readMCPFrame(input, maxMCPFrameBytes)
	require.NoError(t, err)
	require.Equal(t, first, consumed)
	require.Greater(t, input.Buffered(), 0, "the regression requires the next frame to be held above raw stdin")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	started, err := handoffMCPProcess(
		context.Background(),
		executable,
		[]string{"-test.run=^TestMCPHandoffHelperProcess$"},
		consumed,
		input,
		&stdout,
		&stderr,
		append(os.Environ(), "SAGE_MCP_HANDOFF_HELPER=1"),
		true,
	)
	require.NoError(t, err, stderr.String())
	require.True(t, started)
	require.Equal(t, append(append(append([]byte(nil), first...), '\n'), second...), stdout.Bytes())
}

func TestHandoffMCPProcessDistinguishesStartFailureFromChildExit(t *testing.T) {
	started, err := handoffMCPProcess(context.Background(), "", nil, []byte(`{}`), bytes.NewReader(nil), io.Discard, io.Discard, os.Environ(), true)
	require.False(t, started)
	require.ErrorContains(t, err, "path is empty")

	executable, executableErr := os.Executable()
	require.NoError(t, executableErr)
	var stdout bytes.Buffer
	environ := append(os.Environ(), "SAGE_MCP_HANDOFF_HELPER=1", "SAGE_MCP_HANDOFF_FAIL_AFTER_READ=1")
	started, err = handoffMCPProcess(
		context.Background(),
		executable,
		[]string{"-test.run=^TestMCPHandoffHelperProcess$"},
		[]byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call"}`),
		bytes.NewReader(nil),
		&stdout,
		io.Discard,
		environ,
		true,
	)
	require.True(t, started, "a child that owns stdin must never permit fallback execution")
	require.Error(t, err)
	require.Contains(t, stdout.String(), `"id":7`)
}

func TestMCPHandoffAdvertisesToolRegistryChange(t *testing.T) {
	environ := withMCPEnvironment([]string{"PATH=/bin", mcpRuntimeHandoffEnv + "=old"}, mcpRuntimeHandoffEnv, "1")
	require.Equal(t, []string{"PATH=/bin", mcpRuntimeHandoffEnv + "=1"}, environ)

	var notification bytes.Buffer
	require.NoError(t, writeMCPToolsChangedNotification(&notification))
	require.JSONEq(t, `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`, notification.String())
}

func TestMCPHandoffDefersToolChangeUntilInitializationCompletes(t *testing.T) {
	// A bare ambient marker is never enough to emit a server notification.
	lifecycle := newMCPHandoffLifecycle("1", "", "1", 123)
	require.False(t, lifecycle.takeToolsChangedNotification())

	// A verified handoff of an already initialized session can notify before
	// the replayed operational frame is read.
	lifecycle = newMCPHandoffLifecycle("1", "123", "1", 123)
	require.True(t, lifecycle.takeToolsChangedNotification())
	require.False(t, lifecycle.takeToolsChangedNotification())

	// If initialize or notifications/initialized itself triggered the handoff,
	// defer until that notification has been consumed by the replacement.
	lifecycle = newMCPHandoffLifecycle("1", "123", "0", 123)
	require.False(t, lifecycle.takeToolsChangedNotification())
	lifecycle.initialized = true
	require.True(t, lifecycle.takeToolsChangedNotification())
}
