package main

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPTokenCreateHelpDoesNotMint(t *testing.T) {
	orig := os.Args
	t.Cleanup(func() { os.Args = orig })

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = oldStdout })
	os.Args = []string{"sage-gui", "mcp-token", "create", "--help"}
	require.NoError(t, runMCPTokenCreate())
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Contains(t, string(out), "sage-gui mcp-token create")
}

func TestMCPTokenCreateRejectsUnknownFlag(t *testing.T) {
	orig := os.Args
	t.Cleanup(func() { os.Args = orig })
	os.Args = []string{"sage-gui", "mcp-token", "create", "--bogus"}
	err := runMCPTokenCreate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown argument")
}
