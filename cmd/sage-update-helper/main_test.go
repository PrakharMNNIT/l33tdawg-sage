//go:build darwin

package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBundleForExecutableRequiresExactSAGEAppLayout(t *testing.T) {
	valid := filepath.Join("/Applications", "SAGE.app", "Contents", "MacOS", "sage-gui")
	bundle, ok := bundleForExecutable(valid)
	require.True(t, ok)
	require.Equal(t, filepath.Join("/Applications", "SAGE.app"), bundle)

	for _, invalid := range []string{
		filepath.Join("/Applications", "SAGE", "Contents", "MacOS", "sage-gui"),
		filepath.Join("/Applications", "SAGE.app", "Contents", "MacOS", "other"),
		filepath.Join("/tmp", "sage-gui"),
	} {
		_, ok = bundleForExecutable(invalid)
		require.False(t, ok, invalid)
	}
}
