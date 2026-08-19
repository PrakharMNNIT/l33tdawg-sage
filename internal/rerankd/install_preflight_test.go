//go:build unix

package rerankd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeFakeEngine(t *testing.T, m *Manager, script string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(m.engineDir(), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(m.engineDir(), serverBinaryName()), []byte(script), 0o755))
}

// A managed engine that DOWNLOADED and extracted cleanly but cannot LOAD — the
// dynamic loader rejecting it for an older host C/C++ runtime — must surface the
// real reason, not report install success. This is the Jetson / JetPack-6 case:
// the pinned arm64 asset needs a newer glibc than Ubuntu 22.04 provides.
func TestPreflightEngineSurfacesLoaderVersionFailure(t *testing.T) {
	m := New(t.TempDir())
	writeFakeEngine(t, m, "#!/bin/sh\necho 'llama-server: /lib/aarch64-linux-gnu/libstdc++.so.6: version GLIBCXX_3.4.32 not found' 1>&2\nexit 1\n")

	err := m.preflightEngine(context.Background())
	require.Error(t, err)
	var inc *EngineIncompatibleError
	require.ErrorAs(t, err, &inc)
	require.Contains(t, inc.Detail, "GLIBCXX_3.4.32", "the loader's own message is preserved verbatim")
	require.Contains(t, err.Error(), "SAGE_RERANK_KIND=llamacpp", "the honest error points the operator at the bring-your-own path")
}

// A binary that loads and runs is not blocked.
func TestPreflightEnginePassesWhenBinaryLoads(t *testing.T) {
	m := New(t.TempDir())
	writeFakeEngine(t, m, "#!/bin/sh\necho 'version: b9870'\nexit 0\n")
	require.NoError(t, m.preflightEngine(context.Background()))
}

// A non-zero exit WITHOUT a loader version signature is not proof the host is too
// old (an unrecognized flag on a future build, a timeout). It must not block an
// otherwise-good install on an ambiguous signal.
func TestPreflightEngineDoesNotBlockOnAmbiguousFailure(t *testing.T) {
	m := New(t.TempDir())
	writeFakeEngine(t, m, "#!/bin/sh\necho 'error: unknown option --version' 1>&2\nexit 2\n")
	require.NoError(t, m.preflightEngine(context.Background()))
}
