package main

import (
	"crypto/ed25519"
	"encoding/hex"
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
