package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRunRepairChainIsDisabledAndChangesNothing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SAGE_HOME", home)

	sentinelPath := filepath.Join(home, "sentinel")
	if err := os.WriteFile(sentinelPath, []byte("canonical-state"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		nil,
		{"--yes"},
		{"-y"},
		{"--allow-destructive-chain-reset"},
	} {
		err := runRepairChain(args)
		if !errors.Is(err, errDestructiveChainRepairDisabled) {
			t.Fatalf("runRepairChain(%v) must return the typed disabled error, got %v", args, err)
		}
	}
	data, err := os.ReadFile(sentinelPath)
	if err != nil {
		t.Fatalf("sentinel disappeared after aborted repair: %v", err)
	}
	if string(data) != "canonical-state" {
		t.Fatalf("sentinel changed after aborted repair: %q", data)
	}
}
