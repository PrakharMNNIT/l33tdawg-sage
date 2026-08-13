package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"
)

func TestUpgradeWatchdogBroadcastContextIsBounded(t *testing.T) {
	ctx, cancel := upgradeWatchdogBroadcastContext(context.Background(), upgradeWatchdogConfig{
		BroadcastTimeout: 20 * time.Millisecond,
	})
	defer cancel()
	select {
	case <-ctx.Done():
		if ctx.Err() != context.DeadlineExceeded {
			t.Fatalf("broadcast context error = %v, want deadline exceeded", ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("watchdog broadcast context did not enforce its deadline")
	}
}

func TestEveryUpgradeWatchdogBroadcastSharesOneDeadlineAcrossLeaseAndRPC(t *testing.T) {
	sourceBytes, err := os.ReadFile("upgrade_watchdog.go")
	if err != nil {
		t.Fatalf("read upgrade watchdog source: %v", err)
	}
	source := string(sourceBytes)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "upgrade_watchdog.go", source, 0)
	if err != nil {
		t.Fatalf("parse upgrade watchdog source: %v", err)
	}

	wantBroadcast := map[string]string{
		"proposeForAutoAdvance":         "broadcastTxCommitWithSigner(broadcastCtx,",
		"ensureOperatorAdminRegistered": "broadcastTxCommitWithSigner(broadcastCtx,",
		"sendHeartbeatTx":               "broadcastTxSync(broadcastCtx,",
		"maybeProposeUpgrade":           "broadcastTxSync(broadcastCtx,",
	}
	seen := make(map[string]bool, len(wantBroadcast))
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		wantRPC, ok := wantBroadcast[fn.Name.Name]
		if !ok {
			continue
		}
		start := fset.Position(fn.Pos()).Offset
		end := fset.Position(fn.End()).Offset
		body := source[start:end]
		for _, marker := range []string{
			"broadcastCtx, cancel := upgradeWatchdogBroadcastContext(ctx, cfg)",
			"defer cancel()",
			"tx.WithNonceLease(broadcastCtx,",
			wantRPC,
		} {
			if !strings.Contains(body, marker) {
				t.Errorf("%s does not keep one bounded context across lease and RPC; missing %q", fn.Name.Name, marker)
			}
		}
		seen[fn.Name.Name] = true
	}
	for name := range wantBroadcast {
		if !seen[name] {
			t.Errorf("did not inspect watchdog broadcaster %s", name)
		}
	}
}
