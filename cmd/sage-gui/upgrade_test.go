package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	sageabci "github.com/l33tdawg/sage/internal/abci"
	"github.com/l33tdawg/sage/internal/tx"
)

// TestValidateUpgradeTarget exercises the operator-submit guard in isolation —
// the heart of the issue #32 fix: sequential-only targets and canonical names.
func TestValidateUpgradeTarget(t *testing.T) {
	const maxV = 10

	tests := []struct {
		name     string
		current  uint64
		target   uint64
		planName string
		wantName string
		wantErr  string // substring; "" means no error
	}{
		{
			name:     "sequential next, derived name",
			current:  6,
			target:   7,
			wantName: "app-v7",
		},
		{
			name:     "sequential next with matching canonical name",
			current:  6,
			target:   7,
			planName: "app-v7",
			wantName: "app-v7",
		},
		{
			name:     "top supported fork sequential",
			current:  9,
			target:   10,
			wantName: "app-v10",
		},
		{
			name:    "missing target",
			current: 6,
			target:  0,
			wantErr: "--target is required",
		},
		{
			name:    "exceeds max supported",
			current: 9,
			target:  11,
			wantErr: "exceeds the max app version",
		},
		{
			name:    "no-op (target == current)",
			current: 6,
			target:  6,
			wantErr: "would regress or no-op",
		},
		{
			name:    "regression (target < current)",
			current: 7,
			target:  6,
			wantErr: "would regress or no-op",
		},
		{
			name:    "skip-ahead strands single fork",
			current: 8,
			target:  10,
			wantErr: "permanently strand app-v9",
		},
		{
			name:    "skip-ahead strands a range",
			current: 6,
			target:  10,
			wantErr: "permanently strand app-v7…app-v9",
		},
		{
			name:     "non-canonical name rejected",
			current:  6,
			target:   7,
			planName: "v9.2.2",
			wantErr:  "not the canonical activation key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateUpgradeTarget(tc.current, tc.target, maxV, tc.planName)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (name=%q)", tc.wantErr, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantName {
				t.Fatalf("canonical name = %q, want %q", got, tc.wantName)
			}
		})
	}
}

// TestValidateUpgradeTarget_SkipAheadMessageActionable verifies the skip-ahead
// error tells the operator the correct next step (current+1), not the rejected
// jump — the whole point of the guard is to steer them onto the safe path.
func TestValidateUpgradeTarget_SkipAheadMessageActionable(t *testing.T) {
	_, err := validateUpgradeTarget(6, 10, 10, "")
	if err == nil {
		t.Fatal("expected skip-ahead error")
	}
	if !strings.Contains(err.Error(), "--target 7 next") {
		t.Fatalf("skip-ahead error should steer to --target 7; got: %v", err)
	}
}

// TestParseProposeSigningKey covers the issue #34 --agent-key parser: it must
// accept the three key forms an operator has on a node host (a raw 32-byte
// agent.key seed, a 64-byte expanded ed25519 key, and a CometBFT
// priv_validator_key.json) and resolve each to the SAME ed25519 identity, while
// rejecting malformed input with a clear error rather than a wrong key.
func TestParseProposeSigningKey(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	want := ed25519.NewKeyFromSeed(seed)
	wantPub := want.Public().(ed25519.PublicKey)

	// priv_validator_key.json carries the 64-byte ed25519 private key base64'd
	// under priv_key.value — the exact bytes of Go's ed25519.PrivateKey.
	pvJSON, err := json.Marshal(map[string]any{
		"address": "DEADBEEF",
		"pub_key": map[string]any{
			"type":  "tendermint/PubKeyEd25519",
			"value": base64.StdEncoding.EncodeToString(wantPub),
		},
		"priv_key": map[string]any{
			"type":  "tendermint/PrivKeyEd25519",
			"value": base64.StdEncoding.EncodeToString(want),
		},
	})
	if err != nil {
		t.Fatalf("marshal pv json: %v", err)
	}

	good := []struct {
		name string
		data []byte
	}{
		{"raw 32-byte seed", seed},
		{"raw 64-byte expanded key", []byte(want)},
		{"priv_validator_key.json", pvJSON},
	}
	for _, tc := range good {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseProposeSigningKey(tc.data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gotPub, ok := got.Public().(ed25519.PublicKey)
			if !ok || !gotPub.Equal(wantPub) {
				t.Fatalf("resolved a different identity than expected")
			}
			// Prove the parsed key is actually usable for signing.
			sig := ed25519.Sign(got, []byte("upgrade"))
			if !ed25519.Verify(wantPub, []byte("upgrade"), sig) {
				t.Fatalf("parsed key did not produce a verifiable signature")
			}
		})
	}

	bad := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{"empty", []byte{}, "unrecognized key file"},
		{"wrong-length raw", make([]byte, 48), "unrecognized key file"},
		{"json without priv_key", []byte(`{"pub_key":{"value":"x"}}`), "no priv_key.value"},
		{"priv_key not base64", []byte(`{"priv_key":{"value":"!!!not base64!!!"}}`), "base64"},
		{
			name:    "priv_key wrong byte length",
			data:    []byte(`{"priv_key":{"value":"` + base64.StdEncoding.EncodeToString(make([]byte, 10)) + `"}}`),
			wantErr: "want a 32-byte seed or 64-byte ed25519 key",
		},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseProposeSigningKey(tc.data)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestUpgradePropose_AgentKey drives --agent-key end-to-end through
// runUpgradePropose — the half of issue #34 the pure parser test doesn't cover.
// It proves two things the production path must guarantee: (1) the supplied key
// (not the default agent.key) is what actually SIGNS the broadcast tx — the
// identity the post-app-v8 admin gate keys on — and (2) when that key is rejected
// with code 47, the error steers the operator without circular "re-pass
// --agent-key" advice. A stubbed CometBFT (abci_info=app-v8, broadcast_tx_commit
// returning the FinalizeBlock code-47) lets the whole command run hermetically.
func TestUpgradePropose_AgentKey(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	wantPub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	keyFile := filepath.Join(t.TempDir(), "admin.key")
	if err := os.WriteFile(keyFile, seed, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	// Capture the public key the broadcast tx was actually signed with.
	signedPub := make(chan ed25519.PublicKey, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/abci_info", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{"response": map[string]any{"app_version": "8"}},
		})
	})
	mux.HandleFunc("/broadcast_tx_commit", func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.URL.Query().Get("tx"), "0x")
		if decoded, decErr := hex.DecodeString(raw); decErr == nil {
			if ptx, txErr := tx.DecodeTx(decoded); txErr == nil {
				signedPub <- ed25519.PublicKey(ptx.PublicKey)
			}
		}
		// CheckTx admits it; the admin-gate rejection is a FinalizeBlock result.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"hash":      "DEAD",
				"height":    "10",
				"check_tx":  map[string]any{"code": 0},
				"tx_result": map[string]any{"code": 47, "log": "upgrade propose: under app-v8 only admin agents may propose upgrades"},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	err := runUpgradePropose([]string{"--target", "9", "--yes", "--rpc", srv.URL, "--agent-key", keyFile})
	if err == nil {
		t.Fatal("expected a code-47 rejection error, got nil")
	}

	// (1) The supplied key signed the tx — not the default agent.key.
	select {
	case got := <-signedPub:
		if !got.Equal(wantPub) {
			t.Fatalf("tx signed with the wrong identity: the --agent-key was not used")
		}
	default:
		t.Fatal("broadcast handler never received a decodable tx")
	}

	// (2) The error is the --agent-key-supplied branch (no circular re-pass advice)
	// and names the real requirement.
	msg := err.Error()
	if !strings.Contains(msg, "The supplied --agent-key") {
		t.Errorf("error should use the --agent-key-supplied branch; got: %v", err)
	}
	if !strings.Contains(msg, "Role==admin") {
		t.Errorf("error should explain the chain-admin requirement; got: %v", err)
	}
}

func TestResolveProposeSigningKeyUsesCurrentRotatedRootBundle(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SAGE_HOME", home)
	oldKey, _ := testAgentKey(t, 0x81)
	newKey, newID := testAgentKey(t, 0x82)
	writeTestAgentKey(t, filepath.Join(home, "agent.key"), oldKey)
	writeTestAgentKey(t, filepath.Join(home, "bundles", newID, "agent.key"), newKey)

	value, err := json.Marshal(map[string]string{"credential_id": newID})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/abci_query", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("path"); got != `"/appv23/root"` {
			t.Errorf("query path = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{"response": map[string]any{
				"code": 0, "value": base64.StdEncoding.EncodeToString(value),
			}},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	got, source, err := resolveProposeSigningKey("", 23, srv.URL, zerolog.Nop())
	if err != nil {
		t.Fatalf("resolve current Root: %v", err)
	}
	if !got.Public().(ed25519.PublicKey).Equal(newKey.Public()) {
		t.Fatal("default app-v23 proposal did not resolve the rotated Root bundle key")
	}
	if !strings.Contains(source, newID) {
		t.Fatalf("source %q does not identify current Root %s", source, newID)
	}
}

func TestResolveProposeSigningKeyExplicitOverrideWinsAtAppV23(t *testing.T) {
	key, _ := testAgentKey(t, 0x83)
	path := filepath.Join(t.TempDir(), "reviewed-admin.key")
	writeTestAgentKey(t, path, key)

	got, source, err := resolveProposeSigningKey(path, 23, "http://127.0.0.1:1", zerolog.Nop())
	if err != nil {
		t.Fatalf("explicit override: %v", err)
	}
	if !got.Public().(ed25519.PublicKey).Equal(key.Public()) {
		t.Fatal("explicit --agent-key did not win")
	}
	if source != path {
		t.Fatalf("source = %q, want %q", source, path)
	}
}

// TestUpgradeStatus_AdminCaveatPastAppV8 is the issue #34 guard for the
// self-explanatory status output: at app-v8+ the printed next-step must steer the
// operator to --agent-key and explain the chain-admin requirement (otherwise it
// hands them a command that can't run), while below app-v8 it must NOT — there the
// default agent.key works on the legacy self-activating path.
func TestUpgradeStatus_AdminCaveatPastAppV8(t *testing.T) {
	tests := []struct {
		name          string
		appVersion    string
		wantAgentKey  bool
		wantAdminWord bool
	}{
		{"pre app-v8 (v6) — no caveat", "6", false, false},
		{"pre app-v8 (v7) — no caveat", "7", false, false},
		{"at app-v8 — caveat", "8", true, true},
		{"at app-v9 — caveat", "9", true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/abci_info", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"result": map[string]any{
						"response": map[string]any{"app_version": tc.appVersion},
					},
				})
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			out := captureStdout(t, func() {
				if err := runUpgradeStatus([]string{"--rpc", srv.URL}); err != nil {
					t.Fatalf("runUpgradeStatus: %v", err)
				}
			})

			gotAgentKey := strings.Contains(out, "--agent-key")
			gotAdmin := strings.Contains(out, "chain-admin")
			if gotAgentKey != tc.wantAgentKey {
				t.Errorf("--agent-key in next-step = %v, want %v\noutput:\n%s", gotAgentKey, tc.wantAgentKey, out)
			}
			if gotAdmin != tc.wantAdminWord {
				t.Errorf("chain-admin caveat = %v, want %v\noutput:\n%s", gotAdmin, tc.wantAdminWord, out)
			}
		})
	}
}

// TestBuildUpgradeProposeTx_Parameterized proves the builder now honors an
// arbitrary (validated) target — the capability the operator surface needs.
// Before the fix it was hardwired to upgradeTargetAppVersion (6).
func TestBuildUpgradeProposeTx_Parameterized(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	cfg := upgradeWatchdogConfig{
		BinaryVersion: "v9.2.2-test",
		AgentKey:      priv,
	}

	for _, target := range []uint64{7, 8, 9, 10} {
		ptx, err := buildUpgradeProposeTx(cfg, target)
		if err != nil {
			t.Fatalf("target %d: build: %v", target, err)
		}
		if ptx.Type != tx.TxTypeUpgradePropose {
			t.Fatalf("target %d: tx type = %v, want UpgradePropose", target, ptx.Type)
		}
		if ptx.UpgradePropose == nil {
			t.Fatalf("target %d: nil UpgradePropose payload", target)
		}
		if ptx.UpgradePropose.TargetAppVersion != target {
			t.Errorf("target %d: TargetAppVersion = %d", target, ptx.UpgradePropose.TargetAppVersion)
		}
		want := tx.CanonicalUpgradeName(target)
		if ptx.UpgradePropose.Name != want {
			t.Errorf("target %d: Name = %q, want canonical %q", target, ptx.UpgradePropose.Name, want)
		}
		// The plan name must never be the human binary version — that bug bumps
		// the app version while leaving every fork gate false.
		if ptx.UpgradePropose.Name == cfg.BinaryVersion {
			t.Errorf("target %d: plan named after binary version, not canonical key", target)
		}
	}
}

// TestValidateUpgradeTarget_RespectsBinaryCeiling guards the readiness ceiling
// against the actual exported max, so the test tracks the binary's real support
// window rather than a hardcoded 10.
func TestValidateUpgradeTarget_RespectsBinaryCeiling(t *testing.T) {
	maxV := sageabci.MaxSupportedAppVersion()
	// One past the ceiling, proposed sequentially from the top, must be refused.
	if _, err := validateUpgradeTarget(maxV, maxV+1, maxV, ""); err == nil {
		t.Fatalf("expected refusal for target %d > max %d", maxV+1, maxV)
	}
}

// TestPrintUpgradeUsage_CurrentLadder pins the help text to the binary's real
// fork ladder: it once said the forks end at app-v10 long after v11+ shipped.
// The top rung must be derived from MaxSupportedAppVersion (so it can never go
// stale again) and the one-at-a-time sequential rule must be stated.
func TestPrintUpgradeUsage_CurrentLadder(t *testing.T) {
	maxV := sageabci.MaxSupportedAppVersion()
	out := captureStdout(t, printUpgradeUsage)

	top := "app-v" + strconv.FormatUint(maxV, 10)
	if !strings.Contains(out, "app-v7…"+top) {
		t.Errorf("usage ladder should span app-v7…%s; output:\n%s", top, out)
	}
	if !strings.Contains(out, "ONE AT A TIME") {
		t.Errorf("usage should state the one-at-a-time sequential rule; output:\n%s", out)
	}
}

// shrinkProposeRetryDelay makes the landed-anyway probe immediate for tests.
func shrinkProposeRetryDelay(t *testing.T) {
	t.Helper()
	old := proposeBroadcastRetryDelay
	proposeBroadcastRetryDelay = 10 * time.Millisecond
	t.Cleanup(func() { proposeBroadcastRetryDelay = old })
}

// writeProposeTestKey writes a throwaway 32-byte agent.key seed for --agent-key.
func writeProposeTestKey(t *testing.T) string {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	keyFile := filepath.Join(t.TempDir(), "agent.key")
	if err := os.WriteFile(keyFile, seed, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return keyFile
}

// proposeRetryTestServer stubs CometBFT for the broadcast-error retry tests:
// /abci_info reports app-v6 (target 7 — below the admin gate), and
// /broadcast_tx_commit replies with handlers[n] on the n-th call.
func proposeRetryTestServer(t *testing.T, handlers ...http.HandlerFunc) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/abci_info", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{"response": map[string]any{"app_version": "6"}},
		})
	})
	mux.HandleFunc("/broadcast_tx_commit", func(w http.ResponseWriter, r *http.Request) {
		idx := calls
		calls++
		if idx >= len(handlers) {
			t.Errorf("unexpected broadcast_tx_commit call #%d (only %d scripted)", idx+1, len(handlers))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		handlers[idx](w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &calls
}

func broadcastHTTP500(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusInternalServerError)
}

// TestUpgradePropose_BroadcastErrorButLanded reproduces the live papercut: the
// node 500s the broadcast yet the proposal LANDS. The retry probe gets the
// "already pending" rejection — proof the first broadcast committed the plan —
// so the command must report SUCCESS with the standard accepted guidance, not
// hand the operator a scary broadcast error for a proposal that worked.
func TestUpgradePropose_BroadcastErrorButLanded(t *testing.T) {
	shrinkProposeRetryDelay(t)
	srv, calls := proposeRetryTestServer(t,
		broadcastHTTP500,
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": map[string]any{
					"hash":      "RETRY",
					"height":    "12",
					"check_tx":  map[string]any{"code": 0},
					"tx_result": map[string]any{"code": 47, "log": "upgrade plan already pending"},
				},
			})
		},
	)

	var err error
	out := captureStdout(t, func() {
		err = runUpgradePropose([]string{"--target", "7", "--yes", "--rpc", srv.URL, "--agent-key", writeProposeTestKey(t)})
	})
	if err != nil {
		t.Fatalf("expected success when the landed-anyway probe confirms the plan, got: %v", err)
	}
	if *calls != 2 {
		t.Errorf("broadcast_tx_commit called %d times, want 2 (original + probe)", *calls)
	}
	if !strings.Contains(out, "✓ Proposed app-v7") {
		t.Errorf("missing accepted message; output:\n%s", out)
	}
	if !strings.Contains(out, "plan is pending") {
		t.Errorf("success message should say the plan is pending despite the broadcast error; output:\n%s", out)
	}
	if !strings.Contains(out, "sage-gui upgrade status") {
		t.Errorf("success message should carry the standard track-activation guidance; output:\n%s", out)
	}
}

// TestUpgradePropose_BroadcastErrorRetryCommitsClean covers the other recovery
// branch: the first broadcast genuinely never made it (the 500 hit before
// commit) and the probe's re-broadcast lands clean — normal success, with the
// probe's height/hash.
func TestUpgradePropose_BroadcastErrorRetryCommitsClean(t *testing.T) {
	shrinkProposeRetryDelay(t)
	srv, calls := proposeRetryTestServer(t,
		broadcastHTTP500,
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": map[string]any{
					"hash":      "CAFE",
					"height":    "33",
					"check_tx":  map[string]any{"code": 0},
					"tx_result": map[string]any{"code": 0},
				},
			})
		},
	)

	var err error
	out := captureStdout(t, func() {
		err = runUpgradePropose([]string{"--target", "7", "--yes", "--rpc", srv.URL, "--agent-key", writeProposeTestKey(t)})
	})
	if err != nil {
		t.Fatalf("expected success when the probe re-broadcast commits clean, got: %v", err)
	}
	if *calls != 2 {
		t.Errorf("broadcast_tx_commit called %d times, want 2", *calls)
	}
	if !strings.Contains(out, "accepted at height 33") || !strings.Contains(out, "CAFE") {
		t.Errorf("clean retry should report the probe's height/hash; output:\n%s", out)
	}
}

// TestUpgradePropose_BroadcastErrorInconclusive: when the probe can't prove the
// proposal landed (it errors too), the ORIGINAL broadcast error must surface,
// with the existing re-check fallback text intact.
func TestUpgradePropose_BroadcastErrorInconclusive(t *testing.T) {
	shrinkProposeRetryDelay(t)
	srv, calls := proposeRetryTestServer(t, broadcastHTTP500, broadcastHTTP500)

	err := runUpgradePropose([]string{"--target", "7", "--yes", "--rpc", srv.URL, "--agent-key", writeProposeTestKey(t)})
	if err == nil {
		t.Fatal("expected the original broadcast error to surface, got nil")
	}
	if *calls != 2 {
		t.Errorf("broadcast_tx_commit called %d times, want 2 (original + one probe, never more)", *calls)
	}
	if !strings.Contains(err.Error(), "broadcast:") || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error should carry the original broadcast failure; got: %v", err)
	}
	if !strings.Contains(err.Error(), "sage-gui upgrade status") {
		t.Errorf("error should keep the re-check fallback text; got: %v", err)
	}
}

// TestUpgradePropose_BroadcastErrorRetryOtherRejection: a probe rejection that
// is NOT "already pending" (e.g. the code-47 admin gate) proves nothing about
// the original broadcast — the original error must surface, not the probe's.
func TestUpgradePropose_BroadcastErrorRetryOtherRejection(t *testing.T) {
	shrinkProposeRetryDelay(t)
	srv, _ := proposeRetryTestServer(t,
		broadcastHTTP500,
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": map[string]any{
					"hash":      "NOPE",
					"height":    "9",
					"check_tx":  map[string]any{"code": 0},
					"tx_result": map[string]any{"code": 47, "log": "upgrade propose: under app-v8 only admin agents may propose upgrades"},
				},
			})
		},
	)

	err := runUpgradePropose([]string{"--target", "7", "--yes", "--rpc", srv.URL, "--agent-key", writeProposeTestKey(t)})
	if err == nil {
		t.Fatal("expected the original broadcast error to surface, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error should be the original broadcast failure, not the probe rejection; got: %v", err)
	}
}

// TestBroadcastTxCommit_SurfacesBlockExecutionResult is the regression guard for
// the false-success bug: /broadcast_tx_commit admits a well-formed tx at CheckTx
// (Code 0) but the real UpgradePropose rejection (e.g. an already-pending plan,
// or a non-admin proposer) is a Code-47 result produced under FinalizeBlock. The
// fire-and-forget /broadcast_tx_sync the watchdog uses would hide that and the
// command would print a false ✓; commit must expose tx_result so it's reported
// as a failure.
func TestBroadcastTxCommit_SurfacesBlockExecutionResult(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/broadcast_tx_commit", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"hash":      "ABC123",
				"height":    "4242",
				"check_tx":  map[string]any{"code": 0, "log": ""},
				"tx_result": map[string]any{"code": 47, "log": "upgrade plan already pending"},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := broadcastTxCommit(context.Background(), srv.URL, []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("broadcastTxCommit: %v", err)
	}
	if res.CheckTxCode != 0 {
		t.Errorf("CheckTxCode = %d, want 0 (admitted to mempool)", res.CheckTxCode)
	}
	if res.TxResultCode != 47 {
		t.Errorf("TxResultCode = %d, want 47 (the block-execution rejection sync would hide)", res.TxResultCode)
	}
	if !strings.Contains(res.TxResultLog, "already pending") {
		t.Errorf("TxResultLog = %q, want it to carry the rejection reason", res.TxResultLog)
	}
	if res.Height != 4242 {
		t.Errorf("Height = %d, want 4242", res.Height)
	}
	if res.Hash != "ABC123" {
		t.Errorf("Hash = %q, want ABC123", res.Hash)
	}
}

// TestBroadcastTxCommit_Success confirms the happy path: both CheckTx and the
// block-execution result are Code 0.
func TestBroadcastTxCommit_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/broadcast_tx_commit", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"hash":      "FEED",
				"height":    "100",
				"check_tx":  map[string]any{"code": 0},
				"tx_result": map[string]any{"code": 0},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := broadcastTxCommit(context.Background(), srv.URL, []byte{0xaa})
	if err != nil {
		t.Fatalf("broadcastTxCommit: %v", err)
	}
	if res.CheckTxCode != 0 || res.TxResultCode != 0 {
		t.Fatalf("expected success codes, got check=%d tx_result=%d", res.CheckTxCode, res.TxResultCode)
	}
	if res.Height != 100 {
		t.Errorf("Height = %d, want 100", res.Height)
	}
}

// TestBroadcastTxCommit_RPCError surfaces a CometBFT RPC error (e.g. the
// broadcast-commit timeout) as a Go error rather than a nil-result success.
func TestBroadcastTxCommit_RPCError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/broadcast_tx_commit", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "timed out waiting for tx to be included in a block",
				"data":    "",
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	if _, err := broadcastTxCommit(context.Background(), srv.URL, []byte{0x01}); err == nil {
		t.Fatal("expected an error for an RPC-error response, got nil")
	}
}
