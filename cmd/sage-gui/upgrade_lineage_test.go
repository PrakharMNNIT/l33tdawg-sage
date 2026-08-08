package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	sageabci "github.com/l33tdawg/sage/internal/abci"
)

func captureLineageStdout(t *testing.T, run func() error) string {
	t.Helper()
	out, err := captureLineageStdoutResult(t, run)
	require.NoError(t, err)
	return out
}

func captureLineageStdoutResult(t *testing.T, run func() error) (string, error) {
	t.Helper()
	read, write, err := os.Pipe()
	require.NoError(t, err)
	original := os.Stdout
	os.Stdout = write
	runErr := run()
	os.Stdout = original
	require.NoError(t, write.Close())
	out, err := io.ReadAll(read)
	require.NoError(t, err)
	require.NoError(t, read.Close())
	return string(out), runErr
}

func TestUpgradeLineageDoctorEmitsBoundManifestAndManualVoteContract(t *testing.T) {
	status := upgradeLineageRPCStatus{
		Schema: "sage-upgrade-lineage-repair/v2", CurrentAppVersion: 21,
		PersistedHeight: 20, GovernanceDomain: strings.Repeat("a", 64),
		ValidLineageDigest: strings.Repeat("b", 64),
	}
	for version := uint64(6); version <= 21; version++ {
		rung := upgradeLineageRPCRung{Version: version, Name: "app-v" + strconv.FormatUint(version, 10)}
		if version != 9 {
			rung.Present, rung.Valid = true, true
			if version < 9 {
				rung.AppliedHeight = int64(version - 5)
			} else {
				rung.AppliedHeight = int64(version - 4)
			}
		} else {
			rung.Problem = "missing"
		}
		status.Rungs = append(status.Rungs, rung)
	}
	statusJSON, err := json.Marshal(status)
	require.NoError(t, err)
	mux := http.NewServeMux()
	mux.HandleFunc("/abci_query", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"response": map[string]any{
			"code": 0, "value": base64.StdEncoding.EncodeToString(statusJSON),
		}}})
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"node_info": map[string]any{"network": "lineage-chain"}}})
	})
	mux.HandleFunc("/block_results", func(w http.ResponseWriter, r *http.Request) {
		appVersion := ""
		if r.URL.Query().Get("height") == "4" {
			appVersion = "9"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"consensus_param_updates": map[string]any{"version": map[string]any{"app": appVersion}}}})
	})
	mux.HandleFunc("/block", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"block_id": map[string]any{"hash": strings.Repeat("AB", 32)}}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	manifestPath := filepath.Join(t.TempDir(), "repair.json")
	output := captureLineageStdout(t, func() error {
		return runUpgradeLineageDoctor([]string{"--rpc", server.URL, "--json", "--manifest-out", manifestPath})
	})
	var doctor lineageDoctorOutput
	require.NoError(t, json.Unmarshal([]byte(output), &doctor))
	require.True(t, doctor.Repairable)
	require.True(t, doctor.ManualVoteRequired)
	require.Len(t, doctor.ManifestDigest, 64)
	require.Contains(t, strings.Join(doctor.Diagnostics, "\n"), "every validator must reconstruct")
	require.Contains(t, strings.Join(doctor.ReviewSteps, "\n"), "explicit sage_gov_vote")
	require.JSONEq(t, string(doctor.Manifest), string(requireReadFile(t, manifestPath)))
	verifyOutput := captureLineageStdout(t, func() error {
		return runUpgradeLineageVerify([]string{"--rpc", server.URL, "--json", "--manifest", manifestPath})
	})
	var verified lineageVerifyOutput
	require.NoError(t, json.Unmarshal([]byte(verifyOutput), &verified))
	require.True(t, verified.Valid)
	require.True(t, verified.HistoryVerified)
	require.True(t, verified.EligibleForVote)
	require.Equal(t, doctor.ManifestDigest, verified.ManifestDigest)
}

func TestUpgradeLineageDoctorRefusesPresentInvalidRung(t *testing.T) {
	status := upgradeLineageRPCStatus{
		Schema: "sage-upgrade-lineage-repair/v2", CurrentAppVersion: 21, PersistedHeight: 20,
		Rungs: []upgradeLineageRPCRung{
			{Version: 8, Name: "app-v8", Present: true, AppliedHeight: 99, Valid: false, Problem: "invalid order"},
			{Version: 9, Name: "app-v9", Present: false, Problem: "missing"},
		},
	}
	raw, err := json.Marshal(status)
	require.NoError(t, err)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"response": map[string]any{
			"code": 0, "value": base64.StdEncoding.EncodeToString(raw),
		}}})
	}))
	defer server.Close()
	output := captureLineageStdout(t, func() error {
		return runUpgradeLineageDoctor([]string{"--rpc", server.URL, "--json"})
	})
	var doctor lineageDoctorOutput
	require.NoError(t, json.Unmarshal([]byte(output), &doctor))
	require.False(t, doctor.Repairable)
	require.Empty(t, doctor.Manifest)
	require.Contains(t, strings.Join(doctor.Diagnostics, "\n"), "not repairable")
}

func TestUpgradeLineageDoctorAnchorFallbackIsAllOrNothingAndAcknowledged(t *testing.T) {
	status := upgradeLineageRPCStatus{
		Schema: "sage-upgrade-lineage-repair/v2", CurrentAppVersion: 21, PersistedHeight: 10,
		GovernanceDomain: strings.Repeat("a", 64), ValidLineageDigest: strings.Repeat("b", 64),
		Rungs: []upgradeLineageRPCRung{
			{Version: 8, Name: "app-v8", Present: true, AppliedHeight: 1, Valid: true},
			{Version: 9, Name: "app-v9", Problem: "missing"},
			{Version: 10, Name: "app-v10", Problem: "missing"},
			{Version: 11, Name: "app-v11", Present: true, AppliedHeight: 4, Valid: true},
		},
	}
	statusJSON, err := json.Marshal(status)
	require.NoError(t, err)
	mux := http.NewServeMux()
	mux.HandleFunc("/abci_query", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"response": map[string]any{"code": 0, "value": base64.StdEncoding.EncodeToString(statusJSON)}}})
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"node_info": map[string]any{"network": "lineage-chain"}}})
	})
	mux.HandleFunc("/block_results", func(w http.ResponseWriter, r *http.Request) {
		version := ""
		if r.URL.Query().Get("height") == "2" {
			version = "9"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"consensus_param_updates": map[string]any{"version": map[string]any{"app": version}}}})
	})
	mux.HandleFunc("/block", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"block_id": map[string]any{"hash": strings.Repeat("CD", 32)}}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	anchorPath := filepath.Join(t.TempDir(), "anchor.json")
	require.NoError(t, os.WriteFile(anchorPath, []byte(`{"heights":{"9":2,"10":3}}`), 0o600))

	withoutAck := captureLineageStdout(t, func() error {
		return runUpgradeLineageDoctor([]string{"--rpc", server.URL, "--json", "--legacy-anchor", anchorPath})
	})
	var refused lineageDoctorOutput
	require.NoError(t, json.Unmarshal([]byte(withoutAck), &refused))
	require.False(t, refused.Repairable)
	require.Contains(t, strings.Join(refused.Diagnostics, "\n"), "requires --acknowledge-unverified-anchor")

	withAck := captureLineageStdout(t, func() error {
		return runUpgradeLineageDoctor([]string{"--rpc", server.URL, "--json", "--legacy-anchor", anchorPath, "--acknowledge-unverified-anchor"})
	})
	var accepted lineageDoctorOutput
	require.NoError(t, json.Unmarshal([]byte(withAck), &accepted))
	require.True(t, accepted.Repairable)
	var manifest struct {
		AnchorAttestation string                           `json:"anchor_attestation"`
		Evidence          []sageabci.LegacyLineageEvidence `json:"evidence"`
	}
	require.NoError(t, json.Unmarshal(accepted.Manifest, &manifest))
	require.Equal(t, "operator-quorum-attested-unverified-history", manifest.AnchorAttestation)
	require.Len(t, manifest.Evidence, 2)
	for _, claim := range manifest.Evidence {
		require.Equal(t, "legacy-anchor", claim.Source, "partial Comet history must never be blended into an anchor manifest")
		require.Empty(t, claim.BlockHash)
	}
}

func TestValidateDoctorLineageEvidenceRejectsFutureAnchorHeight(t *testing.T) {
	status := &upgradeLineageRPCStatus{PersistedHeight: 10}
	status.Rungs = append(status.Rungs, upgradeLineageRPCRung{Version: 9, Name: "app-v9"})
	err := validateDoctorLineageEvidence(status, []sageabci.LegacyLineageEvidence{{Version: 9, AppliedHeight: 11}})
	require.ErrorContains(t, err, "not a retained")
}

func requireReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	return raw
}

type retainedLineageFixture struct {
	server   *httptest.Server
	status   upgradeLineageRPCStatus
	mu       sync.Mutex
	versions map[int64]uint64
	hashes   map[int64]string
	requests map[string]int
}

func newRetainedLineageFixture(t *testing.T) *retainedLineageFixture {
	t.Helper()
	f := &retainedLineageFixture{
		versions: map[int64]uint64{376: 7, 741: 8, 992: 11},
		hashes:   map[int64]string{376: fmt.Sprintf("%064x", 376), 992: fmt.Sprintf("%064x", 992)},
		requests: make(map[string]int),
		status: upgradeLineageRPCStatus{
			Schema: "sage-upgrade-lineage-repair/v2", CurrentAppVersion: 21, PersistedHeight: 1020,
			GovernanceDomain: strings.Repeat("a", 64), ValidLineageDigest: strings.Repeat("b", 64),
		},
	}
	for version := uint64(6); version <= 21; version++ {
		rung := upgradeLineageRPCRung{Version: version, Name: fmt.Sprintf("app-v%d", version)}
		switch version {
		case 6, 9, 10:
			rung.Problem = "missing"
		case 7:
			rung.Present, rung.Valid, rung.AppliedHeight = true, true, 376
		case 8:
			rung.Present, rung.Valid, rung.AppliedHeight = true, true, 741
		case 11:
			rung.Present, rung.Valid, rung.AppliedHeight = true, true, 992
		default:
			rung.Present, rung.Valid, rung.AppliedHeight = true, true, 989+int64(version)
		}
		f.status.Rungs = append(f.status.Rungs, rung)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/abci_query", func(w http.ResponseWriter, _ *http.Request) {
		raw, err := json.Marshal(f.status)
		require.NoError(t, err)
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"response": map[string]any{"code": 0, "value": base64.StdEncoding.EncodeToString(raw)}}})
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"node_info": map[string]any{"network": "transition-chain"}}})
	})
	mux.HandleFunc("/block_results", func(w http.ResponseWriter, r *http.Request) {
		height, _ := strconv.ParseInt(r.URL.Query().Get("height"), 10, 64)
		f.mu.Lock()
		f.requests[fmt.Sprintf("results:%d", height)]++
		version := f.versions[height]
		f.mu.Unlock()
		app := ""
		if version != 0 {
			app = strconv.FormatUint(version, 10)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"consensus_param_updates": map[string]any{"version": map[string]any{"app": app}}}})
	})
	mux.HandleFunc("/block", func(w http.ResponseWriter, r *http.Request) {
		height, _ := strconv.ParseInt(r.URL.Query().Get("height"), 10, 64)
		f.mu.Lock()
		f.requests[fmt.Sprintf("block:%d", height)]++
		hash := f.hashes[height]
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"block_id": map[string]any{"hash": hash}}})
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *retainedLineageFixture) requestCount(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[key]
}

func TestUpgradeLineageDoctorDerivesTruthfulSubsumptionTransitionsFromRetainedHistory(t *testing.T) {
	f := newRetainedLineageFixture(t)
	manifestPath := filepath.Join(t.TempDir(), "repair.json")
	output := captureLineageStdout(t, func() error {
		return runUpgradeLineageDoctor([]string{"--rpc", f.server.URL, "--json", "--manifest-out", manifestPath})
	})
	var doctor lineageDoctorOutput
	require.NoError(t, json.Unmarshal([]byte(output), &doctor))
	require.True(t, doctor.Repairable)
	require.True(t, doctor.ManualVoteRequired)
	var manifest sageabci.LegacyLineageRepairManifest
	require.NoError(t, json.Unmarshal(doctor.Manifest, &manifest))
	require.Equal(t, "sage-upgrade-lineage-repair/v2", manifest.Schema)
	require.Empty(t, manifest.Evidence)
	require.Empty(t, manifest.AnchorDigest)
	require.Empty(t, manifest.AnchorAttestation)
	require.Equal(t, []sageabci.LineageActivationTransition{
		{FromVersion: 1, ToVersion: 7, AppliedHeight: 376, Source: "comet-block-results", BlockHash: fmt.Sprintf("%064x", 376), SubsumedVersions: []uint64{6}},
		{FromVersion: 8, ToVersion: 11, AppliedHeight: 992, Source: "comet-block-results", BlockHash: fmt.Sprintf("%064x", 992), SubsumedVersions: []uint64{9, 10}},
	}, manifest.Transitions)
	require.JSONEq(t, string(doctor.Manifest), string(requireReadFile(t, manifestPath)))
	raw := string(doctor.Manifest)
	require.NotContains(t, raw, "legacy-anchor")
	require.NotContains(t, raw, `"applied_height":375`)
	require.NotContains(t, raw, `"applied_height":740`)
	require.NotContains(t, raw, `"applied_height":991`)
}

func TestUpgradeLineageVerifyReplaysFullTransitionHistoryOnIndependentValidator(t *testing.T) {
	proposer := newRetainedLineageFixture(t)
	manifestPath := filepath.Join(t.TempDir(), "repair.json")
	doctorOutput := captureLineageStdout(t, func() error {
		return runUpgradeLineageDoctor([]string{"--rpc", proposer.server.URL, "--json", "--manifest-out", manifestPath})
	})
	var doctor lineageDoctorOutput
	require.NoError(t, json.Unmarshal([]byte(doctorOutput), &doctor))
	validator := newRetainedLineageFixture(t)
	verifyOutput := captureLineageStdout(t, func() error {
		return runUpgradeLineageVerify([]string{"--rpc", validator.server.URL, "--json", "--manifest", manifestPath})
	})
	var verified lineageVerifyOutput
	require.NoError(t, json.Unmarshal([]byte(verifyOutput), &verified))
	require.True(t, verified.Valid)
	require.True(t, verified.HistoryVerified)
	require.True(t, verified.EligibleForVote)
	require.Equal(t, doctor.ManifestDigest, verified.ManifestDigest)
	require.Greater(t, validator.requestCount("results:376"), 0)
	require.Greater(t, validator.requestCount("results:741"), 0, "the ordinary 7->8 transition must also be replayed")
	require.Greater(t, validator.requestCount("results:992"), 0)
	require.Greater(t, validator.requestCount("block:376"), 0)
	require.Greater(t, validator.requestCount("block:992"), 0)
}

func TestUpgradeLineageVerifyRejectsTamperedTransitionManifest(t *testing.T) {
	proposer := newRetainedLineageFixture(t)
	manifestPath := filepath.Join(t.TempDir(), "repair.json")
	_ = captureLineageStdout(t, func() error {
		return runUpgradeLineageDoctor([]string{"--rpc", proposer.server.URL, "--json", "--manifest-out", manifestPath})
	})
	var original sageabci.LegacyLineageRepairManifest
	require.NoError(t, json.Unmarshal(requireReadFile(t, manifestPath), &original))
	tests := map[string]func(*sageabci.LegacyLineageRepairManifest){
		"from version":       func(m *sageabci.LegacyLineageRepairManifest) { m.Transitions[1].FromVersion = 7 },
		"to version":         func(m *sageabci.LegacyLineageRepairManifest) { m.Transitions[1].ToVersion = 12 },
		"height":             func(m *sageabci.LegacyLineageRepairManifest) { m.Transitions[1].AppliedHeight = 991 },
		"hash":               func(m *sageabci.LegacyLineageRepairManifest) { m.Transitions[1].BlockHash = strings.Repeat("f", 64) },
		"omitted subsumed":   func(m *sageabci.LegacyLineageRepairManifest) { m.Transitions[1].SubsumedVersions = []uint64{9} },
		"added subsumed":     func(m *sageabci.LegacyLineageRepairManifest) { m.Transitions[1].SubsumedVersions = []uint64{9, 10, 12} },
		"duplicate subsumed": func(m *sageabci.LegacyLineageRepairManifest) { m.Transitions[1].SubsumedVersions = []uint64{9, 9, 10} },
		"unsorted subsumed":  func(m *sageabci.LegacyLineageRepairManifest) { m.Transitions[1].SubsumedVersions = []uint64{10, 9} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := original
			manifest.Transitions = append([]sageabci.LineageActivationTransition(nil), original.Transitions...)
			for i := range manifest.Transitions {
				manifest.Transitions[i].SubsumedVersions = append([]uint64(nil), original.Transitions[i].SubsumedVersions...)
			}
			mutate(&manifest)
			raw, err := json.Marshal(manifest)
			require.NoError(t, err)
			path := filepath.Join(t.TempDir(), "tampered.json")
			require.NoError(t, os.WriteFile(path, append(raw, '\n'), 0o600))
			validator := newRetainedLineageFixture(t)
			output, verifyErr := captureLineageStdoutResult(t, func() error {
				return runUpgradeLineageVerify([]string{"--rpc", validator.server.URL, "--json", "--manifest", path})
			})
			require.Error(t, verifyErr)
			var verified lineageVerifyOutput
			require.NoError(t, json.Unmarshal([]byte(output), &verified))
			require.False(t, verified.Valid)
			require.False(t, verified.HistoryVerified)
			require.False(t, verified.EligibleForVote)
			require.NotContains(t, strings.Join(verified.Diagnostics, "\n"), "anchor")
		})
	}
}

func TestUpgradeLineageVerifyRejectsIndependentArchiveDrift(t *testing.T) {
	proposer := newRetainedLineageFixture(t)
	manifestPath := filepath.Join(t.TempDir(), "repair.json")
	_ = captureLineageStdout(t, func() error {
		return runUpgradeLineageDoctor([]string{"--rpc", proposer.server.URL, "--json", "--manifest-out", manifestPath})
	})
	tests := map[string]func(*retainedLineageFixture){
		"intermediate transition": func(f *retainedLineageFixture) { f.versions[741] = 9 },
		"target transition":       func(f *retainedLineageFixture) { f.versions[992] = 12 },
		"block hash":              func(f *retainedLineageFixture) { f.hashes[992] = strings.Repeat("e", 64) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			validator := newRetainedLineageFixture(t)
			mutate(validator)
			output, verifyErr := captureLineageStdoutResult(t, func() error {
				return runUpgradeLineageVerify([]string{"--rpc", validator.server.URL, "--json", "--manifest", manifestPath})
			})
			require.Error(t, verifyErr)
			var verified lineageVerifyOutput
			require.NoError(t, json.Unmarshal([]byte(output), &verified))
			require.False(t, verified.EligibleForVote)
			require.False(t, verified.HistoryVerified)
		})
	}
}

func TestUpgradeLineageAnchorSupportsFullyPrunedJumpWithVirtualTarget(t *testing.T) {
	status := upgradeLineageRPCStatus{Schema: "sage-upgrade-lineage-repair/v2", CurrentAppVersion: 21, PersistedHeight: 1020, GovernanceDomain: strings.Repeat("a", 64), ValidLineageDigest: strings.Repeat("b", 64)}
	for version := uint64(6); version <= 21; version++ {
		rung := upgradeLineageRPCRung{Version: version, Name: fmt.Sprintf("app-v%d", version)}
		if version <= 11 {
			rung.Problem = "missing"
		} else {
			rung.Present, rung.Valid, rung.AppliedHeight = true, true, 989+int64(version)
		}
		status.Rungs = append(status.Rungs, rung)
	}
	rawStatus, err := json.Marshal(status)
	require.NoError(t, err)
	mux := http.NewServeMux()
	mux.HandleFunc("/abci_query", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"response": map[string]any{"code": 0, "value": base64.StdEncoding.EncodeToString(rawStatus)}}})
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"node_info": map[string]any{"network": "pruned-chain"}}})
	})
	mux.HandleFunc("/block_results", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"consensus_param_updates": map[string]any{"version": map[string]any{"app": ""}}}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	anchorPath := filepath.Join(t.TempDir(), "anchor.json")
	require.NoError(t, os.WriteFile(anchorPath, []byte(`{"transitions":[{"from_version":1,"to_version":11,"applied_height":1000,"subsumed_versions":[6,7,8,9,10]}]}`), 0o600))
	manifestPath := filepath.Join(t.TempDir(), "repair.json")
	output := captureLineageStdout(t, func() error {
		return runUpgradeLineageDoctor([]string{"--rpc", server.URL, "--json", "--legacy-anchor", anchorPath, "--acknowledge-unverified-anchor", "--manifest-out", manifestPath})
	})
	var doctor lineageDoctorOutput
	require.NoError(t, json.Unmarshal([]byte(output), &doctor))
	require.True(t, doctor.Repairable)
	var manifest sageabci.LegacyLineageRepairManifest
	require.NoError(t, json.Unmarshal(doctor.Manifest, &manifest))
	require.Empty(t, manifest.Evidence)
	require.Equal(t, []sageabci.LineageActivationTransition{{FromVersion: 1, ToVersion: 11, AppliedHeight: 1000, Source: "legacy-anchor", SubsumedVersions: []uint64{6, 7, 8, 9, 10}}}, manifest.Transitions)
	verified := captureLineageStdout(t, func() error {
		return runUpgradeLineageVerify([]string{"--rpc", server.URL, "--json", "--manifest", manifestPath, "--acknowledge-unverified-anchor"})
	})
	var verify lineageVerifyOutput
	require.NoError(t, json.Unmarshal([]byte(verified), &verify))
	require.True(t, verify.Valid)
	require.False(t, verify.HistoryVerified)
	require.True(t, verify.EligibleForVote)

	for name, mutate := range map[string]func(*sageabci.LineageActivationTransition){
		"source":   func(tr *sageabci.LineageActivationTransition) { tr.Source = "comet-block-results" },
		"hash":     func(tr *sageabci.LineageActivationTransition) { tr.BlockHash = strings.Repeat("a", 64) },
		"from":     func(tr *sageabci.LineageActivationTransition) { tr.FromVersion = 2 },
		"to":       func(tr *sageabci.LineageActivationTransition) { tr.ToVersion = 12 },
		"height":   func(tr *sageabci.LineageActivationTransition) { tr.AppliedHeight = 1021 },
		"subsumed": func(tr *sageabci.LineageActivationTransition) { tr.SubsumedVersions = []uint64{6, 7, 9, 10} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := manifest
			bad.Transitions = append([]sageabci.LineageActivationTransition(nil), manifest.Transitions...)
			bad.Transitions[0].SubsumedVersions = append([]uint64(nil), manifest.Transitions[0].SubsumedVersions...)
			mutate(&bad.Transitions[0])
			raw, err := json.Marshal(bad)
			require.NoError(t, err)
			path := filepath.Join(t.TempDir(), "bad.json")
			require.NoError(t, os.WriteFile(path, raw, 0o600))
			_, verifyErr := captureLineageStdoutResult(t, func() error {
				return runUpgradeLineageVerify([]string{"--rpc", server.URL, "--json", "--manifest", path, "--acknowledge-unverified-anchor"})
			})
			require.Error(t, verifyErr)
		})
	}
}

func newFullyPrunedAnchorRPC(t *testing.T, missingThrough uint64) *httptest.Server {
	t.Helper()
	status := upgradeLineageRPCStatus{Schema: "sage-upgrade-lineage-repair/v2", CurrentAppVersion: 21, PersistedHeight: 2000, GovernanceDomain: strings.Repeat("a", 64), ValidLineageDigest: strings.Repeat("b", 64)}
	for version := uint64(6); version <= 21; version++ {
		rung := upgradeLineageRPCRung{Version: version, Name: fmt.Sprintf("app-v%d", version)}
		if version <= missingThrough {
			rung.Problem = "missing"
		} else {
			rung.Present, rung.Valid, rung.AppliedHeight = true, true, 1000+int64(version)
		}
		status.Rungs = append(status.Rungs, rung)
	}
	raw, err := json.Marshal(status)
	require.NoError(t, err)
	mux := http.NewServeMux()
	mux.HandleFunc("/abci_query", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"response": map[string]any{"code": 0, "value": base64.StdEncoding.EncodeToString(raw)}}})
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"node_info": map[string]any{"network": "chained-pruned"}}})
	})
	mux.HandleFunc("/block_results", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"consensus_param_updates": map[string]any{"version": map[string]any{"app": ""}}}})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestUpgradeLineageAnchorSupportsChainedVirtualTargets(t *testing.T) {
	server := newFullyPrunedAnchorRPC(t, 15)
	anchor := `{"transitions":[{"from_version":1,"to_version":11,"applied_height":1000,"subsumed_versions":[6,7,8,9,10]},{"from_version":11,"to_version":15,"applied_height":1005,"subsumed_versions":[12,13,14]}]}`
	anchorPath := filepath.Join(t.TempDir(), "anchor.json")
	manifestPath := filepath.Join(t.TempDir(), "repair.json")
	require.NoError(t, os.WriteFile(anchorPath, []byte(anchor), 0o600))
	output := captureLineageStdout(t, func() error {
		return runUpgradeLineageDoctor([]string{"--rpc", server.URL, "--json", "--legacy-anchor", anchorPath, "--acknowledge-unverified-anchor", "--manifest-out", manifestPath})
	})
	var doctor lineageDoctorOutput
	require.NoError(t, json.Unmarshal([]byte(output), &doctor))
	require.True(t, doctor.Repairable)
	var manifest sageabci.LegacyLineageRepairManifest
	require.NoError(t, json.Unmarshal(doctor.Manifest, &manifest))
	require.Len(t, manifest.Transitions, 2)
	require.Equal(t, uint64(11), manifest.Transitions[1].FromVersion)
	require.Equal(t, int64(1000), manifest.Transitions[0].AppliedHeight)
	require.Equal(t, int64(1005), manifest.Transitions[1].AppliedHeight)
	verified := captureLineageStdout(t, func() error {
		return runUpgradeLineageVerify([]string{"--rpc", server.URL, "--json", "--manifest", manifestPath, "--acknowledge-unverified-anchor"})
	})
	var verify lineageVerifyOutput
	require.NoError(t, json.Unmarshal([]byte(verified), &verify))
	require.True(t, verify.EligibleForVote)

	invalid := map[string]string{
		"same height":     `{"transitions":[{"from_version":1,"to_version":11,"applied_height":1000,"subsumed_versions":[6,7,8,9,10]},{"from_version":11,"to_version":15,"applied_height":1000,"subsumed_versions":[12,13,14]}]}`,
		"reverse height":  `{"transitions":[{"from_version":1,"to_version":11,"applied_height":1000,"subsumed_versions":[6,7,8,9,10]},{"from_version":11,"to_version":15,"applied_height":999,"subsumed_versions":[12,13,14]}]}`,
		"subsumed source": `{"transitions":[{"from_version":1,"to_version":11,"applied_height":1000,"subsumed_versions":[6,7,8,9,10]},{"from_version":10,"to_version":15,"applied_height":1005,"subsumed_versions":[11,12,13,14]}]}`,
		"overlap":         `{"transitions":[{"from_version":1,"to_version":11,"applied_height":1000,"subsumed_versions":[6,7,8,9,10]},{"from_version":11,"to_version":15,"applied_height":1005,"subsumed_versions":[10,12,13,14]}]}`,
		"manifest order":  `{"transitions":[{"from_version":11,"to_version":15,"applied_height":1005,"subsumed_versions":[12,13,14]},{"from_version":1,"to_version":11,"applied_height":1000,"subsumed_versions":[6,7,8,9,10]}]}`,
	}
	for name, raw := range invalid {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "invalid-anchor.json")
			require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))
			result := captureLineageStdout(t, func() error {
				return runUpgradeLineageDoctor([]string{"--rpc", server.URL, "--json", "--legacy-anchor", path, "--acknowledge-unverified-anchor"})
			})
			var refused lineageDoctorOutput
			require.NoError(t, json.Unmarshal([]byte(result), &refused))
			require.False(t, refused.Repairable)
			require.Empty(t, refused.Manifest)
		})
	}
}

func TestUpgradeLineageAnchorAllowsIndependentHeightAsTransitionSource(t *testing.T) {
	server := newFullyPrunedAnchorRPC(t, 9)
	anchorPath := filepath.Join(t.TempDir(), "mixed-anchor.json")
	require.NoError(t, os.WriteFile(anchorPath, []byte(`{"heights":{"6":100},"transitions":[{"from_version":6,"to_version":9,"applied_height":200,"subsumed_versions":[7,8]}]}`), 0o600))
	output := captureLineageStdout(t, func() error {
		return runUpgradeLineageDoctor([]string{"--rpc", server.URL, "--json", "--legacy-anchor", anchorPath, "--acknowledge-unverified-anchor"})
	})
	var doctor lineageDoctorOutput
	require.NoError(t, json.Unmarshal([]byte(output), &doctor))
	require.True(t, doctor.Repairable)
	var manifest sageabci.LegacyLineageRepairManifest
	require.NoError(t, json.Unmarshal(doctor.Manifest, &manifest))
	require.Equal(t, uint64(6), manifest.Evidence[0].Version)
	require.Equal(t, uint64(6), manifest.Transitions[0].FromVersion)

	overlapPath := filepath.Join(t.TempDir(), "overlap-anchor.json")
	require.NoError(t, os.WriteFile(overlapPath, []byte(`{"heights":{"6":100,"7":150},"transitions":[{"from_version":6,"to_version":9,"applied_height":200,"subsumed_versions":[7,8]}]}`), 0o600))
	refusedRaw := captureLineageStdout(t, func() error {
		return runUpgradeLineageDoctor([]string{"--rpc", server.URL, "--json", "--legacy-anchor", overlapPath, "--acknowledge-unverified-anchor"})
	})
	var refused lineageDoctorOutput
	require.NoError(t, json.Unmarshal([]byte(refusedRaw), &refused))
	require.False(t, refused.Repairable)
}
