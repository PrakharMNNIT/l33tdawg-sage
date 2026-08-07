package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	sageabci "github.com/l33tdawg/sage/internal/abci"
)

func captureLineageStdout(t *testing.T, run func() error) string {
	t.Helper()
	read, write, err := os.Pipe()
	require.NoError(t, err)
	original := os.Stdout
	os.Stdout = write
	err = run()
	os.Stdout = original
	require.NoError(t, write.Close())
	require.NoError(t, err)
	out, err := io.ReadAll(read)
	require.NoError(t, err)
	require.NoError(t, read.Close())
	return string(out)
}

func TestUpgradeLineageDoctorEmitsBoundManifestAndManualVoteContract(t *testing.T) {
	status := upgradeLineageRPCStatus{
		Schema: "sage-upgrade-lineage-repair/v1", CurrentAppVersion: 21,
		PersistedHeight: 20, GovernanceDomain: strings.Repeat("a", 64),
		ValidLineageDigest: strings.Repeat("b", 64),
	}
	for version := uint64(6); version <= 21; version++ {
		rung := struct {
			Version       uint64 `json:"version"`
			Name          string `json:"name"`
			Present       bool   `json:"present"`
			AppliedHeight int64  `json:"applied_height,omitempty"`
			Valid         bool   `json:"valid"`
			Problem       string `json:"problem,omitempty"`
		}{Version: version, Name: "app-v" + strconv.FormatUint(version, 10)}
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
	require.Contains(t, strings.Join(doctor.Diagnostics, "\n"), "consensus does not independently verify")
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
		Schema: "sage-upgrade-lineage-repair/v1", CurrentAppVersion: 21, PersistedHeight: 20,
		Rungs: []struct {
			Version       uint64 `json:"version"`
			Name          string `json:"name"`
			Present       bool   `json:"present"`
			AppliedHeight int64  `json:"applied_height,omitempty"`
			Valid         bool   `json:"valid"`
			Problem       string `json:"problem,omitempty"`
		}{
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
		Schema: "sage-upgrade-lineage-repair/v1", CurrentAppVersion: 21, PersistedHeight: 10,
		GovernanceDomain: strings.Repeat("a", 64), ValidLineageDigest: strings.Repeat("b", 64),
		Rungs: []struct {
			Version       uint64 `json:"version"`
			Name          string `json:"name"`
			Present       bool   `json:"present"`
			AppliedHeight int64  `json:"applied_height,omitempty"`
			Valid         bool   `json:"valid"`
			Problem       string `json:"problem,omitempty"`
		}{
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
	status.Rungs = append(status.Rungs, struct {
		Version       uint64 `json:"version"`
		Name          string `json:"name"`
		Present       bool   `json:"present"`
		AppliedHeight int64  `json:"applied_height,omitempty"`
		Valid         bool   `json:"valid"`
		Problem       string `json:"problem,omitempty"`
	}{Version: 9, Name: "app-v9"})
	err := validateDoctorLineageEvidence(status, []sageabci.LegacyLineageEvidence{{Version: 9, AppliedHeight: 11}})
	require.ErrorContains(t, err, "not a retained")
}

func requireReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	return raw
}
