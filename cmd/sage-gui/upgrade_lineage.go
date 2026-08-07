package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	sageabci "github.com/l33tdawg/sage/internal/abci"
	"github.com/l33tdawg/sage/internal/tx"
)

type upgradeLineageRPCStatus struct {
	Schema             string `json:"schema"`
	CurrentAppVersion  uint64 `json:"current_app_version"`
	PersistedHeight    int64  `json:"persisted_height"`
	GovernanceDomain   string `json:"governance_domain"`
	ValidLineageDigest string `json:"valid_lineage_digest"`
	RepairAudit        any    `json:"repair_audit,omitempty"`
	Rungs              []struct {
		Version       uint64 `json:"version"`
		Name          string `json:"name"`
		Present       bool   `json:"present"`
		AppliedHeight int64  `json:"applied_height,omitempty"`
		Valid         bool   `json:"valid"`
		Problem       string `json:"problem,omitempty"`
	} `json:"rungs"`
}

type lineageDoctorOutput struct {
	Status             upgradeLineageRPCStatus `json:"status"`
	Repairable         bool                    `json:"repairable"`
	ManualVoteRequired bool                    `json:"manual_vote_required"`
	ManifestDigest     string                  `json:"manifest_digest,omitempty"`
	Diagnostics        []string                `json:"diagnostics"`
	ReviewSteps        []string                `json:"review_steps,omitempty"`
	Manifest           json.RawMessage         `json:"manifest,omitempty"`
}

type lineageVerifyOutput struct {
	Valid           bool                             `json:"valid"`
	HistoryVerified bool                             `json:"history_verified"`
	EligibleForVote bool                             `json:"eligible_for_manual_vote"`
	ManifestDigest  string                           `json:"manifest_digest"`
	EvidenceSource  string                           `json:"evidence_source,omitempty"`
	Claims          []sageabci.LegacyLineageEvidence `json:"claims"`
	Diagnostics     []string                         `json:"diagnostics"`
}

func runUpgradeLineage(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sage-gui upgrade lineage status|doctor --json")
	}
	switch args[0] {
	case "status":
		return runUpgradeLineageStatus(args[1:])
	case "doctor":
		return runUpgradeLineageDoctor(args[1:])
	case "verify":
		return runUpgradeLineageVerify(args[1:])
	default:
		return fmt.Errorf("unknown upgrade lineage subcommand %q", args[0])
	}
}

func runUpgradeLineageVerify(args []string) error {
	fs := flag.NewFlagSet("upgrade lineage verify", flag.ContinueOnError)
	rpc := fs.String("rpc", defaultCometRPC(), "CometBFT RPC endpoint")
	manifestPath := fs.String("manifest", "", "canonical lineage repair manifest to verify")
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON")
	ackAnchor := fs.Bool("acknowledge-unverified-anchor", false, "explicitly accept that anchor claims cannot be checked against retained history")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" {
		return errors.New("--manifest is required")
	}
	raw, err := os.ReadFile(*manifestPath) //nolint:gosec // explicit operator path
	if err != nil {
		return err
	}
	canonical, err := sageabci.CanonicalizeLegacyLineageRepair(raw)
	if err != nil {
		return err
	}
	var manifest sageabci.LegacyLineageRepairManifest
	if err := json.Unmarshal([]byte(canonical), &manifest); err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(canonical))
	out := lineageVerifyOutput{ManifestDigest: hex.EncodeToString(digest[:]), Claims: manifest.Evidence}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	status, statusErr := readUpgradeLineageStatus(ctx, *rpc)
	chainID, chainErr := readCometChainID(ctx, *rpc)
	if statusErr != nil {
		out.Diagnostics = append(out.Diagnostics, "read local lineage status: "+statusErr.Error())
	}
	if chainErr != nil {
		out.Diagnostics = append(out.Diagnostics, "read local chain ID: "+chainErr.Error())
	}
	if statusErr == nil && chainErr == nil {
		if manifest.Schema != status.Schema || manifest.ChainID != chainID ||
			manifest.GovernanceDomain != status.GovernanceDomain || manifest.CurrentAppVersion != 21 ||
			status.CurrentAppVersion != 21 || manifest.PriorLineageDigest != status.ValidLineageDigest {
			out.Diagnostics = append(out.Diagnostics, "manifest chain, app version, governance domain, or prior-lineage digest does not match this validator")
		} else {
			missing := make(map[uint64]bool)
			for _, rung := range status.Rungs {
				if rung.Present && !rung.Valid {
					out.Diagnostics = append(out.Diagnostics, rung.Name+" is present but invalid; create-only repair is forbidden")
				}
				if !rung.Present {
					missing[rung.Version] = true
				}
			}
			if len(manifest.Evidence) != len(missing) {
				out.Diagnostics = append(out.Diagnostics, "manifest evidence does not equal the exact current missing-rung set")
			} else if len(manifest.Evidence) == 0 {
				out.Diagnostics = append(out.Diagnostics, "manifest contains no missing-rung claims")
			} else {
				source := manifest.Evidence[0].Source
				out.EvidenceSource = source
				claimsOK := true
				seen := make(map[uint64]bool, len(manifest.Evidence))
				for _, claim := range manifest.Evidence {
					if !missing[claim.Version] || claim.Name != tx.CanonicalUpgradeName(claim.Version) ||
						claim.AppliedHeight <= 0 || claim.AppliedHeight > status.PersistedHeight || claim.Source != source || seen[claim.Version] {
						claimsOK = false
						break
					}
					seen[claim.Version] = true
				}
				if !claimsOK {
					out.Diagnostics = append(out.Diagnostics, "manifest contains mixed, future-height, duplicate, or non-missing claims")
				} else if source == "comet-block-results" {
					out.HistoryVerified = true
					for _, claim := range manifest.Evidence {
						version, versionErr := readBlockResultAppVersion(ctx, *rpc, claim.AppliedHeight)
						hash, hashErr := readBlockHash(ctx, *rpc, claim.AppliedHeight)
						if versionErr != nil || hashErr != nil || version != claim.Version || hash != claim.BlockHash {
							out.HistoryVerified = false
							out.Diagnostics = append(out.Diagnostics, fmt.Sprintf("app-v%d claim does not match this validator's retained block_results and block hash at height %d", claim.Version, claim.AppliedHeight))
						}
					}
					out.Valid = out.HistoryVerified
					out.EligibleForVote = out.Valid
				} else if source == "legacy-anchor" {
					anchorBytes, anchorErr := hex.DecodeString(manifest.AnchorDigest)
					canonicalAnchor := anchorErr == nil && len(anchorBytes) == sha256.Size && hex.EncodeToString(anchorBytes) == manifest.AnchorDigest
					if !canonicalAnchor {
						out.Diagnostics = append(out.Diagnostics, "legacy-anchor manifest has no canonical anchor_digest")
					} else if manifest.AnchorAttestation != "operator-quorum-attested-unverified-history" || !*ackAnchor {
						out.Diagnostics = append(out.Diagnostics, "legacy-anchor claims are unverified history and require --acknowledge-unverified-anchor before an operator vote")
					} else {
						out.Valid, out.EligibleForVote = true, true
						out.Diagnostics = append(out.Diagnostics, "anchor heights are operator claims, not locally history-verified facts; the explicit vote attests these exact claims")
					}
				} else {
					out.Diagnostics = append(out.Diagnostics, "unsupported or mixed evidence source")
				}
			}
		}
	}
	if *jsonOut {
		if err := writeJSONStdout(out); err != nil {
			return err
		}
	} else {
		for _, diagnostic := range out.Diagnostics {
			fmt.Println(diagnostic)
		}
	}
	if !out.EligibleForVote {
		return errors.New("lineage manifest is not eligible for this validator's manual vote")
	}
	return nil
}

func runUpgradeLineageStatus(args []string) error {
	fs := flag.NewFlagSet("upgrade lineage status", flag.ContinueOnError)
	rpc := fs.String("rpc", defaultCometRPC(), "CometBFT RPC endpoint")
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, err := readUpgradeLineageStatus(ctx, *rpc)
	if err != nil {
		return err
	}
	if *jsonOut {
		return writeJSONStdout(status)
	}
	fmt.Printf("Upgrade lineage: app-v%d at height %d\n", status.CurrentAppVersion, status.PersistedHeight)
	for _, rung := range status.Rungs {
		state := "missing"
		if rung.Valid {
			state = fmt.Sprintf("height %d", rung.AppliedHeight)
		} else if rung.Present {
			state = "INVALID: " + rung.Problem
		}
		fmt.Printf("  app-v%-2d %s\n", rung.Version, state)
	}
	return nil
}

func runUpgradeLineageDoctor(args []string) error {
	fs := flag.NewFlagSet("upgrade lineage doctor", flag.ContinueOnError)
	rpc := fs.String("rpc", defaultCometRPC(), "CometBFT RPC endpoint")
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON")
	manifestOut := fs.String("manifest-out", "", "write only the canonical repair manifest to this file")
	legacyAnchor := fs.String("legacy-anchor", "", "audited JSON fallback containing {\"heights\":{\"7\":123,...}}")
	ackAnchor := fs.Bool("acknowledge-unverified-anchor", false, "explicitly attest that legacy-anchor heights are not locally history-verified and require quorum review")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	status, err := readUpgradeLineageStatus(ctx, *rpc)
	if err != nil {
		return err
	}
	out := lineageDoctorOutput{Status: *status}
	missing := make(map[uint64]struct{})
	invalidPresent := false
	for _, rung := range status.Rungs {
		if rung.Present && !rung.Valid {
			invalidPresent = true
			out.Diagnostics = append(out.Diagnostics, fmt.Sprintf("%s exists but is invalid; repair is forbidden from overwriting it", rung.Name))
		}
		if !rung.Present && rung.Version <= status.CurrentAppVersion {
			missing[rung.Version] = struct{}{}
		}
	}
	if invalidPresent {
		out.Diagnostics = append(out.Diagnostics, "lineage is not repairable while any persisted rung is present but invalid")
		return emitLineageDoctor(out, *jsonOut, "")
	}
	if len(missing) == 0 {
		out.Repairable = true
		out.Diagnostics = append(out.Diagnostics, "no missing activated lineage records")
		return emitLineageDoctor(out, *jsonOut, "")
	}
	if status.CurrentAppVersion != 21 {
		out.Diagnostics = append(out.Diagnostics, "repair manifests are admitted only while the chain is exactly app-v21")
		return emitLineageDoctor(out, *jsonOut, "")
	}
	chainID, err := readCometChainID(ctx, *rpc)
	if err != nil {
		return err
	}
	evidence, diagnostics := discoverCometLineageEvidence(ctx, *rpc, status.PersistedHeight, missing)
	out.Diagnostics = append(out.Diagnostics, diagnostics...)
	if len(evidence) > 0 {
		out.Diagnostics = append(out.Diagnostics,
			"comet-block-results entries and block hashes are evidence from this validator's retained local archive; consensus does not independently verify those hashes")
	}

	anchorDigest := ""
	if len(evidence) < len(missing) && *legacyAnchor != "" {
		if !*ackAnchor {
			out.Diagnostics = append(out.Diagnostics, "legacy-anchor fallback requires --acknowledge-unverified-anchor because its heights cannot be verified from retained local history")
			return emitLineageDoctor(out, *jsonOut, "")
		}
		raw, readErr := os.ReadFile(*legacyAnchor) //nolint:gosec // explicit operator audit file
		if readErr != nil {
			return readErr
		}
		var anchor struct {
			Heights map[string]int64 `json:"heights"`
		}
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.DisallowUnknownFields()
		if decodeErr := decoder.Decode(&anchor); decodeErr != nil {
			return fmt.Errorf("decode legacy anchor: %w", decodeErr)
		}
		canonical, _ := json.Marshal(anchor)
		digest := sha256.Sum256(canonical)
		anchorDigest = hex.EncodeToString(digest[:])
		// Never blend two trust models in one manifest. When retained Comet
		// history is incomplete, the explicit legacy anchor must attest every
		// missing rung and replaces the partial local-history set wholesale.
		evidence = evidence[:0]
		for version := range missing {
			height := anchor.Heights[strconv.FormatUint(version, 10)]
			if height > 0 {
				evidence = append(evidence, sageabci.LegacyLineageEvidence{Version: version, Name: tx.CanonicalUpgradeName(version), AppliedHeight: height, Source: "legacy-anchor"})
			}
		}
	}
	if len(evidence) != len(missing) {
		out.Diagnostics = append(out.Diagnostics, "retained Comet evidence is incomplete; provide --legacy-anchor only after an independent audit")
		return emitLineageDoctor(out, *jsonOut, "")
	}
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].Version < evidence[j].Version })
	if evidenceErr := validateDoctorLineageEvidence(status, evidence); evidenceErr != nil {
		out.Diagnostics = append(out.Diagnostics, evidenceErr.Error())
		return emitLineageDoctor(out, *jsonOut, "")
	}
	manifest := sageabci.LegacyLineageRepairManifest{Schema: status.Schema, ChainID: chainID, GovernanceDomain: status.GovernanceDomain, CurrentAppVersion: 21, PriorLineageDigest: status.ValidLineageDigest, AnchorDigest: anchorDigest, Evidence: evidence}
	if anchorDigest != "" {
		manifest.AnchorAttestation = "operator-quorum-attested-unverified-history"
		out.Diagnostics = append(out.Diagnostics, "legacy-anchor claims are quorum-attested operator assertions and are not verified by retained local history")
	}
	manifestBytes, _ := json.Marshal(manifest)
	canonical, err := sageabci.CanonicalizeLegacyLineageRepair(manifestBytes)
	if err != nil {
		return err
	}
	out.Repairable = true
	out.ManualVoteRequired = true
	out.Manifest = json.RawMessage(canonical)
	manifestDigest := sha256.Sum256([]byte(canonical))
	out.ManifestDigest = hex.EncodeToString(manifestDigest[:])
	out.ReviewSteps = []string{
		"create the candidate manifest with upgrade lineage doctor on the proposing validator",
		"run upgrade lineage verify with that exact manifest independently on every validator and compare manifest_digest before proposing",
		"after proposing, inspect the active proposal with sage_gov_status and cast an explicit sage_gov_vote on every validator; automatic voting is disabled, including on one-validator chains",
	}
	if *manifestOut != "" {
		if err := os.WriteFile(*manifestOut, append([]byte(canonical), '\n'), 0o600); err != nil {
			return fmt.Errorf("write manifest: %w", err)
		}
	}
	return emitLineageDoctor(out, *jsonOut, canonical)
}

func validateDoctorLineageEvidence(status *upgradeLineageRPCStatus, evidence []sageabci.LegacyLineageEvidence) error {
	proposed := make(map[uint64]int64, len(evidence))
	for _, claim := range evidence {
		if _, duplicate := proposed[claim.Version]; duplicate {
			return fmt.Errorf("duplicate app-v%d repair claim", claim.Version)
		}
		proposed[claim.Version] = claim.AppliedHeight
	}
	var previous int64
	for _, rung := range status.Rungs {
		height := rung.AppliedHeight
		if !rung.Present {
			height = proposed[rung.Version]
		}
		if height <= previous || height > status.PersistedHeight {
			return fmt.Errorf("app-v%d claimed height %d is not a retained, strictly ordered committed height", rung.Version, height)
		}
		previous = height
	}
	return nil
}

func emitLineageDoctor(out lineageDoctorOutput, jsonOut bool, canonical string) error {
	if jsonOut {
		return writeJSONStdout(out)
	}
	for _, line := range out.Diagnostics {
		fmt.Println(line)
	}
	if canonical != "" {
		fmt.Printf("Repair manifest digest: %s\n", out.ManifestDigest)
		fmt.Println("Repair manifest is ready; propose it explicitly with --lineage-repair.")
		fmt.Println("Automatic voting is disabled. Every validator must independently review and explicitly vote.")
	}
	return nil
}

func writeJSONStdout(value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err == nil {
		fmt.Println(string(encoded))
	}
	return err
}

func readUpgradeLineageStatus(ctx context.Context, rpc string) (*upgradeLineageRPCStatus, error) {
	raw, err := readABCIQueryValue(ctx, rpc, "/upgrade/lineage")
	if err != nil {
		return nil, err
	}
	var status upgradeLineageRPCStatus
	if err := json.Unmarshal(raw, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

func readABCIQueryValue(ctx context.Context, rpc, path string) ([]byte, error) {
	queryURL := strings.TrimRight(rpc, "/") + "/abci_query?path=" + url.QueryEscape(strconv.Quote(path))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Result struct {
			Response struct {
				Code  uint32 `json:"code"`
				Log   string `json:"log"`
				Value string `json:"value"`
			} `json:"response"`
		} `json:"result"`
		Error any `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Error != nil || out.Result.Response.Code != 0 {
		return nil, fmt.Errorf("ABCI lineage query rejected: %s", out.Result.Response.Log)
	}
	return base64.StdEncoding.DecodeString(out.Result.Response.Value)
}

func discoverCometLineageEvidence(ctx context.Context, rpc string, maxHeight int64, missing map[uint64]struct{}) ([]sageabci.LegacyLineageEvidence, []string) {
	found := make(map[uint64]sageabci.LegacyLineageEvidence)
	diagnostics := []string{}
	for height := int64(1); height <= maxHeight && len(found) < len(missing); height++ {
		version, err := readBlockResultAppVersion(ctx, rpc, height)
		if err != nil {
			diagnostics = append(diagnostics, fmt.Sprintf("retained block-results unavailable at height %d: %v", height, err))
			break
		}
		if _, wanted := missing[version]; !wanted {
			continue
		}
		hash, err := readBlockHash(ctx, rpc, height)
		if err != nil {
			diagnostics = append(diagnostics, fmt.Sprintf("block hash unavailable at height %d: %v", height, err))
			continue
		}
		found[version] = sageabci.LegacyLineageEvidence{Version: version, Name: tx.CanonicalUpgradeName(version), AppliedHeight: height, Source: "comet-block-results", BlockHash: strings.ToLower(hash)}
	}
	result := make([]sageabci.LegacyLineageEvidence, 0, len(found))
	for _, evidence := range found {
		result = append(result, evidence)
	}
	return result, diagnostics
}

func readBlockResultAppVersion(ctx context.Context, rpc string, height int64) (uint64, error) {
	u := fmt.Sprintf("%s/block_results?height=%d", strings.TrimRight(rpc, "/"), height)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	var out struct {
		Result struct {
			Updates struct {
				Version struct {
					App string `json:"app"`
				} `json:"version"`
			} `json:"consensus_param_updates"`
		} `json:"result"`
		Error any `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, err
	}
	if out.Error != nil {
		return 0, errors.New("RPC error")
	}
	if out.Result.Updates.Version.App == "" {
		return 0, nil
	}
	return strconv.ParseUint(out.Result.Updates.Version.App, 10, 64)
}

func readBlockHash(ctx context.Context, rpc string, height int64) (string, error) {
	u := fmt.Sprintf("%s/block?height=%d", strings.TrimRight(rpc, "/"), height)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		Result struct {
			BlockID struct {
				Hash string `json:"hash"`
			} `json:"block_id"`
		} `json:"result"`
	}
	if decodeErr := json.NewDecoder(resp.Body).Decode(&out); decodeErr != nil {
		return "", decodeErr
	}
	decoded, err := hex.DecodeString(strings.ToLower(out.Result.BlockID.Hash))
	if err != nil || len(decoded) != sha256.Size {
		return "", errors.New("invalid block hash")
	}
	return strings.ToLower(out.Result.BlockID.Hash), nil
}
