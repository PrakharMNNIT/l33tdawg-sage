package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type durableClaimantIdentity struct {
	Version           int    `json:"version"`
	AgentID           string `json:"agent_id"`
	Provider          string `json:"provider"`
	Project           string `json:"project"`
	ClaimantSessionID string `json:"claimant_session_id"`
}

// acquireDurableClaimantIdentity gives the primary stdio runtime for one
// (agent, provider, project) tuple a claimant identity that survives ordinary
// process restarts. The OS lock is the liveness fence: a concurrent runtime
// cannot reuse the durable identity and must keep its independently generated
// session ID, preserving one-handler and CAS-handoff semantics.
func acquireDurableClaimantIdentity(agentID, provider, project string) (string, io.Closer, error) {
	home := strings.TrimSpace(os.Getenv("SAGE_HOME"))
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return "", nil, fmt.Errorf("resolve SAGE home for claimant identity: %w", err)
		}
		home = filepath.Join(userHome, ".sage")
	}
	scope := sha256.Sum256([]byte(agentID + "\x00" + provider + "\x00" + project))
	dir := filepath.Join(home, "runtime", "mcp-claimants")
	if err := os.MkdirAll(dir, 0700); err != nil { //nolint:gosec // operator-selected SAGE_HOME, scope leaf is a local hash
		return "", nil, fmt.Errorf("create claimant identity directory: %w", err)
	}
	base := hex.EncodeToString(scope[:])
	lease, acquired, err := tryLockClaimantFile(filepath.Join(dir, base+".lock"))
	if err != nil {
		return "", nil, err
	}
	if !acquired {
		return "", nil, fmt.Errorf("durable claimant identity is owned by a live concurrent runtime")
	}

	identityPath := filepath.Join(dir, base+".json")
	if raw, readErr := os.ReadFile(identityPath); readErr == nil { //nolint:gosec // private path under SAGE_HOME
		var saved durableClaimantIdentity
		if json.Unmarshal(raw, &saved) == nil && saved.Version == 1 && saved.AgentID == agentID &&
			saved.Provider == provider && saved.Project == project && validMCPClaimantSessionID(saved.ClaimantSessionID) {
			return saved.ClaimantSessionID, lease, nil
		}
	}

	id := newMCPClaimantSessionID()
	if id == "" {
		_ = lease.Close()
		return "", nil, fmt.Errorf("generate durable claimant identity")
	}
	record := durableClaimantIdentity{
		Version: 1, AgentID: agentID, Provider: provider, Project: project, ClaimantSessionID: id,
	}
	raw, err := json.Marshal(record)
	if err != nil {
		_ = lease.Close()
		return "", nil, err
	}
	tmp, err := os.CreateTemp(dir, base+".tmp-") //nolint:gosec // private path under SAGE_HOME
	if err != nil {
		_ = lease.Close()
		return "", nil, fmt.Errorf("create claimant identity temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() //nolint:gosec // path returned by os.CreateTemp in the private claimant directory
	if chmodErr := tmp.Chmod(0600); chmodErr != nil {
		_ = tmp.Close()
		_ = lease.Close()
		return "", nil, chmodErr
	}
	if _, writeErr := tmp.Write(raw); writeErr != nil {
		_ = tmp.Close()
		_ = lease.Close()
		return "", nil, writeErr
	}
	if syncErr := tmp.Sync(); syncErr != nil {
		_ = tmp.Close()
		_ = lease.Close()
		return "", nil, syncErr
	}
	if closeErr := tmp.Close(); closeErr != nil {
		_ = lease.Close()
		return "", nil, closeErr
	}
	if renameErr := os.Rename(tmpPath, identityPath); renameErr != nil { //nolint:gosec // both paths are fixed children of the private claimant directory
		_ = lease.Close()
		return "", nil, fmt.Errorf("persist claimant identity: %w", renameErr)
	}
	return id, lease, nil
}

func validMCPClaimantSessionID(id string) bool {
	if len(id) != len("mcp-")+32 || !strings.HasPrefix(id, "mcp-") {
		return false
	}
	_, err := hex.DecodeString(id[len("mcp-"):])
	return err == nil
}
