package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ConsensusForkVersion is the chain's consensus fork tag. Bumped ONLY when
// a SAGE release introduces a consensus-breaking change that makes existing
// chain state (BadgerDB on-chain registry, CometBFT blocks) invalid under
// the new binary — e.g. tx encoding/decoding shape change, BadgerDB key
// prefix or value encoding change, ABCI semantics change, validator/quorum
// rule change, genesis incompatibility.
//
// INDEPENDENT of release semver. Patch and minor releases that don't break
// consensus do not bump it, so operators keep chain state across upgrades:
// domain registry, access grants, org memberships, validator set, agent
// identities. A mismatch is a refusal gate: it requires a deterministic
// history-preserving migration or governed upgrade and never authorizes an
// automatic reset.
//
// History:
//
//	1 — Gate introduced in v7.5.5. All prior v7.5.x deployments are treated
//	    as fork=1 on first boot under this gate so the upgrade that adds the
//	    gate itself does not produce a spurious reset.
//
// Declared as a var (not const) so tests can stage fork transitions without
// rebuilding. Mirrors the existing `version` symbol's pattern.
var ConsensusForkVersion = 1

const forkVersionFile = "fork-version.txt"

// inspectForkVersion distinguishes a genuinely absent legacy marker from a
// malformed or unreadable marker. Only absence is eligible for guarded legacy
// adoption; unknown/corrupt lineage must fail closed.
func inspectForkVersion(path string) (fork int, present bool, err error) {
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return 0, false, nil
		}
		return 0, true, readErr
	}
	raw := strings.TrimSpace(string(data))
	n, parseErr := strconv.Atoi(raw)
	if parseErr != nil || n <= 0 {
		if parseErr == nil {
			parseErr = fmt.Errorf("fork version must be positive")
		}
		return 0, true, fmt.Errorf("invalid fork-version marker %q: %w", raw, parseErr)
	}
	return n, true, nil
}

// readForkVersion is the diagnostics/test convenience wrapper. Migration code
// must use inspectForkVersion so malformed state is never confused with absence.
func readForkVersion(path string) int {
	n, _, _ := inspectForkVersion(path)
	return n
}

// stampForkVersion writes the given fork tag to path after a compatible
// in-place adoption. A refused/incomplete migration must leave the old stamp.
func stampForkVersion(path string, fork int) error {
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", fork)), 0600)
}

// isLegacyForkOneVersion reports whether lastVersion was produced by a
// pre-gate binary whose chain state is already fork=1 compatible. The gate
// shipped in v7.5.5; v7.5.0..v7.5.4 binaries produced the same encoding,
// so adopting fork=1 without a reset is safe for them. Anything older
// (v6.x, v7.0..v7.4) used a different fork lineage and must be refused
// until a history-preserving migration exists.
//
// Accepts both "v7.5.0" and bare "7.5.0" forms and tolerates post-tag
// suffixes ("v7.5.4-1-gabc"). Empty input returns false (caller handles
// fresh-install separately).
func isLegacyForkOneVersion(lastVersion string) bool {
	v := strings.TrimPrefix(lastVersion, "v")
	return strings.HasPrefix(v, "7.5.")
}
