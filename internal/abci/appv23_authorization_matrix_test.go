package abci

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"testing"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/authzdenial"
	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

type appV23MatrixOwnership string

const (
	appV23MatrixOwn       appV23MatrixOwnership = "own"
	appV23MatrixForeign   appV23MatrixOwnership = "foreign"
	appV23MatrixUnowned   appV23MatrixOwnership = "unowned"
	appV23MatrixShared    appV23MatrixOwnership = "shared"
	appV23MatrixRawHeight                       = int64(100)
)

type appV23MatrixOperation struct {
	name string
	verb store.AppV23DomainVerb
}

var appV23MatrixOperations = []appV23MatrixOperation{
	// Corroborate is intentionally the concrete Read transaction: consensus
	// maps it to AppV23VerbRead before it mutates the corroboration marker.
	{name: "read-corroborate", verb: store.AppV23VerbRead},
	{name: "write-submit", verb: store.AppV23VerbWrite},
	{name: "modify-challenge", verb: store.AppV23VerbModify},
}

type appV23MatrixPolicy struct {
	key       agentKey
	role      string
	profile   string
	clearance uint8
	caps      store.AgentCapabilities
	ownDomain string
}

type appV23MatrixFixture struct {
	app              *SageApp
	root             agentKey
	groupOwner       agentKey
	outsider         agentKey
	groupOwnerDomain string
	outsiderDomain   string
	policies         []appV23MatrixPolicy
}

func appV23MatrixCapabilities(role, profile string) store.AgentCapabilities {
	switch profile {
	case store.AppV23ProfileCompanion:
		return store.AgentCapabilities(15)
	case store.AppV23ProfileReadOnly:
		return store.AgentCapabilityReadAllDomains
	case store.AppV23ProfileStandard:
		if role == store.AppV23RoleAdmin {
			return store.AgentCapabilityReadAllDomains
		}
		return 0
	default:
		return 0
	}
}

func appV23MatrixPolicyIsCanonical(role, profile string, clearance uint8) bool {
	switch profile {
	case store.AppV23ProfileStandard:
		return role == store.AppV23RoleMember ||
			role == store.AppV23RoleManager ||
			(role == store.AppV23RoleAdmin && clearance == 4)
	case store.AppV23ProfileCompanion, store.AppV23ProfileReadOnly:
		return role == store.AppV23RoleMember
	default:
		return false
	}
}

func appV23NewMatrixFixture(t *testing.T) appV23MatrixFixture {
	t.Helper()

	app := setupTestApp(t)
	root := newAgentKey(t)
	groupOwner := newAgentKey(t)
	outsider := newAgentKey(t)
	registerAppV23Agent(t, app, root, store.AppV23RoleAdmin, 1, 0)
	registerAppV23Agent(t, app, groupOwner, store.AppV23RoleMember, 2, 0)
	registerAppV23Agent(t, app, outsider, store.AppV23RoleMember, 3, 0)

	roles := []string{
		store.AppV23RoleMember,
		store.AppV23RoleManager,
		store.AppV23RoleAdmin,
	}
	profiles := []string{
		store.AppV23ProfileStandard,
		store.AppV23ProfileCompanion,
		store.AppV23ProfileReadOnly,
	}
	policies := make([]appV23MatrixPolicy, 0, 21)
	height := int64(4)
	for _, role := range roles {
		for _, profile := range profiles {
			for clearance := uint8(0); clearance <= 4; clearance++ {
				if !appV23MatrixPolicyIsCanonical(role, profile, clearance) {
					continue
				}
				key := newAgentKey(t)
				registerAppV23Agent(t, app, key, store.AppV23RoleMember, height, 0)
				height++
				policies = append(policies, appV23MatrixPolicy{
					key: key, role: role, profile: profile, clearance: clearance,
					caps: appV23MatrixCapabilities(role, profile),
				})
			}
		}
	}
	require.Len(t, policies, 21)
	require.NoError(t, app.badgerStore.EnsureAppV23Root("authorization-matrix-scope", 30))

	groupOwnerEnrollment, err := app.badgerStore.GetAppV23Enrollment(groupOwner.id)
	require.NoError(t, err)
	outsiderEnrollment, err := app.badgerStore.GetAppV23Enrollment(outsider.id)
	require.NoError(t, err)
	require.NotEmpty(t, groupOwnerEnrollment.HomeDomain)
	require.NotEmpty(t, outsiderEnrollment.HomeDomain)

	groupMembers := make([]string, 0, len(policies)+1)
	groupMembers = append(groupMembers, groupOwner.id)
	for i := range policies {
		enrollment, enrollmentErr := app.badgerStore.GetAppV23Enrollment(policies[i].key.id)
		require.NoError(t, enrollmentErr)
		roleState, roleErr := app.badgerStore.GetAppV23Role(policies[i].key.id)
		require.NoError(t, roleErr)
		require.NotEmpty(t, enrollment.HomeDomain)
		policies[i].ownDomain = enrollment.HomeDomain
		require.NoError(t, app.badgerStore.SetAppV23Policy(
			root.id,
			policies[i].key.id,
			policies[i].role,
			enrollment.Profile,
			policies[i].profile,
			policies[i].clearance,
			policies[i].caps,
			roleState.Revision,
			enrollment.Revision,
			31+int64(i),
		))
		groupMembers = append(groupMembers, policies[i].key.id)
	}
	sort.Strings(groupMembers)
	require.NoError(t, app.badgerStore.MutateAppV23AccessGroup(
		root.id,
		"authorization-matrix-group",
		"Authorization matrix group",
		groupMembers,
		0,
		false,
		60,
	))
	require.NoError(t, app.badgerStore.ValidateAppV23State())
	// App-v23 requires the canonical predecessor ladder. Corroborate's
	// concrete Read gate and weighted Challenge state machine are activated
	// by app-v21 itself rather than by a skip-ahead subsumption helper.
	app.appV21AppliedHeight = 9
	app.appV23AppliedHeight = 10

	return appV23MatrixFixture{
		app:              app,
		root:             root,
		groupOwner:       groupOwner,
		outsider:         outsider,
		groupOwnerDomain: groupOwnerEnrollment.HomeDomain,
		outsiderDomain:   outsiderEnrollment.HomeDomain,
		policies:         policies,
	}
}

func appV23MatrixExpectedDomain(
	policy appV23MatrixPolicy,
	ownership appV23MatrixOwnership,
	grouped bool,
	verb store.AppV23DomainVerb,
) (bool, authzdenial.Code) {
	if policy.profile == store.AppV23ProfileReadOnly {
		if verb == store.AppV23VerbRead {
			return true, ""
		}
		return false, authzdenial.CodeForeignWriteRestricted
	}
	if policy.profile == store.AppV23ProfileCompanion {
		if verb == store.AppV23VerbRead {
			return true, ""
		}
		switch ownership {
		case appV23MatrixOwn:
			return true, ""
		case appV23MatrixForeign:
			return false, authzdenial.CodeForeignWriteRestricted
		case appV23MatrixUnowned:
			return false, authzdenial.CodeDomainClaimRestricted
		case appV23MatrixShared:
			return false, authzdenial.CodeSharedWriteRestricted
		}
	}
	if policy.role == store.AppV23RoleAdmin {
		return true, ""
	}
	switch ownership {
	case appV23MatrixOwn:
		return true, ""
	case appV23MatrixForeign:
		if grouped {
			if policy.role == store.AppV23RoleManager ||
				verb == store.AppV23VerbRead {
				return true, ""
			}
		}
		if verb == store.AppV23VerbRead {
			return false, ""
		}
		if policy.role == store.AppV23RoleManager {
			return false, authzdenial.CodeManagerScopeDenied
		}
		return false, authzdenial.CodeMissingWriteGrant
	case appV23MatrixUnowned:
		if verb == store.AppV23VerbRead {
			return false, ""
		}
		if verb == store.AppV23VerbWrite &&
			policy.profile == store.AppV23ProfileStandard &&
			(policy.role == store.AppV23RoleMember ||
				policy.role == store.AppV23RoleManager) {
			return true, ""
		}
		if policy.role == store.AppV23RoleManager {
			return false, authzdenial.CodeManagerScopeDenied
		}
		return false, authzdenial.CodeDomainClaimRestricted
	case appV23MatrixShared:
		// Access Groups never own shared domains. The grouped dimension must
		// therefore have no effect in either the unit or raw boundary.
		if verb == store.AppV23VerbRead {
			return false, ""
		}
		if policy.role == store.AppV23RoleManager {
			return false, authzdenial.CodeManagerScopeDenied
		}
		return false, authzdenial.CodeMissingWriteGrant
	}
	return false, ""
}

func appV23MatrixDomain(
	fixture appV23MatrixFixture,
	policy appV23MatrixPolicy,
	ownership appV23MatrixOwnership,
	grouped bool,
	caseID string,
) string {
	switch ownership {
	case appV23MatrixOwn:
		return policy.ownDomain
	case appV23MatrixForeign:
		if grouped {
			return fixture.groupOwnerDomain
		}
		return fixture.outsiderDomain
	case appV23MatrixUnowned:
		return "matrix-unowned-" + caseID
	case appV23MatrixShared:
		return "general"
	default:
		panic("unknown matrix ownership")
	}
}

func appV23MatrixSeedMemory(
	t *testing.T,
	fixture appV23MatrixFixture,
	memoryID, domain string,
	classification uint8,
	status memory.MemoryStatus,
) {
	t.Helper()
	hash := sha256.Sum256([]byte(memoryID))
	require.NoError(t, fixture.app.badgerStore.SetMemoryHash(memoryID, hash[:], string(status)))
	require.NoError(t, fixture.app.badgerStore.SetMemoryDomain(memoryID, domain))
	require.NoError(t, fixture.app.badgerStore.SetMemoryClassification(memoryID, classification))
	require.NoError(t, fixture.app.badgerStore.SetMemoryAuthor(memoryID, fixture.root.id))
	require.NoError(t, fixture.app.badgerStore.SetMemoryAuthorPrincipal(memoryID, fixture.root.id))
}

func appV23MatrixProcessRaw(
	t *testing.T,
	app *SageApp,
	parsed *tx.ParsedTx,
	signer agentKey,
	nonce uint64,
	height int64,
) *abcitypes.ExecTxResult {
	t.Helper()
	signAppV23Outer(t, parsed, signer, nonce)
	raw, err := tx.EncodeTx(parsed)
	require.NoError(t, err)
	decoded, err := tx.DecodeTx(raw)
	require.NoError(t, err)
	require.Equal(t, raw, mustEncodeAppV23MatrixTx(t, decoded))
	return app.processTx(decoded, height, appV23BlockTime())
}

func mustEncodeAppV23MatrixTx(t *testing.T, parsed *tx.ParsedTx) []byte {
	t.Helper()
	raw, err := tx.EncodeTx(parsed)
	require.NoError(t, err)
	return raw
}

func appV23MatrixRawTransaction(
	t *testing.T,
	policy appV23MatrixPolicy,
	operation appV23MatrixOperation,
	memoryID, domain string,
	classification uint8,
) *tx.ParsedTx {
	t.Helper()
	switch operation.verb {
	case store.AppV23VerbRead:
		return makeMemoryCorroborateTx(t, policy.key, memoryID, "authorization matrix read")
	case store.AppV23VerbWrite:
		parsed := makeMemorySubmitTx(t, policy.key, domain, "authorization matrix "+memoryID)
		parsed.MemorySubmit.MemoryID = memoryID
		parsed.MemorySubmit.Classification = tx.ClearanceLevel(classification)
		return parsed
	case store.AppV23VerbModify:
		return makeMemoryChallengeTx(t, policy.key, memoryID, "authorization matrix modify")
	default:
		panic("unsupported matrix operation")
	}
}

func appV23RequireMatrixRawResult(
	t *testing.T,
	result *abcitypes.ExecTxResult,
	allowed, withinClearance bool,
	verb store.AppV23DomainVerb,
	code authzdenial.Code,
) {
	t.Helper()
	if allowed && withinClearance {
		require.Zero(t, result.Code, result.Log)
		return
	}
	if !withinClearance || verb == store.AppV23VerbRead || code == "" {
		require.Equal(t, appV23ControlDenied(), result)
		return
	}
	require.Equal(t, appV23Denial(code), result)
}

// TestAppV23AuthorizationDecisionAndSignedRawMatrix is the mandatory app-v23
// data-plane cross product. Each case is checked twice:
//   - directly at the deterministic consensus policy/clearance boundary; and
//   - through a same-key signed transaction, canonical EncodeTx/DecodeTx, and
//     processTx dispatch.
//
// The matrix contains 21 canonical role/profile/clearance policies × four
// ownership classes × two group relationships × five record classifications ×
// three concrete verbs = 2,520 unit decisions and 2,520 raw transactions.
func TestAppV23AuthorizationDecisionAndSignedRawMatrix(t *testing.T) {
	fixture := appV23NewMatrixFixture(t)
	ownerships := []appV23MatrixOwnership{
		appV23MatrixOwn,
		appV23MatrixForeign,
		appV23MatrixUnowned,
		appV23MatrixShared,
	}
	caseCount := 0
	for _, policy := range fixture.policies {
		for _, ownership := range ownerships {
			for _, grouped := range []bool{false, true} {
				for classification := uint8(0); classification <= 4; classification++ {
					for _, operation := range appV23MatrixOperations {
						caseCount++
						caseID := fmt.Sprintf("%04d", caseCount)
						name := fmt.Sprintf(
							"%s/%s/c%d/%s/group-%t/class-%d/%s",
							policy.role,
							policy.profile,
							policy.clearance,
							ownership,
							grouped,
							classification,
							operation.name,
						)
						t.Run(name, func(t *testing.T) {
							domain := appV23MatrixDomain(
								fixture, policy, ownership, grouped, caseID,
							)
							memoryID := "matrix-memory-" + caseID
							switch operation.verb {
							case store.AppV23VerbRead:
								appV23MatrixSeedMemory(
									t, fixture, memoryID, domain, classification, memory.StatusProposed,
								)
							case store.AppV23VerbModify:
								appV23MatrixSeedMemory(
									t, fixture, memoryID, domain, classification, memory.StatusCommitted,
								)
							}

							wantAllowed, wantCode := appV23MatrixExpectedDomain(
								policy, ownership, grouped, operation.verb,
							)
							allowed, code, err := fixture.app.appV23DomainDecision(
								&tx.ParsedTx{},
								policy.key.id,
								domain,
								operation.verb,
								appV23MatrixRawHeight,
								appV23BlockTime(),
							)
							require.NoError(t, err)
							require.Equal(t, wantAllowed, allowed)
							require.Equal(t, wantCode, code)

							withinClearance := classification <= policy.clearance
							if operation.verb != store.AppV23VerbWrite {
								actualWithinClearance, clearanceErr :=
									fixture.app.appV23MemoryWithinClearance(policy.key.id, memoryID)
								require.NoError(t, clearanceErr)
								require.Equal(t, withinClearance, actualWithinClearance)
							}

							parsed := appV23MatrixRawTransaction(
								t, policy, operation, memoryID, domain, classification,
							)
							if policy.role == store.AppV23RoleAdmin {
								attachAppV23Elevation(
									t,
									parsed,
									fixture.root,
									policy.key,
									"authorization-matrix-scope",
									"matrix-data-"+caseID,
									appV23MatrixRawHeight,
								)
							}
							result := appV23MatrixProcessRaw(
								t,
								fixture.app,
								parsed,
								policy.key,
								uint64(caseCount),
								appV23MatrixRawHeight,
							)
							appV23RequireMatrixRawResult(
								t,
								result,
								wantAllowed,
								withinClearance,
								operation.verb,
								wantCode,
							)
						})
					}
				}
			}
		}
	}
	require.Equal(t, 2520, caseCount)
}

// TestAppV23ExplicitClaimSignedRawMatrix complements the implicit first-write
// claim cases above with TxTypeDomainRegister. Claim has no record
// classification, so the relevant product is every canonical
// role/profile/clearance policy × both group labels. The group label is
// deliberately inert because an ownerless resource cannot be in a local
// owner's group.
func TestAppV23ExplicitClaimSignedRawMatrix(t *testing.T) {
	fixture := appV23NewMatrixFixture(t)
	caseCount := 0
	for _, policy := range fixture.policies {
		for _, grouped := range []bool{false, true} {
			caseCount++
			caseID := fmt.Sprintf("%03d", caseCount)
			name := fmt.Sprintf(
				"%s/%s/c%d/group-%t",
				policy.role, policy.profile, policy.clearance, grouped,
			)
			t.Run(name, func(t *testing.T) {
				domain := "matrix-explicit-claim-" + caseID
				wantAllowed, wantCode := appV23MatrixExpectedDomain(
					policy, appV23MatrixUnowned, grouped, store.AppV23VerbWrite,
				)
				allowed, code, err := fixture.app.appV23DomainDecision(
					&tx.ParsedTx{},
					policy.key.id,
					domain,
					store.AppV23VerbWrite,
					appV23MatrixRawHeight,
					appV23BlockTime(),
				)
				require.NoError(t, err)
				require.Equal(t, wantAllowed, allowed)
				require.Equal(t, wantCode, code)

				pub, sig, bodyHash, timestamp := signAgentProof(
					t, policy.key, []byte("explicit claim "+domain),
				)
				parsed := &tx.ParsedTx{
					Type: tx.TxTypeDomainRegister,
					DomainRegister: &tx.DomainRegister{
						DomainName: domain, OwnerAgentID: policy.key.id,
					},
					AgentPubKey: pub, AgentSig: sig,
					AgentBodyHash: bodyHash, AgentTimestamp: timestamp,
				}
				if policy.role == store.AppV23RoleAdmin {
					attachAppV23Elevation(
						t,
						parsed,
						fixture.root,
						policy.key,
						"authorization-matrix-scope",
						"matrix-claim-"+caseID,
						appV23MatrixRawHeight,
					)
				}
				result := appV23MatrixProcessRaw(
					t,
					fixture.app,
					parsed,
					policy.key,
					uint64(caseCount),
					appV23MatrixRawHeight,
				)
				appV23RequireMatrixRawResult(
					t,
					result,
					wantAllowed,
					true,
					store.AppV23VerbWrite,
					wantCode,
				)
			})
		}
	}
	require.Equal(t, 42, caseCount)
}

func appV23FindMatrixPolicy(
	t *testing.T,
	fixture appV23MatrixFixture,
	role, profile string,
	clearance uint8,
) appV23MatrixPolicy {
	t.Helper()
	for _, policy := range fixture.policies {
		if policy.role == role &&
			policy.profile == profile &&
			policy.clearance == clearance {
			return policy
		}
	}
	t.Fatalf("matrix policy %s/%s/c%d not found", role, profile, clearance)
	return appV23MatrixPolicy{}
}

// TestAppV23ExplicitGrantPrecedenceAtUnitAndSignedRawBoundaries prevents the
// exhaustive no-grant grid from becoming tautological. It pins the documented
// union/override ordering:
//   - compatible explicit grants extend Standard access outside local groups;
//   - an insufficient grant level cannot satisfy a stronger verb;
//   - Companion and Read-only hard mutation denies override every grant; and
//   - shared-domain grants remain independent of Access Group labels.
func TestAppV23ExplicitGrantPrecedenceAtUnitAndSignedRawBoundaries(t *testing.T) {
	fixture := appV23NewMatrixFixture(t)
	member := appV23FindMatrixPolicy(
		t, fixture, store.AppV23RoleMember, store.AppV23ProfileStandard, 4,
	)
	manager := appV23FindMatrixPolicy(
		t, fixture, store.AppV23RoleManager, store.AppV23ProfileStandard, 4,
	)
	companion := appV23FindMatrixPolicy(
		t, fixture, store.AppV23RoleMember, store.AppV23ProfileCompanion, 4,
	)
	readOnly := appV23FindMatrixPolicy(
		t, fixture, store.AppV23RoleMember, store.AppV23ProfileReadOnly, 4,
	)

	type grantCase struct {
		name      string
		policy    appV23MatrixPolicy
		domain    string
		level     uint8
		operation appV23MatrixOperation
		allowed   bool
		code      authzdenial.Code
	}
	read := appV23MatrixOperations[0]
	write := appV23MatrixOperations[1]
	modify := appV23MatrixOperations[2]
	initialCases := [...]grantCase{
		{
			name:   "standard member level-2 read outside group",
			policy: member, domain: fixture.outsiderDomain, level: 2,
			operation: read, allowed: true,
		},
		{
			name:   "standard member level-2 write outside group",
			policy: member, domain: fixture.outsiderDomain, level: 2,
			operation: write, allowed: true,
		},
		{
			name:   "standard member level-2 cannot modify outside group",
			policy: member, domain: fixture.outsiderDomain, level: 2,
			operation: modify, code: authzdenial.CodeMissingWriteGrant,
		},
		{
			name:   "standard manager level-3 modifies outside group",
			policy: manager, domain: fixture.outsiderDomain, level: 3,
			operation: modify, allowed: true,
		},
		{
			name:   "standard member shared grant remains outside group-label-false",
			policy: member, domain: "general", level: 2,
			operation: write, allowed: true,
		},
		{
			name:   "standard member shared grant remains outside group-label-true",
			policy: member, domain: "general", level: 2,
			operation: write, allowed: true,
		},
		{
			name:   "standard member shared level-3 grant modifies",
			policy: member, domain: "general", level: 3,
			operation: modify, allowed: true,
		},
		{
			name:   "companion level-3 foreign write hard deny",
			policy: companion, domain: fixture.outsiderDomain, level: 3,
			operation: write, code: authzdenial.CodeForeignWriteRestricted,
		},
		{
			name:   "companion level-3 foreign modify hard deny",
			policy: companion, domain: fixture.outsiderDomain, level: 3,
			operation: modify, code: authzdenial.CodeForeignWriteRestricted,
		},
		{
			name:   "companion shared level-3 write group-label-false",
			policy: companion, domain: "general", level: 3,
			operation: write, code: authzdenial.CodeSharedWriteRestricted,
		},
		{
			name:   "companion shared level-3 modify group-label-true",
			policy: companion, domain: "general", level: 3,
			operation: modify, code: authzdenial.CodeSharedWriteRestricted,
		},
	}
	cases := make([]grantCase, 0, 17)
	cases = append(cases, initialCases[:]...)
	for _, domainCase := range []struct {
		name, domain string
	}{
		{name: "own", domain: readOnly.ownDomain},
		{name: "foreign", domain: fixture.outsiderDomain},
		{name: "shared", domain: "general"},
	} {
		for _, operation := range []appV23MatrixOperation{write, modify} {
			cases = append(cases, grantCase{
				name: fmt.Sprintf(
					"read-only level-3 %s %s hard deny",
					domainCase.name, operation.name,
				),
				policy: readOnly, domain: domainCase.domain, level: 3,
				operation: operation, code: authzdenial.CodeForeignWriteRestricted,
			})
		}
	}

	for i, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			require.NoError(t, fixture.app.badgerStore.SetAccessGrant(
				testCase.domain,
				testCase.policy.key.id,
				testCase.level,
				0,
				fixture.root.id,
			))
			level, expiresAt, granterID, getGrantErr := fixture.app.badgerStore.GetAccessGrant(
				testCase.domain, testCase.policy.key.id,
			)
			require.NoError(t, getGrantErr)
			require.Equal(t, testCase.level, level)
			require.Zero(t, expiresAt)
			require.Equal(t, fixture.root.id, granterID)
			grantCount, grantCountExceeded, countGrantErr :=
				fixture.app.badgerStore.CountGrantsByDomainUpTo(testCase.domain, 64)
			require.NoError(t, countGrantErr)
			require.False(t, grantCountExceeded)
			require.Positive(t, grantCount)
			if testCase.name == "standard manager level-3 modifies outside group" {
				require.GreaterOrEqual(t, grantCount, 2,
					"the earlier Member L2 grant and this Manager L3 grant must coexist")
			}
			caseID := fmt.Sprintf("grant-%02d", i+1)
			memoryID := "matrix-" + caseID
			switch testCase.operation.verb {
			case store.AppV23VerbRead:
				appV23MatrixSeedMemory(
					t, fixture, memoryID, testCase.domain, 0, memory.StatusProposed,
				)
			case store.AppV23VerbModify:
				appV23MatrixSeedMemory(
					t, fixture, memoryID, testCase.domain, 0, memory.StatusCommitted,
				)
			}

			allowed, code, err := fixture.app.appV23DomainDecision(
				&tx.ParsedTx{},
				testCase.policy.key.id,
				testCase.domain,
				testCase.operation.verb,
				appV23MatrixRawHeight,
				appV23BlockTime(),
			)
			require.NoError(t, err)
			require.Equal(t, testCase.allowed, allowed)
			require.Equal(t, testCase.code, code)
			if testCase.allowed && testCase.operation.verb == store.AppV23VerbRead {
				eligible, eligibleErr := fixture.app.eligibleAppV23ChallengePrincipals(
					memoryID,
					testCase.domain,
					[]string{testCase.policy.key.id},
					store.AppV23VerbRead,
					appV23BlockTime(),
					appV23MatrixRawHeight,
				)
				require.NoError(t, eligibleErr)
				require.Contains(t, eligible, testCase.policy.key.id,
					"explicit Read grantee must remain a canonical corroborator")
			}
			if testCase.allowed && testCase.operation.verb == store.AppV23VerbModify {
				holders, overLimit, holdersErr := fixture.app.badgerStore.AppV23ModifyVerbHoldersUpTo(
					testCase.domain,
					fixture.app.isSharedDomain(testCase.domain, appV23MatrixRawHeight),
					appV23BlockTime(),
					store.MaxChallengeElectorateV21,
				)
				require.NoError(t, holdersErr)
				require.False(t, overLimit)
				require.Contains(t, holders, testCase.policy.key.id)
				eligible, eligibleErr := fixture.app.eligibleAppV23ChallengePrincipals(
					memoryID,
					testCase.domain,
					holders,
					store.AppV23VerbModify,
					appV23BlockTime(),
					appV23MatrixRawHeight,
				)
				require.NoError(t, eligibleErr)
				require.Contains(t, eligible, testCase.policy.key.id)
			}

			parsed := appV23MatrixRawTransaction(
				t,
				testCase.policy,
				testCase.operation,
				memoryID,
				testCase.domain,
				0,
			)
			result := appV23MatrixProcessRaw(
				t,
				fixture.app,
				parsed,
				testCase.policy.key,
				uint64(i+1),
				appV23MatrixRawHeight,
			)
			appV23RequireMatrixRawResult(
				t,
				result,
				testCase.allowed,
				true,
				testCase.operation.verb,
				testCase.code,
			)
		})
	}
	require.Len(t, cases, 17)
}

func TestAppV23StaleGrantCannotAuthorizeOwnerlessResource(t *testing.T) {
	fixture := appV23NewMatrixFixture(t)
	manager := appV23FindMatrixPolicy(
		t, fixture, store.AppV23RoleManager, store.AppV23ProfileStandard, 4,
	)
	const domain = "matrix-stale-grant-ownerless"
	const memoryID = "matrix-stale-grant-ownerless-memory"
	require.NoError(t, fixture.app.badgerStore.SetAccessGrant(
		domain, manager.key.id, 3, 0, fixture.root.id,
	))
	appV23MatrixSeedMemory(
		t, fixture, memoryID, domain, 4, memory.StatusCommitted,
	)

	allowed, denial, err := fixture.app.appV23DomainDecision(
		&tx.ParsedTx{},
		manager.key.id,
		domain,
		store.AppV23VerbModify,
		appV23MatrixRawHeight,
		appV23BlockTime(),
	)
	require.NoError(t, err)
	require.False(t, allowed)
	require.Equal(t, authzdenial.CodeManagerScopeDenied, denial)

	holders, overLimit, err := fixture.app.badgerStore.AppV23ModifyVerbHoldersUpTo(
		domain, false, appV23BlockTime(), store.MaxChallengeElectorateV21,
	)
	require.NoError(t, err)
	require.False(t, overLimit)
	require.Contains(t, holders, manager.key.id,
		"the stale grant is present in legacy storage enumeration")
	eligible, err := fixture.app.eligibleAppV23ChallengePrincipals(
		memoryID,
		domain,
		holders,
		store.AppV23VerbModify,
		appV23BlockTime(),
		appV23MatrixRawHeight,
	)
	require.NoError(t, err)
	require.NotContains(t, eligible, manager.key.id,
		"an ownerless non-shared name cannot become mutable through a stale grant")

	parsed := makeMemoryChallengeTx(t, manager.key, memoryID, "stale grant")
	result := appV23MatrixProcessRaw(
		t,
		fixture.app,
		parsed,
		manager.key,
		1,
		appV23MatrixRawHeight,
	)
	require.Equal(t, appV23Denial(authzdenial.CodeManagerScopeDenied), result)
}

// TestAppV23RoleProfileClearanceCompatibilityThroughSignedRawTx proves the
// same 45-cell compatibility product as the store test at the canonical wire
// and processTx boundary. Invalid cells fail before any policy mutation.
func TestAppV23RoleProfileClearanceCompatibilityThroughSignedRawTx(t *testing.T) {
	app := setupTestApp(t)
	root := newAgentKey(t)
	registerAppV23Agent(t, app, root, store.AppV23RoleAdmin, 1, 0)

	roles := []string{
		store.AppV23RoleMember,
		store.AppV23RoleManager,
		store.AppV23RoleAdmin,
	}
	profiles := []string{
		store.AppV23ProfileStandard,
		store.AppV23ProfileCompanion,
		store.AppV23ProfileReadOnly,
	}
	type compatibilityCase struct {
		key               agentKey
		role, profile     string
		clearance         uint8
		expectedCanonical bool
	}
	cases := make([]compatibilityCase, 0, 45)
	height := int64(2)
	for _, role := range roles {
		for _, profile := range profiles {
			for clearance := uint8(0); clearance <= 4; clearance++ {
				key := newAgentKey(t)
				registerAppV23Agent(t, app, key, store.AppV23RoleMember, height, 0)
				height++
				cases = append(cases, compatibilityCase{
					key: key, role: role, profile: profile, clearance: clearance,
					expectedCanonical: appV23MatrixPolicyIsCanonical(role, profile, clearance),
				})
			}
		}
	}
	require.Len(t, cases, 45)
	require.NoError(t, app.badgerStore.EnsureAppV23Root("compatibility-matrix-scope", 60))
	app.appV23AppliedHeight = 10

	for i, testCase := range cases {
		name := fmt.Sprintf(
			"%s/%s/clearance-%d", testCase.role, testCase.profile, testCase.clearance,
		)
		t.Run(name, func(t *testing.T) {
			enrollment, err := app.badgerStore.GetAppV23Enrollment(testCase.key.id)
			require.NoError(t, err)
			roleState, err := app.badgerStore.GetAppV23Role(testCase.key.id)
			require.NoError(t, err)
			change := &tx.AgentRoleChange{
				AgentID:            testCase.key.id,
				ExpectedRevision:   roleState.Revision,
				EnrollmentRevision: enrollment.Revision,
				Role:               testCase.role,
				ExpectedProfile:    enrollment.Profile,
				Profile:            testCase.profile,
				Clearance:          testCase.clearance,
				Capabilities: uint32(appV23MatrixCapabilities(
					testCase.role, testCase.profile,
				)),
			}
			pub, sig, bodyHash, timestamp := signAgentProof(
				t, root, []byte("compatibility "+name),
			)
			parsed := &tx.ParsedTx{
				Type: tx.TxTypeAgentRoleChange, AgentRoleChange: change,
				AgentPubKey: pub, AgentSig: sig,
				AgentBodyHash: bodyHash, AgentTimestamp: timestamp,
			}
			result := appV23MatrixProcessRaw(
				t,
				app,
				parsed,
				root,
				uint64(i+1),
				appV23MatrixRawHeight,
			)
			if testCase.expectedCanonical {
				require.Zero(t, result.Code, result.Log)
				updatedEnrollment, getErr := app.badgerStore.GetAppV23Enrollment(testCase.key.id)
				require.NoError(t, getErr)
				require.Equal(t, testCase.profile, updatedEnrollment.Profile)
				require.Equal(t, testCase.clearance, updatedEnrollment.Clearance)
				updatedRole, roleErr := app.badgerStore.GetAppV23Role(testCase.key.id)
				require.NoError(t, roleErr)
				require.Equal(t, testCase.role, updatedRole.Role)
			} else {
				require.Equal(t, uint32(111), result.Code)
				require.Equal(t, "invalid app-v23 role change payload", result.Log)
				unchangedEnrollment, getErr := app.badgerStore.GetAppV23Enrollment(testCase.key.id)
				require.NoError(t, getErr)
				require.Equal(t, enrollment, unchangedEnrollment)
			}
		})
	}
}

func TestAppV23OrdinaryRoleChangeCannotMintRootProfile(t *testing.T) {
	fixture := appV23NewMatrixFixture(t)
	target := appV23FindMatrixPolicy(
		t, fixture, store.AppV23RoleMember, store.AppV23ProfileStandard, 4,
	)
	beforeEnrollment, err := fixture.app.badgerStore.GetAppV23Enrollment(target.key.id)
	require.NoError(t, err)
	beforeRole, err := fixture.app.badgerStore.GetAppV23Role(target.key.id)
	require.NoError(t, err)

	caseCount := 0
	for _, role := range []string{
		store.AppV23RoleMember,
		store.AppV23RoleManager,
		store.AppV23RoleAdmin,
	} {
		for clearance := uint8(0); clearance <= 4; clearance++ {
			caseCount++
			name := fmt.Sprintf("%s/clearance-%d", role, clearance)
			t.Run(name, func(t *testing.T) {
				change := &tx.AgentRoleChange{
					AgentID:            target.key.id,
					ExpectedRevision:   beforeRole.Revision,
					EnrollmentRevision: beforeEnrollment.Revision,
					Role:               role,
					ExpectedProfile:    beforeEnrollment.Profile,
					Profile:            store.AppV23ProfileRoot,
					Clearance:          clearance,
					Capabilities:       0,
				}
				pub, sig, bodyHash, timestamp := signAgentProof(
					t, fixture.root, []byte("reserved root profile "+name),
				)
				parsed := &tx.ParsedTx{
					Type: tx.TxTypeAgentRoleChange, AgentRoleChange: change,
					AgentPubKey: pub, AgentSig: sig,
					AgentBodyHash: bodyHash, AgentTimestamp: timestamp,
				}
				result := appV23MatrixProcessRaw(
					t,
					fixture.app,
					parsed,
					fixture.root,
					uint64(caseCount),
					appV23MatrixRawHeight,
				)
				require.Equal(t, uint32(111), result.Code)
				require.Equal(t, "invalid app-v23 role change payload", result.Log)
			})
		}
	}
	require.Equal(t, 15, caseCount)
	afterEnrollment, err := fixture.app.badgerStore.GetAppV23Enrollment(target.key.id)
	require.NoError(t, err)
	require.Equal(t, beforeEnrollment, afterEnrollment)
	afterRole, err := fixture.app.badgerStore.GetAppV23Role(target.key.id)
	require.NoError(t, err)
	require.Equal(t, beforeRole, afterRole)
}

// TestAppV23GroupAuthorityStartsAtHPlusOne is a replay control over the same
// signed raw write. The activation block retains app-v22 behavior and ignores
// the new Manager/group allow; H+1 applies app-v23 and accepts it.
func TestAppV23GroupAuthorityStartsAtHPlusOne(t *testing.T) {
	app := setupTestApp(t)
	root := newAgentKey(t)
	owner := newAgentKey(t)
	manager := newAgentKey(t)
	registerAppV23Agent(t, app, root, store.AppV23RoleAdmin, 1, 0)
	registerAppV23Agent(t, app, owner, store.AppV23RoleMember, 2, 0)
	registerAppV23Agent(t, app, manager, store.AppV23RoleMember, 3, 0)
	require.NoError(t, app.badgerStore.EnsureAppV23Root("matrix-replay-scope", 8))

	managerEnrollment, err := app.badgerStore.GetAppV23Enrollment(manager.id)
	require.NoError(t, err)
	managerRole, err := app.badgerStore.GetAppV23Role(manager.id)
	require.NoError(t, err)
	require.NoError(t, app.badgerStore.SetAppV23Policy(
		root.id,
		manager.id,
		store.AppV23RoleManager,
		managerEnrollment.Profile,
		store.AppV23ProfileStandard,
		2,
		0,
		managerRole.Revision,
		managerEnrollment.Revision,
		9,
	))
	ownerEnrollment, err := app.badgerStore.GetAppV23Enrollment(owner.id)
	require.NoError(t, err)
	members := []string{owner.id, manager.id}
	sort.Strings(members)
	require.NoError(t, app.badgerStore.MutateAppV23AccessGroup(
		root.id, "matrix-replay-group", "Matrix replay group", members, 0, false, 9,
	))

	app.appV22AppliedHeight = 9
	app.appV23AppliedHeight = 10

	pre := makeMemorySubmitTx(t, manager, ownerEnrollment.HomeDomain, "activation block")
	pre.MemorySubmit.MemoryID = "matrix-replay-pre-v23"
	pre.MemorySubmit.Classification = tx.ClearanceInternal
	preResult := appV23MatrixProcessRaw(t, app, pre, manager, 1, 10)
	require.Equal(t, uint32(11), preResult.Code, preResult.Log)
	require.Contains(t, preResult.Log, "no write access")

	post := makeMemorySubmitTx(t, manager, ownerEnrollment.HomeDomain, "first app-v23 block")
	post.MemorySubmit.MemoryID = "matrix-replay-app-v23"
	post.MemorySubmit.Classification = tx.ClearanceInternal
	postResult := appV23MatrixProcessRaw(t, app, post, manager, 2, 11)
	require.Zero(t, postResult.Code, postResult.Log)
}

// TestAppV23ExactSharedGrantStartsAtHPlusOne pins both sides of the fork. The
// activation block still uses the legacy shared-domain barrier for direct
// authorization and holder enumeration; the first post-v23 block recognizes
// the exact shared grant without making it inheritable.
func TestAppV23ExactSharedGrantStartsAtHPlusOne(t *testing.T) {
	app := setupTestApp(t)
	root := newAgentKey(t)
	grantee := newAgentKey(t)
	registerAppV23Agent(t, app, root, store.AppV23RoleAdmin, 1, 0)
	registerAppV23Agent(t, app, grantee, store.AppV23RoleMember, 2, 0)
	require.NoError(t, app.badgerStore.EnsureAppV23Root("matrix-shared-replay-scope", 8))

	enrollment, err := app.badgerStore.GetAppV23Enrollment(grantee.id)
	require.NoError(t, err)
	roleState, err := app.badgerStore.GetAppV23Role(grantee.id)
	require.NoError(t, err)
	require.NoError(t, app.badgerStore.SetAppV23Policy(
		root.id,
		grantee.id,
		store.AppV23RoleMember,
		enrollment.Profile,
		store.AppV23ProfileStandard,
		4,
		0,
		roleState.Revision,
		enrollment.Revision,
		9,
	))
	require.NoError(t, app.badgerStore.SetAccessGrant("general", grantee.id, 3, 0, root.id))

	blockTime := appV23BlockTime()
	legacyAccess, err := app.badgerStore.HasAccessOrAncestor("general", grantee.id, 3, blockTime)
	require.NoError(t, err)
	require.False(t, legacyAccess)
	v23Access, err := app.badgerStore.HasAppV23AccessOrAncestor(
		"general", grantee.id, 3, blockTime, true,
	)
	require.NoError(t, err)
	require.True(t, v23Access)
	legacyHolders, legacyOverLimit, err := app.badgerStore.ModifyVerbHoldersUpTo(
		"general", blockTime, store.MaxChallengeElectorateV21,
	)
	require.NoError(t, err)
	require.False(t, legacyOverLimit)
	require.NotContains(t, legacyHolders, grantee.id)
	v23Holders, v23OverLimit, err := app.badgerStore.AppV23ModifyVerbHoldersUpTo(
		"general", true, blockTime, store.MaxChallengeElectorateV21,
	)
	require.NoError(t, err)
	require.False(t, v23OverLimit)
	require.Contains(t, v23Holders, grantee.id)

	const memoryID = "matrix-shared-replay-memory"
	appV23MatrixSeedMemory(
		t,
		appV23MatrixFixture{app: app, root: root},
		memoryID,
		"general",
		0,
		memory.StatusCommitted,
	)
	app.appV15AppliedHeight = 1
	app.appV21AppliedHeight = 5
	app.appV22AppliedHeight = 9
	app.appV23AppliedHeight = 10

	pre := makeMemoryChallengeTx(t, grantee, memoryID, "activation block")
	preResult := appV23MatrixProcessRaw(t, app, pre, grantee, 1, 10)
	require.Equal(t, uint32(92), preResult.Code, preResult.Log)
	require.Contains(t, preResult.Log, "need domain ownership or a level-3 modify grant")

	post := makeMemoryChallengeTx(t, grantee, memoryID, "first app-v23 block")
	postResult := appV23MatrixProcessRaw(t, app, post, grantee, 2, 11)
	require.Zero(t, postResult.Code, postResult.Log)

	descendantAccess, err := app.badgerStore.HasAppV23AccessOrAncestor(
		"general.child", grantee.id, 3, blockTime, false,
	)
	require.NoError(t, err)
	require.False(t, descendantAccess)
}

// TestAppV23CurrentRootCanModifySharedAndOwnerlessWithoutGrant proves the
// stable Root principal remains sudo-equivalent for local historical/shared
// data without an artificial self-grant. The wire signer is the current Root
// credential and the v21 electorate is frozen over the stable principal.
func TestAppV23CurrentRootCanModifySharedAndOwnerlessWithoutGrant(t *testing.T) {
	fixture := appV23NewMatrixFixture(t)
	for i, testCase := range []struct {
		name, domain string
	}{
		{name: "shared", domain: "general"},
		{name: "ownerless", domain: "matrix-root-ownerless"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			grantCount, overLimit, err := fixture.app.badgerStore.CountGrantsByDomainUpTo(
				testCase.domain, 8,
			)
			require.NoError(t, err)
			require.False(t, overLimit)
			require.Zero(t, grantCount)

			memoryID := fmt.Sprintf("matrix-root-%s-%d", testCase.name, i)
			appV23MatrixSeedMemory(
				t, fixture, memoryID, testCase.domain, 4, memory.StatusCommitted,
			)
			parsed := makeMemoryChallengeTx(t, fixture.root, memoryID, "root modify")
			result := appV23MatrixProcessRaw(
				t,
				fixture.app,
				parsed,
				fixture.root,
				uint64(i+1),
				appV23MatrixRawHeight,
			)
			require.Zero(t, result.Code, result.Log)
		})
	}
}

func TestAppV23DynamicSharedDropsStaleOwnerGroupAuthority(t *testing.T) {
	fixture := appV23NewMatrixFixture(t)
	manager := appV23FindMatrixPolicy(
		t, fixture, store.AppV23RoleManager, store.AppV23ProfileStandard, 4,
	)

	before, err := fixture.app.badgerStore.AuthorizeAppV23PolicyPrincipalDomain(
		manager.key.id,
		fixture.groupOwnerDomain,
		store.AppV23VerbModify,
		false,
	)
	require.NoError(t, err)
	require.True(t, before.Allowed)
	require.False(t, before.ExplicitDeny)
	beforeHolders, beforeOverLimit, err := fixture.app.badgerStore.AppV23AdditionalModifyHolders(
		fixture.groupOwnerDomain, false, store.MaxChallengeElectorateV21,
	)
	require.NoError(t, err)
	require.False(t, beforeOverLimit)
	require.Contains(t, beforeHolders, manager.key.id)

	after, err := fixture.app.badgerStore.AuthorizeAppV23PolicyPrincipalDomain(
		manager.key.id,
		fixture.groupOwnerDomain,
		store.AppV23VerbModify,
		true,
	)
	require.NoError(t, err)
	require.False(t, after.Allowed)
	require.False(t, after.ExplicitDeny)
	afterHolders, afterOverLimit, err := fixture.app.badgerStore.AppV23AdditionalModifyHolders(
		fixture.groupOwnerDomain, true, store.MaxChallengeElectorateV21,
	)
	require.NoError(t, err)
	require.False(t, afterOverLimit)
	require.NotContains(t, afterHolders, manager.key.id,
		"a dynamic shared resource cannot retain stale owner-group authority")

	require.NoError(t, fixture.app.badgerStore.SetAccessGrant(
		fixture.groupOwnerDomain, manager.key.id, 2, 0, fixture.root.id,
	))
	hasWrite, err := fixture.app.badgerStore.HasAppV23AccessOrAncestor(
		fixture.groupOwnerDomain, manager.key.id, 2, appV23BlockTime(), true,
	)
	require.NoError(t, err)
	require.True(t, hasWrite)
	hasModify, err := fixture.app.badgerStore.HasAppV23AccessOrAncestor(
		fixture.groupOwnerDomain, manager.key.id, 3, appV23BlockTime(), true,
	)
	require.NoError(t, err)
	require.False(t, hasModify, "an exact L2 grant restores Write, not Modify")

	admin := appV23FindMatrixPolicy(
		t, fixture, store.AppV23RoleAdmin, store.AppV23ProfileStandard, 4,
	)
	adminDecision, err := fixture.app.badgerStore.AuthorizeAppV23PolicyPrincipalDomain(
		admin.key.id,
		fixture.groupOwnerDomain,
		store.AppV23VerbModify,
		true,
	)
	require.NoError(t, err)
	require.True(t, adminDecision.Allowed)
	require.False(t, adminDecision.ExplicitDeny)
}

func TestAppV23GroupAuthorityCoversFutureDescendantsWithoutGrants(t *testing.T) {
	fixture := appV23NewMatrixFixture(t)
	member := appV23FindMatrixPolicy(
		t, fixture, store.AppV23RoleMember, store.AppV23ProfileStandard, 4,
	)
	manager := appV23FindMatrixPolicy(
		t, fixture, store.AppV23RoleManager, store.AppV23ProfileStandard, 4,
	)
	futurePrefix := fixture.groupOwnerDomain + ".future"

	type decisionCase struct {
		name      string
		policy    appV23MatrixPolicy
		domain    string
		verb      store.AppV23DomainVerb
		allowed   bool
		denial    authzdenial.Code
		memoryID  string
		operation appV23MatrixOperation
	}
	cases := []decisionCase{
		{
			name: "group Member reads future descendant", policy: member,
			domain: futurePrefix + ".read",
			verb:   store.AppV23VerbRead, allowed: true,
			memoryID: "matrix-future-read", operation: appV23MatrixOperations[0],
		},
		{
			name: "group Manager writes future descendant", policy: manager,
			domain: futurePrefix + ".write",
			verb:   store.AppV23VerbWrite, allowed: true,
			memoryID: "matrix-future-write", operation: appV23MatrixOperations[1],
		},
		{
			name: "group Manager modifies future descendant", policy: manager,
			domain: futurePrefix + ".modify",
			verb:   store.AppV23VerbModify, allowed: true,
			memoryID: "matrix-future-modify", operation: appV23MatrixOperations[2],
		},
	}
	for i, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, exactOwnerErr := fixture.app.badgerStore.GetDomainOwner(testCase.domain)
			require.Error(t, exactOwnerErr,
				"the descendant must not exist when group authority is derived")
			resolvedOwner, owningAncestor, resolveErr :=
				fixture.app.badgerStore.ResolveOwningAncestor(testCase.domain)
			require.NoError(t, resolveErr)
			require.Equal(t, fixture.groupOwner.id, resolvedOwner)
			require.Equal(t, fixture.groupOwnerDomain, owningAncestor)
			grantCount, grantOverLimit, grantErr :=
				fixture.app.badgerStore.CountGrantsByDomainUpTo(testCase.domain, 8)
			require.NoError(t, grantErr)
			require.False(t, grantOverLimit)
			require.Zero(t, grantCount)

			switch testCase.verb {
			case store.AppV23VerbRead:
				appV23MatrixSeedMemory(
					t, fixture, testCase.memoryID, testCase.domain, 4, memory.StatusProposed,
				)
			case store.AppV23VerbModify:
				appV23MatrixSeedMemory(
					t, fixture, testCase.memoryID, testCase.domain, 4, memory.StatusCommitted,
				)
			}
			allowed, denial, decisionErr := fixture.app.appV23DomainDecision(
				&tx.ParsedTx{},
				testCase.policy.key.id,
				testCase.domain,
				testCase.verb,
				appV23MatrixRawHeight,
				appV23BlockTime(),
			)
			require.NoError(t, decisionErr)
			require.Equal(t, testCase.allowed, allowed)
			require.Equal(t, testCase.denial, denial)

			parsed := appV23MatrixRawTransaction(
				t,
				testCase.policy,
				testCase.operation,
				testCase.memoryID,
				testCase.domain,
				4,
			)
			result := appV23MatrixProcessRaw(
				t,
				fixture.app,
				parsed,
				testCase.policy.key,
				uint64(i+1),
				appV23MatrixRawHeight,
			)
			require.Zero(t, result.Code, result.Log)
		})
	}

	outsiderPolicy := appV23MatrixPolicy{
		key: fixture.outsider, role: store.AppV23RoleMember,
		profile: store.AppV23ProfileStandard, clearance: 4,
	}
	outsiderEnrollment, err := fixture.app.badgerStore.GetAppV23Enrollment(fixture.outsider.id)
	require.NoError(t, err)
	outsiderPolicy.clearance = outsiderEnrollment.Clearance
	outsiderDescendant := futurePrefix + ".outsider"
	for i, operation := range appV23MatrixOperations {
		name := "non-group " + operation.name + " denied on future descendant"
		t.Run(name, func(t *testing.T) {
			memoryID := fmt.Sprintf("matrix-future-outsider-%d", i)
			switch operation.verb {
			case store.AppV23VerbRead:
				appV23MatrixSeedMemory(
					t, fixture, memoryID, outsiderDescendant, 0, memory.StatusProposed,
				)
			case store.AppV23VerbModify:
				appV23MatrixSeedMemory(
					t, fixture, memoryID, outsiderDescendant, 0, memory.StatusCommitted,
				)
			}
			allowed, denial, decisionErr := fixture.app.appV23DomainDecision(
				&tx.ParsedTx{},
				fixture.outsider.id,
				outsiderDescendant,
				operation.verb,
				appV23MatrixRawHeight,
				appV23BlockTime(),
			)
			require.NoError(t, decisionErr)
			require.False(t, allowed)
			if operation.verb == store.AppV23VerbRead {
				require.Empty(t, denial)
			} else {
				require.Equal(t, authzdenial.CodeMissingWriteGrant, denial)
			}
			parsed := appV23MatrixRawTransaction(
				t,
				outsiderPolicy,
				operation,
				memoryID,
				outsiderDescendant,
				0,
			)
			result := appV23MatrixProcessRaw(
				t,
				fixture.app,
				parsed,
				fixture.outsider,
				uint64(20+i),
				appV23MatrixRawHeight,
			)
			if operation.verb == store.AppV23VerbRead {
				require.Equal(t, appV23ControlDenied(), result)
			} else {
				require.Equal(t, appV23Denial(authzdenial.CodeMissingWriteGrant), result)
			}
		})
	}

	for _, excludedDomain := range []string{"general", "matrix-future-ownerless"} {
		allowed, denial, decisionErr := fixture.app.appV23DomainDecision(
			&tx.ParsedTx{},
			manager.key.id,
			excludedDomain,
			store.AppV23VerbModify,
			appV23MatrixRawHeight,
			appV23BlockTime(),
		)
		require.NoError(t, decisionErr)
		require.False(t, allowed)
		require.Equal(t, authzdenial.CodeManagerScopeDenied, denial)
	}
}
