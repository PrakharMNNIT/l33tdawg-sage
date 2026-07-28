package abci

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

func TestAppV22AgentRegistrationBindsPayloadToAuthenticatedSigner(t *testing.T) {
	app := setupTestApp(t)
	app.appV22AppliedHeight = 10
	signer := newAgentKey(t)
	victim := newAgentKey(t)

	mismatched := makeAgentRegisterTx(t, signer, "squatter", "member", "", "test", "")
	mismatched.AgentRegister.AgentID = victim.id

	var resultCode uint32
	require.NotPanics(t, func() {
		result := app.processAgentRegister(mismatched, 11, time.Now())
		resultCode = result.Code
		require.Contains(t, result.Log, "authenticated signer")
	})
	assert.NotZero(t, resultCode)
	assert.False(t, app.badgerStore.IsAgentRegistered(victim.id))
	assert.False(t, app.badgerStore.IsAgentRegistered(signer.id))

	legitimate := app.processAgentRegister(
		makeAgentRegisterTx(t, victim, "victim", "member", "", "test", ""),
		12,
		time.Now(),
	)
	require.Zero(t, legitimate.Code, legitimate.Log)
	assert.True(t, app.badgerStore.IsAgentRegistered(victim.id))
}

func TestAppV22OrgMemberMutationRejectsMalformedAgentIDBeforeWrite(t *testing.T) {
	app := setupTestApp(t)
	app.appV22AppliedHeight = 10
	admin := newAgentKey(t)
	registerAgent(t, app, admin, "global-admin", "admin")
	require.NoError(t, app.badgerStore.RegisterOrg("short-org", "Short Org", "", admin.id, 1))
	require.NoError(t, app.badgerStore.AddOrgMember("short-org", admin.id, 4, "admin", 1))

	body := []byte("short target")
	pub, sig, bodyHash, ts := signAgentProof(t, admin, body)
	malformed := &tx.ParsedTx{
		Type: tx.TxTypeOrgAddMember,
		OrgAddMember: &tx.OrgAddMember{
			OrgID: "short-org", AgentID: "x", Clearance: tx.ClearanceInternal, Role: "member",
		},
		AgentPubKey: pub, AgentSig: sig, AgentBodyHash: bodyHash, AgentTimestamp: ts,
	}

	var resultCode uint32
	require.NotPanics(t, func() {
		result := app.processOrgAddMember(malformed, 11, time.Now())
		resultCode = result.Code
		require.Contains(t, result.Log, "invalid or unregistered")
	})
	assert.NotZero(t, resultCode)
	member, err := app.badgerStore.IsAgentInOrg("x", "short-org")
	require.NoError(t, err)
	assert.False(t, member)
}

func TestAppV22FederationShortLegacyOrgIDsCannotPanicAfterMutation(t *testing.T) {
	app := setupTestApp(t)
	app.appV22AppliedHeight = 10
	admin := newAgentKey(t)
	registerAgent(t, app, admin, "global-admin", "admin")

	const proposerOrg = "org-a"
	const targetOrg = "org-b"
	require.NoError(t, app.badgerStore.RegisterOrg(proposerOrg, "A", "", admin.id, 1))
	require.NoError(t, app.badgerStore.RegisterOrg(targetOrg, "B", "", admin.id, 1))
	require.NoError(t, app.badgerStore.AddOrgMember(proposerOrg, admin.id, 4, "admin", 1))
	require.NoError(t, app.badgerStore.AddOrgMember(targetOrg, admin.id, 4, "admin", 1))

	proposeBody := []byte("short org federation")
	pub, sig, bodyHash, ts := signAgentProof(t, admin, proposeBody)
	propose := &tx.ParsedTx{
		Type: tx.TxTypeFederationPropose,
		FederationPropose: &tx.FederationPropose{
			ProposerOrgID: proposerOrg,
			TargetOrgID:   targetOrg,
			AllowedDomains: []string{
				"shared.research",
			},
			MaxClearance: tx.ClearanceInternal,
		},
		AgentPubKey: pub, AgentSig: sig, AgentBodyHash: bodyHash, AgentTimestamp: ts,
	}

	var federationID string
	require.NotPanics(t, func() {
		result := app.processFederationPropose(propose, 11, time.Now())
		require.Zero(t, result.Code, result.Log)
		federationID = string(result.Data)
	})
	require.NotEmpty(t, federationID)
	_, _, _, _, status, err := app.badgerStore.GetFederation(federationID)
	require.NoError(t, err)
	assert.Equal(t, "proposed", status)

	approveBody := []byte("short approver org")
	pub, sig, bodyHash, ts = signAgentProof(t, admin, approveBody)
	approve := &tx.ParsedTx{
		Type: tx.TxTypeFederationApprove,
		FederationApprove: &tx.FederationApprove{
			FederationID:  federationID,
			ApproverOrgID: "x",
		},
		AgentPubKey: pub, AgentSig: sig, AgentBodyHash: bodyHash, AgentTimestamp: ts,
	}
	require.NotPanics(t, func() {
		result := app.processFederationApprove(approve, 12, time.Now())
		require.Zero(t, result.Code, result.Log)
	})
	_, _, _, _, status, err = app.badgerStore.GetFederation(federationID)
	require.NoError(t, err)
	assert.Equal(t, "active", status)
}

func TestShortConsensusIDPreservesValidPrefixAndNeverPanics(t *testing.T) {
	assert.Equal(t, "short", shortConsensusID("short"))
	assert.Equal(t, "0123456789abcdef", shortConsensusID("0123456789abcdef-extra"))
	assert.Equal(t, "", shortConsensusID(""))
}

func TestAppV22DomainReassignRequiresCanonicalRegisteredOwnerBeforeMutation(t *testing.T) {
	tests := []struct {
		name            string
		newOwner        func(string) string
		registerTarget  bool
		wantCode        uint32
		wantLogContains string
	}{
		{
			name:            "short malformed target",
			newOwner:        func(string) string { return "x" },
			wantCode:        80,
			wantLogContains: "not a canonical agent identity",
		},
		{
			name:            "canonical but unknown target",
			newOwner:        func(generated string) string { return generated },
			wantCode:        80,
			wantLogContains: "not a registered on-chain agent",
		},
		{
			name:           "canonical registered target",
			newOwner:       func(generated string) string { return generated },
			registerTarget: true,
			wantCode:       0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			app, admin, previousOwner, generatedTarget := setupReassignTestApp(t)
			app.appV22AppliedHeight = 90
			target := tc.newOwner(generatedTarget)
			if tc.registerTarget {
				require.NoError(t, app.badgerStore.RegisterAgent(
					target, "replacement-owner", "member", "", "", "", 91,
				))
			}

			body := tx.DomainReassign{
				Domain:     "protocol.lending_pool",
				NewOwnerID: target,
			}
			body.ProposalID = seedExecutedReassignProposal(t, app, admin.id, body, 80)

			var resultCode uint32
			require.NotPanics(t, func() {
				result := app.processDomainReassign(
					makeDomainReassignTx(t, admin, &body, 1),
					100,
					time.Unix(1_700_000_000, 0),
				)
				resultCode = result.Code
				if tc.wantLogContains != "" {
					require.Contains(t, result.Log, tc.wantLogContains)
				}
			})
			require.Equal(t, tc.wantCode, resultCode)

			owner, err := app.badgerStore.GetDomainOwner(body.Domain)
			require.NoError(t, err)
			if tc.wantCode == 0 {
				assert.Equal(t, target, owner)
			} else {
				assert.Equal(t, previousOwner, owner, "rejected target must not mutate ownership")
			}
		})
	}
}

func TestPreAppV22DomainReassignPreservesLegacyUnknownOwnerAcceptanceWithoutPanic(t *testing.T) {
	app, admin, _, _ := setupReassignTestApp(t)
	body := tx.DomainReassign{
		Domain:     "protocol.lending_pool",
		NewOwnerID: "x",
	}
	body.ProposalID = seedExecutedReassignProposal(t, app, admin.id, body, 80)

	var resultCode uint32
	require.NotPanics(t, func() {
		result := app.processDomainReassign(
			makeDomainReassignTx(t, admin, &body, 1),
			100,
			time.Unix(1_700_000_000, 0),
		)
		resultCode = result.Code
	})
	require.Zero(t, resultCode, "pre-app-v22 replay retains the legacy accepted transition")
	owner, err := app.badgerStore.GetDomainOwner(body.Domain)
	require.NoError(t, err)
	assert.Equal(t, "x", owner)
}

func TestMemoryReassignProjectionShortLegacySourceCannotPanic(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	require.NoError(t, app.offchainStore.CreateAgent(ctx, &store.AgentEntry{
		AgentID:   "y",
		Name:      "target",
		Status:    "active",
		CreatedAt: time.Unix(1_700_000_000, 0),
	}))
	writes := []pendingWrite{{
		writeType: "memory_reassign",
		data: &memoryReassignData{
			SourceAgentID: "x",
			TargetAgentID: "y",
		},
	}}

	require.NotPanics(t, func() {
		require.NoError(t, app.offchainStore.RunInAgentContactTx(ctx, func(s store.OffchainStore) error {
			return app.flushPendingWrites(ctx, s, writes)
		}))
	})
}
