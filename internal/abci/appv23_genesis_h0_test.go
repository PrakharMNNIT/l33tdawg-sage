package abci

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	cryptoproto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

func directAppV23GenesisTestApp(t *testing.T) (*SageApp, agentKey, agentKey) {
	t.Helper()
	app := setupTestApp(t)
	root := newAgentKey(t)
	companion := newAgentKey(t)
	validatorKey := newAgentKey(t)
	manifest := AppV23GenesisManifest{
		Version: AppV23GenesisManifestVersion,
		RootID:  root.id, AgentID: companion.id,
		Profile: store.AppV23ProfileCompanion, Clearance: 1,
		Capabilities: 15, HomeDomain: "voice-interface",
		ValidatorID: validatorKey.id, ValidatorPower: 10,
	}
	signBytes := AppV23GenesisManifestSignBytes("sage-direct-h0", manifest)
	manifest.RootSignature = hex.EncodeToString(ed25519.Sign(root.priv, signBytes))
	manifest.AgentSignature = hex.EncodeToString(ed25519.Sign(companion.priv, signBytes))
	appState, err := json.Marshal(struct {
		Sage struct {
			InitialAdmin    string                `json:"initial_admin"`
			AppV23Bootstrap AppV23GenesisManifest `json:"app_v23_bootstrap"`
		} `json:"sage"`
	}{
		Sage: struct {
			InitialAdmin    string                `json:"initial_admin"`
			AppV23Bootstrap AppV23GenesisManifest `json:"app_v23_bootstrap"`
		}{InitialAdmin: root.id, AppV23Bootstrap: manifest},
	})
	require.NoError(t, err)
	_, err = app.InitChain(context.Background(), &abcitypes.RequestInitChain{
		ChainId: "sage-direct-h0", AppStateBytes: appState,
		Validators: []abcitypes.ValidatorUpdate{{
			Power: 10,
			PubKey: cryptoproto.PublicKey{Sum: &cryptoproto.PublicKey_Ed25519{
				Ed25519: validatorKey.pub,
			}},
		}},
	})
	require.NoError(t, err)
	require.Zero(t, app.state.Height)
	require.True(t, app.IsAppV23ActiveForNextTx())
	return app, root, companion
}

func encodeDirectH0Tx(t *testing.T, parsed *tx.ParsedTx, signer agentKey, nonce uint64) []byte {
	t.Helper()
	parsed.Nonce = nonce
	require.NoError(t, tx.SignTx(parsed, signer.priv))
	raw, err := tx.EncodeTx(parsed)
	require.NoError(t, err)
	return raw
}

func directH0AccessQuery(t *testing.T, signer agentKey) *tx.ParsedTx {
	t.Helper()
	pub, sig, bodyHash, timestamp := signAgentProof(t, signer, []byte("direct-h0-query"))
	return &tx.ParsedTx{
		Type: tx.TxTypeAccessQuery,
		AccessQuery: &tx.AccessQuery{
			Domain: "voice-interface", Embedding: []float32{0.1}, TopK: 1,
		},
		AgentPubKey: pub, AgentSig: sig, AgentBodyHash: bodyHash,
		AgentTimestamp: timestamp,
	}
}

func TestAppV23GenesisManifestAuthenticatesValidatorIdentityAndPower(t *testing.T) {
	root := newAgentKey(t)
	companion := newAgentKey(t)
	validatorKey := newAgentKey(t)
	manifest := AppV23GenesisManifest{
		Version: AppV23GenesisManifestVersion,
		RootID:  root.id, AgentID: companion.id,
		Profile: store.AppV23ProfileCompanion, Clearance: 1,
		Capabilities: 15, HomeDomain: "voice-interface",
		ValidatorID: validatorKey.id, ValidatorPower: 10,
	}
	signBytes := AppV23GenesisManifestSignBytes("sage-validator-binding", manifest)
	manifest.RootSignature = hex.EncodeToString(ed25519.Sign(root.priv, signBytes))
	manifest.AgentSignature = hex.EncodeToString(ed25519.Sign(companion.priv, signBytes))
	_, err := VerifyAppV23GenesisManifest("sage-validator-binding", manifest)
	require.NoError(t, err)

	keyTamper := manifest
	keyTamper.ValidatorID = newAgentKey(t).id
	_, err = VerifyAppV23GenesisManifest("sage-validator-binding", keyTamper)
	require.ErrorContains(t, err, "signature is invalid")

	powerTamper := manifest
	powerTamper.ValidatorPower++
	_, err = VerifyAppV23GenesisManifest("sage-validator-binding", powerTamper)
	require.ErrorContains(t, err, "signature is invalid")
}

func TestAppV23DirectGenesisHeightZeroCheckTxMatchesBlockOneGates(t *testing.T) {
	tests := []struct {
		name      string
		build     func(*testing.T, agentKey) *tx.ParsedTx
		wantCode  uint32
		notCode10 bool
	}{
		{
			name: "nonce zero rejected",
			build: func(t *testing.T, signer agentKey) *tx.ParsedTx {
				return directH0AccessQuery(t, signer)
			},
			wantCode: 4,
		},
		{
			name: "domain reassign admitted",
			build: func(t *testing.T, signer agentKey) *tx.ParsedTx {
				return makeDomainReassignTx(t, signer, &tx.DomainReassign{
					Domain: "voice-interface", NewOwnerID: signer.id, ProposalID: "missing",
				}, 1)
			},
			notCode10: true,
		},
		{
			name: "co-commit submit admitted",
			build: func(t *testing.T, signer agentKey) *tx.ParsedTx {
				envelope, _ := buildCoCommitEnvelope(
					t, signer, "voice-interface", []byte("direct-h0"), "sage-peer",
				)
				return coCommitSubmitTx(t, signer, envelope)
			},
			notCode10: true,
		},
		{
			name: "co-commit attest admitted",
			build: func(t *testing.T, signer agentKey) *tx.ParsedTx {
				peer := newAgentKey(t)
				parsed := signedReceiptAttest(
					"missing", "sage-peer", peer.pub, peer.priv, []byte("core"),
				)
				pub, sig, bodyHash, timestamp :=
					signAgentProof(t, signer, []byte("direct-h0-attest"))
				parsed.AgentPubKey, parsed.AgentSig = pub, sig
				parsed.AgentBodyHash, parsed.AgentTimestamp = bodyHash, timestamp
				return parsed
			},
			notCode10: true,
		},
		{
			name: "cross federation set admitted",
			build: func(t *testing.T, signer agentKey) *tx.ParsedTx {
				return crossFedSetTx(t, signer, termsFor("sage-peer", []string{"*"}))
			},
			notCode10: true,
		},
		{
			name: "cross federation revoke admitted",
			build: func(t *testing.T, signer agentKey) *tx.ParsedTx {
				return crossFedRevokeTx(t, signer, "sage-peer", "test")
			},
			notCode10: true,
		},
		{
			name: "access query retired",
			build: func(t *testing.T, signer agentKey) *tx.ParsedTx {
				return directH0AccessQuery(t, signer)
			},
			wantCode: 10,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			app, _, companion := directAppV23GenesisTestApp(t)
			nonce := uint64(1)
			if testCase.wantCode == 4 {
				nonce = 0
			}
			raw := encodeDirectH0Tx(t, testCase.build(t, companion), companion, nonce)
			checked, err := app.CheckTx(
				context.Background(),
				&abcitypes.RequestCheckTx{Tx: raw},
			)
			require.NoError(t, err)
			if testCase.notCode10 {
				require.NotEqual(t, uint32(10), checked.Code, checked.Log)
			} else {
				require.Equal(t, testCase.wantCode, checked.Code, checked.Log)
			}

			finalized, err := app.FinalizeBlock(
				context.Background(),
				&abcitypes.RequestFinalizeBlock{
					Height: 1, Time: time.Now().UTC(), Txs: [][]byte{raw},
				},
			)
			require.NoError(t, err)
			require.Len(t, finalized.TxResults, 1)
			if testCase.notCode10 {
				require.NotEqual(t, uint32(10), finalized.TxResults[0].Code, finalized.TxResults[0].Log)
			} else {
				require.Equal(t, testCase.wantCode, finalized.TxResults[0].Code, finalized.TxResults[0].Log)
			}
		})
	}
}

func TestAppV23DirectGenesisHeightZeroRecognizesEveryV23WireType(t *testing.T) {
	tests := []struct {
		name  string
		build func(*testing.T, *SageApp, agentKey, agentKey) (*tx.ParsedTx, agentKey)
	}{
		{
			name: "local agent approve",
			build: func(t *testing.T, app *SageApp, root, _ agentKey) (*tx.ParsedTx, agentKey) {
				target := newAgentKey(t)
				rootState, err := app.badgerStore.GetAppV23Root()
				require.NoError(t, err)
				approval := &tx.LocalAgentApprove{
					AgentID: target.id, Active: true,
					Role: store.AppV23RoleMember, Profile: store.AppV23ProfileStandard,
					HomeDomain: "approved-home", Clearance: 1,
					Scope: rootState.Scope,
				}
				approval.TargetSignature = ed25519.Sign(
					target.priv,
					tx.LocalAgentApprovalSignBytes(root.id, approval),
				)
				return &tx.ParsedTx{
					Type: tx.TxTypeLocalAgentApprove, LocalAgentApprove: approval,
				}, root
			},
		},
		{
			name: "agent role change",
			build: func(_ *testing.T, _ *SageApp, root, companion agentKey) (*tx.ParsedTx, agentKey) {
				return &tx.ParsedTx{
					Type: tx.TxTypeAgentRoleChange,
					AgentRoleChange: &tx.AgentRoleChange{
						AgentID: companion.id, ExpectedRevision: 1, EnrollmentRevision: 1,
						Role: store.AppV23RoleManager, ExpectedProfile: store.AppV23ProfileCompanion,
						Profile: store.AppV23ProfileStandard, Clearance: 1,
					},
				}, root
			},
		},
		{
			name: "access group mutate",
			build: func(_ *testing.T, _ *SageApp, root, companion agentKey) (*tx.ParsedTx, agentKey) {
				return &tx.ParsedTx{
					Type: tx.TxTypeAccessGroupMutate,
					AccessGroupMutate: &tx.AccessGroupMutate{
						GroupID: "direct-h0-group", Name: "Direct H0 Group",
						Members: []string{companion.id},
					},
				}, root
			},
		},
		{
			name: "root credential rotate",
			build: func(t *testing.T, app *SageApp, root, _ agentKey) (*tx.ParsedTx, agentKey) {
				replacement := newAgentKey(t)
				rootState, err := app.badgerStore.GetAppV23Root()
				require.NoError(t, err)
				rotation := &tx.RootCredentialRotate{
					ExpectedGeneration: rootState.Generation,
					NewCredentialID:    replacement.id,
					Scope:              rootState.Scope,
				}
				rotation.NewCredentialSignature = ed25519.Sign(
					replacement.priv,
					tx.RootCredentialRotationSignBytes(root.id, rotation),
				)
				return &tx.ParsedTx{
					Type: tx.TxTypeRootCredentialRotate, RootCredentialRotate: rotation,
				}, root
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			app, root, companion := directAppV23GenesisTestApp(t)
			parsed, signer := testCase.build(t, app, root, companion)
			raw := encodeDirectH0Tx(t, parsed, signer, 1)
			checked, err := app.CheckTx(
				context.Background(),
				&abcitypes.RequestCheckTx{Tx: raw},
			)
			require.NoError(t, err)
			require.NotEqual(t, uint32(10), checked.Code, checked.Log)

			finalized, err := app.FinalizeBlock(
				context.Background(),
				&abcitypes.RequestFinalizeBlock{
					Height: 1, Time: time.Now().UTC(), Txs: [][]byte{raw},
				},
			)
			require.NoError(t, err)
			require.Len(t, finalized.TxResults, 1)
			require.NotEqual(t, uint32(10), finalized.TxResults[0].Code, finalized.TxResults[0].Log)
		})
	}
}
