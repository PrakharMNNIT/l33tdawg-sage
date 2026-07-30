package abci

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/dgraph-io/badger/v4"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/consensuskeys"
	"github.com/l33tdawg/sage/internal/poe"
	"github.com/l33tdawg/sage/internal/statesync"
	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

func TestAppV23DirectGenesisCanonicalStateSyncRoundTrip(t *testing.T) {
	rootDir := t.TempDir()
	source, err := store.NewBadgerStore(filepath.Join(rootDir, "source"))
	require.NoError(t, err)
	root := deterministicScopedAgent(17)
	companion := deterministicScopedAgent(49)
	scope := strings.Repeat("5a", 32)
	require.NoError(t, source.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: root.id, Scope: scope, AgentID: companion.id,
		Profile: store.AppV23ProfileCompanion, HomeDomain: "voice-interface",
		Clearance: 1, Capabilities: 15, Height: 1,
		BootstrapDigest: strings.Repeat("6b", 32), ActivateAtGenesis: true,
		ValidatorID: root.id, ValidatorPower: 10,
	}))
	state := &AppState{Height: 2, EpochNum: poe.EpochNumber(2)}
	appHash, err := source.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	state.AppHash = append([]byte(nil), appHash...)
	require.NoError(t, SaveState(source, state))
	appHash, err = source.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	state.AppHash = append([]byte(nil), appHash...)
	require.NoError(t, SaveState(source, state))

	backupPath := filepath.Join(rootDir, "direct-v23.backup")
	backup, err := os.OpenFile(
		backupPath,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	require.NoError(t, err)
	require.NoError(t, statesync.WriteCanonicalState(context.Background(), source.DB(), backup))
	require.NoError(t, backup.Close())
	require.NoError(t, source.CloseBadger())

	target := filepath.Join(rootDir, "restored")
	require.NoError(t, PrepareAppV20StateSyncBackup(
		context.Background(),
		backupPath,
		target,
		2,
		appHash,
	))
	height, inspectedHash, err :=
		InspectAppV20StateSyncDirectory(context.Background(), target)
	require.NoError(t, err)
	require.Equal(t, uint64(2), height)
	require.Equal(t, appHash, inspectedHash)

	restored, err := store.NewBadgerStore(target)
	require.NoError(t, err)
	projection, err := store.NewSQLiteStore(
		context.Background(),
		filepath.Join(rootDir, "restored.db"),
	)
	require.NoError(t, err)
	app, err := NewSageAppWithStores(restored, projection, zerolog.Nop())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	info, err := app.Info(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, AppV23GenesisAppVersion, info.AppVersion)
	require.Equal(t, int64(2), info.LastBlockHeight)
	require.Equal(t, appHash, info.LastBlockAppHash)
	require.True(t, app.IsAppV23ActiveForNextTx())
	require.NoError(t, restored.ValidateAppV23GenesisLineage())
	require.NoError(t, restored.ValidateAppV23State())
	activation, err := restored.GetAppV23GenesisActivation()
	require.NoError(t, err)
	require.Equal(t, root.id, activation.ValidatorID)
	require.Equal(t, int64(10), activation.ValidatorPower)
	require.Equal(t, []string{root.id}, app.ValidatorIDs())
	owner, err := restored.GetDomainOwner("voice-interface")
	require.NoError(t, err)
	require.Equal(t, companion.id, owner)
	nextHeight := activateDirectAppV24ForTest(
		t, app, time.Unix(3, 0).UTC(),
	)

	submit := makeMemorySubmitTx(
		t,
		companion,
		"voice-interface",
		"direct app-v23 state-sync receiver remains writable",
	)
	submit.Nonce = 1
	require.NoError(t, tx.SignTx(submit, companion.priv))
	raw, err := tx.EncodeTx(submit)
	require.NoError(t, err)
	checked, err := app.CheckTx(
		context.Background(),
		&abcitypes.RequestCheckTx{Tx: raw},
	)
	require.NoError(t, err)
	require.Zero(t, checked.Code, checked.Log)
	finalized, err := app.FinalizeBlock(
		context.Background(),
		&abcitypes.RequestFinalizeBlock{
			Height: nextHeight, Time: time.Unix(nextHeight, 0).UTC(), Txs: [][]byte{raw},
		},
	)
	require.NoError(t, err)
	require.Len(t, finalized.TxResults, 1)
	require.Zero(t, finalized.TxResults[0].Code, finalized.TxResults[0].Log)
	require.NotEmpty(t, finalized.TxResults[0].Data)
	_, err = app.Commit(context.Background(), &abcitypes.RequestCommit{})
	require.NoError(t, err)
	projected, err := projection.GetMemory(
		context.Background(),
		string(finalized.TxResults[0].Data),
	)
	require.NoError(t, err)
	require.Equal(t, "voice-interface", projected.DomainTag)
}

func TestAppV23DirectGenesisConstructorRejectsMixedLineage(t *testing.T) {
	tests := []struct {
		name        string
		errorText   string
		contaminate func(*testing.T, *store.BadgerStore)
	}{
		{
			name:      "governed applied upgrade",
			errorText: "applied app-v22",
			contaminate: func(t *testing.T, badgerStore *store.BadgerStore) {
				require.NoError(t, badgerStore.MarkUpgradeApplied("app-v22", 22, 10))
			},
		},
		{
			name:      "orphan migration stage",
			errorText: "invalid app-v23 genesis lineage",
			contaminate: func(t *testing.T, badgerStore *store.BadgerStore) {
				require.NoError(t, badgerStore.DB().Update(func(txn *badger.Txn) error {
					return txn.Set(
						consensuskeys.AppV23MigrationStageKey([]byte("agent:orphan")),
						[]byte(`{}`),
					)
				}))
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			rootDir := t.TempDir()
			badgerStore, err := store.NewBadgerStore(filepath.Join(rootDir, "badger"))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, badgerStore.CloseBadger()) })
			root := deterministicScopedAgent(18)
			companion := deterministicScopedAgent(50)
			require.NoError(t, badgerStore.BootstrapAppV23Genesis(
				store.AppV23GenesisBootstrap{
					RootID: root.id, Scope: strings.Repeat("7c", 32),
					AgentID: companion.id, Profile: store.AppV23ProfileCompanion,
					HomeDomain: "voice-interface", Clearance: 1, Capabilities: 15,
					Height: 1, BootstrapDigest: strings.Repeat("8d", 32),
					ActivateAtGenesis: true,
					ValidatorID:       root.id, ValidatorPower: 10,
				},
			))
			testCase.contaminate(t, badgerStore)
			projection, err := store.NewSQLiteStore(
				context.Background(),
				filepath.Join(rootDir, "projection.db"),
			)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, projection.Close()) })
			_, err = NewSageAppWithStores(badgerStore, projection, zerolog.Nop())
			require.ErrorContains(t, err, testCase.errorText)
		})
	}
}
