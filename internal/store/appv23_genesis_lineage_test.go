package store

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/consensuskeys"
)

func TestAppV23DirectGenesisRejectsPreexistingValidatorRowsAtomically(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value []byte
	}{
		{
			name: "stale canonical validator",
			key:  "validator:" + strings.Repeat("66", 32),
			value: func() []byte {
				value := make([]byte, 8)
				binary.BigEndian.PutUint64(value, 10)
				return value
			}(),
		},
		{
			name:  "malformed validator",
			key:   "validator:not-canonical",
			value: []byte{1},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			s, err := NewBadgerStore(t.TempDir())
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
			require.NoError(t, s.DB().Update(func(txn *badger.Txn) error {
				return txn.Set([]byte(testCase.key), testCase.value)
			}))
			input := AppV23GenesisBootstrap{
				RootID: strings.Repeat("11", 32), Scope: strings.Repeat("22", 32),
				AgentID: strings.Repeat("33", 32), Profile: AppV23ProfileCompanion,
				HomeDomain: "voice-interface", Clearance: 1, Capabilities: 15,
				Height: 1, BootstrapDigest: strings.Repeat("44", 32),
				ActivateAtGenesis: true, ValidatorID: strings.Repeat("55", 32),
				ValidatorPower: 10,
			}
			require.ErrorContains(t, s.BootstrapAppV23Genesis(input), "preexisting consensus key")
			root, err := s.GetAppV23Root()
			require.NoError(t, err)
			require.Nil(t, root)
			activation, err := s.GetAppV23GenesisActivation()
			require.NoError(t, err)
			require.Nil(t, activation)
		})
	}
}

func TestAppV23DirectGenesisIdempotenceRequiresExactValidator(t *testing.T) {
	s, input := appV23DirectGenesisLineageFixture(t)
	extra := make([]byte, 8)
	binary.BigEndian.PutUint64(extra, 10)
	require.NoError(t, s.DB().Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("validator:"+strings.Repeat("66", 32)), extra)
	}))
	require.ErrorContains(
		t,
		s.BootstrapAppV23Genesis(input),
		"validator set does not match manifest",
	)
}

func appV23DirectGenesisLineageFixture(t *testing.T) (*BadgerStore, AppV23GenesisBootstrap) {
	t.Helper()
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
	input := AppV23GenesisBootstrap{
		RootID:            strings.Repeat("11", 32),
		Scope:             strings.Repeat("22", 32),
		AgentID:           strings.Repeat("33", 32),
		Profile:           AppV23ProfileCompanion,
		HomeDomain:        "voice-interface",
		Clearance:         1,
		Capabilities:      15,
		Height:            1,
		BootstrapDigest:   strings.Repeat("44", 32),
		ActivateAtGenesis: true,
		ValidatorID:       strings.Repeat("55", 32),
		ValidatorPower:    10,
	}
	require.NoError(t, s.BootstrapAppV23Genesis(input))
	require.NoError(t, s.BootstrapAppV23Genesis(input),
		"an exact clean re-Init must remain idempotent")
	return s, input
}

func TestAppV23DirectGenesisIdempotenceRejectsGovernedAndMigrationLineage(t *testing.T) {
	tests := []struct {
		name        string
		contaminate func(*testing.T, *BadgerStore)
	}{
		{
			name: "canonical applied upgrade",
			contaminate: func(t *testing.T, s *BadgerStore) {
				require.NoError(t, s.MarkUpgradeApplied("app-v22", 22, 10))
			},
		},
		{
			name: "migration state",
			contaminate: func(t *testing.T, s *BadgerStore) {
				payload, err := json.Marshal(AppV23MigrationState{Height: 10})
				require.NoError(t, err)
				require.NoError(t, s.DB().Update(func(txn *badger.Txn) error {
					return txn.Set(appV23MigrationStateKey(), payload)
				}))
			},
		},
		{
			name: "migration prepare",
			contaminate: func(t *testing.T, s *BadgerStore) {
				require.NoError(t, s.DB().Update(func(txn *badger.Txn) error {
					return txn.Set(consensuskeys.AppV23MigrationPrepareKey, []byte(`{}`))
				}))
			},
		},
		{
			name: "migration stage",
			contaminate: func(t *testing.T, s *BadgerStore) {
				require.NoError(t, s.DB().Update(func(txn *badger.Txn) error {
					return txn.Set(
						consensuskeys.AppV23MigrationStageKey([]byte("agent:stale")),
						[]byte(`{}`),
					)
				}))
			},
		},
		{
			name: "migration disposition",
			contaminate: func(t *testing.T, s *BadgerStore) {
				require.NoError(t, s.DB().Update(func(txn *badger.Txn) error {
					return txn.Set(
						appV23MigrationKey(strings.Repeat("55", 32)),
						[]byte(`{}`),
					)
				}))
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			s, input := appV23DirectGenesisLineageFixture(t)
			testCase.contaminate(t, s)
			require.ErrorContains(
				t,
				s.BootstrapAppV23Genesis(input),
				"cannot coexist",
			)
		})
	}
}
