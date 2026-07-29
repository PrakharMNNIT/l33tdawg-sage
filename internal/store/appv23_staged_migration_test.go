package store

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/consensuskeys"
)

func seedAppV23LegacyRoster(t *testing.T, s *BadgerStore, count int) []string {
	t.Helper()
	ids := make([]string, count)
	const chunk = 256
	for start := 0; start < count; start += chunk {
		end := start + chunk
		if end > count {
			end = count
		}
		require.NoError(t, s.update(func(txn *badger.Txn) error {
			for i := start; i < end; i++ {
				id := fmt.Sprintf("%064x", i+1)
				ids[i] = id
				role := AppV23RoleMember
				if i == 0 {
					role = AppV23RoleAdmin
				}
				data, err := appV23Marshal(OnChainAgent{
					AgentID: id, Name: fmt.Sprintf("legacy-%d", i),
					RegisteredName: fmt.Sprintf("legacy-%d", i),
					Role:           role, Clearance: 1, RegisteredAt: int64(i + 1),
				})
				if err != nil {
					return err
				}
				if err := s.txnSet(txn, agentOnChainKey(id), data); err != nil {
					return err
				}
			}
			return nil
		}))
	}
	return ids
}

func TestAppV23StagedMigrationCrashRecoveryAtEveryBatch(t *testing.T) {
	// 513 zero-mask agents produce 3,078 staged logical records:
	// projected agent + enrollment + role + disposition + immutable legacy-read
	// baseline per principal, 512 owned home domains, and one immutable
	// legacy-Admin audit row.
	const stageBatches = 13
	for failBatch := 1; failBatch <= stageBatches; failBatch++ {
		t.Run(fmt.Sprintf("batch-%02d", failBatch), func(t *testing.T) {
			s, err := NewBadgerStore(t.TempDir())
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
			seedAppV23LegacyRoster(t, s, appV23MaxInlineMigrationAgents+1)
			before, err := s.ComputeAppHashExcludingBookkeeping()
			require.NoError(t, err)

			reached := 0
			s.appV23StageFaultHook = func(batch int) error {
				reached = batch
				if batch == failBatch {
					return errors.New("injected app-v23 stage crash")
				}
				return nil
			}
			require.ErrorContains(t, s.EnsureAppV23Root("stage-crash", 100), "injected app-v23 stage crash")
			require.Equal(t, failBatch, reached)
			root, err := s.GetAppV23Root()
			require.NoError(t, err)
			require.Nil(t, root)
			migration, err := s.GetAppV23MigrationState()
			require.NoError(t, err)
			require.Nil(t, migration)
			afterPartial, err := s.ComputeAppHashExcludingBookkeeping()
			require.NoError(t, err)
			require.Equal(t, before, afterPartial,
				"orphan/partial stage rows must be invisible before the marker")

			s.appV23StageFaultHook = nil
			require.NoError(t, s.EnsureAppV23Root("stage-crash", 100))
			require.NoError(t, s.ValidateAppV23State())
		})
	}
}

func TestAppV23StagedMigrationRejectsMismatchedRawRosterIdentity(t *testing.T) {
	s, openErr := NewBadgerStore(t.TempDir())
	require.NoError(t, openErr)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
	ids := seedAppV23LegacyRoster(t, s, appV23MaxInlineMigrationAgents+1)
	target := ids[len(ids)-1]
	agent, err := s.GetRegisteredAgent(target)
	require.NoError(t, err)
	agent.AgentID = appV23TestID("staged-mismatched-value-id")
	value, err := appV23Marshal(agent)
	require.NoError(t, err)
	require.NoError(t, s.SetRawForTest(agentOnChainKey(target), value))

	require.Error(t, s.PrepareAppV23Migration("staged-roster", 100))
	require.Error(t, s.EnsureAppV23Root("staged-roster", 100))
	root, err := s.GetAppV23Root()
	require.NoError(t, err)
	require.Nil(t, root)
	migration, err := s.GetAppV23MigrationState()
	require.NoError(t, err)
	require.Nil(t, migration)
}

func TestAppV23StagedMigrationRestartRebuildsOrphanCorruption(t *testing.T) {
	path := t.TempDir()
	s, err := NewBadgerStore(path)
	require.NoError(t, err)
	seedAppV23LegacyRoster(t, s, appV23MaxInlineMigrationAgents+1)
	before, err := s.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	s.appV23StageFaultHook = func(batch int) error {
		if batch == 2 {
			return errors.New("simulated process death")
		}
		return nil
	}
	require.Error(t, s.EnsureAppV23Root("restart-stage", 100))
	require.NoError(t, s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(
			consensuskeys.AppV23MigrationStageKey([]byte("corrupt:orphan")),
			[]byte("not part of the plan"),
		)
	}))
	require.NoError(t, s.CloseBadger())

	reopened, err := NewBadgerStore(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reopened.CloseBadger()) })
	afterRestart, err := reopened.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	require.Equal(t, before, afterRestart)
	require.NoError(t, reopened.EnsureAppV23Root("restart-stage", 100))
	require.NoError(t, reopened.ValidateAppV23State())
}

func TestAppV23StagedMigrationConcurrentActivationIsIdempotent(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
	seedAppV23LegacyRoster(t, s, appV23MaxInlineMigrationAgents+1)
	const callers = 12
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.EnsureAppV23Root("concurrent-stage", 100)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.NoError(t, s.ValidateAppV23State())
	migration, err := s.GetAppV23MigrationState()
	require.NoError(t, err)
	require.Positive(t, migration.StageCount)
}

func TestAppV23StagedMigrationBoundsLargeLegacyAdminAuditHeader(t *testing.T) {
	s, openErr := NewBadgerStore(t.TempDir())
	require.NoError(t, openErr)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
	const count = appV23InlineLegacyAdminAuditLimit + 1
	for start := 0; start < count; start += 256 {
		end := start + 256
		if end > count {
			end = count
		}
		require.NoError(t, s.update(func(txn *badger.Txn) error {
			for i := start; i < end; i++ {
				id := fmt.Sprintf("%064x", i+1)
				data, err := appV23Marshal(OnChainAgent{
					AgentID: id, Name: fmt.Sprintf("legacy-admin-%d", i),
					RegisteredName: fmt.Sprintf("legacy-admin-%d", i),
					Role:           AppV23RoleAdmin, Clearance: 1, RegisteredAt: int64(i + 1),
				})
				if err != nil {
					return err
				}
				if err := s.txnSet(txn, agentOnChainKey(id), data); err != nil {
					return err
				}
			}
			return nil
		}))
	}
	require.NoError(t, s.EnsureAppV23Root("large-admin-audit", 100))
	require.NoError(t, s.ValidateAppV23State())
	migration, err := s.GetAppV23MigrationState()
	require.NoError(t, err)
	require.Equal(t, count, migration.LegacyAdminCount)
	require.Empty(t, migration.LegacyAdmins,
		"large immutable audit rosters are represented by staged per-ID rows")
	require.Len(t, migration.LegacyAdminDigest, 64)
	adminCount := 0
	require.NoError(t, s.view(func(txn *badger.Txn) error {
		prefix := []byte("appv23:admin:")
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			adminCount++
		}
		return nil
	}))
	require.Equal(t, 1, adminCount,
		"only deterministic Root is promoted; every other legacy Admin requires local review")
}

func TestAppV23StagedMigrationReconcilesLargeGenesisBootstrapRoster(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
	rootID := fmt.Sprintf("%064x", 1)
	companionID := fmt.Sprintf("%064x", 2)
	require.NoError(t, s.BootstrapAppV23Genesis(AppV23GenesisBootstrap{
		RootID: rootID, AgentID: companionID, Scope: "large-bootstrap",
		Profile: AppV23ProfileCompanion, HomeDomain: "voice-interface",
		Clearance: 1, Capabilities: 15, Height: 1,
		BootstrapDigest: "signed-large-bootstrap",
	}))
	for i := 3; i <= appV23MaxInlineMigrationAgents+1; i++ {
		id := fmt.Sprintf("%064x", i)
		require.NoError(t, s.RegisterAgentWithCapabilities(
			id, fmt.Sprintf("legacy-%d", i), AppV23RoleMember,
			"", "", "", int64(i), 0,
		))
	}
	extraID := fmt.Sprintf("%064x", appV23MaxInlineMigrationAgents+1)
	require.NoError(t, s.EnsureAppV23Root("large-bootstrap", 100))
	require.NoError(t, s.ValidateAppV23State())
	root, err := s.GetAppV23Root()
	require.NoError(t, err)
	require.Equal(t, "signed-large-bootstrap", root.BootstrapDigest)
	migration, err := s.GetAppV23MigrationState()
	require.NoError(t, err)
	require.Positive(t, migration.StageCount)
	require.Equal(t, "signed-large-bootstrap", migration.RootBootstrapDigest)
	companion, err := s.GetAppV23Enrollment(companionID)
	require.NoError(t, err)
	require.Equal(t, AppV23ProfileCompanion, companion.Profile)
	require.Equal(t, "voice-interface", companion.HomeDomain)
	extra, err := s.GetAppV23Enrollment(extraID)
	require.NoError(t, err)
	require.NotNil(t, extra)
	require.True(t, extra.Active)
	owner, err := s.GetDomainOwner(extra.HomeDomain)
	require.NoError(t, err)
	require.Equal(t, extraID, owner)
}

func TestAppV23PromotedStageCorruptionFailsClosed(t *testing.T) {
	for _, mode := range []string{"missing", "bytes"} {
		t.Run(mode, func(t *testing.T) {
			s, err := NewBadgerStore(t.TempDir())
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
			seedAppV23LegacyRoster(t, s, appV23MaxInlineMigrationAgents+1)
			require.NoError(t, s.EnsureAppV23Root("promoted-corruption", 100))
			require.NoError(t, s.ValidateAppV23State())

			var victim, original []byte
			require.NoError(t, s.db.View(func(txn *badger.Txn) error {
				opts := badger.DefaultIteratorOptions
				opts.Prefix = consensuskeys.AppV23MigrationStagePrefix
				opts.PrefetchValues = false
				it := txn.NewIterator(opts)
				defer it.Close()
				it.Seek(opts.Prefix)
				require.True(t, it.ValidForPrefix(opts.Prefix))
				victim = it.Item().KeyCopy(nil)
				var valueErr error
				original, valueErr = it.Item().ValueCopy(nil)
				return valueErr
			}))
			require.NoError(t, s.db.Update(func(txn *badger.Txn) error {
				if mode == "missing" {
					return txn.Delete(victim)
				}
				return txn.Set(victim, append(append([]byte(nil), original...), 0xff))
			}))
			if mode == "missing" {
				require.ErrorContains(t, s.ValidateAppV23State(), "stage count mismatch")
			} else {
				require.ErrorContains(t, s.ValidateAppV23State(), "stage digest mismatch")
			}
			require.Error(t, s.EnsureAppV23Root("promoted-corruption", 101),
				"an activated stage must never be silently regenerated")
			err = s.db.View(func(txn *badger.Txn) error {
				item, getErr := txn.Get(victim)
				if getErr != nil {
					return getErr
				}
				value, valueErr := item.ValueCopy(nil)
				if mode == "bytes" {
					require.Equal(t, append(append([]byte(nil), original...), 0xff), value)
				}
				return valueErr
			})
			if mode == "missing" {
				require.ErrorIs(t, err, badger.ErrKeyNotFound)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAppV23StagedMigrationScopedReplayIsIdentical(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
	seedAppV23LegacyRoster(t, s, appV23MaxInlineMigrationAgents+1)
	before, err := s.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)

	require.NoError(t, s.PrepareAppV23Migration("scoped-replay", 100))
	require.NoError(t, s.db.View(func(txn *badger.Txn) error {
		_, lookupErr := txn.Get(consensuskeys.AppV23MigrationPrepareKey)
		return lookupErr
	}))
	first := s.BeginConsensusTransaction(nil)
	require.NoError(t, first.EnsureAppV23Root("scoped-replay", 100))
	require.NoError(t, first.ValidateAppV23State())
	firstHash, err := first.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	require.False(t, bytes.Equal(before, firstHash))
	require.NoError(t, func() error {
		root, readErr := s.GetAppV23Root()
		require.NoError(t, readErr)
		require.Nil(t, root, "the durable stage must remain invisible until Commit")
		return nil
	}())
	durableBeforeCommit, err := s.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	require.Equal(t, before, durableBeforeCommit)
	first.DiscardConsensusTransaction()
	require.NoError(t, s.db.View(func(txn *badger.Txn) error {
		_, lookupErr := txn.Get(consensuskeys.AppV23MigrationPrepareKey)
		return lookupErr
	}), "discard/crash before the activation marker must retain readiness for exact replay")

	require.NoError(t, s.PrepareAppV23Migration("scoped-replay", 100))
	second := s.BeginConsensusTransaction(nil)
	require.NoError(t, second.EnsureAppV23Root("scoped-replay", 100))
	secondHash, err := second.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	require.Equal(t, firstHash, secondHash)
	require.NoError(t, second.CommitConsensusTransaction())
	committedHash, err := s.ComputeAppHashExcludingBookkeeping()
	require.NoError(t, err)
	require.Equal(t, secondHash, committedHash)
	require.NoError(t, s.ValidateAppV23State())
	require.ErrorIs(t, s.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(consensuskeys.AppV23MigrationPrepareKey)
		return err
	}), badger.ErrKeyNotFound,
		"successful activation must atomically prune the temporary readiness record")
}

func TestAppV23InlineAndStagedMigrationBoundaryParity(t *testing.T) {
	build := func(t *testing.T, count int) (*BadgerStore, []string) {
		t.Helper()
		s, err := NewBadgerStore(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
		ids := seedAppV23LegacyRoster(t, s, count)
		require.NoError(t, s.EnsureAppV23Root("boundary-parity", 100))
		require.NoError(t, s.ValidateAppV23State())
		return s, ids
	}
	inline, inlineIDs := build(t, appV23MaxInlineMigrationAgents)
	staged, stagedIDs := build(t, appV23MaxInlineMigrationAgents+1)

	inlineRoot, inlineRootErr := inline.GetAppV23Root()
	require.NoError(t, inlineRootErr)
	stagedRoot, stagedRootErr := staged.GetAppV23Root()
	require.NoError(t, stagedRootErr)
	require.Equal(t, inlineRoot.PrincipalID, stagedRoot.PrincipalID)
	require.Equal(t, inlineRoot.Scope, stagedRoot.Scope)
	require.Equal(t, inlineRoot.Generation, stagedRoot.Generation)

	for _, index := range []int{0, 1, appV23MaxInlineMigrationAgents - 1} {
		require.Equal(t, inlineIDs[index], stagedIDs[index])
		id := inlineIDs[index]
		inlineEnrollment, err := inline.GetAppV23Enrollment(id)
		require.NoError(t, err)
		stagedEnrollment, err := staged.GetAppV23Enrollment(id)
		require.NoError(t, err)
		require.Equal(t, inlineEnrollment, stagedEnrollment)
		inlineRole, err := inline.GetAppV23Role(id)
		require.NoError(t, err)
		stagedRole, err := staged.GetAppV23Role(id)
		require.NoError(t, err)
		require.Equal(t, inlineRole, stagedRole)
		inlineAgent, err := inline.GetRegisteredAgent(id)
		require.NoError(t, err)
		stagedAgent, err := staged.GetRegisteredAgent(id)
		require.NoError(t, err)
		require.Equal(t, inlineAgent, stagedAgent)
		if inlineEnrollment.HomeDomain != "" {
			inlineOwner, err := inline.GetDomainOwner(inlineEnrollment.HomeDomain)
			require.NoError(t, err)
			stagedOwner, err := staged.GetDomainOwner(stagedEnrollment.HomeDomain)
			require.NoError(t, err)
			require.Equal(t, id, inlineOwner)
			require.Equal(t, inlineOwner, stagedOwner)
			_, _, _, inlineGrantErr := inline.GetAccessGrant(inlineEnrollment.HomeDomain, id)
			_, _, _, stagedGrantErr := staged.GetAccessGrant(stagedEnrollment.HomeDomain, id)
			require.ErrorIs(t, inlineGrantErr, ErrAccessGrantNotFound)
			require.ErrorIs(t, stagedGrantErr, ErrAccessGrantNotFound)
			inlineAuth, err := inline.AuthorizeAppV23LocalDomain(
				id, inlineEnrollment.HomeDomain, AppV23VerbWrite, false,
			)
			require.NoError(t, err)
			stagedAuth, err := staged.AuthorizeAppV23LocalDomain(
				id, stagedEnrollment.HomeDomain, AppV23VerbWrite, false,
			)
			require.NoError(t, err)
			require.Equal(t, inlineAuth, stagedAuth)
			require.True(t, stagedAuth.Allowed)
		}
	}

	inlineMigration, err := inline.GetAppV23MigrationState()
	require.NoError(t, err)
	stagedMigration, err := staged.GetAppV23MigrationState()
	require.NoError(t, err)
	require.Zero(t, inlineMigration.StageCount)
	require.Positive(t, stagedMigration.StageCount)
	require.Equal(t, inlineMigration.LegacyAdmins, stagedMigration.LegacyAdmins)
	require.Equal(t, inlineMigration.LegacyAdminDigest, stagedMigration.LegacyAdminDigest)

	// A live logical key must override its immutable stage baseline.
	target := stagedIDs[1]
	enrollment, err := staged.GetAppV23Enrollment(target)
	require.NoError(t, err)
	role, err := staged.GetAppV23Role(target)
	require.NoError(t, err)
	require.NoError(t, staged.SetAppV23Policy(
		stagedRoot.CredentialID, target,
		AppV23RoleManager, AppV23ProfileStandard, AppV23ProfileStandard,
		enrollment.Clearance, 0, role.Revision, enrollment.Revision, 101,
	))
	overriddenRole, err := staged.GetAppV23Role(target)
	require.NoError(t, err)
	require.Equal(t, AppV23RoleManager, overriddenRole.Role)
	require.Equal(t, uint64(2), overriddenRole.Revision)
	require.NoError(t, staged.ValidateAppV23State())
}

func TestAppV23GenesisHomeUsesOwnershipWithoutSyntheticGrant(t *testing.T) {
	s, err := NewBadgerStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.CloseBadger()) })
	rootID := fmt.Sprintf("%064x", 1)
	agentID := fmt.Sprintf("%064x", 2)
	require.NoError(t, s.BootstrapAppV23Genesis(AppV23GenesisBootstrap{
		RootID: rootID, AgentID: agentID, Scope: "genesis-owned-home",
		Profile: AppV23ProfileCompanion, HomeDomain: "voice-interface",
		Clearance: 1, Capabilities: 15, Height: 1,
		BootstrapDigest: "signed-bootstrap",
	}))
	owner, err := s.GetDomainOwner("voice-interface")
	require.NoError(t, err)
	require.Equal(t, agentID, owner)
	_, _, _, err = s.GetAccessGrant("voice-interface", agentID)
	require.ErrorIs(t, err, ErrAccessGrantNotFound)
	authz, err := s.AuthorizeAppV23LocalDomain(
		agentID, "voice-interface", AppV23VerbWrite, false,
	)
	require.NoError(t, err)
	require.True(t, authz.Allowed)
}
