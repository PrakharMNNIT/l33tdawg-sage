package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func federatedReaderTestBinding(t *testing.T, chainID, epoch, pinByte string) FederatedReaderBinding {
	t.Helper()
	return FederatedReaderBinding{
		RemoteChainID: chainID,
		PeerAgentID:   testPeerAgentID(t),
		PolicyEpoch:   epoch,
		RemoteCAPin:   strings.Repeat(pinByte, 32),
	}
}

func activateFederatedReaderTestBinding(t *testing.T, s *SQLiteStore, binding FederatedReaderBinding) {
	t.Helper()
	ctx := context.Background()
	control := SyncControl{
		RemoteChainID:     binding.RemoteChainID,
		Role:              "guest",
		ControllerChainID: "chain-local", ControllerAgentID: binding.PeerAgentID,
		PeerAgentID: binding.PeerAgentID, PolicyEpoch: binding.PolicyEpoch,
		RemoteCAPin: binding.RemoteCAPin, PolicyVersion: CurrentPeerRBACPolicyVersion,
	}
	if err := s.PrepareSyncControl(ctx, control); err != nil {
		t.Fatalf("PrepareSyncControl: %v", err)
	}
	if err := s.ActivateSyncControl(ctx, binding.RemoteChainID, binding.PolicyEpoch); err != nil {
		t.Fatalf("ActivateSyncControl: %v", err)
	}
}

func federatedReaderTestRestriction(
	binding FederatedReaderBinding, agentID string, revision int64, denies ...string,
) FederatedReaderRestriction {
	return FederatedReaderRestriction{
		RemoteChainID: binding.RemoteChainID, LocalAgentID: agentID,
		PeerAgentID: binding.PeerAgentID, PolicyEpoch: binding.PolicyEpoch,
		RemoteCAPin: binding.RemoteCAPin, DeniedDomains: denies,
		Revision: revision, State: FederatedReaderRestrictionStateActive,
	}
}

func TestFederatedReaderRestrictionDefaultAllowAndSubtreeDeny(t *testing.T) {
	ctx := context.Background()
	s := newSyncTestStore(t)
	binding := federatedReaderTestBinding(t, "chain-reader", "epoch-reader", "ab")
	activateFederatedReaderTestBinding(t, s, binding)
	agentID := testPeerAgentID(t)

	allowed, err := s.FederatedReaderAllows(ctx, binding, agentID, "finance.private")
	if err != nil || !allowed {
		t.Fatalf("absent restriction = allowed %v, err %v; want true,nil", allowed, err)
	}

	created, err := s.PutBoundFederatedReaderRestrictionCAS(ctx,
		federatedReaderTestRestriction(binding, agentID, 1, "secret", "finance.private"), 0)
	if err != nil {
		t.Fatalf("create restriction: %v", err)
	}
	if got, want := strings.Join(created.DeniedDomains, ","), "finance.private,secret"; got != want {
		t.Fatalf("canonical denied domains = %q, want %q", got, want)
	}
	for _, domain := range []string{"finance.private", "finance.private.q1", "finance", "secret"} {
		allowed, err = s.FederatedReaderAllows(ctx, binding, agentID, domain)
		if err != nil || allowed {
			t.Fatalf("denied overlap %q = allowed %v, err %v", domain, allowed, err)
		}
	}
	for _, domain := range []string{"finance.public", "secretary"} {
		allowed, err = s.FederatedReaderAllows(ctx, binding, agentID, domain)
		if err != nil || !allowed {
			t.Fatalf("sibling %q = allowed %v, err %v; want true,nil", domain, allowed, err)
		}
	}

	denyAll := *created
	denyAll.Revision = 2
	denyAll.DenyAll = true
	denyAll.DeniedDomains = nil
	updated, err := s.PutBoundFederatedReaderRestrictionCAS(ctx, denyAll, 1)
	if err != nil {
		t.Fatalf("set deny-all: %v", err)
	}
	if allowed, err = s.FederatedReaderAllows(ctx, binding, agentID, "anything"); err != nil || allowed {
		t.Fatalf("deny-all = allowed %v, err %v", allowed, err)
	}

	revoked := *updated
	revoked.Revision = 3
	revoked.State = FederatedReaderRestrictionStateRevoked
	if _, err = s.PutBoundFederatedReaderRestrictionCAS(ctx, revoked, 2); err != nil {
		t.Fatalf("revoke restriction: %v", err)
	}
	if allowed, err = s.FederatedReaderAllows(ctx, binding, agentID, "anything"); err != nil || !allowed {
		t.Fatalf("revoked restriction = allowed %v, err %v; want true,nil", allowed, err)
	}

	stale := revoked
	stale.Revision = 3
	if _, err = s.PutBoundFederatedReaderRestrictionCAS(ctx, stale, 2); !errors.Is(err, ErrFederatedReaderRestrictionRevisionConflict) {
		t.Fatalf("stale CAS error = %v, want revision conflict", err)
	}
}

func TestFederatedReaderRestrictionBindingMismatchAndControlledRepairReset(t *testing.T) {
	ctx := context.Background()
	s := newSyncTestStore(t)
	oldBinding := federatedReaderTestBinding(t, "chain-repair", "epoch-old", "ab")
	activateFederatedReaderTestBinding(t, s, oldBinding)
	agentID := testPeerAgentID(t)
	if _, err := s.PutBoundFederatedReaderRestrictionCAS(ctx,
		federatedReaderTestRestriction(oldBinding, agentID, 1, "private"), 0); err != nil {
		t.Fatalf("create old restriction: %v", err)
	}

	if err := s.DeleteSyncControl(ctx, oldBinding.RemoteChainID); err != nil {
		t.Fatalf("DeleteSyncControl: %v", err)
	}
	newBinding := federatedReaderTestBinding(t, oldBinding.RemoteChainID, "epoch-new", "bc")
	activateFederatedReaderTestBinding(t, s, newBinding)
	if allowed, err := s.FederatedReaderAllows(ctx, newBinding, agentID, "public"); allowed ||
		!errors.Is(err, ErrFederatedReaderRestrictionBindingMismatch) {
		t.Fatalf("unexpected generation mismatch = allowed %v, err %v", allowed, err)
	}

	affected, err := s.ResetFederatedReaderRestrictionsForBinding(ctx, newBinding)
	if err != nil || affected != 1 {
		t.Fatalf("controlled reset = affected %d, err %v; want 1,nil", affected, err)
	}
	reset, err := s.GetFederatedReaderRestriction(ctx, oldBinding.RemoteChainID, agentID)
	if err != nil || reset == nil || reset.State != FederatedReaderRestrictionStateRevoked || reset.Revision != 2 {
		t.Fatalf("reset row = %#v, err %v", reset, err)
	}
	if allowed, err := s.FederatedReaderAllows(ctx, newBinding, agentID, "private"); err != nil || !allowed {
		t.Fatalf("new generation after reset = allowed %v, err %v", allowed, err)
	}
	if affected, err = s.ResetFederatedReaderRestrictionsForBinding(ctx, newBinding); err != nil || affected != 0 {
		t.Fatalf("idempotent reset = affected %d, err %v", affected, err)
	}

	reactivated := federatedReaderTestRestriction(newBinding, agentID, 3, "new-private")
	if _, err = s.PutBoundFederatedReaderRestrictionCAS(ctx, reactivated, 2); err != nil {
		t.Fatalf("reactivate against new binding: %v", err)
	}
	if allowed, err := s.FederatedReaderAllows(ctx, newBinding, agentID, "new-private.child"); err != nil || allowed {
		t.Fatalf("reactivated deny = allowed %v, err %v", allowed, err)
	}
}

func TestFederatedReaderRestrictionBoundMutationRequiresExactActiveControl(t *testing.T) {
	ctx := context.Background()
	s := newSyncTestStore(t)
	binding := federatedReaderTestBinding(t, "chain-bound", "epoch-bound", "ab")
	agentID := testPeerAgentID(t)
	restriction := federatedReaderTestRestriction(binding, agentID, 1, "private")

	if _, err := s.PutBoundFederatedReaderRestrictionCAS(ctx, restriction, 0); !errors.Is(err, ErrFederatedReaderRestrictionBindingMismatch) {
		t.Fatalf("missing control error = %v, want binding mismatch", err)
	}
	activateFederatedReaderTestBinding(t, s, binding)
	wrong := restriction
	wrong.PeerAgentID = testPeerAgentID(t)
	if _, err := s.PutBoundFederatedReaderRestrictionCAS(ctx, wrong, 0); !errors.Is(err, ErrFederatedReaderRestrictionBindingMismatch) {
		t.Fatalf("wrong peer error = %v, want binding mismatch", err)
	}
	if _, err := s.PutBoundFederatedReaderRestrictionCAS(ctx, restriction, 0); err != nil {
		t.Fatalf("matching bound mutation: %v", err)
	}

	if err := s.RunInTx(ctx, func(txStore OffchainStore) error {
		_, err := txStore.(*SQLiteStore).PutBoundFederatedReaderRestrictionCAS(ctx, restriction, 0)
		return err
	}); err == nil || !strings.Contains(err.Error(), "not permitted inside SQLite transaction") {
		t.Fatalf("nested transaction mutation error = %v", err)
	}
}

func TestFederatedReaderRestrictionCASSerializesConcurrentEditors(t *testing.T) {
	ctx := context.Background()
	s := newSyncTestStore(t)
	binding := federatedReaderTestBinding(t, "chain-cas", "epoch-cas", "ab")
	activateFederatedReaderTestBinding(t, s, binding)
	agentID := testPeerAgentID(t)
	created, err := s.PutBoundFederatedReaderRestrictionCAS(ctx,
		federatedReaderTestRestriction(binding, agentID, 1, "initial"), 0)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, denied := range []string{"editor-a", "editor-b"} {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			<-start
			update := *created
			update.Revision = 2
			update.DeniedDomains = []string{domain}
			_, err := s.PutBoundFederatedReaderRestrictionCAS(ctx, update, 1)
			errs <- err
		}(denied)
	}
	close(start)
	wg.Wait()
	close(errs)
	var successes, conflicts int
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrFederatedReaderRestrictionRevisionConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent CAS error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent CAS successes=%d conflicts=%d; want 1,1", successes, conflicts)
	}
}

func TestFederatedReaderRestrictionIsolationListingAndValidation(t *testing.T) {
	ctx := context.Background()
	s := newSyncTestStore(t)
	bindingA := federatedReaderTestBinding(t, "chain-a", "epoch-a", "ab")
	bindingB := federatedReaderTestBinding(t, "chain-b", "epoch-b", "bc")
	activateFederatedReaderTestBinding(t, s, bindingA)
	activateFederatedReaderTestBinding(t, s, bindingB)
	agentID := testPeerAgentID(t)
	if _, err := s.PutBoundFederatedReaderRestrictionCAS(ctx,
		federatedReaderTestRestriction(bindingA, agentID, 1, "private"), 0); err != nil {
		t.Fatal(err)
	}
	if allowed, err := s.FederatedReaderAllows(ctx, bindingB, agentID, "private"); err != nil || !allowed {
		t.Fatalf("peer isolation = allowed %v, err %v", allowed, err)
	}
	rows, err := s.ListFederatedReaderRestrictions(ctx, bindingA.RemoteChainID)
	if err != nil || len(rows) != 1 || rows[0].LocalAgentID != agentID {
		t.Fatalf("list = %#v, err %v", rows, err)
	}
	if rows, err = s.ListFederatedReaderRestrictions(ctx, bindingB.RemoteChainID); err != nil || len(rows) != 0 {
		t.Fatalf("empty peer list = %#v, err %v", rows, err)
	}

	invalid := federatedReaderTestRestriction(bindingA, testPeerAgentID(t), 1, "*")
	if _, err := s.PutBoundFederatedReaderRestrictionCAS(ctx, invalid, 0); err == nil {
		t.Fatal("wildcard denied domain unexpectedly accepted")
	}
	invalid.DeniedDomains = []string{"duplicate", "duplicate"}
	if _, err := s.PutBoundFederatedReaderRestrictionCAS(ctx, invalid, 0); err == nil {
		t.Fatal("duplicate denied domain unexpectedly accepted")
	}
	invalid.DeniedDomains = make([]string, MaxFederatedReaderDeniedDomains+1)
	for i := range invalid.DeniedDomains {
		invalid.DeniedDomains[i] = fmt.Sprintf("domain-%d", i)
	}
	if _, err := s.PutBoundFederatedReaderRestrictionCAS(ctx, invalid, 0); err == nil {
		t.Fatal("oversized denied-domain snapshot unexpectedly accepted")
	}
	newRevoked := federatedReaderTestRestriction(bindingA, testPeerAgentID(t), 1)
	newRevoked.State = FederatedReaderRestrictionStateRevoked
	if _, err := s.PutBoundFederatedReaderRestrictionCAS(ctx, newRevoked, 0); err == nil {
		t.Fatal("new revoked row unexpectedly accepted")
	}
}

func TestFederatedReaderRestrictionPerPeerBoundAndMalformedStateFailClosed(t *testing.T) {
	ctx := context.Background()
	s := newSyncTestStore(t)
	binding := federatedReaderTestBinding(t, "chain-limit", "epoch-limit", "ab")
	activateFederatedReaderTestBinding(t, s, binding)
	for i := 1; i <= MaxFederatedReaderRestrictionsPerPeer; i++ {
		agentID := fmt.Sprintf("%064x", i)
		if _, err := s.conn.ExecContext(ctx, `
			INSERT INTO federated_reader_restriction
			(remote_chain_id,local_agent_id,peer_agent_id,policy_epoch,remote_ca_pin,deny_all,revision,state)
			VALUES(?,?,?,?,?,?,?,?)`, binding.RemoteChainID, agentID, binding.PeerAgentID,
			binding.PolicyEpoch, binding.RemoteCAPin, 0, 1,
			FederatedReaderRestrictionStateActive); err != nil {
			t.Fatalf("seed bound row %d: %v", i, err)
		}
	}
	extra := federatedReaderTestRestriction(binding, fmt.Sprintf("%064x", MaxFederatedReaderRestrictionsPerPeer+1), 1, "private")
	if _, err := s.PutBoundFederatedReaderRestrictionCAS(ctx, extra, 0); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("per-peer bound error = %v", err)
	}

	corruptStore := newSyncTestStore(t)
	corruptBinding := federatedReaderTestBinding(t, "chain-corrupt", "epoch-corrupt", "bc")
	activateFederatedReaderTestBinding(t, corruptStore, corruptBinding)
	corruptAgent := testPeerAgentID(t)
	if _, err := corruptStore.PutBoundFederatedReaderRestrictionCAS(ctx,
		federatedReaderTestRestriction(corruptBinding, corruptAgent, 1, "private"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := corruptStore.conn.ExecContext(ctx, `
		INSERT INTO federated_reader_denied_domain(remote_chain_id,local_agent_id,domain_tag)
		VALUES(?,?,?)`, corruptBinding.RemoteChainID, corruptAgent, "*"); err != nil {
		t.Fatal(err)
	}
	if allowed, err := corruptStore.FederatedReaderAllows(ctx, corruptBinding, corruptAgent, "public"); allowed || err == nil {
		t.Fatalf("corrupt stored state = allowed %v, err %v; want false,error", allowed, err)
	}
}

func TestFederatedReaderRestrictionPersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "reader-restrictions.db")
	binding := federatedReaderTestBinding(t, "chain-durable", "epoch-durable", "ab")
	agentID := testPeerAgentID(t)

	s, err := NewSQLiteStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("open initial store: %v", err)
	}
	activateFederatedReaderTestBinding(t, s, binding)
	if _, err = s.PutBoundFederatedReaderRestrictionCAS(ctx,
		federatedReaderTestRestriction(binding, agentID, 1, "durable.private"), 0); err != nil {
		_ = s.Close()
		t.Fatalf("persist restriction: %v", err)
	}
	if err = s.Close(); err != nil {
		t.Fatalf("close initial store: %v", err)
	}

	reopened, err := NewSQLiteStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if allowed, err := reopened.FederatedReaderAllows(ctx, binding, agentID, "durable.private.child"); err != nil || allowed {
		t.Fatalf("reopened deny = allowed %v, err %v", allowed, err)
	}
	row, err := reopened.GetFederatedReaderRestriction(ctx, binding.RemoteChainID, agentID)
	if err != nil || row == nil || row.Revision != 1 || len(row.DeniedDomains) != 1 {
		t.Fatalf("reopened row = %#v, err %v", row, err)
	}
}
