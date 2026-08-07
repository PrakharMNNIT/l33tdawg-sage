package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func testFederatedAgentExport(t *testing.T, s *SQLiteStore) FederatedAgentExport {
	t.Helper()
	peerID := testPeerAgentID(t)
	localID := testPeerAgentID(t)
	epoch, pin := testPeerRBACBinding()
	control := SyncControl{
		RemoteChainID: "chain-peer", Role: "host",
		ControllerChainID: "chain-local", ControllerAgentID: localID,
		PeerAgentID: peerID, PolicyEpoch: epoch, RemoteCAPin: pin,
		PolicyVersion: CurrentPeerRBACPolicyVersion,
	}
	if err := s.PrepareSyncControl(context.Background(), control); err != nil {
		t.Fatal(err)
	}
	if err := s.ActivateSyncControl(context.Background(), control.RemoteChainID, epoch); err != nil {
		t.Fatal(err)
	}
	return FederatedAgentExport{
		RemoteChainID: control.RemoteChainID, LocalAgentID: localID,
		PeerAgentID: peerID, PolicyEpoch: epoch, RemoteCAPin: pin,
		MaxClassification: 4, DomainExclusions: []string{"private.notes", "finance"},
		Revision: 1, State: FederatedAgentExportStateActive,
	}
}

func TestFederatedAgentExportBoundCASAndFailClosedLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newSyncTestStore(t)
	export := testFederatedAgentExport(t, s)
	stored, err := s.PutBoundFederatedAgentExportCAS(ctx, export, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stored.DomainExclusions, []string{"finance", "private.notes"}) {
		t.Fatalf("canonical exclusions = %v", stored.DomainExclusions)
	}
	if _, replayErr := s.PutBoundFederatedAgentExportCAS(ctx, export, 0); !errors.Is(replayErr, ErrFederatedAgentExportRevisionConflict) {
		t.Fatalf("replayed create = %v", replayErr)
	}

	paused := *stored
	paused.Revision++
	paused.State = FederatedAgentExportStatePaused
	paused, err = valueOrZero(s.PutBoundFederatedAgentExportCAS(ctx, paused, stored.Revision))
	if err != nil || paused.State != FederatedAgentExportStatePaused {
		t.Fatalf("pause = %+v err=%v", paused, err)
	}
	stale := paused
	stale.Revision++
	stale.PolicyEpoch = "replacement-generation"
	if _, staleErr := s.PutBoundFederatedAgentExportCAS(ctx, stale, paused.Revision); !errors.Is(staleErr, ErrFederatedAgentExportBindingMismatch) {
		t.Fatalf("stale generation mutation = %v", staleErr)
	}

	revoked := paused
	revoked.Revision++
	revoked.State = FederatedAgentExportStateRevoked
	if _, revokeErr := s.PutBoundFederatedAgentExportCAS(ctx, revoked, paused.Revision); revokeErr != nil {
		t.Fatal(revokeErr)
	}
	auditRows, err := s.ListFederatedAgentExports(ctx, export.RemoteChainID)
	if err != nil || len(auditRows) != 1 || auditRows[0].State != FederatedAgentExportStateRevoked {
		t.Fatalf("revoked export audit state: exports=%v err=%v", auditRows, err)
	}
	reactivated := revoked
	reactivated.Revision++
	reactivated.State = FederatedAgentExportStateActive
	if _, reactivationErr := s.PutBoundFederatedAgentExportCAS(ctx, reactivated, revoked.Revision); reactivationErr == nil {
		t.Fatal("revoked export was resurrected without a new generation-bound create")
	}
}

func TestFederatedAgentExportPersistsAcrossSQLiteRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "exports.db")
	s, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	export := testFederatedAgentExport(t, s)
	if _, putErr := s.PutBoundFederatedAgentExportCAS(ctx, export, 0); putErr != nil {
		t.Fatal(putErr)
	}
	if closeErr := s.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	reopened, err := NewSQLiteStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	got, err := reopened.GetFederatedAgentExport(ctx, export.RemoteChainID, export.LocalAgentID)
	if err != nil || got == nil || got.Revision != 1 || got.State != FederatedAgentExportStateActive {
		t.Fatalf("restarted export = %+v err=%v", got, err)
	}
	if !reflect.DeepEqual(got.DomainExclusions, []string{"finance", "private.notes"}) {
		t.Fatalf("restarted exclusions = %v", got.DomainExclusions)
	}
}

func TestFederatedAgentExportRejectsInvalidClassificationAndBinding(t *testing.T) {
	ctx := context.Background()
	s := newSyncTestStore(t)
	export := testFederatedAgentExport(t, s)
	export.MaxClassification = 5
	if _, err := s.PutBoundFederatedAgentExportCAS(ctx, export, 0); err == nil {
		t.Fatal("classification above 4 was accepted")
	}
	export.MaxClassification = 4
	export.PeerAgentID = testPeerAgentID(t)
	if _, err := s.PutBoundFederatedAgentExportCAS(ctx, export, 0); !errors.Is(err, ErrFederatedAgentExportBindingMismatch) {
		t.Fatalf("wrong peer binding = %v", err)
	}
}

func valueOrZero[T any](value *T, err error) (T, error) {
	if value == nil {
		var zero T
		return zero, err
	}
	return *value, err
}
