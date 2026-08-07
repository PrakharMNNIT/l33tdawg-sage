package store

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestFederatedAgentExportSnapshotAndExclusionsCommitAtomically(t *testing.T) {
	ctx := context.Background()
	s := newSyncTestStore(t)
	export := testFederatedAgentExport(t, s)
	export.DomainExclusions = []string{"old-private"}
	if _, err := s.PutBoundFederatedAgentExportCAS(ctx, export, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.conn.ExecContext(ctx, `
		CREATE TRIGGER reject_export_exclusion
		BEFORE INSERT ON federated_agent_export_exclusion
		WHEN NEW.domain_tag='explode'
		BEGIN SELECT RAISE(ABORT, 'forced exclusion failure'); END`); err != nil {
		t.Fatal(err)
	}

	updated := export
	updated.Revision = 2
	updated.State = FederatedAgentExportStatePaused
	updated.MaxClassification = 1
	updated.DomainExclusions = []string{"explode"}
	if _, err := s.PutBoundFederatedAgentExportCAS(ctx, updated, 1); err == nil {
		t.Fatal("forced child-row failure committed the export header")
	}
	got, err := s.GetFederatedAgentExport(ctx, export.RemoteChainID, export.LocalAgentID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != 1 || got.State != FederatedAgentExportStateActive ||
		got.MaxClassification != 4 || len(got.DomainExclusions) != 1 ||
		got.DomainExclusions[0] != "old-private" {
		t.Fatalf("partial export snapshot survived rollback: %+v", got)
	}
}

func TestFederatedAgentExportAndDomainOnlyPeerRBACStayIndependent(t *testing.T) {
	ctx := context.Background()
	s := newSyncTestStore(t)
	export := testFederatedAgentExport(t, s)
	policy := PeerRBACPolicy{
		RemoteChainID: export.RemoteChainID,
		PeerAgentID:   export.PeerAgentID,
		PolicyEpoch:   export.PolicyEpoch,
		RemoteCAPin:   export.RemoteCAPin,
		PolicyVersion: CurrentPeerRBACPolicyVersion,
		Domains: []PeerRBACDomainPermission{{
			Domain: "manual-domain-only", Read: true,
		}},
	}
	if _, err := s.ReplaceBoundPeerRBACPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	missing, err := s.GetFederatedAgentExport(ctx, export.RemoteChainID, export.LocalAgentID)
	if err != nil || missing != nil {
		t.Fatalf("domain-only grant synthesized export membership: export=%+v err=%v", missing, err)
	}
	if _, err := s.PutBoundFederatedAgentExportCAS(ctx, export, 0); err != nil {
		t.Fatal(err)
	}
	stillPolicy, err := s.GetPeerRBACPolicy(ctx, export.RemoteChainID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stillPolicy.Domains) != 1 || stillPolicy.Domains[0].Domain != "manual-domain-only" ||
		!stillPolicy.Domains[0].Read {
		t.Fatalf("export membership rewrote manual domain-only policy: %+v", stillPolicy.Domains)
	}
}

func TestFederatedAgentExportConcurrentCASHasOneWinner(t *testing.T) {
	ctx := context.Background()
	s := newSyncTestStore(t)
	export := testFederatedAgentExport(t, s)
	if _, err := s.PutBoundFederatedAgentExportCAS(ctx, export, 0); err != nil {
		t.Fatal(err)
	}
	paused := export
	paused.Revision = 2
	paused.State = FederatedAgentExportStatePaused
	revoked := export
	revoked.Revision = 2
	revoked.State = FederatedAgentExportStateRevoked

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, candidate := range []FederatedAgentExport{paused, revoked} {
		candidate := candidate
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.PutBoundFederatedAgentExportCAS(ctx, candidate, 1)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrFederatedAgentExportRevisionConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent CAS result: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("CAS winners=%d conflicts=%d, want 1/1", successes, conflicts)
	}
}

func TestFederatedAgentExportValidationFailsClosed(t *testing.T) {
	ctx := context.Background()
	s := newSyncTestStore(t)
	valid := testFederatedAgentExport(t, s)
	tests := map[string]func(*FederatedAgentExport){
		"noncanonical local agent": func(e *FederatedAgentExport) { e.LocalAgentID = "agent" },
		"noncanonical peer agent":  func(e *FederatedAgentExport) { e.PeerAgentID = "peer" },
		"uppercase CA pin":         func(e *FederatedAgentExport) { e.RemoteCAPin = strings.Repeat("AB", 32) },
		"invalid state":            func(e *FederatedAgentExport) { e.State = "enabled" },
		"classification overflow":  func(e *FederatedAgentExport) { e.MaxClassification = 5 },
		"wildcard exclusion":       func(e *FederatedAgentExport) { e.DomainExclusions = []string{"*"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.DomainExclusions = append([]string(nil), valid.DomainExclusions...)
			mutate(&candidate)
			if _, err := s.PutFederatedAgentExportCAS(ctx, candidate, 0); err == nil {
				t.Fatal("unsafe export snapshot was accepted")
			}
		})
	}
}

func TestFederatedAgentExportStoredCorruptionFailsClosed(t *testing.T) {
	ctx := context.Background()
	s := newSyncTestStore(t)
	export := testFederatedAgentExport(t, s)
	if _, err := s.PutBoundFederatedAgentExportCAS(ctx, export, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.conn.ExecContext(ctx, `
		UPDATE federated_agent_export SET remote_ca_pin='not-hex'
		WHERE remote_chain_id=? AND local_agent_id=?`,
		export.RemoteChainID, export.LocalAgentID); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetFederatedAgentExport(ctx, export.RemoteChainID, export.LocalAgentID); err == nil || got != nil {
		t.Fatalf("corrupt stored export was returned: export=%+v err=%v", got, err)
	}
}
