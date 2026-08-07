package federation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/store"
)

func TestFederatedAgentExportOwnershipPauseAndUnexportOverMTLS(t *testing.T) {
	source := newTestChain(t, "export-source")
	destination := newTestChain(t, "export-destination")
	listener := startListener(t, destination)
	federate(t, destination, source, "https://unused.invalid", []string{"manual-only"}, 4, 0)
	federate(t, source, destination, listener.URL, []string{"manual-only"}, 4, 0)
	enableV23Pair(t, source, destination, []string{"manual-only"})

	readerPub, readerKey, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	readerID := hex.EncodeToString(readerPub)
	enrollV23SourceReadAllAdmin(t, source, "ordinary-reader", readerPub, 10)

	ownerPub, _, ownerKeyErr := ed25519.GenerateKey(rand.Reader)
	if ownerKeyErr != nil {
		t.Fatal(ownerKeyErr)
	}
	ownerID := hex.EncodeToString(ownerPub)
	enrollV23SourceReadAllAdmin(t, destination, "exported-owner", ownerPub, 20)
	domain := "exported.owner.notes"
	if registerErr := destination.badger.RegisterDomain(domain, ownerID, "", 21); registerErr != nil {
		t.Fatal(registerErr)
	}
	insertCommittedClassified(t, destination, "export-class-2", domain,
		"agent export visible at classification two", 2)
	insertCommittedClassified(t, destination, "export-class-3", domain,
		"agent export classification three remains hidden", 3)

	exported, err := destination.mgr.SetFederatedAgentExport(
		context.Background(), source.chainID, ownerID,
		store.FederatedAgentExportStateActive, 2, nil, 0,
	)
	if err != nil || exported.Revision != 1 {
		t.Fatalf("create agent export: export=%+v err=%v", exported, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if got, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, readerID, []string{domain, "manual-only"},
	); availabilityErr != nil || !reflect.DeepEqual(got, []string{domain, "manual-only"}) {
		t.Fatalf("agent export availability: domains=%v err=%v", got, availabilityErr)
	}
	plan := planV23QueryForAgent(t, source, destination, readerID, domain)
	query := signV23QueryAs(t, readerKey, plan, &QueryRequest{
		Mode: ModeText, Query: "agent export classification", DomainTag: domain, TopK: 5,
	})
	response, err := source.mgr.QueryPeer(ctx, destination.chainID, query)
	if err != nil || len(response.Results) != 1 || response.Results[0].MemoryID != "export-class-2" {
		t.Fatalf("classification-clamped export recall: response=%+v err=%v", response, err)
	}

	paused, err := destination.mgr.SetFederatedAgentExport(
		ctx, source.chainID, ownerID, store.FederatedAgentExportStatePaused, 2, nil, 1,
	)
	if err != nil || paused.Revision != 2 {
		t.Fatalf("pause export: export=%+v err=%v", paused, err)
	}
	if got, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, readerID, []string{domain},
	); availabilityErr != nil || len(got) != 0 {
		t.Fatalf("paused export remained readable: domains=%v err=%v", got, availabilityErr)
	}
	resumed, err := destination.mgr.SetFederatedAgentExport(
		ctx, source.chainID, ownerID, store.FederatedAgentExportStateActive, 2, nil, 2,
	)
	if err != nil || resumed.Revision != 3 {
		t.Fatalf("resume export: export=%+v err=%v", resumed, err)
	}

	newOwnerPub, _, newOwnerKeyErr := ed25519.GenerateKey(rand.Reader)
	if newOwnerKeyErr != nil {
		t.Fatal(newOwnerKeyErr)
	}
	newOwnerID := hex.EncodeToString(newOwnerPub)
	enrollV23SourceReadAllAdmin(t, destination, "replacement-owner", newOwnerPub, 30)
	if transferErr := destination.badger.TransferDomainAppV23(domain, newOwnerID, "", 31, false); transferErr != nil {
		t.Fatal(transferErr)
	}
	if got, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, readerID, []string{domain},
	); availabilityErr != nil || len(got) != 0 {
		t.Fatalf("ownership transfer silently followed old export: domains=%v err=%v", got, availabilityErr)
	}
	if _, exportErr := destination.mgr.SetFederatedAgentExport(
		ctx, source.chainID, newOwnerID, store.FederatedAgentExportStateActive, 2, nil, 0,
	); exportErr != nil {
		t.Fatal(exportErr)
	}
	if got, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, readerID, []string{domain},
	); availabilityErr != nil || !reflect.DeepEqual(got, []string{domain}) {
		t.Fatalf("explicit replacement-owner export: domains=%v err=%v", got, availabilityErr)
	}
	if _, revokeErr := destination.mgr.SetFederatedAgentExport(
		ctx, source.chainID, newOwnerID, store.FederatedAgentExportStateRevoked, 2, nil, 1,
	); revokeErr != nil {
		t.Fatal(revokeErr)
	}
	if got, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, readerID, []string{domain},
	); availabilityErr != nil || len(got) != 0 {
		t.Fatalf("unexported owner remained readable: domains=%v err=%v", got, availabilityErr)
	}
}

func insertCommittedClassified(
	t *testing.T, chain *testChain, memoryID, domain, content string, classification uint8,
) {
	t.Helper()
	insertCommitted(t, chain, memoryID, domain, content)
	if err := chain.badger.SetMemoryClassification(memoryID, classification); err != nil {
		t.Fatal(err)
	}
}
