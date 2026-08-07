package federation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/l33tdawg/sage/internal/store"
)

func TestFederatedReaderRestrictionsFilterDiscoveryPlanAndQueryOverMTLS(t *testing.T) {
	source := newTestChain(t, "reader-source")
	destination := newTestChain(t, "reader-destination")
	listener := startListener(t, destination)
	domains := []string{"team.private.notes", "team.public.notes"}
	federate(t, destination, source, "https://unused.invalid", domains, 4, 0)
	federate(t, source, destination, listener.URL, domains, 4, 0)
	enableV23Pair(t, source, destination, domains)

	readerPub, readerKey, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	readerID := hex.EncodeToString(readerPub)
	enrollV23SourceReadAllAdmin(t, source, "reader-restriction-member", readerPub, 10)
	insertCommitted(t, destination, "private-memory", domains[0], "private federation note")
	insertCommitted(t, destination, "public-memory", domains[1], "public federation note")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if got, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, readerID, domains,
	); availabilityErr != nil || !reflect.DeepEqual(got, domains) {
		t.Fatalf("absent restriction must default allow: domains=%v err=%v", got, availabilityErr)
	}
	privatePlan := planV23QueryForAgent(t, source, destination, readerID, domains[0])
	privateQuery := signV23QueryAs(t, readerKey, privatePlan, &QueryRequest{
		Mode: ModeText, Query: "private federation", DomainTag: domains[0], TopK: 5,
	})
	privateResponse, err := source.mgr.QueryPeer(ctx, destination.chainID, privateQuery)
	if err != nil || len(privateResponse.Results) != 1 ||
		privateResponse.Results[0].MemoryID != "private-memory" {
		t.Fatalf("default-allowed query: response=%+v err=%v", privateResponse, err)
	}

	restriction, err := source.mgr.SetFederatedReaderRestriction(
		ctx, destination.chainID, readerID,
		store.FederatedReaderRestrictionStateActive, false, []string{"team.private"}, 0,
	)
	if err != nil || restriction.Revision != 1 {
		t.Fatalf("create subtree restriction: restriction=%+v err=%v", restriction, err)
	}
	if got, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, readerID, domains,
	); availabilityErr != nil || !reflect.DeepEqual(got, []string{domains[1]}) {
		t.Fatalf("subtree restriction did not preserve sibling: domains=%v err=%v", got, availabilityErr)
	}
	deniedPlan, err := source.mgr.PlanRecall(
		ctx, []string{destination.chainID}, readerID, domains[0],
	)
	if err != nil || len(deniedPlan.Destinations) != 0 ||
		deniedPlan.Errors[destination.chainID] != "local federation access controls deny this peer domain" {
		t.Fatalf("denied subtree remained plannable: plan=%+v err=%v", deniedPlan, err)
	}
	publicPlan := planV23QueryForAgent(t, source, destination, readerID, domains[1])
	publicQuery := signV23QueryAs(t, readerKey, publicPlan, &QueryRequest{
		Mode: ModeText, Query: "public federation", DomainTag: domains[1], TopK: 5,
	})
	publicResponse, err := source.mgr.QueryPeer(ctx, destination.chainID, publicQuery)
	if err != nil || len(publicResponse.Results) != 1 ||
		publicResponse.Results[0].MemoryID != "public-memory" {
		t.Fatalf("sibling query was denied: response=%+v err=%v", publicResponse, err)
	}

	denyAll, err := source.mgr.SetFederatedReaderRestriction(
		ctx, destination.chainID, readerID,
		store.FederatedReaderRestrictionStateActive, true, nil, 1,
	)
	if err != nil || denyAll.Revision != 2 {
		t.Fatalf("activate deny-all: restriction=%+v err=%v", denyAll, err)
	}
	if got, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, readerID, domains,
	); availabilityErr != nil || len(got) != 0 {
		t.Fatalf("deny-all discovery: domains=%v err=%v", got, availabilityErr)
	}
	if _, queryErr := source.mgr.QueryPeer(ctx, destination.chainID, publicQuery); queryErr == nil {
		t.Fatal("deny-all did not recheck and reject a previously signed query")
	}

	revoked, err := source.mgr.SetFederatedReaderRestriction(
		ctx, destination.chainID, readerID,
		store.FederatedReaderRestrictionStateRevoked, false, nil, 2,
	)
	if err != nil || revoked.Revision != 3 {
		t.Fatalf("revoke restriction: restriction=%+v err=%v", revoked, err)
	}
	if got, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, destination.chainID, readerID, domains,
	); availabilityErr != nil || !reflect.DeepEqual(got, domains) {
		t.Fatalf("revocation did not restore default allow: domains=%v err=%v", got, availabilityErr)
	}

	// Restrictions are keyed by the exact peer binding. Re-activate deny-all
	// for destination, then prove discovery, planning, and querying still work
	// against a different live peer in the same three-SAGE topology.
	if _, restrictionErr := source.mgr.SetFederatedReaderRestriction(
		ctx, destination.chainID, readerID,
		store.FederatedReaderRestrictionStateActive, true, nil, 3,
	); restrictionErr != nil {
		t.Fatalf("reactivate destination-only deny-all: %v", restrictionErr)
	}
	otherPeer := newTestChain(t, "reader-other-peer")
	otherListener := startListener(t, otherPeer)
	const otherDomain = "other.private.notes"
	federate(t, otherPeer, source, "https://unused.invalid", []string{otherDomain}, 4, 0)
	federate(t, source, otherPeer, otherListener.URL, []string{otherDomain}, 4, 0)
	enableAdditionalV23Peer(t, source, otherPeer, []string{otherDomain})
	insertCommitted(t, otherPeer, "other-memory", otherDomain, "other peer isolation note")
	if got, availabilityErr := source.mgr.AvailableRecallDomains(
		ctx, otherPeer.chainID, readerID, []string{otherDomain},
	); availabilityErr != nil || !reflect.DeepEqual(got, []string{otherDomain}) {
		t.Fatalf("restriction leaked into other peer discovery: domains=%v err=%v", got, availabilityErr)
	}
	otherPlan := planV23QueryForAgent(t, source, otherPeer, readerID, otherDomain)
	otherQuery := signV23QueryAs(t, readerKey, otherPlan, &QueryRequest{
		Mode: ModeText, Query: "other peer isolation", DomainTag: otherDomain, TopK: 5,
	})
	otherResponse, err := source.mgr.QueryPeer(ctx, otherPeer.chainID, otherQuery)
	if err != nil || len(otherResponse.Results) != 1 ||
		otherResponse.Results[0].MemoryID != "other-memory" {
		t.Fatalf("restriction leaked into other peer query: response=%+v err=%v", otherResponse, err)
	}
}

func TestFederatedReaderRestrictionMutationLinearizesWithInFlightQuery(t *testing.T) {
	source := newTestChain(t, "reader-lease-source")
	destination := newTestChain(t, "reader-lease-destination")
	queryArrived := make(chan struct{})
	releaseQuery := make(chan struct{})
	var queryRequests atomic.Int32
	listener := startBlockingQueryListener(t, destination, queryArrived, releaseQuery, &queryRequests)
	const domain = "lease.notes"
	federate(t, destination, source, "https://unused.invalid", []string{domain}, 4, 0)
	federate(t, source, destination, listener.URL, []string{domain}, 4, 0)
	enableV23Pair(t, source, destination, []string{domain})

	readerPub, readerKey, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	readerID := hex.EncodeToString(readerPub)
	enrollV23SourceReadAllAdmin(t, source, "reader-lease-member", readerPub, 10)
	insertCommitted(t, destination, "lease-memory", domain, "authorization lease note")
	plan := planV23QueryForAgent(t, source, destination, readerID, domain)
	query := signV23QueryAs(t, readerKey, plan, &QueryRequest{
		Mode: ModeText, Query: "authorization lease", DomainTag: domain, TopK: 5,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	queryDone := make(chan error, 1)
	go func() {
		_, queryErr := source.mgr.QueryPeer(ctx, destination.chainID, query)
		queryDone <- queryErr
	}()
	select {
	case <-queryArrived:
	case <-ctx.Done():
		t.Fatal("authorized query never reached peer")
	}
	mutationDone := make(chan error, 1)
	go func() {
		_, mutationErr := source.mgr.SetFederatedReaderRestriction(
			ctx, destination.chainID, readerID,
			store.FederatedReaderRestrictionStateActive, true, nil, 0,
		)
		mutationDone <- mutationErr
	}()
	select {
	case mutationErr := <-mutationDone:
		t.Fatalf("restriction completed while an authorized request held its policy snapshot: %v", mutationErr)
	case <-time.After(150 * time.Millisecond):
	}
	close(releaseQuery)
	if queryErr := <-queryDone; queryErr != nil {
		t.Fatalf("in-flight authorized query: %v", queryErr)
	}
	if mutationErr := <-mutationDone; mutationErr != nil {
		t.Fatalf("restriction mutation after query drained: %v", mutationErr)
	}
	if got := queryRequests.Load(); got != 1 {
		t.Fatalf("peer query requests = %d, want 1", got)
	}
	if _, queryErr := source.mgr.QueryPeer(ctx, destination.chainID, query); queryErr == nil {
		t.Fatal("completed restriction did not deny a stale signed query")
	}
	if got := queryRequests.Load(); got != 1 {
		t.Fatalf("denied query reached peer; query requests = %d", got)
	}
}

func startBlockingQueryListener(
	t *testing.T,
	chain *testChain,
	arrived chan<- struct{},
	release <-chan struct{},
	requests *atomic.Int32,
) *httptest.Server {
	t.Helper()
	tlsConfig, tlsErr := chain.mgr.ServerTLSConfig()
	if tlsErr != nil {
		t.Fatal(tlsErr)
	}
	router := chain.mgr.Router()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fed/v1/query" {
			if requests.Add(1) == 1 {
				close(arrived)
			}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		router.ServeHTTP(w, r)
	})
	server := httptest.NewUnstartedServer(handler)
	server.TLS = tlsConfig
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func enableAdditionalV23Peer(
	t *testing.T, initialized, fresh *testChain, domains []string,
) {
	t.Helper()
	companion, _, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	if err := fresh.badger.BootstrapAppV23Genesis(store.AppV23GenesisBootstrap{
		RootID: hex.EncodeToString(fresh.agentPub), Scope: "test-" + fresh.chainID,
		AgentID: hex.EncodeToString(companion), Profile: store.AppV23ProfileStandard,
		HomeDomain: "local-" + fresh.chainID, Clearance: 1, Capabilities: 0,
		Height: 1, BootstrapDigest: strings.Repeat("77", 32),
	}); err != nil {
		t.Fatal(err)
	}
	freshSQLite := fresh.mem.(*store.SQLiteStore)
	fresh.mgr.federatedGuestStore = freshSQLite
	fresh.mgr.queryChallengeStore = freshSQLite
	fresh.mgr.localGroupResolver = v23GroupResolverFake{"v23-test-readers": {}}
	fresh.mgr.postV23ForNextTx = func() bool { return true }

	pair := []string{initialized.chainID, fresh.chainID}
	sort.Strings(pair)
	seed := sha256.Sum256([]byte(pair[0] + "\x00" + pair[1]))
	epoch := "v23-" + pair[0] + "-" + pair[1]
	for _, direction := range [][2]*testChain{{initialized, fresh}, {fresh, initialized}} {
		local, remote := direction[0], direction[1]
		agreement, agreementErr := local.mgr.ActiveAgreement(remote.chainID)
		if agreementErr != nil {
			t.Fatal(agreementErr)
		}
		sqlite := local.mem.(*store.SQLiteStore)
		if err := sqlite.PrepareSyncControl(context.Background(), store.SyncControl{
			RemoteChainID: remote.chainID, Role: "host",
			ControllerChainID: local.chainID,
			ControllerAgentID: hex.EncodeToString(local.agentPub),
			PeerAgentID:       hex.EncodeToString(remote.agentPub),
			PolicyEpoch:       epoch, RemoteCAPin: hex.EncodeToString(agreement.PeerPubKey),
			PolicyVersion: SyncPolicyVersionPeerRBAC,
		}); err != nil {
			t.Fatal(err)
		}
		if err := sqlite.ActivateSyncControl(context.Background(), remote.chainID, epoch); err != nil {
			t.Fatal(err)
		}
		permissions := make([]store.PeerRBACDomainPermission, 0, len(domains))
		for _, domain := range domains {
			permissions = append(permissions, store.PeerRBACDomainPermission{Domain: domain, Read: true})
		}
		if _, err := sqlite.ReplaceBoundPeerRBACPolicy(context.Background(), store.PeerRBACPolicy{
			RemoteChainID: remote.chainID,
			PeerAgentID:   hex.EncodeToString(remote.agentPub),
			PolicyEpoch:   epoch, RemoteCAPin: hex.EncodeToString(agreement.PeerPubKey),
			PolicyVersion: store.CurrentPeerRBACPolicyVersion, Domains: permissions,
		}); err != nil {
			t.Fatal(err)
		}
		commit, rollback, stageErr := local.mgr.stageSeed(
			remote.chainID, seed[:], seed[:], time.Now().Unix(),
		)
		if stageErr != nil {
			t.Fatal(stageErr)
		}
		t.Cleanup(rollback)
		if err := commit(); err != nil {
			t.Fatal(err)
		}
	}
}
