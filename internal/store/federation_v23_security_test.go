package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFederatedQueryChallengeDurableSingleUseAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "federation.db")
	s, openErr := NewSQLiteStore(ctx, path)
	if openErr != nil {
		t.Fatal(openErr)
	}
	peer, _, _ := ed25519.GenerateKey(rand.Reader)
	agent, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	challenge := FederatedQueryChallenge{
		ChallengeID: strings.Repeat("11", 32), RemoteChainID: "chain-a",
		PeerAgentID: stringHex(peer), RequestedAgentID: stringHex(agent),
		DomainTag: "research.notes", AgreementBindingDigest: strings.Repeat("22", 32),
		ExpiresAt: now.Add(time.Minute).Unix(),
	}
	if err := s.IssueFederatedQueryChallenge(ctx, challenge, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, reopenErr := NewSQLiteStore(ctx, path)
	if reopenErr != nil {
		t.Fatal(reopenErr)
	}
	t.Cleanup(func() { _ = s.Close() })

	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.ConsumeFederatedQueryChallenge(ctx, challenge, now.Add(time.Second)) == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("challenge successful consumers=%d, want exactly 1", got)
	}
	if err := s.ConsumeFederatedQueryChallenge(ctx, challenge, now.Add(2*time.Second)); err == nil {
		t.Fatal("durable challenge replay was accepted")
	}
}

func TestFederatedGuestElevationReplayRollsBackGuestCAS(t *testing.T) {
	ctx := context.Background()
	s, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "guest.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	_, admin, _ := ed25519.GenerateKey(rand.Reader)
	remote, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().Unix()
	makeGuest := func(group string) FederatedGroupGuest {
		guest := FederatedGroupGuest{
			GroupID: group, RemoteChainID: "chain-a", RemoteAgentID: stringHex(remote),
			AgreementBindingDigest: strings.Repeat("33", 32), MaxClassification: 2,
			Revision: 1, State: FederatedGuestStateActive,
		}
		if err := SignFederatedGroupGuest(&guest, admin); err != nil {
			t.Fatal(err)
		}
		return guest
	}
	use := &FederatedAdminElevationUse{
		Scope: "sage-federated-guest-admin-v23", RootGeneration: 7,
		AdminID: stringHex(admin.Public().(ed25519.PublicKey)),
		Nonce:   strings.Repeat("44", 16), ExpiresAt: now + 60,
	}
	if err := s.CommitFederatedGroupGuestLocked(ctx, makeGuest("g1"), 0, use, now); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitFederatedGroupGuestLocked(ctx, makeGuest("g2"), 0, use, now); err == nil {
		t.Fatal("replayed elevation committed a second guest")
	}
	if guest, err := s.GetFederatedGroupGuest(ctx, "g2", "chain-a", stringHex(remote)); err != nil || guest != nil {
		t.Fatalf("replay failure did not roll back guest CAS: guest=%v err=%v", guest, err)
	}
}

func TestFederatedGuestLiveGroupUnionBoundAndCAS(t *testing.T) {
	ctx := context.Background()
	s, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "limits.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	_, admin, _ := ed25519.GenerateKey(rand.Reader)
	remote, _, _ := ed25519.GenerateKey(rand.Reader)
	remoteID := stringHex(remote)
	makeGuest := func(index int) FederatedGroupGuest {
		guest := FederatedGroupGuest{
			GroupID: fmt.Sprintf("g-%02d", index), RemoteChainID: "chain-a",
			RemoteAgentID: remoteID, AgreementBindingDigest: strings.Repeat("55", 32),
			MaxClassification: 1, Revision: 1, State: FederatedGuestStateActive,
		}
		if err := SignFederatedGroupGuest(&guest, admin); err != nil {
			t.Fatal(err)
		}
		return guest
	}
	for i := 0; i < MaxFederatedGuestGroupsPerAgent; i++ {
		if err := s.PutFederatedGroupGuest(ctx, makeGuest(i)); err != nil {
			t.Fatalf("insert group %d: %v", i, err)
		}
	}
	if err := s.PutFederatedGroupGuest(ctx, makeGuest(MaxFederatedGuestGroupsPerAgent)); err == nil {
		t.Fatal("live group union bound was not enforced")
	}
	first := makeGuest(0)
	first.Revision = 2
	first.State = FederatedGuestStateRevoked
	if err := SignFederatedGroupGuest(&first, admin); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFederatedGroupGuest(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFederatedGroupGuest(ctx, makeGuest(MaxFederatedGuestGroupsPerAgent)); err != nil {
		t.Fatalf("revoked link did not free live union capacity: %v", err)
	}
	reactivated := first
	reactivated.Revision = 3
	reactivated.State = FederatedGuestStateActive
	if err := SignFederatedGroupGuest(&reactivated, admin); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFederatedGroupGuest(ctx, reactivated); err == nil {
		t.Fatal("direct-store reactivation bypassed the live group union bound")
	}
	if err := s.CommitFederatedGroupGuestLocked(
		ctx, reactivated, 2, nil, time.Now().Unix(),
	); err == nil {
		t.Fatal("transactional reactivation bypassed the live group union bound")
	}
	stale := makeGuest(1)
	if err := s.CommitFederatedGroupGuestLocked(ctx, stale, 0, nil, time.Now().Unix()); !errors.Is(err, ErrAppV23RevisionConflict) {
		t.Fatalf("stale expected revision err=%v, want conflict", err)
	}
}
