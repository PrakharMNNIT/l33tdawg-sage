package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestFederatedGroupGuestSignedRevisionStore(t *testing.T) {
	ctx := context.Background()
	s, openErr := NewSQLiteStore(ctx, t.TempDir()+"/guest.db")
	if openErr != nil {
		t.Fatal(openErr)
	}
	t.Cleanup(func() { _ = s.Close() })
	_, operator, operatorKeyErr := ed25519.GenerateKey(rand.Reader)
	if operatorKeyErr != nil {
		t.Fatal(operatorKeyErr)
	}
	remotePub, _, remoteKeyErr := ed25519.GenerateKey(rand.Reader)
	if remoteKeyErr != nil {
		t.Fatal(remoteKeyErr)
	}
	guest := FederatedGroupGuest{
		GroupID:                     "local-research",
		RemoteChainID:               "chain-a",
		RemoteAgentID:               strings.ToLower(stringHex(remotePub)),
		AgreementBindingDigest:      strings.Repeat("ab", 32),
		MaxClassification:           2,
		Revision:                    1,
		State:                       FederatedGuestStateActive,
		AuthorityKind:               FederatedGuestAuthorityAdmin,
		AuthorityRootGeneration:     7,
		AuthorityRoleRevision:       3,
		AuthorityEnrollmentRevision: 5,
	}
	if err := SignFederatedGroupGuest(&guest, operator); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFederatedGroupGuest(ctx, guest); err != nil {
		t.Fatal(err)
	}
	got, listErr := s.ListFederatedGroupGuests(ctx, guest.RemoteChainID, guest.RemoteAgentID)
	if listErr != nil || len(got) != 1 {
		t.Fatalf("list guest: len=%d err=%v", len(got), listErr)
	}
	if err := VerifyFederatedGroupGuest(got[0]); err != nil {
		t.Fatalf("stored signature: %v", err)
	}
	if got[0].AuthorityKind != FederatedGuestAuthorityAdmin ||
		got[0].AuthorityRootGeneration != 7 ||
		got[0].AuthorityRoleRevision != 3 ||
		got[0].AuthorityEnrollmentRevision != 5 {
		t.Fatalf("stored authority lifecycle metadata changed: %+v", got[0])
	}
	identities, identitiesErr := s.ListFederatedGuestIdentities(ctx)
	if identitiesErr != nil || len(identities) != 1 {
		t.Fatalf("list guest identities: len=%d err=%v", len(identities), identitiesErr)
	}
	if identities[0].RemoteChainID != guest.RemoteChainID ||
		identities[0].RemoteAgentID != guest.RemoteAgentID ||
		identities[0].LinkCount != 1 {
		t.Fatalf("unexpected guest identity: %+v", identities[0])
	}

	rollback := guest
	rollback.Revision = 0
	if err := SignFederatedGroupGuest(&rollback, operator); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFederatedGroupGuest(ctx, rollback); err == nil {
		t.Fatal("revision rollback was accepted")
	}

	equalRevisionMutation := guest
	equalRevisionMutation.State = FederatedGuestStateRevoked
	if err := SignFederatedGroupGuest(&equalRevisionMutation, operator); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFederatedGroupGuest(ctx, equalRevisionMutation); err == nil {
		t.Fatal("equal-revision mutation was accepted")
	}
}

func stringHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for i, b := range value {
		out[i*2] = alphabet[b>>4]
		out[i*2+1] = alphabet[b&0xf]
	}
	return string(out)
}

func TestFederatedGroupGuestRejectsTamperedSignature(t *testing.T) {
	_, operator, _ := ed25519.GenerateKey(rand.Reader)
	remotePub, _, _ := ed25519.GenerateKey(rand.Reader)
	guest := FederatedGroupGuest{
		GroupID:                "g",
		RemoteChainID:          "chain-a",
		RemoteAgentID:          stringHex(remotePub),
		AgreementBindingDigest: strings.Repeat("cd", 32),
		MaxClassification:      1,
		Revision:               1,
		State:                  FederatedGuestStateActive,
	}
	if err := SignFederatedGroupGuest(&guest, operator); err != nil {
		t.Fatal(err)
	}
	guest.MaxClassification = 4
	if err := VerifyFederatedGroupGuest(guest); err == nil {
		t.Fatal("tampered signed guest was accepted")
	}
}
