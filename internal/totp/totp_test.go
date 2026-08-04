package totp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	libcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// TestRFC6238Vectors checks Code against the RFC-6238 Appendix-B SHA-1 vectors
// (seed = ASCII "12345678901234567890"), truncated to 6 digits — i.e. the exact
// values Google Authenticator produces, proving GA interop.
func TestRFC6238Vectors(t *testing.T) {
	seed := []byte("12345678901234567890") // 20 bytes, the RFC test seed
	cases := []struct {
		unix int64
		want string // last 6 digits of the RFC's 8-digit vector
	}{
		{59, "287082"},         // RFC 8-digit 94287082
		{1111111109, "081804"}, // 07081804
		{1111111111, "050471"}, // 14050471
		{1234567890, "005924"}, // 89005924
		{2000000000, "279037"}, // 69279037
	}
	for _, c := range cases {
		got := Code(seed, StepAt(c.unix))
		if got != c.want {
			t.Errorf("Code at unix=%d = %s, want %s (RFC-6238/GA interop)", c.unix, got, c.want)
		}
		if !Verify(seed, c.want, StepAt(c.unix)) {
			t.Errorf("Verify failed for the RFC vector at unix=%d", c.unix)
		}
	}
}

func TestProvisioningP2PRoundTripAndPeerBinding(t *testing.T) {
	priv, _, err := libcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := NewSecret()
	pin := sha256.Sum256([]byte("host-ca-spki"))
	sid := b32.EncodeToString([]byte{1, 2, 3, 4, 5, 6})
	relayPriv, _, _ := libcrypto.GenerateEd25519Key(rand.Reader)
	relayID, _ := peer.IDFromPrivateKey(relayPriv)
	base := "/ip4/203.0.113.7/tcp/4001/p2p/" + relayID.String()
	// Only the terminal destination identity is security-relevant to parsing;
	// the relay portion remains a normal full multiaddr.
	relay := base + "/p2p-circuit/p2p/" + id.String()
	uri := ProvisioningURIWithP2P(seed, "acme-chain", "SAGE", pin[:], "https://host:8444", sid,
		"host", "/sage/fed/1.0.0", id.String(), []string{relay})
	e, err := ParseEnrollment(uri, false)
	if err != nil {
		t.Fatalf("ParseEnrollment p2p: %v", err)
	}
	if e.Transport != "p2p" || e.PeerID != id.String() || len(e.P2PAddrs) != 1 {
		t.Fatalf("p2p fields mismatch: %+v", e)
	}

	otherPriv, _, _ := libcrypto.GenerateEd25519Key(rand.Reader)
	otherID, _ := peer.IDFromPrivateKey(otherPriv)
	bad := ProvisioningURIWithP2P(seed, "acme-chain", "SAGE", pin[:], "https://host:8444", sid,
		"host", "/sage/fed/1.0.0", otherID.String(), []string{relay})
	if _, err := ParseEnrollment(bad, false); err == nil {
		t.Fatal("accepted route whose terminal peer differs from x_sage_peer")
	}
}

func TestProvisioningP2PAcceptsLiveSixRouteBundleAndRejectsOverLimit(t *testing.T) {
	priv, _, err := libcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	relayPriv, _, err := libcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	relayID, err := peer.IDFromPrivateKey(relayPriv)
	if err != nil {
		t.Fatal(err)
	}
	destination := "/p2p/" + id.String()
	addrs := []string{
		"/ip4/127.0.0.1/tcp/4001" + destination,
		"/ip4/127.0.0.1/udp/4001/quic-v1" + destination,
		"/ip4/192.0.2.10/tcp/4001" + destination,
		"/ip4/192.0.2.10/udp/4001/quic-v1" + destination,
		"/ip4/198.51.100.10/tcp/4001/p2p/" + relayID.String() + "/p2p-circuit" + destination,
		"/ip4/198.51.100.10/udp/4001/quic-v1/p2p/" + relayID.String() + "/p2p-circuit" + destination,
	}
	seed, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256([]byte("host-ca-spki-six-routes"))
	sid := b32.EncodeToString([]byte{1, 2, 3, 4, 5, 6})
	uri := ProvisioningURIWithP2P(seed, "six-route-chain", "SAGE", pin[:], "https://host:8444", sid,
		"host", "/sage/fed/1.0.0", id.String(), addrs)
	enrollment, err := ParseEnrollment(uri, false)
	if err != nil {
		t.Fatalf("live six-route bundle must parse: %v", err)
	}
	if len(enrollment.P2PAddrs) != len(addrs) {
		t.Fatalf("parsed %d routes, want %d", len(enrollment.P2PAddrs), len(addrs))
	}

	overLimit := make([]string, MaxEnrollmentRouteCount+1)
	for i := range overLimit {
		overLimit[i] = fmt.Sprintf("/ip4/192.0.2.%d/tcp/4001%s", i+1, destination)
	}
	// Keep one live relay-shaped candidate while exercising only the count bound.
	overLimit[len(overLimit)-1] = addrs[len(addrs)-1]
	tooManyURI := ProvisioningURIWithP2P(seed, "too-many-routes", "SAGE", pin[:], "https://host:8444", sid,
		"host", "/sage/fed/1.0.0", id.String(), overLimit)
	if _, err := ParseEnrollment(tooManyURI, false); err == nil || !strings.Contains(err.Error(), "bad route count") {
		t.Fatalf("over-limit route bundle error = %v, want bad route count", err)
	}

	longHost := strings.TrimSuffix(strings.Repeat("abcdefghij.", 18), ".") + ".example"
	longRoute := "/dns4/" + longHost + "/tcp/4001" + destination
	if len(longRoute) > MaxEnrollmentRouteLength {
		t.Fatalf("test route length = %d, want <= %d", len(longRoute), MaxEnrollmentRouteLength)
	}
	overBytes := make([]string, MaxEnrollmentRouteCount)
	for i := range overBytes {
		overBytes[i] = longRoute
	}
	overBytesURI := ProvisioningURIWithP2P(seed, "too-many-route-bytes", "SAGE", pin[:], "https://host:8444", sid,
		"host", "/sage/fed/1.0.0", id.String(), overBytes)
	if _, err := ParseEnrollment(overBytesURI, false); err == nil || !strings.Contains(err.Error(), "route too large") {
		t.Fatalf("over-byte route bundle error = %v, want route too large", err)
	}
}

func TestNewSecretLen(t *testing.T) {
	s, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != SeedLen {
		t.Fatalf("seed len = %d, want %d", len(s), SeedLen)
	}
}

// TestProvisioningRoundTrip: a URI built by ProvisioningURI parses back to the
// same seed/pin/endpoint/role via ParseEnrollment.
func TestProvisioningRoundTrip(t *testing.T) {
	seed, _ := NewSecret()
	pin := sha256.Sum256([]byte("host-ca-spki"))
	sid := b32.EncodeToString([]byte{1, 2, 3, 4, 5, 6}) // 48 bits
	uri := ProvisioningURI(seed[:], "acme-chain", "SAGE", pin[:], "https://host.example:8444", sid, "host")

	e, err := ParseEnrollment(uri, false)
	if err != nil {
		t.Fatalf("ParseEnrollment: %v", err)
	}
	if string(e.Seed) != string(seed) {
		t.Error("seed round-trip mismatch")
	}
	if string(e.Pin) != string(pin[:]) {
		t.Error("pin round-trip mismatch")
	}
	if e.Endpoint != "https://host.example:8444" || e.Role != "host" || e.ChainID != "acme-chain" {
		t.Errorf("field mismatch: %+v", e)
	}
	// GA reads the same seed → same code (interop): the standard fields are present.
	if Code(e.Seed, StepAt(59)) != Code(seed[:], StepAt(59)) {
		t.Error("GA-visible code differs after round-trip")
	}
}

// TestFailClosedEnrollmentParse — acceptance #14 / redteam #3: a plain GA /
// pin-less / weak-sid / bad-endpoint / role-less QR is REFUSED.
func TestFailClosedEnrollmentParse(t *testing.T) {
	goodPin := sha256.Sum256([]byte("pin"))
	pinB64 := base64.RawURLEncoding.EncodeToString(goodPin[:])
	goodSeed := b32.EncodeToString([]byte("12345678901234567890"))
	goodSid := b32.EncodeToString([]byte{9, 9, 9, 9, 9, 9})

	bad := []string{
		// plain Google Authenticator QR — no x_sage_* at all
		"otpauth://totp/ACME:acme?secret=" + goodSeed + "&issuer=ACME&algorithm=SHA1&digits=6&period=30",
		// pin-less SAGE-ish QR
		"otpauth://totp/SAGE:acme?secret=" + goodSeed + "&x_sage_sid=" + goodSid + "&x_sage_role=host&x_sage_ep=https://h:8444",
		// short pin (16 bytes)
		"otpauth://totp/SAGE:acme?secret=" + goodSeed + "&x_sage_pin=" + base64.RawURLEncoding.EncodeToString(make([]byte, 16)) + "&x_sage_sid=" + goodSid + "&x_sage_role=host&x_sage_ep=https://h:8444",
		// weak session id (16 bits)
		"otpauth://totp/SAGE:acme?secret=" + goodSeed + "&x_sage_pin=" + pinB64 + "&x_sage_sid=" + b32.EncodeToString([]byte{1, 2}) + "&x_sage_role=host&x_sage_ep=https://h:8444",
		// bad role
		"otpauth://totp/SAGE:acme?secret=" + goodSeed + "&x_sage_pin=" + pinB64 + "&x_sage_sid=" + goodSid + "&x_sage_role=admin&x_sage_ep=https://h:8444",
		// non-https endpoint
		"otpauth://totp/SAGE:acme?secret=" + goodSeed + "&x_sage_pin=" + pinB64 + "&x_sage_sid=" + goodSid + "&x_sage_role=host&x_sage_ep=http://h:8444",
		// endpoint with a path
		"otpauth://totp/SAGE:acme?secret=" + goodSeed + "&x_sage_pin=" + pinB64 + "&x_sage_sid=" + goodSid + "&x_sage_role=host&x_sage_ep=https://h:8444/x",
		// wrong scheme
		"https://evil/totp?x_sage_pin=" + pinB64,
	}
	for i, uri := range bad {
		if _, err := ParseEnrollment(uri, false); err == nil {
			t.Errorf("case %d: expected refusal, got accept: %s", i, uri)
		}
	}

	// A pin-only reciprocal card is refused unless allowPinOnly=true.
	pinOnly := "otpauth://totp/SAGE:guest?x_sage_pin=" + pinB64 + "&x_sage_sid=" + goodSid + "&x_sage_role=guest&x_sage_ep=https://g:8444"
	if _, err := ParseEnrollment(pinOnly, false); err == nil {
		t.Error("pin-only card accepted without allowPinOnly")
	}
	e, err := ParseEnrollment(pinOnly, true)
	if err != nil {
		t.Fatalf("pin-only card refused with allowPinOnly: %v", err)
	}
	if len(e.Seed) != 0 || len(e.Pin) != PinLen {
		t.Errorf("pin-only parse wrong: seed=%d pin=%d", len(e.Seed), len(e.Pin))
	}
}
