package rest

import "testing"

func TestFederatedGuestBrokerUsesSocketPeerLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8443", "[::1]:8443"} {
		if !federatedGuestBrokerLoopback(addr) {
			t.Fatalf("loopback %q was denied", addr)
		}
	}
	for _, addr := range []string{
		"192.0.2.1:8443",
		"10.0.0.4:8443",
		"",
		"127.0.0.1",
		"for=127.0.0.1:8443",
	} {
		if federatedGuestBrokerLoopback(addr) {
			t.Fatalf("non-socket/non-loopback %q was trusted", addr)
		}
	}
}
