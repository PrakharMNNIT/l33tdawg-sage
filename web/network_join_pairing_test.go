package web

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestRedeemRateLimiter_ConcurrentAllowSweep exercises allow() and sweep()
// concurrently. With the limiter's internal mutex this must be race-free under
// `go test -race` (the reaper calls sweep() while guest handlers call allow()).
func TestRedeemRateLimiter_ConcurrentAllowSweep(t *testing.T) {
	rl := &redeemRateLimiter{}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ips := []string{"10.0.0.1", "10.0.0.2", "192.168.1.5"}
			for i := 0; i < 500; i++ {
				rl.allow(ips[i%len(ips)])
				if i%50 == 0 {
					rl.sweep()
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestRedeemRateLimiter_Caps confirms the 10/window cap still holds.
func TestRedeemRateLimiter_Caps(t *testing.T) {
	rl := &redeemRateLimiter{}
	allowed := 0
	for i := 0; i < 20; i++ {
		if rl.allow("1.2.3.4") {
			allowed++
		}
	}
	if allowed != redeemMaxAttempts {
		t.Fatalf("allowed %d, want %d", allowed, redeemMaxAttempts)
	}
	// A different IP has its own budget.
	if !rl.allow("5.6.7.8") {
		t.Fatal("second IP should be allowed independently")
	}
}

func TestRedeemRateLimiter_ReclaimsExpiredBucketsAtBound(t *testing.T) {
	rl := &redeemRateLimiter{attempts: make(map[string][]time.Time, redeemMaxTrackedIPs)}
	expired := time.Now().Add(-redeemWindow - time.Second)
	for i := 0; i < redeemMaxTrackedIPs; i++ {
		rl.attempts[fmt.Sprintf("198.51.100.%d", i)] = []time.Time{expired}
	}

	require.True(t, rl.allow("203.0.113.1"))
	require.Len(t, rl.attempts, 1)
	require.Contains(t, rl.attempts, "203.0.113.1")
}

func TestRedeemRateLimiter_CapsLiveDistinctIPBuckets(t *testing.T) {
	rl := &redeemRateLimiter{}
	for i := 0; i < redeemMaxTrackedIPs; i++ {
		require.True(t, rl.allow(fmt.Sprintf("2001:db8::%x", i)))
	}

	require.False(t, rl.allow("2001:db8::ffff:ffff"))
	require.Len(t, rl.attempts, redeemMaxTrackedIPs)
}
