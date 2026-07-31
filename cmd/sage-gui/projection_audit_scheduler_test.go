package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCanonicalProjectionAuditSchedulerDebouncesCommitBurst(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	requests := make(chan struct{}, 1)
	audited := make(chan int32, 4)
	var calls atomic.Int32
	go runCanonicalProjectionAuditScheduler(
		ctx,
		requests,
		40*time.Millisecond,
		func(context.Context) {
			audited <- calls.Add(1)
		},
	)

	select {
	case call := <-audited:
		require.Equal(t, int32(1), call, "startup audit must run immediately")
	case <-time.After(time.Second):
		t.Fatal("startup projection audit did not run")
	}

	request := func() {
		select {
		case requests <- struct{}{}:
		default:
		}
	}
	for range 20 {
		request()
	}
	time.Sleep(20 * time.Millisecond)
	for range 20 {
		request()
	}

	select {
	case call := <-audited:
		require.Equal(t, int32(2), call)
	case <-time.After(time.Second):
		t.Fatal("debounced projection audit did not run")
	}
	select {
	case call := <-audited:
		t.Fatalf("commit burst started an extra full audit: call %d", call)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestCanonicalProjectionAuditSchedulerSerializesRequestDuringAudit(
	t *testing.T,
) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	requests := make(chan struct{}, 1)
	started := make(chan int32, 3)
	releaseStartup := make(chan struct{})
	var calls atomic.Int32
	go runCanonicalProjectionAuditScheduler(
		ctx,
		requests,
		10*time.Millisecond,
		func(context.Context) {
			call := calls.Add(1)
			started <- call
			if call == 1 {
				<-releaseStartup
			}
		},
	)

	select {
	case call := <-started:
		require.Equal(t, int32(1), call)
	case <-time.After(time.Second):
		t.Fatal("startup projection audit did not start")
	}
	select {
	case requests <- struct{}{}:
	default:
		t.Fatal("request channel unexpectedly full")
	}
	close(releaseStartup)

	select {
	case call := <-started:
		require.Equal(t, int32(2), call)
	case <-time.After(time.Second):
		t.Fatal("request made during an audit was lost")
	}
	require.Equal(t, int32(2), calls.Load(),
		"the scheduler must never overlap or duplicate full audits")
}
