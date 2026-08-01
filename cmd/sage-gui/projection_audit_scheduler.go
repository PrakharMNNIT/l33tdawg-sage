package main

import (
	"context"
	"time"
)

const canonicalProjectionAuditDebounce = 30 * time.Second

// runCanonicalProjectionAuditScheduler owns the one process-local full
// projection-audit lane. It performs the startup audit immediately, then
// trailing-edge debounces commit notifications. A burst of app-v25 adoption
// batches therefore produces one follow-up inventory walk instead of one
// goroutine/full scan per batch. Route-local audits still join the dashboard's
// existing in-flight audit and remain independently fail-closed.
func runCanonicalProjectionAuditScheduler(
	ctx context.Context,
	requests <-chan struct{},
	debounce time.Duration,
	audit func(context.Context),
) {
	if audit == nil {
		return
	}
	audit(ctx)

	var (
		timer  *time.Timer
		timerC <-chan time.Time
	)
	stopTimer := func() {
		if timer == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer = nil
		timerC = nil
	}
	defer stopTimer()

	for {
		select {
		case <-ctx.Done():
			return
		case <-requests:
			if debounce <= 0 {
				audit(ctx)
				continue
			}
			if timer == nil {
				timer = time.NewTimer(debounce)
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(debounce)
			}
			timerC = timer.C
		case <-timerC:
			timer = nil
			timerC = nil
			audit(ctx)
		}
	}
}
