package main

import "github.com/l33tdawg/sage/internal/metrics"

// vendoredAgentProtocolStatus keeps a configured first-party companion
// fail-closed until the node's next admitted transaction executes under
// app-v24. Direct app-v23 genesis remains the authenticated historical origin;
// it is not itself sufficient write readiness after the v23 lifecycle defect.
func vendoredAgentProtocolStatus(appV24ActiveForNextTx bool) metrics.VendoredAgentEnrollmentStatus {
	if !appV24ActiveForNextTx {
		return metrics.VendoredAgentEnrollmentStatus{
			Required: true,
			State:    "waiting_for_app_v24",
		}
	}
	return metrics.VendoredAgentEnrollmentStatus{
		Required: true,
		OK:       true,
		State:    "ready",
	}
}
