package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// MemoriesTotal counts memories by type, domain, and status.
	MemoriesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sage_memories_total",
		Help: "Total number of memories processed",
	}, []string{"type", "domain", "status"})

	// TxTotal counts transactions by type and result.
	TxTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sage_tx_total",
		Help: "Total number of transactions processed",
	}, []string{"type", "result"})

	// TxRejectedTotal counts rejected transactions by reason.
	TxRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sage_tx_rejected_total",
		Help: "Total number of rejected transactions",
	}, []string{"reason"})

	// VotesTotal counts votes by decision type.
	VotesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sage_votes_total",
		Help: "Total number of votes cast",
	}, []string{"decision"})

	// CorroborationsTotal counts corroborations.
	CorroborationsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sage_corroborations_total",
		Help: "Total number of corroborations",
	})

	// ChallengesTotal counts challenges.
	ChallengesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sage_challenges_total",
		Help: "Total number of challenges",
	})

	// TxDuration tracks transaction processing duration.
	TxDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sage_tx_duration_seconds",
		Help:    "Transaction processing duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"type"})

	// QueryLatency tracks query latency.
	QueryLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sage_query_latency_seconds",
		Help:    "Memory query latency in seconds",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
	}, []string{"domain"})

	// FinalizeBlockDuration tracks FinalizeBlock processing time.
	FinalizeBlockDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "sage_finalize_block_duration_seconds",
		Help:    "FinalizeBlock processing duration in seconds",
		Buckets: prometheus.DefBuckets,
	})

	// ActiveMemories tracks active memories by status.
	ActiveMemories = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sage_active_memories",
		Help: "Number of active memories by status",
	}, []string{"status"})

	// ValidatorCount tracks the number of active validators.
	ValidatorCount = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sage_validator_count",
		Help: "Number of active validators",
	})

	// EpochCurrent tracks the current epoch number.
	EpochCurrent = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sage_epoch_current",
		Help: "Current epoch number",
	})

	// PoEWeight tracks PoE weight per validator.
	PoEWeight = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sage_poe_weight",
		Help: "PoE weight per validator",
	}, []string{"validator_id"})

	// ForkBranchTotal counts how often each consensus-rule fork gate
	// took the pre-fork vs post-fork branch. Operators watch this to
	// confirm the cutover landed live on a chain: pre rolls up to zero,
	// post climbs from zero, on the same block. fork="v8" is the v8.0
	// access-control fork (HasAccessOrAncestor / processAccessGrant
	// auto-register / TxTypeDomainReassign).
	ForkBranchTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sage_fork_branch_total",
		Help: "Per-fork count of pre- vs post-fork branches taken inside fork-gated consensus handlers",
	}, []string{"fork", "branch"})

	// VoterRunning is 1 while the memory auto-voter goroutine (voter.Run) is
	// live, 0 once it exits — and 0 forever on a node where it never started
	// (gauges default to 0). A node showing 0 here cannot move memories out of
	// status='proposed' by itself.
	VoterRunning = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sage_voter_running",
		Help: "1 while the memory auto-voter goroutine is running, 0 when exited or never started",
	})

	// ProposedOldestAgeSeconds is the age of the oldest memory still in
	// status='proposed' — THE stuck-memory alarm. With a healthy voter this
	// hovers near the poll interval; a value that climbs without bound means
	// nothing is voting memories through quorum. 0 when nothing is pending.
	// NODE-LOCAL view of this node's off-chain mirror, refreshed by the voter
	// loop each poll tick.
	ProposedOldestAgeSeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sage_proposed_oldest_age_seconds",
		Help: "Age in seconds of the oldest memory still in status='proposed' (0 when none pending)",
	})

	// ProposedPendingCount is the number of memories currently in
	// status='proposed', refreshed alongside ProposedOldestAgeSeconds.
	ProposedPendingCount = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sage_proposed_pending_count",
		Help: "Number of memories currently in status='proposed'",
	})

	// The five series below publish the signer fence (internal/tx/nonce_fence.go).
	// A fence refuses EVERY signing request for one key until that key's
	// abandoned transaction is proven committed or proven refused, and nothing —
	// no timer, no budget — reopens it. That is a deliberate trade of liveness
	// for correctness, and it is only defensible while the hold is visible: an
	// invisible fence is a mystery outage for one agent. These are the alarm.

	// NonceFencesActive is the number of signing keys currently fenced. Any
	// non-zero value means at least one key cannot sign. Steady state is 0.
	NonceFencesActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sage_nonce_fences_active",
		Help: "Number of signing keys currently fenced awaiting proof of an indeterminate submission's fate",
	})

	// NonceFenceOldestAgeSeconds is how long the longest-held fence has stood.
	// This is the field to alarm on: fences normally clear in seconds once
	// reconciliation re-submits, so a value that climbs without bound means
	// reconciliation cannot reach a verdict and an operator must intervene.
	NonceFenceOldestAgeSeconds = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sage_nonce_fence_oldest_age_seconds",
		Help: "Age in seconds of the longest-held signer fence (0 when no key is fenced)",
	})

	// NonceFenceIndeterminateTotal counts submissions whose outcome this process
	// never observed — i.e. how often a fence was raised at all. Its rate is the
	// health of the local CometBFT RPC path, independent of how fences resolve.
	NonceFenceIndeterminateTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sage_nonce_fence_indeterminate_total",
		Help: "Total submissions with an unobserved outcome that fenced their signing key",
	})

	// NonceFenceReconcileFailuresTotal counts reconciliation attempts that
	// produced no verdict, labelled by typed cause. The label values are
	// internal/tx's fenceCause strings — timeout / canceled / transport /
	// decode / rpc / pending / resolver_panic / no_resolver / no_encoded_tx —
	// and "pending" is the most common in practice (the node answered but
	// declined to be definitive). See docs/reference/concepts/
	// signer-nonce-fence.md for the same list; dashboards must sum over these
	// values, not a guessed subset. Never labelled with error text: an RPC
	// error can carry the signed transaction, which must never reach a metric
	// label.
	NonceFenceReconcileFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sage_nonce_fence_reconcile_failures_total",
		Help: "Reconciliation attempts that failed to prove a fenced transaction's fate, by typed cause",
	}, []string{"cause"})

	// NonceFenceResolvedTotal counts fences that lifted, by proven fate
	// (committed/rejected). A fence lifts for no other reason, so the sum of
	// this series against NonceFenceIndeterminateTotal is exactly the number of
	// still-held fences.
	NonceFenceResolvedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sage_nonce_fence_resolved_total",
		Help: "Signer fences lifted, by the proven fate that lifted them",
	}, []string{"fate"})
)

// SetNonceFenceGauges publishes the held-fence alarm pair in one shot: how many
// signing keys are fenced and how long the oldest has been held. Called by
// internal/tx whenever a fence is raised, lifted, or re-reported, so the gauges
// track the map rather than a sampling interval.
func SetNonceFenceGauges(active int, oldestAgeSeconds float64) {
	NonceFencesActive.Set(float64(active))
	NonceFenceOldestAgeSeconds.Set(oldestAgeSeconds)
}

// RecordTx records a transaction metric.
func RecordTx(txType string, duration time.Duration, err error) {
	result := "success"
	if err != nil {
		result = "error"
	}
	TxTotal.WithLabelValues(txType, result).Inc()
	TxDuration.WithLabelValues(txType).Observe(duration.Seconds())
}

// RecordQuery records a query metric.
func RecordQuery(domain string, duration time.Duration) {
	QueryLatency.WithLabelValues(domain).Observe(duration.Seconds())
}

// SetVoterRunning flips the sage_voter_running liveness gauge (1=running,
// 0=stopped). Called by voter.Run on start and — via defer — on every exit
// path, so a crashed or cancelled voter always drops the gauge back to 0.
func SetVoterRunning(running bool) {
	if running {
		VoterRunning.Set(1)
	} else {
		VoterRunning.Set(0)
	}
}

// SetProposedBacklog publishes the stuck-memory alarm pair in one shot:
// the age of the oldest status='proposed' memory and how many are pending.
// Called by the voter loop each poll tick from this node's off-chain store.
func SetProposedBacklog(oldestAgeSeconds float64, pending int) {
	ProposedOldestAgeSeconds.Set(oldestAgeSeconds)
	ProposedPendingCount.Set(float64(pending))
}

// SetPoEWeights publishes the per-validator sage_poe_weight gauge from a freshly
// computed normalized weight set (called once per epoch boundary). Reset() drops
// every prior series first, then the current set is repopulated — so a validator
// removed via governance does not leave a frozen, misleading last-known weight.
// Gauge writes are process-local and order-independent: this touches no BadgerDB
// key and no pendingWrite, so it never affects the AppHash.
func SetPoEWeights(weights map[string]float64) {
	PoEWeight.Reset()
	for id, w := range weights {
		PoEWeight.WithLabelValues(id).Set(w)
	}
}
