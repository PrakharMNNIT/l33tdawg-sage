package metrics

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
)

// EmbedderStatus is the health checker's view of the embedding provider, refreshed by
// the node's background watchdog. It lets /ready report whether SEMANTIC recall is
// actually available — a down embedder silently degrades hybrid recall to keyword-only.
type EmbedderStatus struct {
	Checked  bool   `json:"checked"`            // has the watchdog probed yet?
	OK       bool   `json:"ok"`                 // reachable this probe
	Semantic bool   `json:"semantic"`           // true=meaning-based (Ollama/…); false=hash fallback
	Provider string `json:"provider,omitempty"` // e.g. "ollama"
	Model    string `json:"model,omitempty"`    // e.g. "nomic-embed-text"
	Detail   string `json:"detail,omitempty"`   // error summary when down
}

// VoterStatus is the health checker's view of the memory auto-voter, refreshed
// every poll tick by the voter loop. It lets /ready show whether memories can
// actually leave status='proposed' on this node — with no voter anywhere,
// submissions strand at proposed forever with no other signal. Informational
// only: it NEVER gates readiness, because a voter-less node is a legitimate
// deployment (another validator may vote memories through).
type VoterStatus struct {
	Checked                  bool    `json:"checked"`                     // has the voter reported yet?
	Running                  bool    `json:"running"`                     // voter goroutine live right now
	ValidatorID              string  `json:"validator_id,omitempty"`      // hex consensus pubkey the voter signs with
	LastVoteUnix             int64   `json:"last_vote_unix,omitempty"`    // when this node last broadcast a memory vote (0 = never this session)
	OldestProposedAgeSeconds float64 `json:"oldest_proposed_age_seconds"` // node-local stuck-memory watermark
	PendingProposed          int     `json:"pending_proposed"`            // node-local count of status='proposed'
}

// ScopedProjectionStatus reports whether AppHash-covered v11.9 scoped content
// has been verified into this node's local serving projection. Consensus can
// remain healthy while this is false, but the node must not advertise serving
// readiness until canonical scoped records are queryable locally.
type ScopedProjectionStatus struct {
	Checked  bool   `json:"checked"`
	Required bool   `json:"required"`
	OK       bool   `json:"ok"`
	Records  int    `json:"records"`
	Rebuilt  int    `json:"rebuilt"`
	Detail   string `json:"detail,omitempty"`
}

// VendoredAgentEnrollmentStatus reports whether an explicitly configured
// first-party companion has its exact committed app-v23 policy. A configured
// companion is a serving dependency: advertising readiness while it remains
// mute would hide a broken installation behind an otherwise healthy node.
type VendoredAgentEnrollmentStatus struct {
	Checked  bool   `json:"checked"`
	Required bool   `json:"required"`
	OK       bool   `json:"ok"`
	State    string `json:"state,omitempty"`
}

// CanonicalMemoryProjectionStatus reports whether the complete ordinary-memory
// SQL serving projection has been checked against the canonical Badger
// envelopes required by app-v23. It deliberately contains no record counts,
// domains, IDs, or error strings: /ready is public and must not become an
// inventory side channel.
type CanonicalMemoryProjectionStatus struct {
	Checked          bool   `json:"checked"`
	Required         bool   `json:"required"`
	OK               bool   `json:"ok"`
	State            string `json:"state"`
	LegacyCompatible bool   `json:"legacy_compatible,omitempty"`
	Quarantined      bool   `json:"quarantined,omitempty"`
}

type canonicalMemoryProjectionProvider func() CanonicalMemoryProjectionStatus

// AppV25MaintenanceStatus reports whether this running process has verified
// the automatic legacy-memory adoption cutoff. Recovery means only localized
// historical rows remain preserved; it is operational but degraded.
type AppV25MaintenanceStatus struct {
	Checked  bool   `json:"checked"`
	Required bool   `json:"required"`
	OK       bool   `json:"ok"`
	Recovery bool   `json:"recovery,omitempty"`
	State    string `json:"state"`
}

type appV25MaintenanceProvider func() AppV25MaintenanceStatus

// HealthChecker tracks the health status of dependencies.
// EmbeddingSpaceStatus reports whether the store's committed vectors all live in
// the vector space the active embedder produces. A node booted configured for
// one space over a store written in another does not error: recall filters by
// embedding_provider = active space, so every row in a foreign space silently
// becomes invisible. That is a quality loss, not an outage — so it surfaces as a
// queryable degraded status and a loud boot log rather than a refusal to start,
// which would brick a deliberate re-embed migration (the exact legitimate case).
type EmbeddingSpaceStatus struct {
	Checked       bool           `json:"checked"`                  // has the boot check run?
	OK            bool           `json:"ok"`                       // no committed rows in a foreign non-empty space
	ActiveSpace   string         `json:"active_space,omitempty"`   // SpaceID the node writes and queries now
	ForeignRows   int            `json:"foreign_rows,omitempty"`   // committed rows the active space cannot see
	ForeignSpaces map[string]int `json:"foreign_spaces,omitempty"` // foreign space id -> row count
}

type HealthChecker struct {
	postgresOK     atomic.Bool
	cometbftOK     atomic.Bool
	embedder       atomic.Value // EmbedderStatus, set by SetEmbedderHealth
	embeddingSpace atomic.Value // EmbeddingSpaceStatus, set once at boot by the store-vs-config space check
	voter          atomic.Value // VoterStatus, set by SetVoterStatus
	scoped         atomic.Value // ScopedProjectionStatus, set by recovery wiring
	vendored       atomic.Value // VendoredAgentEnrollmentStatus, set by bootstrap/repair wiring
	canonical      atomic.Value // canonicalMemoryProjectionProvider, wired after the final Badger store is selected
	maintenance    atomic.Value // appV25MaintenanceProvider, current-process migration proof
	Version        string
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{}
}

// SetEmbedderHealth records the latest embedding-provider probe (called by the node's
// watchdog). Until the first call, the embedder reads as not-yet-checked.
func (h *HealthChecker) SetEmbedderHealth(s EmbedderStatus) {
	s.Checked = true
	h.embedder.Store(s)
}

func (h *HealthChecker) embedderStatus() EmbedderStatus {
	if v, ok := h.embedder.Load().(EmbedderStatus); ok {
		return v
	}
	return EmbedderStatus{}
}

// SetEmbeddingSpaceStatus records the boot-time comparison of the store's
// committed vector spaces against the active embedder's space. Called once at
// startup; until then the check reads as not-yet-run.
func (h *HealthChecker) SetEmbeddingSpaceStatus(s EmbeddingSpaceStatus) {
	s.Checked = true
	h.embeddingSpace.Store(s)
}

func (h *HealthChecker) embeddingSpaceStatus() EmbeddingSpaceStatus {
	if v, ok := h.embeddingSpace.Load().(EmbeddingSpaceStatus); ok {
		return v
	}
	return EmbeddingSpaceStatus{}
}

// SetVoterStatus records the memory auto-voter's latest self-report (called by
// the voter loop each poll tick). Until the first call, the voter reads as
// not-yet-checked. Informational only — it never changes the
// ready/degraded/not_ready decision; the alerting surface for a stuck backlog
// is the sage_proposed_oldest_age_seconds gauge.
func (h *HealthChecker) SetVoterStatus(s VoterStatus) {
	s.Checked = true
	h.voter.Store(s)
}

func (h *HealthChecker) voterStatus() VoterStatus {
	if v, ok := h.voter.Load().(VoterStatus); ok {
		return v
	}
	return VoterStatus{}
}

// SetScopedProjectionStatus records the latest canonical projection rebuild.
// Callers set Required only when canonical scoped envelopes actually exist, so
// pre-v20 nodes and empty app-v20 scopes do not acquire a synthetic dependency.
func (h *HealthChecker) SetScopedProjectionStatus(s ScopedProjectionStatus) {
	s.Checked = true
	h.scoped.Store(s)
}

func (h *HealthChecker) scopedProjectionStatus() ScopedProjectionStatus {
	if v, ok := h.scoped.Load().(ScopedProjectionStatus); ok {
		return v
	}
	return ScopedProjectionStatus{}
}

// SetVendoredAgentEnrollmentStatus records the first-party companion's exact
// enrollment state. State is a finite, non-sensitive machine label suitable
// for readiness responses; detailed repair failures stay in local logs.
func (h *HealthChecker) SetVendoredAgentEnrollmentStatus(s VendoredAgentEnrollmentStatus) {
	s.Checked = true
	h.vendored.Store(s)
}

func (h *HealthChecker) vendoredAgentEnrollmentStatus() VendoredAgentEnrollmentStatus {
	if v, ok := h.vendored.Load().(VendoredAgentEnrollmentStatus); ok {
		return v
	}
	return VendoredAgentEnrollmentStatus{}
}

// SetCanonicalMemoryProjectionProvider wires the final Badger-backed
// process-local audit view into /ready. A provider is used instead of a copied
// status because CEREBRUM collection walks can discover or clear quarantine
// after startup. The callback is installed before listeners serve.
func (h *HealthChecker) SetCanonicalMemoryProjectionProvider(
	provider func() CanonicalMemoryProjectionStatus,
) {
	if provider == nil {
		return
	}
	h.canonical.Store(canonicalMemoryProjectionProvider(provider))
}

func (h *HealthChecker) canonicalMemoryProjectionStatus() CanonicalMemoryProjectionStatus {
	if provider, ok := h.canonical.Load().(canonicalMemoryProjectionProvider); ok && provider != nil {
		return provider()
	}
	return CanonicalMemoryProjectionStatus{State: "unchecked"}
}

func (h *HealthChecker) SetAppV25MaintenanceProvider(
	provider func() AppV25MaintenanceStatus,
) {
	if provider == nil {
		return
	}
	h.maintenance.Store(appV25MaintenanceProvider(provider))
}

func (h *HealthChecker) appV25MaintenanceStatus() AppV25MaintenanceStatus {
	if provider, ok := h.maintenance.Load().(appV25MaintenanceProvider); ok &&
		provider != nil {
		return provider()
	}
	return AppV25MaintenanceStatus{State: "unchecked"}
}

// SetPostgresHealth updates the PostgreSQL health status.
func (h *HealthChecker) SetPostgresHealth(ok bool) {
	h.postgresOK.Store(ok)
}

// SetCometBFTHealth updates the CometBFT health status.
func (h *HealthChecker) SetCometBFTHealth(ok bool) {
	h.cometbftOK.Store(ok)
}

// IsHealthy returns true if all dependencies are healthy.
func (h *HealthChecker) IsHealthy() bool {
	return h.postgresOK.Load() && h.cometbftOK.Load()
}

// HealthHandler handles GET /health requests.
func (h *HealthChecker) HealthHandler(w http.ResponseWriter, r *http.Request) {
	status := "healthy"
	httpStatus := http.StatusOK

	if !h.IsHealthy() {
		status = "unhealthy"
		httpStatus = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	// /health is reachable through the wizard's tunnel allowlist; we keep
	// it minimal so internet visitors can't easily fingerprint a SAGE node
	// to a specific version.
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": status,
	})
}

// ReadinessHandler handles GET /ready requests.
func (h *HealthChecker) ReadinessHandler(w http.ResponseWriter, r *http.Request) {
	pgOK := h.postgresOK.Load()
	cmtOK := h.cometbftOK.Load()
	emb := h.embedderStatus()
	scoped := h.scopedProjectionStatus()
	vendored := h.vendoredAgentEnrollmentStatus()
	canonical := h.canonicalMemoryProjectionStatus()
	maintenance := h.appV25MaintenanceStatus()
	embSpace := h.embeddingSpaceStatus()

	status := "ready"
	httpStatus := http.StatusOK

	switch {
	case !pgOK || !cmtOK:
		// Core infrastructure down — genuinely not ready.
		status = "not_ready"
		httpStatus = http.StatusServiceUnavailable
	case scoped.Required && (!scoped.Checked || !scoped.OK):
		// Canonical scoped content exists but the local serving projection is
		// absent, locked, or failed verification. Reporting ready here would let
		// a state-synced replica silently serve an incomplete selected domain.
		status = "not_ready"
		httpStatus = http.StatusServiceUnavailable
	case vendored.Required && (!vendored.Checked || !vendored.OK):
		// A configured first-party application must not be reported ready until
		// its exact consensus enrollment and owned home domain are confirmed.
		status = "not_ready"
		httpStatus = http.StatusServiceUnavailable
	case canonical.Required && !canonical.Checked &&
		canonical.State == "checking":
		// Broad memory routes validate their bounded candidates and sealed
		// export still performs a complete walk. Do not restart-loop a healthy
		// node merely because its background aggregate audit is still warming.
		status = "degraded"
		if r.URL.Query().Get("strict") == "1" {
			httpStatus = http.StatusServiceUnavailable
		}
	case canonical.Required &&
		(!canonical.Checked || (!canonical.OK && !canonical.Quarantined)):
		// No completed audit, or an unlocalized projection failure: broad reads
		// cannot prove which records are safe, so the serving process is not ready.
		status = "not_ready"
		httpStatus = http.StatusServiceUnavailable
	case maintenance.Required && (!maintenance.Checked || !maintenance.OK):
		// The current process still has to verify the app-v25 adoption cutoff,
		// but bounded serving routes perform their own canonical checks. Keep
		// ordinary traffic available while the background inventory warms; a
		// strict readiness consumer can still wait for the complete proof. This
		// case intentionally follows the hard projection gate so maintenance
		// warm-up can never hide an unlocalized canonical failure.
		status = "degraded"
		if r.URL.Query().Get("strict") == "1" {
			httpStatus = http.StatusServiceUnavailable
		}
	case emb.Checked && emb.Semantic && !emb.OK:
		// A semantic embedder that has been probed and is down: the node still SERVES
		// (keyword recall works) but semantic/hybrid recall is unavailable. Report
		// "degraded" with HTTP 200 by default so orchestrators pick their own
		// strictness; ?strict=1 makes it a hard 503 for readiness gates that require
		// semantic recall. A hash provider (Semantic=false) is a capability, not a
		// fault, so it stays "ready".
		status = "degraded"
		if r.URL.Query().Get("strict") == "1" {
			httpStatus = http.StatusServiceUnavailable
		}
	case embSpace.Checked && !embSpace.OK:
		// The store holds committed vectors in a space the active embedder does not
		// produce; recall filters by the active space, so those rows are silently
		// invisible. The node still SERVES — this is a quality loss, not an outage —
		// so report degraded (HTTP 200) with the mismatch visible for reconciliation
		// (re-embed, or boot with the config that wrote them). ?strict=1 gates on it.
		status = "degraded"
		if r.URL.Query().Get("strict") == "1" {
			httpStatus = http.StatusServiceUnavailable
		}
	case canonical.Required && canonical.Quarantined:
		// Record-local projection faults are isolated and omitted from broad
		// reads. Keep the node operational and advertise the degraded state
		// instead of making one historical record brick every agent.
		status = "degraded"
		if r.URL.Query().Get("strict") == "1" {
			httpStatus = http.StatusServiceUnavailable
		}
	case maintenance.Required && appV25MaintenanceIsOperationallyDegraded(maintenance.State):
		// A stable current-process adoption scan has localized the historical
		// rows. Governance/signing remains in progress, but ordinary serving is
		// safe; strict operators may still choose to wait for completion. Keep
		// this after every hard projection gate so it cannot mask another fault.
		status = "degraded"
		if r.URL.Query().Get("strict") == "1" {
			httpStatus = http.StatusServiceUnavailable
		}
	case maintenance.Required && maintenance.Recovery:
		// Unconvertible historical rows remain preserved and isolated. Ordinary
		// agents continue operating while CEREBRUM reports recovery as degraded.
		status = "degraded"
		if r.URL.Query().Get("strict") == "1" {
			httpStatus = http.StatusServiceUnavailable
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":              status,
		"postgres":            pgOK,
		"cometbft":            cmtOK,
		"embedder":            emb,
		"embedding_space":     embSpace,
		"scoped_projection":   scoped,
		"vendored_agent":      vendored,
		"memory_projection":   canonical,
		"app_v25_maintenance": maintenance,
		// Informational voter/backlog block — never gates the status above
		// (a voter-less node is legitimate; peers may vote memories through).
		"voter": h.voterStatus(),
	})
}

func appV25MaintenanceIsOperationallyDegraded(state string) bool {
	switch state {
	case "migrating", "waiting", "attesting":
		return true
	default:
		return false
	}
}
