package store

import "sync"

const (
	CanonicalMemoryProjectionUnchecked        = "unchecked"
	CanonicalMemoryProjectionNotRequired      = "not_required"
	CanonicalMemoryProjectionExact            = "exact"
	CanonicalMemoryProjectionLegacyCompatible = "legacy_compatible"
	CanonicalMemoryProjectionSubset           = "canonical_subset"
	CanonicalMemoryProjectionQuarantined      = "quarantined"
)

// CanonicalMemoryProjectionHealth is the process-local readiness view of the
// SQL-to-Badger memory projection. It contains no memory IDs, domains, or raw
// counts, so it is safe to surface from /ready without leaking hidden records.
//
// Checked is set only by PublishCanonicalMemoryProjectionAudit, which represents
// a complete inventory walk. An individual unsafe validation may prove the
// projection unhealthy early; an individual success never proves it healthy.
type CanonicalMemoryProjectionHealth struct {
	Checked          bool   `json:"checked"`
	Required         bool   `json:"required"`
	OK               bool   `json:"ok"`
	State            string `json:"state"`
	LegacyCompatible bool   `json:"legacy_compatible,omitempty"`
	Quarantined      bool   `json:"quarantined,omitempty"`
}

type canonicalMemoryProjectionHealthTracker struct {
	mu     sync.RWMutex
	status CanonicalMemoryProjectionHealth
}

func newCanonicalMemoryProjectionHealthTracker() *canonicalMemoryProjectionHealthTracker {
	return &canonicalMemoryProjectionHealthTracker{status: CanonicalMemoryProjectionHealth{
		State: CanonicalMemoryProjectionUnchecked,
	}}
}

// CanonicalMemoryProjectionHealth returns a race-safe snapshot for readiness
// wiring. It never reads or mutates consensus state.
func (s *BadgerStore) CanonicalMemoryProjectionHealth() CanonicalMemoryProjectionHealth {
	if s == nil || s.canonicalMemoryProjectionHealth == nil {
		return CanonicalMemoryProjectionHealth{State: CanonicalMemoryProjectionUnchecked}
	}
	s.canonicalMemoryProjectionHealth.mu.RLock()
	defer s.canonicalMemoryProjectionHealth.mu.RUnlock()
	return s.canonicalMemoryProjectionHealth.status
}

// BeginCanonicalMemoryProjectionAudit invalidates any previously completed
// inventory result before a new full walk starts. If that walk is interrupted
// or encounters a backend failure, readiness must not keep advertising a stale
// success (including a stale, localized quarantine).
func (s *BadgerStore) BeginCanonicalMemoryProjectionAudit() {
	if s == nil || s.canonicalMemoryProjectionHealth == nil {
		return
	}
	s.canonicalMemoryProjectionHealth.mu.Lock()
	status := s.canonicalMemoryProjectionHealth.status
	status.Checked = false
	status.Required = true
	status.OK = false
	s.canonicalMemoryProjectionHealth.status = status
	s.canonicalMemoryProjectionHealth.mu.Unlock()
}

// PublishCanonicalMemoryProjectionAudit publishes the result of one complete
// serving-projection inventory walk. Partial list/search requests must not call
// this method because seeing one valid page cannot clear a quarantine elsewhere.
func (s *BadgerStore) PublishCanonicalMemoryProjectionAudit(
	required, legacyCompatible, quarantined bool,
) {
	s.publishCanonicalMemoryProjectionAudit(
		required, legacyCompatible, quarantined, false,
	)
}

// PublishCanonicalMemoryProjectionSubsetAudit publishes a complete audit of
// the SQL rows this state-synced node actually stores. Every present row still
// has to match canonical Badger state; historical canonical IDs absent from SQL
// are intentional because ordinary plaintext is not part of state sync.
func (s *BadgerStore) PublishCanonicalMemoryProjectionSubsetAudit(
	legacyCompatible, quarantined bool,
) {
	s.publishCanonicalMemoryProjectionAudit(
		true, legacyCompatible, quarantined, true,
	)
}

func (s *BadgerStore) publishCanonicalMemoryProjectionAudit(
	required, legacyCompatible, quarantined, subset bool,
) {
	if s == nil || s.canonicalMemoryProjectionHealth == nil {
		return
	}
	status := CanonicalMemoryProjectionHealth{
		Checked:          true,
		Required:         required,
		OK:               !required || !quarantined,
		LegacyCompatible: legacyCompatible,
		Quarantined:      quarantined,
	}
	switch {
	case !required:
		status.State = CanonicalMemoryProjectionNotRequired
	case quarantined:
		status.State = CanonicalMemoryProjectionQuarantined
	case subset:
		status.State = CanonicalMemoryProjectionSubset
	case legacyCompatible:
		status.State = CanonicalMemoryProjectionLegacyCompatible
	default:
		status.State = CanonicalMemoryProjectionExact
	}
	s.canonicalMemoryProjectionHealth.mu.Lock()
	s.canonicalMemoryProjectionHealth.status = status
	s.canonicalMemoryProjectionHealth.mu.Unlock()
}

// observeMemoryProjectionDisposition records facts proven by an individual
// validation. Unsafe rows make health fail immediately and stick until a later
// complete audit clears them. Legacy compatibility is remembered as a
// non-failing state but does not by itself mark the inventory checked.
func (s *BadgerStore) observeMemoryProjectionDisposition(
	disposition MemoryProjectionDisposition,
) {
	if s == nil || s.canonicalMemoryProjectionHealth == nil {
		return
	}
	s.canonicalMemoryProjectionHealth.mu.Lock()
	defer s.canonicalMemoryProjectionHealth.mu.Unlock()
	status := s.canonicalMemoryProjectionHealth.status
	status.Required = true
	switch disposition {
	case MemoryProjectionLegacyTerminalHashless:
		status.LegacyCompatible = true
		if !status.Quarantined {
			status.State = CanonicalMemoryProjectionLegacyCompatible
		}
	case MemoryProjectionLegacyUnanchored, MemoryProjectionQuarantined, MemoryProjectionUnpublished:
		// A single failed validation proves the prior complete audit stale, but
		// it does not prove the failure is record-local. Only a later complete
		// inventory walk may first publish Checked=true with Quarantined=true.
		// Revalidating an already localized quarantine cannot make that completed
		// walk incomplete; a new full walk calls Begin... before touching rows.
		if !(status.Checked && status.Quarantined) {
			status.Checked = false
		}
		status.OK = false
		status.Quarantined = true
		status.State = CanonicalMemoryProjectionQuarantined
	}
	s.canonicalMemoryProjectionHealth.status = status
}
