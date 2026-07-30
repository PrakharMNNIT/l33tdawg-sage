package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
)

const appV23DashboardProjectionPageSize = 256

const appV23PartialProjectionMessage = "Some memories are temporarily hidden because their canonical state could not be verified. Your stored data was not changed."

var errAppV23DashboardProjectionUnavailable = errors.New(
	"app-v23 dashboard memory projection is unavailable",
)

// appV23ProjectionResponse is safe to expose to CEREBRUM. It deliberately
// contains no skipped count, memory identity, domain, author, status, or reason.
type appV23ProjectionResponse struct {
	Complete     bool   `json:"complete"`
	Partial      bool   `json:"partial"`
	VerifiedOnly bool   `json:"verified_only"`
	State        string `json:"state"`
	Message      string `json:"message,omitempty"`
}

func (h *DashboardHandler) appV23ProjectionResponse() *appV23ProjectionResponse {
	if !h.appV23IsActive() || h.BadgerStore == nil {
		return nil
	}
	health := h.BadgerStore.CanonicalMemoryProjectionHealth()
	complete := health.Checked && health.Required && health.OK && !health.Quarantined
	response := &appV23ProjectionResponse{
		Complete:     complete,
		Partial:      !complete,
		VerifiedOnly: true,
		State:        health.State,
	}
	if !complete {
		response.Message = appV23PartialProjectionMessage
	}
	return response
}

func appV23ProjectionResponseFromAudit(
	legacyCompatible, quarantined, subset bool,
) *appV23ProjectionResponse {
	state := store.CanonicalMemoryProjectionExact
	switch {
	case quarantined:
		state = store.CanonicalMemoryProjectionQuarantined
	case subset:
		state = store.CanonicalMemoryProjectionSubset
	case legacyCompatible:
		state = store.CanonicalMemoryProjectionLegacyCompatible
	}
	response := &appV23ProjectionResponse{
		Complete:     !quarantined,
		Partial:      quarantined,
		VerifiedOnly: true,
		State:        state,
	}
	if quarantined {
		response.Message = appV23PartialProjectionMessage
	}
	return response
}

func appV23DashboardProjectionError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", errAppV23DashboardProjectionUnavailable, err)
}

func writeAppV23DashboardProjectionFailure(w http.ResponseWriter, err error) bool {
	if !errors.Is(err, errAppV23DashboardProjectionUnavailable) {
		return false
	}
	writeError(
		w,
		http.StatusServiceUnavailable,
		"canonical memory projection is temporarily unavailable",
	)
	return true
}

// validateAppV23DashboardRecord prevents CEREBRUM from treating the SQL
// serving projection as an authority boundary. After app-v23, content may be
// serialized or used in an aggregate only when the complete SQL record matches
// the canonical Badger disclosure snapshot.
func (h *DashboardHandler) validateAppV23DashboardRecord(
	record *memory.MemoryRecord,
) error {
	_, err := h.classifyAppV23DashboardRecord(record)
	return err
}

func (h *DashboardHandler) classifyAppV23DashboardRecord(
	record *memory.MemoryRecord,
) (store.MemoryProjectionDisposition, error) {
	if !h.appV23IsActive() {
		return store.MemoryProjectionExact, nil
	}
	if h.BadgerStore == nil {
		return store.MemoryProjectionUnpublished,
			appV23DashboardProjectionError(errors.New("canonical store is unavailable"))
	}
	_, disposition, err := h.BadgerStore.ClassifyMemoryProjection(record)
	if err != nil {
		return disposition, appV23DashboardProjectionError(err)
	}
	return disposition, nil
}

func isAppV23LegacyUnanchoredDashboardRecord(
	disposition store.MemoryProjectionDisposition,
	err error,
) bool {
	return disposition == store.MemoryProjectionLegacyUnanchored &&
		errors.Is(err, store.ErrMemoryProjectionUnpublished) &&
		errors.Is(err, store.ErrMemoryDisclosureNotFound)
}

// filterAppV23BroadDashboardRecords omits unsafe rows before they consume a
// visible result/count. Exact/detail and export paths intentionally do not use
// this helper: they retain fail-closed behavior. Broad callers must surface the
// aggregate projection health alongside their verified result so an all-hidden
// projection can never be mistaken for a genuinely empty brain.
func (h *DashboardHandler) filterAppV23BroadDashboardRecords(
	records []*memory.MemoryRecord,
) ([]*memory.MemoryRecord, error) {
	if !h.appV23IsActive() {
		return records, nil
	}
	kept := make([]*memory.MemoryRecord, 0, len(records))
	for _, record := range records {
		disposition, err := h.classifyAppV23DashboardRecord(record)
		if err != nil {
			if isAppV23LegacyUnanchoredDashboardRecord(disposition, err) {
				continue
			}
			return nil, err
		}
		kept = append(kept, record)
	}
	return kept, nil
}

type appV23ProjectionWalkAudit struct {
	legacyCompatible bool
	quarantined      bool
	seenMemoryIDs    map[string]struct{}
}

// requireAppV23DashboardProjectionAudited performs a complete canonical
// inventory audit and returns only the verified rows' aggregates. A quarantined
// row is deliberately not an error here: broad routes omit it and surface the
// aggregate health explicitly. Backend failures and an incomplete audit still
// fail closed.
func (h *DashboardHandler) requireAppV23DashboardProjectionAudited(
	ctx context.Context,
) (*store.StoreStats, map[string]string, *appV23ProjectionResponse, error) {
	if !h.appV23IsActive() {
		return nil, nil, nil, nil
	}
	if h.BadgerStore == nil {
		return nil, nil, nil,
			appV23DashboardProjectionError(errors.New("canonical store is unavailable"))
	}
	stats, activity, projection, err := h.cerebrumVisibleStatsAndActivity(ctx)
	if err != nil {
		return nil, nil, nil, appV23DashboardProjectionError(err)
	}
	health := h.BadgerStore.CanonicalMemoryProjectionHealth()
	if !health.Checked || !health.Required {
		return nil, nil, nil, appV23DashboardProjectionError(
			errors.New("canonical memory projection audit is unavailable"),
		)
	}
	return stats, activity, projection, nil
}

// requireAppV23DashboardProjectionAvailable performs a complete canonical
// inventory audit before every memory-derived CEREBRUM read. A missing or
// filter-hidden canonical memory has no row for a route-local query to validate,
// and a previously healthy audit cannot detect later SQL tamper. Re-auditing
// here also prevents a cached graph or tag aggregate from bypassing validation.
// Emergency correctness intentionally takes priority over read performance.
// Older app versions retain their historical behavior.
func (h *DashboardHandler) requireAppV23DashboardProjectionAvailable(
	ctx context.Context,
) (*store.StoreStats, map[string]string, *appV23ProjectionResponse, error) {
	stats, activity, projection, err := h.requireAppV23DashboardProjectionAudited(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	if !h.appV23IsActive() {
		return stats, activity, projection, nil
	}
	if projection == nil || projection.Partial {
		return nil, nil, nil, appV23DashboardProjectionError(
			errors.New("canonical memory projection audit is unavailable"),
		)
	}
	return stats, activity, projection, nil
}

// AuditAppV23CanonicalMemoryProjection performs the complete, deterministic
// ordinary-memory inventory walk used by readiness. It publishes only the
// safe finite-state result through BadgerStore; no memory identifiers or raw
// counts enter the public health surface.
func (h *DashboardHandler) AuditAppV23CanonicalMemoryProjection(
	ctx context.Context,
) error {
	if h.BadgerStore == nil {
		return appV23DashboardProjectionError(errors.New("canonical store is unavailable"))
	}
	if !h.appV23IsActive() {
		h.BadgerStore.PublishCanonicalMemoryProjectionAudit(false, false, false)
		return nil
	}
	_, _, _, err := h.requireAppV23DashboardProjectionAvailable(ctx)
	return err
}

// walkAppV23CanonicalDashboardRecords pages deterministically through one SQL
// result set and validates each row before passing it to visit. It deliberately
// returns no raw count: even aggregate metadata must be derived only from
// canonically published records.
func (h *DashboardHandler) walkAppV23CanonicalDashboardRecords(
	ctx context.Context,
	opts store.ListOptions,
	visit func(*memory.MemoryRecord) error,
) error {
	if !h.appV23IsActive() {
		return errors.New("app-v23 canonical dashboard walk requested before activation")
	}
	if h.BadgerStore == nil {
		return appV23DashboardProjectionError(errors.New("canonical store is unavailable"))
	}
	opts.Limit = appV23DashboardProjectionPageSize
	opts.Offset = 0
	opts.StablePaging = true
	for offset := 0; ; offset += appV23DashboardProjectionPageSize {
		opts.Offset = offset
		records, _, err := h.store.ListMemories(ctx, opts)
		if err != nil {
			return err
		}
		for _, record := range records {
			if err := h.validateAppV23DashboardRecord(record); err != nil {
				return err
			}
			if visit != nil {
				if err := visit(record); err != nil {
					return err
				}
			}
		}
		if len(records) < appV23DashboardProjectionPageSize {
			return nil
		}
	}
}

// walkAppV23BroadDashboardRecords is the collection-safe companion to the exact
// walker above. Unsafe rows are omitted before visit, pagination, and aggregate
// counts. The audit retains only health booleans and an internal inventory; no
// hidden identity or count enters a response.
func (h *DashboardHandler) walkAppV23BroadDashboardRecords(
	ctx context.Context,
	opts store.ListOptions,
	visit func(*memory.MemoryRecord) error,
) (appV23ProjectionWalkAudit, error) {
	audit := appV23ProjectionWalkAudit{
		seenMemoryIDs: make(map[string]struct{}),
	}
	if !h.appV23IsActive() {
		return audit, errors.New("app-v23 broad dashboard walk requested before activation")
	}
	if h.BadgerStore == nil {
		return audit, appV23DashboardProjectionError(errors.New("canonical store is unavailable"))
	}
	opts.Limit = appV23DashboardProjectionPageSize
	opts.Offset = 0
	opts.StablePaging = true
	for offset := 0; ; offset += appV23DashboardProjectionPageSize {
		opts.Offset = offset
		records, _, err := h.store.ListMemories(ctx, opts)
		if err != nil {
			return audit, err
		}
		for _, record := range records {
			if record != nil {
				audit.seenMemoryIDs[record.MemoryID] = struct{}{}
			}
			disposition, projectionErr := h.classifyAppV23DashboardRecord(record)
			if projectionErr != nil {
				if isAppV23LegacyUnanchoredDashboardRecord(disposition, projectionErr) {
					audit.quarantined = true
					continue
				}
				return audit, projectionErr
			}
			if disposition == store.MemoryProjectionLegacyTerminalHashless {
				audit.legacyCompatible = true
			}
			if visit != nil {
				if visitErr := visit(record); visitErr != nil {
					return audit, visitErr
				}
			}
		}
		if len(records) < appV23DashboardProjectionPageSize {
			return audit, nil
		}
	}
}

// spoolAppV23CanonicalDashboardExport builds the entire portable backup in a
// private temporary file before the HTTP response is committed. App-v23 must
// never validate one live SQL walk and serialize a second: a projection ghost
// appearing between those walks could otherwise turn a 200 response into a
// plausible, truncated JSONL backup. The caller owns and removes the returned
// file. CreateTemp uses mode 0600, which matters because an unlocked encrypted
// node writes plaintext export content here briefly.
func (h *DashboardHandler) spoolAppV23CanonicalDashboardExport(
	ctx context.Context,
	opts store.ListOptions,
) (*os.File, int64, error) {
	snapshot, err := os.CreateTemp("", "sage-appv23-export-*.jsonl")
	if err != nil {
		return nil, 0, fmt.Errorf("create app-v23 export snapshot: %w", err)
	}
	keepSnapshot := false
	defer func() {
		if keepSnapshot {
			return
		}
		_ = snapshot.Close()
		_ = os.Remove(snapshot.Name())
	}()

	encoder := json.NewEncoder(snapshot)
	exported := 0
	seenMemoryIDs := make(map[string]struct{})
	// The sealed walk must inventory every SQL memory, including deprecated and
	// internal rows that are not portable export content. Comparing a separate
	// preflight walk with this file would create a deletion/commit race that
	// could still label a partial file as a complete backup.
	inventoryOpts := opts
	inventoryOpts.Status = ""
	inventoryOpts.ExcludeDomainPrefixes = nil
	if walkErr := h.walkAppV23CanonicalDashboardRecords(
		ctx,
		inventoryOpts,
		func(record *memory.MemoryRecord) error {
			seenMemoryIDs[record.MemoryID] = struct{}{}
			if record.Status == memory.StatusDeprecated ||
				isCerebrumInternalMemoryDomain(record.DomainTag) {
				return nil
			}
			if encodeErr := encoder.Encode(portableDashboardMemoryRecord(record)); encodeErr != nil {
				return fmt.Errorf("encode app-v23 export snapshot: %w", encodeErr)
			}
			exported++
			return nil
		},
	); walkErr != nil {
		return nil, 0, walkErr
	}
	canonicalMemoryIDs, inventoryErr := store.CanonicalMemoryIDs(h.BadgerStore)
	if inventoryErr != nil {
		return nil, 0, appV23DashboardProjectionError(inventoryErr)
	}
	for _, memoryID := range canonicalMemoryIDs {
		if _, ok := seenMemoryIDs[memoryID]; !ok {
			return nil, 0, appV23DashboardProjectionError(
				errors.New("serving projection is missing canonical memory records"),
			)
		}
	}
	if exported == 0 {
		if encodeErr := encoder.Encode(dashboardExportManifest()); encodeErr != nil {
			return nil, 0, fmt.Errorf("encode app-v23 export manifest: %w", encodeErr)
		}
	}

	info, err := snapshot.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("stat app-v23 export snapshot: %w", err)
	}
	if _, seekErr := snapshot.Seek(0, io.SeekStart); seekErr != nil {
		return nil, 0, fmt.Errorf("rewind app-v23 export snapshot: %w", seekErr)
	}
	keepSnapshot = true
	return snapshot, info.Size(), nil
}

// appV23CanonicalDashboardPage applies limit and offset only after the
// canonical validation walk. This keeps SQL-only crash ghosts out of both the
// returned page and its total.
func (h *DashboardHandler) appV23CanonicalDashboardPage(
	ctx context.Context,
	opts store.ListOptions,
) ([]*memory.MemoryRecord, int, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}
	page := make([]*memory.MemoryRecord, 0, limit)
	total := 0
	_, err := h.walkAppV23BroadDashboardRecords(
		ctx, opts,
		func(record *memory.MemoryRecord) error {
			if total >= offset && len(page) < limit {
				page = append(page, record)
			}
			total++
			return nil
		},
	)
	if err != nil {
		return nil, 0, err
	}
	if offset >= total {
		return []*memory.MemoryRecord{}, total, nil
	}
	return page, total, nil
}

func (h *DashboardHandler) cerebrumVisibleStatsAndActivity(
	ctx context.Context,
) (*store.StoreStats, map[string]string, *appV23ProjectionResponse, error) {
	if !h.appV23IsActive() {
		stats, err := h.legacyCerebrumVisibleStats(ctx)
		if err != nil {
			return nil, nil, nil, err
		}
		var activity map[string]string
		if provider, ok := h.store.(domainActivityProvider); ok {
			activity, _ = provider.GetDomainLastActivity(ctx)
			for domain := range activity {
				if isCerebrumInternalMemoryDomain(domain) {
					delete(activity, domain)
				}
			}
		}
		return stats, activity, nil, nil
	}

	// Preserve backend-local size metadata, but never any SQL-derived counts.
	rawStats, err := h.store.GetStats(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	stats := &store.StoreStats{
		ByDomain: make(map[string]int),
		ByStatus: make(map[string]int),
		ByAgent:  make(map[string]int),
	}
	if rawStats != nil {
		stats.DBSizeBytes = rawStats.DBSizeBytes
	}
	latestByDomain := make(map[string]time.Time)
	audit, err := h.walkAppV23BroadDashboardRecords(
		ctx,
		store.ListOptions{Sort: "oldest"},
		func(record *memory.MemoryRecord) error {
			if isCerebrumInternalMemoryDomain(record.DomainTag) {
				return nil
			}
			status := string(record.Status)
			stats.ByStatus[status]++
			stats.ByAgent[record.SubmittingAgent]++
			if stats.LastActivity == nil || record.CreatedAt.After(*stats.LastActivity) {
				at := record.CreatedAt
				stats.LastActivity = &at
			}
			if record.Status != memory.StatusDeprecated {
				stats.TotalMemories++
				stats.ByDomain[record.DomainTag]++
				if latest, ok := latestByDomain[record.DomainTag]; !ok || record.CreatedAt.After(latest) {
					latestByDomain[record.DomainTag] = record.CreatedAt
				}
			}
			return nil
		},
	)
	if err != nil {
		return nil, nil, nil, err
	}
	subsetAllowed := h.CanonicalProjectionMissingAllowedFn != nil
	canonicalMemoryIDs, inventoryErr := store.CanonicalMemoryIDs(h.BadgerStore)
	if inventoryErr != nil {
		return nil, nil, nil, appV23DashboardProjectionError(inventoryErr)
	}
	for _, memoryID := range canonicalMemoryIDs {
		if _, ok := audit.seenMemoryIDs[memoryID]; ok {
			continue
		}
		if subsetAllowed && h.CanonicalProjectionMissingAllowedFn(memoryID) {
			continue
		}
		audit.quarantined = true
		if subsetAllowed {
			h.BadgerStore.PublishCanonicalMemoryProjectionSubsetAudit(
				audit.legacyCompatible, true,
			)
		} else {
			h.BadgerStore.PublishCanonicalMemoryProjectionAudit(
				true, audit.legacyCompatible, true,
			)
		}
		return nil, nil, nil, appV23DashboardProjectionError(
			errors.New("serving projection is missing canonical memory records"),
		)
	}
	if subsetAllowed {
		h.BadgerStore.PublishCanonicalMemoryProjectionSubsetAudit(
			audit.legacyCompatible, audit.quarantined,
		)
	} else {
		h.BadgerStore.PublishCanonicalMemoryProjectionAudit(
			true, audit.legacyCompatible, audit.quarantined,
		)
	}
	activity := make(map[string]string, len(latestByDomain))
	for domain, at := range latestByDomain {
		activity[domain] = at.UTC().Format(time.RFC3339Nano)
	}
	return stats, activity, appV23ProjectionResponseFromAudit(
		audit.legacyCompatible, audit.quarantined, subsetAllowed,
	), nil
}

func (h *DashboardHandler) appV23CanonicalTimeline(
	ctx context.Context,
	from, to time.Time,
	domain, bucket string,
) ([]store.TimelineBucket, error) {
	counts := make(map[string]int)
	formatter, _ := h.store.(store.TimelinePeriodFormatter)
	_, err := h.walkAppV23BroadDashboardRecords(
		ctx,
		cerebrumListOptions(store.ListOptions{
			DomainTag:   domain,
			CreatedFrom: from.UTC().Format(time.RFC3339Nano),
			CreatedTo:   to.UTC().Format(time.RFC3339Nano),
			Sort:        "oldest",
		}),
		func(record *memory.MemoryRecord) error {
			// Keep the exact public time bounds even for a custom store whose
			// ListOptions implementation does not support CreatedFrom/CreatedTo.
			if record.CreatedAt.Before(from) || record.CreatedAt.After(to) {
				return nil
			}
			period := record.CreatedAt.UTC().Format("2006-01-02")
			if formatter != nil {
				period = formatter.FormatTimelinePeriod(record.CreatedAt, bucket)
			}
			counts[period]++
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	periods := make([]string, 0, len(counts))
	for period := range counts {
		periods = append(periods, period)
	}
	sort.Strings(periods)
	result := make([]store.TimelineBucket, 0, len(periods))
	for _, period := range periods {
		result = append(result, store.TimelineBucket{
			Period: period,
			Count:  counts[period],
			Domain: domain,
		})
	}
	return result, nil
}
