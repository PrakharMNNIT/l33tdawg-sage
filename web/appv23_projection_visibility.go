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

var errAppV23DashboardProjectionUnavailable = errors.New(
	"app-v23 dashboard memory projection is unavailable",
)

func appV23DashboardProjectionError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %v", errAppV23DashboardProjectionUnavailable, err)
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
	if !h.appV23IsActive() {
		return nil
	}
	if h.BadgerStore == nil {
		return appV23DashboardProjectionError(errors.New("canonical store is unavailable"))
	}
	if _, err := h.BadgerStore.ValidateMemoryProjection(record); err != nil {
		return appV23DashboardProjectionError(err)
	}
	return nil
}

func (h *DashboardHandler) validateAppV23DashboardRecords(
	records []*memory.MemoryRecord,
) error {
	for _, record := range records {
		if err := h.validateAppV23DashboardRecord(record); err != nil {
			return err
		}
	}
	return nil
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
	if walkErr := h.walkAppV23CanonicalDashboardRecords(
		ctx,
		opts,
		func(record *memory.MemoryRecord) error {
			if encodeErr := encoder.Encode(portableDashboardMemoryRecord(record)); encodeErr != nil {
				return fmt.Errorf("encode app-v23 export snapshot: %w", encodeErr)
			}
			exported++
			return nil
		},
	); walkErr != nil {
		return nil, 0, walkErr
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
	if err := h.walkAppV23CanonicalDashboardRecords(
		ctx, opts,
		func(record *memory.MemoryRecord) error {
			if total >= offset && len(page) < limit {
				page = append(page, record)
			}
			total++
			return nil
		},
	); err != nil {
		return nil, 0, err
	}
	if offset >= total {
		return []*memory.MemoryRecord{}, total, nil
	}
	return page, total, nil
}

func (h *DashboardHandler) cerebrumVisibleStatsAndActivity(
	ctx context.Context,
) (*store.StoreStats, map[string]string, error) {
	if !h.appV23IsActive() {
		stats, err := h.legacyCerebrumVisibleStats(ctx)
		if err != nil {
			return nil, nil, err
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
		return stats, activity, nil
	}

	// Preserve backend-local size metadata, but never any SQL-derived counts.
	rawStats, err := h.store.GetStats(ctx)
	if err != nil {
		return nil, nil, err
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
	err = h.walkAppV23CanonicalDashboardRecords(
		ctx,
		cerebrumListOptions(store.ListOptions{Sort: "oldest"}),
		func(record *memory.MemoryRecord) error {
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
		return nil, nil, err
	}
	activity := make(map[string]string, len(latestByDomain))
	for domain, at := range latestByDomain {
		activity[domain] = at.UTC().Format(time.RFC3339Nano)
	}
	return stats, activity, nil
}

func (h *DashboardHandler) appV23CanonicalTimeline(
	ctx context.Context,
	from, to time.Time,
	domain, bucket string,
) ([]store.TimelineBucket, error) {
	counts := make(map[string]int)
	formatter, _ := h.store.(store.TimelinePeriodFormatter)
	err := h.walkAppV23CanonicalDashboardRecords(
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
