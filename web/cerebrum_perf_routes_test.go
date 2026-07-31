package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/memory"
	"github.com/l33tdawg/sage/internal/store"
)

type oneShotBlockingListStore struct {
	*store.SQLiteStore
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

type graphWindowCountStore struct {
	*store.SQLiteStore
	skipTotals []bool
}

func (s *graphWindowCountStore) ListMemories(
	ctx context.Context,
	opts store.ListOptions,
) ([]*memory.MemoryRecord, int, error) {
	s.skipTotals = append(s.skipTotals, opts.SkipTotal)
	records, total, err := s.SQLiteStore.ListMemories(ctx, opts)
	if err == nil && opts.Offset == 0 {
		total = 1024
	}
	return records, total, err
}

type graphProjectionCountingStore struct {
	*store.SQLiteStore
	reads atomic.Int64
}

func (s *graphProjectionCountingStore) GetLegacyMemoryProjectionRecords(
	ctx context.Context,
	memoryIDs []string,
) ([]*store.LegacyMemoryProjectionRecord, error) {
	s.reads.Add(1)
	return s.SQLiteStore.GetLegacyMemoryProjectionRecords(ctx, memoryIDs)
}

type oneShotAfterListStore struct {
	*store.SQLiteStore
	once    sync.Once
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int64
}

func (s *oneShotAfterListStore) ListMemories(
	ctx context.Context,
	opts store.ListOptions,
) ([]*memory.MemoryRecord, int, error) {
	records, total, err := s.SQLiteStore.ListMemories(ctx, opts)
	s.calls.Add(1)
	s.once.Do(func() {
		close(s.entered)
		select {
		case <-ctx.Done():
		case <-s.release:
		}
	})
	return records, total, err
}

func (s *oneShotBlockingListStore) ListMemories(
	ctx context.Context,
	opts store.ListOptions,
) ([]*memory.MemoryRecord, int, error) {
	s.once.Do(func() {
		close(s.entered)
		select {
		case <-ctx.Done():
		case <-s.release:
		}
	})
	return s.SQLiteStore.ListMemories(ctx, opts)
}

type slowDashboardClient struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *slowDashboardClient) Write(body []byte) (int, error) {
	w.once.Do(func() {
		close(w.entered)
		<-w.release
	})
	return w.ResponseRecorder.Write(body)
}

func TestAppV23CerebrumListDoesNotHoldPublicationLocksWhileBuilding(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "list-build-memory", "list-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "list-build-memory",
		uint8(store.ClearanceInternal), true,
	)

	blocking := &oneShotBlockingListStore{
		SQLiteStore: fixture.sql,
		entered:     make(chan struct{}),
		release:     make(chan struct{}),
	}
	fixture.handler.store = blocking
	req := httptest.NewRequest(
		http.MethodGet, "/v1/dashboard/memory/list?status=proposed", nil,
	)
	markLocalCEREBRUM(fixture.handler, req)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		fixture.handler.handleListMemories(rec, req)
		close(done)
	}()

	select {
	case <-blocking.entered:
	case <-time.After(time.Second):
		t.Fatal("memory list did not reach the bounded serving query")
	}
	mutationDone := make(chan error, 1)
	go func() {
		mutationDone <- fixture.sql.SetTags(
			context.Background(), "list-build-memory", []string{"during-build"},
		)
	}()
	select {
	case err := <-mutationDone:
		require.NoError(t, err)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("memory list held the SQL publication lock while building")
	}
	close(blocking.release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("memory list did not retry after the source revision changed")
	}
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "list-build-memory")
}

func TestAppV23CerebrumListDoesNotHoldPublicationLocksDuringClientWrite(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "slow-client-memory", "list-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "slow-client-memory",
		uint8(store.ClearanceInternal), true,
	)

	req := httptest.NewRequest(
		http.MethodGet, "/v1/dashboard/memory/list?status=proposed", nil,
	)
	markLocalCEREBRUM(fixture.handler, req)
	client := &slowDashboardClient{
		ResponseRecorder: httptest.NewRecorder(),
		entered:          make(chan struct{}),
		release:          make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		fixture.handler.handleListMemories(client, req)
		close(done)
	}()
	select {
	case <-client.entered:
	case <-time.After(time.Second):
		t.Fatal("memory list did not reach the client write")
	}

	mutationDone := make(chan error, 1)
	go func() {
		mutationDone <- fixture.badger.SetMemoryDomain(
			"slow-client-memory", "domain-after-seal",
		)
	}()
	select {
	case err := <-mutationDone:
		require.NoError(t, err)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("slow client held the canonical publication lock")
	}
	close(client.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("memory list did not finish after the client resumed")
	}
	require.Equal(t, http.StatusOK, client.Code, client.Body.String())
	require.Contains(t, client.Body.String(), "slow-client-memory")
}

func TestAppV23CerebrumGraphDoesNotHoldPublicationLocksDuringClientWrite(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "slow-graph-client-memory", "graph-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "slow-graph-client-memory",
		uint8(store.ClearanceInternal), true,
	)

	req := httptest.NewRequest(
		http.MethodGet,
		"/v1/dashboard/memory/graph?status=proposed&limit=50",
		nil,
	)
	markLocalCEREBRUM(fixture.handler, req)
	client := &slowDashboardClient{
		ResponseRecorder: httptest.NewRecorder(),
		entered:          make(chan struct{}),
		release:          make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		fixture.handler.handleGraph(client, req)
		close(done)
	}()
	select {
	case <-client.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("memory graph did not reach the client write")
	}

	mutationDone := make(chan error, 1)
	go func() {
		mutationDone <- fixture.badger.SetMemoryDomain(
			"slow-graph-client-memory", "domain-after-graph-seal",
		)
	}()
	select {
	case err := <-mutationDone:
		require.NoError(t, err)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("slow graph client held the canonical publication lock")
	}
	close(client.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("memory graph did not finish after the client resumed")
	}
	require.Equal(t, http.StatusOK, client.Code, client.Body.String())
	require.Contains(t, client.Body.String(), "slow-graph-client-memory")
}

func TestAppV23CerebrumGraphPagesPastRecentQuarantine(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "older-visible-memory", "visible-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "older-visible-memory",
		uint8(store.ClearanceInternal), true,
	)

	for i := 0; i < 32; i++ {
		insertTestMemory(
			t, fixture.sql,
			"recent-quarantined-"+time.Unix(int64(i), 0).UTC().Format("150405"),
			"quarantined-domain",
		)
	}

	rec := requestLocalProjectionRoute(
		t, fixture,
		"/v1/dashboard/memory/graph?status=proposed&limit=1",
	)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "older-visible-memory")
	require.NotContains(t, rec.Body.String(), "recent-quarantined-")
}

func TestGraphFirstPaintCandidateScanIsFixed(t *testing.T) {
	require.Equal(t, appV23CerebrumInteractiveScanBudget, graphFirstPaintScanBudget)
	require.Equal(t, appV23CerebrumInteractiveScanBudget, graphCandidateScanBudget(1))
	require.Equal(t, appV23CerebrumInteractiveScanBudget, graphCandidateScanBudget(2500))
	require.Equal(t, appV23CerebrumInteractiveScanBudget,
		graphCandidateScanBudget(store.CandidateFilterScanBudget+1),
		"custom graph limits must not raise the absolute first-paint scan budget")
	require.Less(t, graphFirstPaintScanBudget, store.CandidateFilterScanBudget,
		"interactive CEREBRUM work must stay below the recall authorization budget")
	require.Less(t, graphCandidateScanBudget(2500), 40_000,
		"first paint must never scale its candidate work to the full brain")
}

func TestRepresentativeGraphWindowsCountOnlyOnce(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "count-once-memory", "count-once-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "count-once-memory",
		uint8(store.ClearanceInternal), true,
	)
	tracking := &graphWindowCountStore{SQLiteStore: fixture.sql}
	fixture.handler.store = tracking

	_, _, err := fixture.handler.appV23CanonicalDashboardCandidates(
		context.Background(),
		store.ListOptions{Limit: 50, Sort: "newest"},
		50, 1024,
	)
	require.NoError(t, err)
	require.Equal(t, []bool{false, true}, tracking.skipTotals,
		"only the first representative window should count the filtered table")
}

func TestValidatedStableGraphIsPromotedToExactRevisionCache(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	counting := &graphProjectionCountingStore{SQLiteStore: fixture.sql}
	fixture.handler.store = counting

	insertTestMemory(t, fixture.sql, "promoted-cache-memory", "cache-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "promoted-cache-memory",
		uint8(store.ClearanceInternal), true,
	)
	primeAppV23ProjectionSnapshot(t, fixture)
	fixture.handler.RunBackground = func(func(context.Context)) {}
	first := requestLocalProjectionRoute(
		t, fixture,
		"/v1/dashboard/memory/graph?status=proposed&limit=50",
	)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())

	insertTestMemory(t, fixture.sql, "promoted-cache-new-memory", "cache-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "promoted-cache-new-memory",
		uint8(store.ClearanceInternal), true,
	)
	second := requestLocalProjectionRoute(
		t, fixture,
		"/v1/dashboard/memory/graph?status=proposed&limit=50",
	)
	require.Equal(t, http.StatusOK, second.Code, second.Body.String())
	require.Contains(t, second.Body.String(), `"stale_cache":true`)
	require.EqualValues(t, 1, counting.reads.Load())

	third := requestLocalProjectionRoute(
		t, fixture,
		"/v1/dashboard/memory/graph?status=proposed&limit=50",
	)
	require.Equal(t, http.StatusOK, third.Code, third.Body.String())
	require.Equal(t, second.Body.String(), third.Body.String())
	require.EqualValues(t, 1, counting.reads.Load(),
		"the same exact source revision must not repeat stale-node validation")
}

func TestValidatedGraphCacheRejectsSQLClassificationTamper(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	const memoryID = "cached-classification-memory"
	insertTestMemory(t, fixture.sql, memoryID, "cached-classification-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, memoryID,
		uint8(store.ClearanceInternal), true,
	)
	records, err := fixture.sql.GetLegacyMemoryProjectionRecords(
		context.Background(), []string{memoryID},
	)
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.NotNil(t, records[0])
	node := graphNode{
		ID: records[0].MemoryID, Content: truncate(records[0].Content, 200),
		Domain: records[0].Domain, Status: string(records[0].Status),
		Agent:     records[0].SubmittingAgent,
		CreatedAt: records[0].CreatedAt.Format(time.RFC3339),
	}
	valid, err := fixture.handler.validateStaleGraphNodes(
		context.Background(), []graphNode{node},
	)
	require.NoError(t, err)
	require.True(t, valid)

	require.NoError(t, fixture.sql.UpdateMemoryClassification(
		context.Background(), memoryID, store.ClearanceSecret,
	))
	valid, err = fixture.handler.validateStaleGraphNodes(
		context.Background(), []graphNode{node},
	)
	require.NoError(t, err)
	require.False(t, valid,
		"a cached graph must not survive SQL classification drift from canonical state")
}

func TestRepresentativeGraphRecordsKeepsRareDomainsAndHistory(t *testing.T) {
	candidates := make([]*memory.MemoryRecord, 0, 5000)
	for i := 0; i < 5000; i++ {
		domain := "common"
		switch i {
		case 1:
			domain = "rare-new"
		case 2500:
			domain = "rare-middle"
		case 4999:
			domain = "rare-old"
		}
		candidates = append(candidates, &memory.MemoryRecord{
			MemoryID:  fmt.Sprintf("candidate-%04d", i),
			DomainTag: domain,
		})
	}

	selected := representativeGraphRecords(candidates, 2500)
	require.Len(t, selected, 2500)
	ids := make(map[string]struct{}, len(selected))
	domains := make(map[string]struct{})
	for _, record := range selected {
		ids[record.MemoryID] = struct{}{}
		domains[record.DomainTag] = struct{}{}
	}
	require.Contains(t, domains, "rare-new")
	require.Contains(t, domains, "rare-middle")
	require.Contains(t, domains, "rare-old")
	require.Contains(t, ids, "candidate-4999",
		"the representative fill must not collapse back to a newest-only prefix")
}

func TestAppV23CerebrumGraphServesValidatedCacheWhileNewMemoryRefreshes(
	t *testing.T,
) {
	fixture := newAppV23ProjectionRouteFixture(t, false)
	insertTestMemory(t, fixture.sql, "cached-graph-memory", "cached-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "cached-graph-memory",
		uint8(store.ClearanceInternal), true,
	)
	primeAppV23ProjectionSnapshot(t, fixture)

	first := requestLocalProjectionRoute(
		t, fixture,
		"/v1/dashboard/memory/graph?status=proposed&limit=50",
	)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	require.Contains(t, first.Body.String(), "cached-graph-memory")

	blocking := &oneShotBlockingListStore{
		SQLiteStore: fixture.sql,
		entered:     make(chan struct{}),
		release:     make(chan struct{}),
	}
	fixture.handler.store = blocking
	insertTestMemory(t, fixture.sql, "new-graph-memory", "new-domain")
	publishAppV23DashboardRecord(
		t, fixture.sql, fixture.badger, "new-graph-memory",
		uint8(store.ClearanceInternal), true,
	)

	req := httptest.NewRequest(
		http.MethodGet,
		"/v1/dashboard/memory/graph?status=proposed&limit=50",
		nil,
	)
	markLocalCEREBRUM(fixture.handler, req)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		fixture.handler.handleGraph(rec, req)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("additive memory write blocked graph first paint on its refresh")
	}
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "cached-graph-memory")
	require.NotContains(t, rec.Body.String(), "new-graph-memory")
	require.Contains(t, rec.Body.String(), `"stale_cache":true`)

	select {
	case <-blocking.entered:
	case <-time.After(time.Second):
		t.Fatal("validated stale response did not start a background refresh")
	}
	close(blocking.release)
	require.Eventually(t, func() bool {
		blocking.MemoryProjectionRevision(context.Background())
		fixture.handler.graphCacheMu.Lock()
		defer fixture.handler.graphCacheMu.Unlock()
		for _, entry := range fixture.handler.graphCache {
			if entry != nil && !entry.refreshing &&
				string(entry.body) != first.Body.String() {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond)
}

func TestAppV23CerebrumGraphRetainsSafeStableAliasAcrossComputeRace(
	t *testing.T,
) {
	t.Run("additive memory revision does not repeat the full scan", func(t *testing.T) {
		fixture := newAppV23ProjectionRouteFixture(t, false)
		insertTestMemory(t, fixture.sql, "race-existing-memory", "race-domain")
		publishAppV23DashboardRecord(
			t, fixture.sql, fixture.badger, "race-existing-memory",
			uint8(store.ClearanceInternal), true,
		)
		primeAppV23ProjectionSnapshot(t, fixture)

		blocking := &oneShotAfterListStore{
			SQLiteStore: fixture.sql,
			entered:     make(chan struct{}),
			release:     make(chan struct{}),
		}
		fixture.handler.store = blocking
		// The response must not wait for the stale-while-refresh follow-up. This
		// test counts only request-path full scans; production owns the queued job.
		fixture.handler.RunBackground = func(func(context.Context)) {}

		req := httptest.NewRequest(
			http.MethodGet,
			"/v1/dashboard/memory/graph?status=proposed&limit=50",
			nil,
		)
		markLocalCEREBRUM(fixture.handler, req)
		rec := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			fixture.handler.handleGraph(rec, req)
			close(done)
		}()

		select {
		case <-blocking.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("graph did not finish its first bounded source scan")
		}
		insertTestMemory(t, fixture.sql, "race-new-memory", "race-new-domain")
		publishAppV23DashboardRecord(
			t, fixture.sql, fixture.badger, "race-new-memory",
			uint8(store.ClearanceInternal), true,
		)
		close(blocking.release)

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("graph repeated or stalled after an additive source revision")
		}
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Contains(t, rec.Body.String(), "race-existing-memory")
		require.NotContains(t, rec.Body.String(), "race-new-memory",
			"the validated alias is an intentionally stale safe subset")
		require.Contains(t, rec.Body.String(), `"stale_cache":true`)
		require.EqualValues(t, 1, blocking.calls.Load(),
			"a memory-only source race must not trigger a second full candidate scan")
	})

	t.Run("changed canonical node rejects the alias", func(t *testing.T) {
		fixture := newAppV23ProjectionRouteFixture(t, false)
		insertTestMemory(t, fixture.sql, "race-revoked-memory", "race-domain")
		publishAppV23DashboardRecord(
			t, fixture.sql, fixture.badger, "race-revoked-memory",
			uint8(store.ClearanceInternal), true,
		)
		primeAppV23ProjectionSnapshot(t, fixture)

		blocking := &oneShotAfterListStore{
			SQLiteStore: fixture.sql,
			entered:     make(chan struct{}),
			release:     make(chan struct{}),
		}
		fixture.handler.store = blocking
		fixture.handler.RunBackground = func(func(context.Context)) {}
		req := httptest.NewRequest(
			http.MethodGet,
			"/v1/dashboard/memory/graph?status=proposed&limit=50",
			nil,
		)
		markLocalCEREBRUM(fixture.handler, req)
		rec := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			fixture.handler.handleGraph(rec, req)
			close(done)
		}()

		select {
		case <-blocking.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("graph did not finish its first bounded source scan")
		}
		require.NoError(t, fixture.badger.SetMemoryDomain(
			"race-revoked-memory", "canonical-domain-after-scan",
		))
		close(blocking.release)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("graph did not finish after rejecting a changed cached node")
		}
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.NotContains(t, rec.Body.String(), "race-revoked-memory",
			"a node changed after the scan must never survive stable-alias validation")
		require.NotContains(t, rec.Body.String(), `"stale_cache":true`,
			"a rejected alias must not be represented as safely reusable")
		require.GreaterOrEqual(t, blocking.calls.Load(), int64(2),
			"rejecting the unsafe alias must fall back to a fresh safe scan")
	})
}

func TestAppV23EncryptedKeywordSearchContinuesPastBoundedPage(t *testing.T) {
	fixture := newAppV23ProjectionRouteFixture(t, true)
	for _, id := range []string{"encrypted-search-a", "encrypted-search-b"} {
		insertTestMemory(t, fixture.sql, id, "encrypted-search-domain")
		publishAppV23DashboardRecord(
			t, fixture.sql, fixture.badger, id,
			uint8(store.ClearanceInternal), true,
		)
	}

	var first struct {
		Memories   []*memory.MemoryRecord `json:"memories"`
		NextCursor string                 `json:"next_cursor"`
	}
	rec := requestLocalProjectionRoute(
		t, fixture,
		"/v1/dashboard/memory/list?q=encrypted-search&status=proposed&limit=1",
	)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &first))
	require.Len(t, first.Memories, 1)
	require.NotEmpty(t, first.NextCursor)

	var second struct {
		Memories   []*memory.MemoryRecord `json:"memories"`
		NextCursor string                 `json:"next_cursor"`
	}
	rec = requestLocalProjectionRoute(
		t, fixture,
		"/v1/dashboard/memory/list?q=encrypted-search&status=proposed&limit=1&cursor="+
			url.QueryEscape(first.NextCursor),
	)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &second))
	require.Len(t, second.Memories, 1)
	require.NotEqual(t, first.Memories[0].MemoryID, second.Memories[0].MemoryID)
	require.Empty(t, second.NextCursor)
}
