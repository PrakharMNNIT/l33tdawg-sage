package embedding

import (
	"container/list"
	"context"
	"crypto/sha256"
	"sync"
	"time"
)

const (
	// Completed embeddings are not retained by default because the provider is
	// shared across agents and domains. A plaintext-only process-global key would
	// otherwise create a cross-principal exact-input timing oracle. In-flight
	// coalescing remains enabled and operators of already-isolated providers may
	// opt into retained entries explicitly with NewCachedProvider.
	defaultCacheEntries = 0
	defaultCacheTTL     = 10 * time.Minute
)

type cacheEntry struct {
	key       [sha256.Size]byte
	vector    []float32
	expiresAt time.Time
}

type embedFlight struct {
	done   chan struct{}
	vector []float32
	err    error
}

// CachedProvider adds a bounded in-memory LRU and concurrent-request
// coalescing to any Provider. Vectors are copied on read/write so callers
// cannot mutate cached data. Failed calls are never cached.
type CachedProvider struct {
	Provider
	maxEntries int
	ttl        time.Duration
	now        func() time.Time

	mu      sync.Mutex
	entries map[[sha256.Size]byte]*list.Element
	lru     *list.List

	flightMu sync.Mutex
	flights  map[[sha256.Size]byte]*embedFlight
}

// NewCachedProvider wraps p with a bounded cache. Non-positive limits turn off
// retained caching while keeping singleflight request coalescing.
func NewCachedProvider(p Provider, maxEntries int, ttl time.Duration) *CachedProvider {
	if maxEntries < 0 {
		maxEntries = 0
	}
	if ttl < 0 {
		ttl = 0
	}
	return &CachedProvider{
		Provider:   p,
		maxEntries: maxEntries,
		ttl:        ttl,
		now:        time.Now,
		entries:    make(map[[sha256.Size]byte]*list.Element),
		lru:        list.New(),
		flights:    make(map[[sha256.Size]byte]*embedFlight),
	}
}

// acquireFlight joins an in-flight request for key or reserves a new one for
// the caller to execute. The cache is checked while flightMu is held so a
// completed flight cannot disappear between the cache check and reservation.
func (p *CachedProvider) acquireFlight(key [sha256.Size]byte) (*embedFlight, bool, []float32, bool) {
	p.flightMu.Lock()
	defer p.flightMu.Unlock()
	if flight, ok := p.flights[key]; ok {
		return flight, false, nil, false
	}
	if vector, ok := p.get(key); ok {
		return nil, false, vector, true
	}
	flight := &embedFlight{done: make(chan struct{})}
	p.flights[key] = flight
	return flight, true, nil, false
}

func (p *CachedProvider) finishFlight(key [sha256.Size]byte, flight *embedFlight, vector []float32, err error) {
	if err == nil {
		p.put(key, vector)
	}
	p.flightMu.Lock()
	flight.vector = cloneVector(vector)
	flight.err = err
	delete(p.flights, key)
	close(flight.done)
	p.flightMu.Unlock()
}

func waitForFlight(ctx context.Context, flight *embedFlight) ([]float32, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-flight.done:
		if flight.err != nil {
			return nil, flight.err
		}
		return cloneVector(flight.vector), nil
	}
}

// NewDefaultCachedProvider coalesces overlapping identical requests without
// retaining completed vectors across later callers.
func NewDefaultCachedProvider(p Provider) Provider {
	if p == nil {
		return nil
	}
	return NewCachedProvider(p, defaultCacheEntries, defaultCacheTTL)
}

func cloneVector(vector []float32) []float32 {
	return append([]float32(nil), vector...)
}

func (p *CachedProvider) get(key [sha256.Size]byte) ([]float32, bool) {
	if p.maxEntries == 0 || p.ttl == 0 {
		return nil, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	element, ok := p.entries[key]
	if !ok {
		return nil, false
	}
	entry := element.Value.(*cacheEntry)
	if !p.now().Before(entry.expiresAt) {
		p.lru.Remove(element)
		delete(p.entries, key)
		return nil, false
	}
	p.lru.MoveToFront(element)
	return cloneVector(entry.vector), true
}

func (p *CachedProvider) put(key [sha256.Size]byte, vector []float32) {
	if p.maxEntries == 0 || p.ttl == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if element, ok := p.entries[key]; ok {
		entry := element.Value.(*cacheEntry)
		entry.vector = cloneVector(vector)
		entry.expiresAt = p.now().Add(p.ttl)
		p.lru.MoveToFront(element)
		return
	}
	entry := &cacheEntry{key: key, vector: cloneVector(vector), expiresAt: p.now().Add(p.ttl)}
	p.entries[key] = p.lru.PushFront(entry)
	for p.lru.Len() > p.maxEntries {
		oldest := p.lru.Back()
		delete(p.entries, oldest.Value.(*cacheEntry).key)
		p.lru.Remove(oldest)
	}
}

// Embed returns a cached vector or coalesces identical concurrent work.
func (p *CachedProvider) Embed(ctx context.Context, text string) ([]float32, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := sha256.Sum256([]byte(text))
	flight, leader, vector, cached := p.acquireFlight(key)
	if cached {
		return vector, nil
	}
	if leader {
		// Shared provider work must not inherit one waiter's cancellation. Concrete
		// remote providers retain their own HTTP timeout, while each caller below
		// can still stop waiting independently.
		sharedCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), resolveHTTPTimeout())
		go func() {
			defer cancel()
			result, err := p.Provider.Embed(sharedCtx, text)
			p.finishFlight(key, flight, result, err)
		}()
	}
	return waitForFlight(ctx, flight)
}

// EmbedBatch serves cached values first, sends only misses to a native batch
// provider when possible, then fills the result in original input order.
func (p *CachedProvider) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	results := make([][]float32, len(texts))
	if len(texts) == 0 {
		return results, nil
	}
	type batchLeader struct {
		key    [sha256.Size]byte
		text   string
		flight *embedFlight
	}
	leaders := make([]batchLeader, 0, len(texts))
	flights := make([]*embedFlight, len(texts))
	for i, input := range texts {
		key := sha256.Sum256([]byte(input))
		flight, leader, vector, cached := p.acquireFlight(key)
		if cached {
			results[i] = vector
			continue
		}
		flights[i] = flight
		if leader {
			leaders = append(leaders, batchLeader{key: key, text: input, flight: flight})
		}
	}
	if len(leaders) > 0 {
		sharedCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), resolveHTTPTimeout())
		go func() {
			defer cancel()
			inputs := make([]string, len(leaders))
			for i := range leaders {
				inputs[i] = leaders[i].text
			}
			vectors, err := EmbedMany(sharedCtx, p.Provider, inputs)
			for i, leader := range leaders {
				if err != nil {
					p.finishFlight(leader.key, leader.flight, nil, err)
					continue
				}
				p.finishFlight(leader.key, leader.flight, vectors[i], nil)
			}
		}()
	}
	for i, flight := range flights {
		if flight == nil {
			continue
		}
		vector, err := waitForFlight(ctx, flight)
		if err != nil {
			return nil, err
		}
		results[i] = vector
	}
	return results, nil
}

// Optional provider metadata must survive decoration so vector-space IDs and
// dashboard status remain exact.
func (p *CachedProvider) Name() string {
	if named, ok := p.Provider.(Named); ok {
		return named.Name()
	}
	return ""
}

func (p *CachedProvider) Model() string {
	if modeled, ok := p.Provider.(Modeler); ok {
		return modeled.Model()
	}
	return ""
}

func (p *CachedProvider) Ping(ctx context.Context) error {
	if pinger, ok := p.Provider.(Pinger); ok {
		return pinger.Ping(ctx)
	}
	return nil
}
