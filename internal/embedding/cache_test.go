package embedding

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type countingProvider struct {
	calls atomic.Int32
	delay time.Duration
}

func (p *countingProvider) Embed(ctx context.Context, text string) ([]float32, error) {
	p.calls.Add(1)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(p.delay):
		return []float32{float32(len(text)), 1}, nil
	}
}

func (*countingProvider) Dimension() int { return 2 }
func (*countingProvider) Ready() bool    { return true }
func (*countingProvider) Semantic() bool { return true }

type controlledProvider struct {
	scalarCalls atomic.Int32
	batchCalls  atomic.Int32
	started     chan struct{}
	release     chan struct{}
	batchInputs chan []string
}

func (p *controlledProvider) Embed(ctx context.Context, text string) ([]float32, error) {
	p.scalarCalls.Add(1)
	if p.started != nil {
		select {
		case p.started <- struct{}{}:
		default:
		}
	}
	if p.release != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.release:
		}
	}
	return []float32{float32(len(text)), 1}, nil
}

func (p *controlledProvider) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	p.batchCalls.Add(1)
	if p.batchInputs != nil {
		p.batchInputs <- append([]string(nil), texts...)
	}
	if p.release != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.release:
		}
	}
	vectors := make([][]float32, len(texts))
	for i, text := range texts {
		vectors[i] = []float32{float32(len(text)), 1}
	}
	return vectors, nil
}

func (*controlledProvider) Dimension() int { return 2 }
func (*controlledProvider) Ready() bool    { return true }
func (*controlledProvider) Semantic() bool { return true }

type wrongCardinalityProvider struct {
	count int
}

func (*wrongCardinalityProvider) Embed(context.Context, string) ([]float32, error) {
	return nil, fmt.Errorf("scalar path must not be used")
}

func (p *wrongCardinalityProvider) EmbedBatch(context.Context, []string) ([][]float32, error) {
	return make([][]float32, p.count), nil
}

func (*wrongCardinalityProvider) Dimension() int { return 2 }
func (*wrongCardinalityProvider) Ready() bool    { return true }
func (*wrongCardinalityProvider) Semantic() bool { return true }

func TestCachedProvider_CachesCopiesAndExpires(t *testing.T) {
	base := &countingProvider{}
	cached := NewCachedProvider(base, 2, time.Minute)
	now := time.Unix(100, 0)
	cached.now = func() time.Time { return now }

	first, err := cached.Embed(context.Background(), "same")
	require.NoError(t, err)
	first[0] = 999
	second, err := cached.Embed(context.Background(), "same")
	require.NoError(t, err)
	assert.Equal(t, float32(4), second[0], "callers must not mutate the cached vector")
	assert.Equal(t, int32(1), base.calls.Load())

	now = now.Add(time.Minute)
	_, err = cached.Embed(context.Background(), "same")
	require.NoError(t, err)
	assert.Equal(t, int32(2), base.calls.Load(), "expired entries must be recomputed")
}

func TestCachedProvider_CoalescesConcurrentIdenticalCalls(t *testing.T) {
	base := &countingProvider{delay: 40 * time.Millisecond}
	cached := NewCachedProvider(base, 16, time.Minute)
	const workers = 12
	var wg sync.WaitGroup
	wg.Add(workers)
	errs := make(chan error, workers)
	for range workers {
		go func() {
			defer wg.Done()
			_, err := cached.Embed(context.Background(), "shared topic")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, int32(1), base.calls.Load())
}

func TestDefaultCachedProvider_DoesNotRetainSequentialValuesButCoalescesConcurrent(t *testing.T) {
	t.Run("sequential callers recompute", func(t *testing.T) {
		base := &countingProvider{}
		cached := NewDefaultCachedProvider(base)
		for range 2 {
			_, err := cached.Embed(context.Background(), "same plaintext")
			require.NoError(t, err)
		}
		assert.Equal(t, int32(2), base.calls.Load())
	})

	t.Run("overlapping batch callers share identical work", func(t *testing.T) {
		base := &controlledProvider{
			release:     make(chan struct{}),
			batchInputs: make(chan []string, 2),
		}
		cached := NewDefaultCachedProvider(base).(BatchProvider)
		firstErr := make(chan error, 1)
		go func() {
			_, err := cached.EmbedBatch(context.Background(), []string{"shared"})
			firstErr <- err
		}()
		require.Equal(t, []string{"shared"}, <-base.batchInputs)

		secondErr := make(chan error, 1)
		go func() {
			_, err := cached.EmbedBatch(context.Background(), []string{"shared", "other"})
			secondErr <- err
		}()
		// Seeing only "other" enter the provider proves the second public call
		// joined the first call's flight for the identical "shared" plaintext.
		require.Equal(t, []string{"other"}, <-base.batchInputs)
		close(base.release)
		require.NoError(t, <-firstErr)
		require.NoError(t, <-secondErr)
		assert.Equal(t, int32(2), base.batchCalls.Load())
	})
}

func TestCachedProvider_CanceledLeaderDoesNotCancelFollower(t *testing.T) {
	base := &controlledProvider{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	cached := NewCachedProvider(base, 16, time.Minute)
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() {
		_, err := cached.Embed(leaderCtx, "shared")
		leaderErr <- err
	}()
	<-base.started
	cancelLeader()
	require.ErrorIs(t, <-leaderErr, context.Canceled)

	followerResult := make(chan []float32, 1)
	followerErr := make(chan error, 1)
	go func() {
		vector, err := cached.Embed(context.Background(), "shared")
		followerResult <- vector
		followerErr <- err
	}()
	close(base.release)
	require.NoError(t, <-followerErr)
	assert.Equal(t, []float32{6, 1}, <-followerResult)
	assert.Equal(t, int32(1), base.scalarCalls.Load())
}

func TestCachedProvider_SharedFlightHasIndependentTimeout(t *testing.T) {
	t.Setenv("SAGE_EMBEDDING_TIMEOUT", "20ms")
	base := &controlledProvider{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	cached := NewCachedProvider(base, 16, time.Minute)

	result := make(chan error, 1)
	go func() {
		_, err := cached.Embed(context.Background(), "hung")
		result <- err
	}()
	<-base.started
	require.ErrorIs(t, <-result, context.DeadlineExceeded)
	assert.Equal(t, int32(1), base.scalarCalls.Load())
}

func TestCachedProvider_BatchDeduplicatesInputs(t *testing.T) {
	base := &controlledProvider{batchInputs: make(chan []string, 1)}
	cached := NewCachedProvider(base, 16, time.Minute)

	vectors, err := cached.EmbedBatch(context.Background(), []string{"same", "other", "same"})
	require.NoError(t, err)
	assert.Equal(t, []string{"same", "other"}, <-base.batchInputs)
	assert.Equal(t, [][]float32{{4, 1}, {5, 1}, {4, 1}}, vectors)
	assert.Equal(t, int32(1), base.batchCalls.Load())
	assert.Zero(t, base.scalarCalls.Load())
}

func TestCachedProvider_BatchCoalescesConcurrentScalarMiss(t *testing.T) {
	base := &controlledProvider{
		started:     make(chan struct{}, 1),
		release:     make(chan struct{}),
		batchInputs: make(chan []string, 1),
	}
	cached := NewCachedProvider(base, 16, time.Minute)
	scalarResult := make(chan []float32, 1)
	scalarErr := make(chan error, 1)
	go func() {
		vector, err := cached.Embed(context.Background(), "shared")
		scalarResult <- vector
		scalarErr <- err
	}()
	<-base.started

	batchResult := make(chan [][]float32, 1)
	batchErr := make(chan error, 1)
	go func() {
		vectors, err := cached.EmbedBatch(context.Background(), []string{"shared", "batch-only"})
		batchResult <- vectors
		batchErr <- err
	}()
	require.Equal(t, []string{"batch-only"}, <-base.batchInputs)
	close(base.release)

	require.NoError(t, <-batchErr)
	require.NoError(t, <-scalarErr)
	assert.Equal(t, [][]float32{{6, 1}, {10, 1}}, <-batchResult)
	assert.Equal(t, []float32{6, 1}, <-scalarResult)
	assert.Equal(t, int32(1), base.batchCalls.Load())
	assert.Equal(t, int32(1), base.scalarCalls.Load())
}

func TestCachedProvider_BatchCardinalityMismatchReturnsError(t *testing.T) {
	for _, count := range []int{1, 3} {
		t.Run(fmt.Sprintf("returned_%d", count), func(t *testing.T) {
			cached := NewCachedProvider(&wrongCardinalityProvider{count: count}, 16, time.Minute)
			vectors, err := cached.EmbedBatch(context.Background(), []string{"one", "two"})
			require.Error(t, err)
			assert.Nil(t, vectors)
			assert.Contains(t, err.Error(), fmt.Sprintf("returned %d vectors for 2 inputs", count))
		})
	}
}

func TestCachedProvider_LRUEvictsOldest(t *testing.T) {
	base := &countingProvider{}
	cached := NewCachedProvider(base, 2, time.Minute)
	for _, text := range []string{"a", "b", "c", "a"} {
		_, err := cached.Embed(context.Background(), text)
		require.NoError(t, err)
	}
	assert.Equal(t, int32(4), base.calls.Load())
}

func BenchmarkCachedProvider_RepeatedInput(b *testing.B) {
	base := &countingProvider{delay: time.Millisecond}
	cached := NewCachedProvider(base, 16, time.Minute)
	_, _ = cached.Embed(context.Background(), "repeated topic")
	b.ResetTimer()
	for range b.N {
		_, _ = cached.Embed(context.Background(), "repeated topic")
	}
}
