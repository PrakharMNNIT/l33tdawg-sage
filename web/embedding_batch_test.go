package web

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/memory"
)

type batchFallbackEmbedder struct {
	batchResult [][]float32
	batchErr    error
	poison      string
	scalarCalls []string
}

func (e *batchFallbackEmbedder) Embed(_ context.Context, text string) ([]float32, error) {
	e.scalarCalls = append(e.scalarCalls, text)
	if text == e.poison {
		return nil, errors.New("poison input")
	}
	return []float32{float32(len(text))}, nil
}

func (e *batchFallbackEmbedder) EmbedBatch(_ context.Context, _ []string) ([][]float32, error) {
	return e.batchResult, e.batchErr
}

func TestEmbedBestEffortFallsBackPerItemAfterBatchFailure(t *testing.T) {
	provider := &batchFallbackEmbedder{batchErr: errors.New("batch rejected"), poison: "bad"}
	vectors, errs := embedBestEffort(context.Background(), provider, []string{"one", "bad", "three"})

	require.Equal(t, [][]float32{{3}, nil, {5}}, vectors)
	require.NoError(t, errs[0])
	require.ErrorContains(t, errs[1], "poison input")
	require.NoError(t, errs[2])
	require.Equal(t, []string{"one", "bad", "three"}, provider.scalarCalls)
}

func TestEmbedBestEffortFallsBackAfterMalformedBatchCardinality(t *testing.T) {
	for _, resultCount := range []int{1, 3} {
		t.Run(fmt.Sprintf("result_count_%d", resultCount), func(t *testing.T) {
			provider := &batchFallbackEmbedder{batchResult: make([][]float32, resultCount)}
			vectors, errs := embedBestEffort(context.Background(), provider, []string{"one", "two"})

			require.Equal(t, [][]float32{{3}, {3}}, vectors)
			require.NoError(t, errs[0])
			require.NoError(t, errs[1])
			require.Equal(t, []string{"one", "two"}, provider.scalarCalls)
		})
	}
}

type importBatchCountingEmbedder struct {
	batchSizes []int
	batchTexts [][]string
}

func (e *importBatchCountingEmbedder) Embed(_ context.Context, text string) ([]float32, error) {
	return []float32{float32(len(text))}, nil
}

func (e *importBatchCountingEmbedder) EmbedBatch(_ context.Context, texts []string) ([][]float32, error) {
	e.batchSizes = append(e.batchSizes, len(texts))
	e.batchTexts = append(e.batchTexts, append([]string(nil), texts...))
	vectors := make([][]float32, len(texts))
	for i, text := range texts {
		vectors[i] = []float32{float32(len(text))}
	}
	return vectors, nil
}

func TestImportEmbeddingWindowsStayBoundedForLargeInputs(t *testing.T) {
	const recordCount = 10_001
	records := make([]*memory.MemoryRecord, recordCount)
	authErrors := make([]string, recordCount)
	for i := range records {
		records[i] = &memory.MemoryRecord{Content: fmt.Sprintf("record-%d", i)}
	}
	// One unauthorized record in every window must never reach the provider.
	denied := 0
	for i := 0; i+1 < recordCount; i += embeddingBatchSize {
		authErrors[i] = "denied"
		denied++
	}

	provider := &importBatchCountingEmbedder{}
	processed := 0
	for start := 0; start < len(records); start += embeddingBatchSize {
		window := embedImportRecordBatch(
			context.Background(), provider, records, authErrors, start,
		)
		require.LessOrEqual(t, len(window), embeddingBatchSize)
		processed += len(window)
	}

	require.Equal(t, recordCount, processed)
	require.Len(t, provider.batchSizes, (recordCount+embeddingBatchSize-1)/embeddingBatchSize)
	providerItems := 0
	for _, size := range provider.batchSizes {
		require.LessOrEqual(t, size, embeddingBatchSize)
		providerItems += size
	}
	require.Equal(t, recordCount-denied, providerItems)
	for _, texts := range provider.batchTexts {
		for _, text := range texts {
			var recordIndex int
			_, err := fmt.Sscanf(text, "record-%d", &recordIndex)
			require.NoError(t, err)
			require.Empty(t, authErrors[recordIndex], "unauthorized content reached the embedding provider")
		}
	}
}
