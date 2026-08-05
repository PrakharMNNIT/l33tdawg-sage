package web

import (
	"context"
	"fmt"

	"github.com/l33tdawg/sage/internal/embedding"
	"github.com/l33tdawg/sage/internal/memory"
)

const embeddingBatchSize = 16

// embedImportRecordBatch keeps import vector memory strictly bounded to one
// provider batch. Authorized content only enters the provider, and callers
// consume this returned window before requesting the next one.
func embedImportRecordBatch(
	ctx context.Context,
	provider Embedder,
	records []*memory.MemoryRecord,
	authErrors []string,
	start int,
) [][]float32 {
	if start < 0 || start >= len(records) {
		return [][]float32{}
	}
	end := min(start+embeddingBatchSize, len(records))
	window := make([][]float32, end-start)
	texts := make([]string, 0, end-start)
	offsets := make([]int, 0, end-start)
	for i := start; i < end; i++ {
		if records[i].Content == "" || (i < len(authErrors) && authErrors[i] != "") {
			continue
		}
		texts = append(texts, records[i].Content)
		offsets = append(offsets, i-start)
	}
	vectors, errs := embedBestEffort(ctx, provider, texts)
	for i, offset := range offsets {
		if errs[i] == nil {
			window[offset] = vectors[i]
		}
	}
	return window
}

// embedBestEffort batches providers that support it and preserves an error for
// every failed item so background jobs can continue deterministically.
func embedBestEffort(ctx context.Context, provider Embedder, texts []string) ([][]float32, []error) {
	vectors := make([][]float32, len(texts))
	errs := make([]error, len(texts))
	if batch, ok := provider.(embedding.BatchProvider); ok {
		for start := 0; start < len(texts); start += embeddingBatchSize {
			end := min(start+embeddingBatchSize, len(texts))
			chunk, err := batch.EmbedBatch(ctx, texts[start:end])
			if err == nil && len(chunk) != end-start {
				err = fmt.Errorf("embed batch returned %d vectors for %d inputs", len(chunk), end-start)
			}
			if err != nil {
				// One poisoned input or malformed third-party batch response must not
				// discard every otherwise-embeddable memory in the chunk. Retry each
				// item through the scalar contract and retain only its own failure.
				for i := start; i < end; i++ {
					vectors[i], errs[i] = provider.Embed(ctx, texts[i])
					if errs[i] != nil {
						errs[i] = fmt.Errorf("embed batch fallback item %d: %w", i, errs[i])
					}
				}
				continue
			}
			copy(vectors[start:end], chunk)
		}
		return vectors, errs
	}
	for i, text := range texts {
		vectors[i], errs[i] = provider.Embed(ctx, text)
	}
	return vectors, errs
}
