package embedding

import (
	"context"
	"fmt"
	"strings"
)

// Provider is the interface for embedding generation.
type Provider interface {
	// Embed generates a vector embedding for the given text.
	Embed(ctx context.Context, text string) ([]float32, error)
	// Dimension returns the output dimension of this provider.
	Dimension() int
	// Ready returns true if the provider is operational.
	Ready() bool
	// Semantic returns true if embeddings carry semantic meaning (e.g. Ollama).
	// Hash-based providers return false — cosine similarity is meaningless.
	Semantic() bool
}

// BatchProvider is an optional extension implemented by providers whose wire
// protocol can embed several texts in one request. Call EmbedBatch through
// EmbedMany so providers without native batching retain the Provider contract.
type BatchProvider interface {
	EmbedBatch(ctx context.Context, texts []string) ([][]float32, error)
}

// EmbedMany uses native provider batching when available and otherwise falls
// back to the scalar Provider method. An empty input returns an empty result.
func EmbedMany(ctx context.Context, p Provider, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return [][]float32{}, nil
	}
	if batch, ok := p.(BatchProvider); ok {
		results, err := batch.EmbedBatch(ctx, texts)
		if err != nil {
			return nil, err
		}
		if len(results) != len(texts) {
			return nil, fmt.Errorf("embed batch returned %d vectors for %d inputs", len(results), len(texts))
		}
		return results, nil
	}
	results := make([][]float32, len(texts))
	for i, input := range texts {
		vector, err := p.Embed(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("embed item %d: %w", i, err)
		}
		results[i] = vector
	}
	return results, nil
}

// Named is an optional interface a Provider can implement to expose its
// canonical name. Operator-facing surfaces (e.g. /v1/embed/info) prefer this
// over inferring "ollama" vs "hash" from Semantic() alone, so providers other
// than the original two don't get mislabeled.
type Named interface {
	Name() string
}

// Modeler is an optional interface a Provider can implement to expose the
// model identifier it serves. The CEREBRUM dashboard surfaces this in the
// embedder status pill so operators running multi-model stacks (vLLM /
// LiteLLM / Ollama with several embedding models loaded) can confirm at a
// glance which one SAGE actually talks to. Providers that don't implement
// this simply don't get a model label in the UI.
type Modeler interface {
	Model() string
}

// Pinger is an optional interface a Provider can implement to expose a
// cheap liveness check. The dashboard health endpoint prefers Ping over
// Ready when present, because Ready is a sticky "has-ever-succeeded" flag
// — useful for /v1/embed/info but unhelpful for a real-time operator pill
// where the upstream embed server may have gone away after boot.
type Pinger interface {
	Ping(ctx context.Context) error
}

// SpaceID identifies the exact vector space produced by p. The default legacy
// spaces keep their historical stamps so existing personal nodes do not need a
// full re-embed on upgrade; configurable/non-default models include model and
// dimension so changing either can never silently mix incompatible vectors.
func SpaceID(p Provider) string {
	if p == nil {
		return ""
	}
	name := "hash"
	if named, ok := p.(Named); ok && strings.TrimSpace(named.Name()) != "" {
		name = strings.TrimSpace(named.Name())
	} else if p.Semantic() {
		name = "ollama"
	}
	model := ""
	if modeled, ok := p.(Modeler); ok {
		model = strings.TrimSpace(modeled.Model())
	}
	dimension := p.Dimension()
	if name == "ollama" && model == "nomic-embed-text" && dimension == 768 {
		return "ollama"
	}
	if name == "hash" && dimension == 768 {
		return "hash"
	}
	if model == "" {
		return fmt.Sprintf("%s:%d", name, dimension)
	}
	return fmt.Sprintf("%s:%s:%d", name, model, dimension)
}

// CanonicalSpaceID collapses a SpaceID to a form that ignores an organization
// prefix on the MODEL name, so a model served under two spellings —
// "openai-compatible:Alibaba-NLP/gte-Qwen2-1.5B-instruct:1536" and
// "openai-compatible:gte-Qwen2-1.5B-instruct:1536" — map to the same canonical
// id. Only a leading "org/" on the model component is stripped; the provider
// name and dimension are left untouched, so two genuinely different models, or
// the same model at a different dimension, never collapse together.
//
// This is a heuristic for TELLING an operator "this foreign space is most likely
// your own model under another name," not a change to how recall partitions:
// recall still compares the exact SpaceID, because two spellings could in
// principle be different builds, and silently widening the match would be exactly
// the cross-space cosine SpaceID exists to prevent.
func CanonicalSpaceID(spaceID string) string {
	parts := strings.Split(spaceID, ":")
	if len(parts) != 3 {
		return spaceID // "hash" / "ollama" / "name:dim" — no model component to canonicalize
	}
	if i := strings.LastIndex(parts[1], "/"); i >= 0 {
		parts[1] = parts[1][i+1:]
	}
	return strings.Join(parts, ":")
}

// LikelySpaceAlias is deliberately narrower than canonical equality: exactly
// one spelling must carry an organization path and the other must be bare.
// Two different organizations can publish repositories with the same final
// model name, so org-a/model and org-b/model are not enough evidence to label
// one an alias of the other. Ambiguous IDs (including model names containing
// the ':' SpaceID delimiter) fail closed as not-classified.
func LikelySpaceAlias(a, b string) bool {
	pa, pb := strings.Split(a, ":"), strings.Split(b, ":")
	if len(pa) != 3 || len(pb) != 3 || a == b {
		return false
	}
	aQualified := strings.Contains(pa[1], "/")
	bQualified := strings.Contains(pb[1], "/")
	return aQualified != bQualified && CanonicalSpaceID(a) == CanonicalSpaceID(b)
}
