// Package embedding provides vector embedding generation via local Ollama.
//
// All embeddings stay local — no cloud API calls. Sovereign by design.
package embedding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// isTimeout reports whether err is a request/response timeout (client Timeout or a
// caller-ctx deadline). A timeout means Ollama is hung/overloaded, so retrying just
// multiplies the wait — such errors are NOT retried.
func isTimeout(err error) bool {
	var netErr net.Error
	return (errors.As(err, &netErr) && netErr.Timeout()) || errors.Is(err, context.DeadlineExceeded)
}

// Dimension is the legacy output dimension of nomic-embed-text.
const Dimension = 768

// Client generates embeddings via a local Ollama instance.
type Client struct {
	baseURL   string
	model     string
	dimension int
	// keepAlive is a duration STRING ("30m") or an int64 (seconds; -1 pins in memory,
	// 0 unloads) — the two forms Ollama's /api/embed keep_alive field accepts.
	keepAlive  any
	httpClient *http.Client
	mu         sync.RWMutex
	ready      bool
}

// NewClient creates an Ollama embedding client.
// baseURL defaults to OLLAMA_URL env var or "http://localhost:11434".
// model defaults to "nomic-embed-text".
func NewClient(baseURL, model string) *Client {
	return NewClientWithDimension(baseURL, model, Dimension)
}

// NewClientWithDimension creates an Ollama client bound to an exact vector
// dimension. The response is validated so a model/config mismatch cannot mix
// incompatible vectors in one space.
func NewClientWithDimension(baseURL, model string, dimension int) *Client {
	if baseURL == "" {
		baseURL = os.Getenv("OLLAMA_URL")
	}
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	if model == "" {
		model = "nomic-embed-text"
	}
	if dimension <= 0 {
		dimension = Dimension
	}
	return &Client{
		baseURL:   baseURL,
		model:     model,
		dimension: dimension,
		keepAlive: resolveKeepAlive(),
		httpClient: &http.Client{
			Timeout: resolveHTTPTimeout(),
		},
	}
}

// resolveKeepAlive picks the Ollama keep_alive value from OLLAMA_KEEP_ALIVE, defaulting
// to "30m". Keeping the embed model resident between calls is the fix for the
// intermittent-embed-failure root cause: Ollama's 5-minute default unloads the model
// after a short idle, so the next sage_turn embed pays a cold reload that can blip/time
// out.
//
// GRAMMAR (do not "simplify"): the JSON keep_alive field on /api/embed accepts a
// duration STRING ("30m", "24h") OR a NUMBER (seconds; -1 pins in memory, 0 unloads),
// but NOT an integer AS A STRING — {"keep_alive":"-1"} 400s with `missing unit in
// duration`. Ollama's server-side OLLAMA_KEEP_ALIVE env var (which a user may already
// have exported, e.g. =-1) accepts bare integers, so we translate an integer-form value
// to a JSON number rather than forward it as a string that would 400 every embed. An
// unparseable value falls back to "30m" instead of breaking all embeddings.
func resolveKeepAlive() any {
	v := os.Getenv("OLLAMA_KEEP_ALIVE")
	if v == "" {
		return "30m"
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return n // JSON number (seconds; -1 pins, 0 unloads)
	}
	if _, err := time.ParseDuration(v); err == nil {
		return v // valid duration string
	}
	fmt.Fprintf(os.Stderr, "SAGE: ignoring invalid OLLAMA_KEEP_ALIVE=%q (want a duration like 24h or integer seconds like -1); using 30m\n", v)
	return "30m"
}

type embedRequest struct {
	Model     string `json:"model"`
	Input     any    `json:"input"`
	KeepAlive any    `json:"keep_alive,omitempty"`
}

type embedResponse struct {
	Embeddings [][]float64 `json:"embeddings"`
}

// embedRetryBackoffs is the inter-attempt backoff schedule for transient Ollama
// embed failures; len+1 is the max attempt count. A var so tests can shrink it.
var embedRetryBackoffs = []time.Duration{250 * time.Millisecond, 500 * time.Millisecond}

// Embed generates an embedding for the given text, retrying transient
// failures. Ollama commonly blips on the first call after an idle model-unload, a
// cold load, or a sidecar restart; a couple of short retries absorb that so a single
// hiccup doesn't fail a sage_turn (whose recall AND store both embed). Combined with
// keep_alive keeping the model resident, this is the fix for the intermittent
// "embed failed / can't connect to Ollama" errors.
func (c *Client) Embed(ctx context.Context, text string) ([]float32, error) {
	results, err := c.embedTexts(ctx, []string{text})
	if err != nil {
		return nil, err
	}
	return results[0], nil
}

// EmbedBatch uses Ollama's native input-array support so migrations and imports
// amortize model scheduling and HTTP overhead.
func (c *Client) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return [][]float32{}, nil
	}
	return c.embedTexts(ctx, texts)
}

func (c *Client) embedTexts(ctx context.Context, texts []string) ([][]float32, error) {
	var lastErr error
	for attempt := 0; ; attempt++ {
		result, retryable, err := c.embedOnce(ctx, texts)
		if err == nil {
			return result, nil
		}
		lastErr = err
		if !retryable || attempt >= len(embedRetryBackoffs) {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(embedRetryBackoffs[attempt]):
		}
	}
	return nil, lastErr
}

// embedOnce performs a single embed attempt. retryable is true for a transient
// condition worth retrying (network error, 5xx/429, empty result); false for a
// definite failure (marshal error, 4xx) that a retry won't fix.
func (c *Client) embedOnce(ctx context.Context, texts []string) (result [][]float32, retryable bool, err error) {
	var input any = texts
	if len(texts) == 1 {
		input = texts[0]
	}
	req := embedRequest{
		Model:     c.model,
		Input:     input,
		KeepAlive: c.keepAlive,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, false, fmt.Errorf("marshal embed request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/api/embed", bytes.NewReader(body))
	if err != nil {
		return nil, false, fmt.Errorf("create embed request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		// Connection refused/reset/EOF means Ollama restarted or briefly went away —
		// transient, worth a quick retry. A TIMEOUT means it's hung/overloaded, so
		// retrying just multiplies the wait: fail in one attempt like before.
		return nil, !isTimeout(err), fmt.Errorf("ollama embed request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB max
		// 5xx / 429 are transient (model loading, overloaded); 4xx is a real client
		// error (bad model/request) that a retry won't fix.
		retry := resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
		return nil, retry, fmt.Errorf("ollama embed error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var embedResp embedResponse
	if err := json.NewDecoder(resp.Body).Decode(&embedResp); err != nil {
		// A body-read timeout surfaces here; don't retry it (same reasoning as the
		// request timeout above). A genuine parse error of a complete body is transient.
		return nil, !isTimeout(err), fmt.Errorf("decode embed response: %w", err)
	}

	if len(embedResp.Embeddings) == 0 {
		return nil, true, fmt.Errorf("ollama returned no embeddings")
	}

	// Convert float64 to float32 for pgvector
	if len(embedResp.Embeddings) != len(texts) {
		return nil, true, fmt.Errorf("ollama returned %d embeddings for %d inputs", len(embedResp.Embeddings), len(texts))
	}
	result = make([][]float32, len(embedResp.Embeddings))
	for item, f64 := range embedResp.Embeddings {
		if len(f64) != c.dimension {
			return nil, false, fmt.Errorf("ollama embed dimension mismatch: configured %d, got %d", c.dimension, len(f64))
		}
		result[item] = make([]float32, len(f64))
		for i, v := range f64 {
			result[item][i] = float32(v)
		}
	}

	c.mu.Lock()
	c.ready = true
	c.mu.Unlock()

	return result, false, nil
}

// Dimension returns the output dimension of this provider.
func (c *Client) Dimension() int {
	return c.dimension
}

// Ready returns true if at least one successful embedding has been generated.
func (c *Client) Ready() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ready
}

// Semantic returns true — Ollama produces semantically meaningful embeddings.
func (c *Client) Semantic() bool {
	return true
}

// Name implements embedding.Named so /v1/embed/info reports "ollama" via the
// explicit method instead of the inferred fallback in the REST handler.
func (c *Client) Name() string {
	return "ollama"
}

// Model implements embedding.Modeler so the CEREBRUM status pill can show
// which Ollama model is currently bound (e.g. "nomic-embed-text").
func (c *Client) Model() string {
	return c.model
}

// Ping checks if Ollama is reachable.
func (c *Client) Ping(ctx context.Context) error {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/tags", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("ollama ping: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama ping: status %d", resp.StatusCode)
	}
	return nil
}
