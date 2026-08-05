// Command sage-embedding-bench measures a real embedding endpoint without
// storing memories or touching consensus state.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type config struct {
	Provider      string
	BaseURL       string
	Model         string
	APIKey        string
	Dimension     int
	Timeout       time.Duration
	ScalarRuns    int
	BatchSize     int
	ColdResetURL  string
	SkipColdReset bool
	KeepAlive     any
}

type machineContext struct {
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	CPU       string `json:"cpu"`
	CPUs      int    `json:"logical_cpus"`
	GoVersion string `json:"go_version"`
}

type phaseResult struct {
	Name        string    `json:"name"`
	Items       int       `json:"items"`
	Requests    int64     `json:"http_requests"`
	TotalMS     float64   `json:"total_ms"`
	PerItemMS   float64   `json:"per_item_ms"`
	SampleMS    []float64 `json:"sample_ms"`
	Controlled  bool      `json:"cold_controlled,omitempty"`
	ControlNote string    `json:"control_note,omitempty"`
}

type benchmarkResult struct {
	Machine   machineContext `json:"machine"`
	Provider  string         `json:"provider"`
	BaseURL   string         `json:"base_url"`
	Model     string         `json:"model"`
	Dimension int            `json:"dimension"`
	Timeout   string         `json:"timeout"`
	KeepAlive any            `json:"ollama_keep_alive,omitempty"`
	Phases    []phaseResult  `json:"phases"`
}

type countingTransport struct {
	base  http.RoundTripper
	count atomic.Int64
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.count.Add(1)
	return t.base.RoundTrip(req)
}

func (t *countingTransport) reset() { t.count.Store(0) }

type wireClient struct {
	cfg       config
	http      *http.Client
	transport *countingTransport
}

func newWireClient(cfg config) *wireClient {
	transport := &countingTransport{base: http.DefaultTransport}
	return &wireClient{
		cfg:       cfg,
		http:      &http.Client{Timeout: cfg.Timeout, Transport: transport},
		transport: transport,
	}
}

func (c *wireClient) embed(ctx context.Context, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return [][]float32{}, nil
	}
	switch c.cfg.Provider {
	case "ollama":
		keepAlive := c.cfg.KeepAlive
		if keepAlive == nil {
			keepAlive = "30m"
		}
		return c.embedOllama(ctx, texts, keepAlive)
	case "openai-compatible":
		return c.embedOpenAI(ctx, texts)
	default:
		return nil, fmt.Errorf("unsupported provider %q (want ollama or openai-compatible)", c.cfg.Provider)
	}
}

func (c *wireClient) embedOllama(ctx context.Context, texts []string, keepAlive any) ([][]float32, error) {
	var input any = texts
	if len(texts) == 1 {
		input = texts[0]
	}
	body, err := json.Marshal(map[string]any{
		"model":      c.cfg.Model,
		"input":      input,
		"keep_alive": keepAlive,
	})
	if err != nil {
		return nil, err
	}
	var response struct {
		Embeddings [][]float64 `json:"embeddings"`
	}
	if err := c.postJSON(ctx, strings.TrimRight(c.cfg.BaseURL, "/")+"/api/embed", body, &response); err != nil {
		return nil, err
	}
	return validateVectors("ollama", response.Embeddings, len(texts), c.cfg.Dimension)
}

func (c *wireClient) embedOpenAI(ctx context.Context, texts []string) ([][]float32, error) {
	var input any = texts
	if len(texts) == 1 {
		input = texts[0]
	}
	body, err := json.Marshal(map[string]any{"model": c.cfg.Model, "input": input})
	if err != nil {
		return nil, err
	}
	var response struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
			Index     int       `json:"index"`
		} `json:"data"`
	}
	if err := c.postJSON(ctx, strings.TrimRight(c.cfg.BaseURL, "/")+"/v1/embeddings", body, &response); err != nil {
		return nil, err
	}
	if len(response.Data) != len(texts) {
		return nil, fmt.Errorf("openai-compatible cardinality mismatch: requested %d embeddings, got %d", len(texts), len(response.Data))
	}
	ordered := make([][]float64, len(texts))
	seen := make([]bool, len(texts))
	for position, item := range response.Data {
		index := item.Index
		if len(texts) == 1 {
			index = 0
		}
		if index < 0 || index >= len(texts) || seen[index] {
			return nil, fmt.Errorf("openai-compatible invalid or duplicate index %d at response item %d", index, position)
		}
		seen[index] = true
		ordered[index] = item.Embedding
	}
	return validateVectors("openai-compatible", ordered, len(texts), c.cfg.Dimension)
}

func validateVectors(provider string, vectors [][]float64, count, dimension int) ([][]float32, error) {
	if len(vectors) != count {
		return nil, fmt.Errorf("%s cardinality mismatch: requested %d embeddings, got %d", provider, count, len(vectors))
	}
	result := make([][]float32, count)
	for i, vector := range vectors {
		if len(vector) != dimension {
			return nil, fmt.Errorf("%s dimension mismatch at item %d: configured %d, got %d", provider, i, dimension, len(vector))
		}
		result[i] = make([]float32, dimension)
		for j, value := range vector {
			result[i][j] = float32(value)
		}
	}
	return result, nil
}

func (c *wireClient) postJSON(ctx context.Context, url string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(message)))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func runBenchmark(ctx context.Context, cfg config) (*benchmarkResult, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	client := newWireClient(cfg)
	controlled, note, err := prepareCold(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("prepare cold sample: %w", err)
	}
	client.transport.reset()

	coldName := "cold_scalar"
	if !controlled {
		coldName = "first_observed_scalar"
	}
	cold, err := measurePhase(ctx, client, coldName, []string{"SAGE CPU benchmark cold sample"}, false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", coldName, err)
	}
	cold.Controlled = controlled
	cold.ControlNote = note

	warmTexts := make([]string, cfg.ScalarRuns)
	for i := range warmTexts {
		warmTexts[i] = fmt.Sprintf("SAGE CPU benchmark warm scalar sample %d", i+1)
	}
	warm, err := measurePhase(ctx, client, "warm_scalar", warmTexts, true)
	if err != nil {
		return nil, fmt.Errorf("warm scalar: %w", err)
	}

	batchTexts := make([]string, cfg.BatchSize)
	for i := range batchTexts {
		batchTexts[i] = fmt.Sprintf("SAGE CPU benchmark native batch sample %d", i+1)
	}
	batch, err := measurePhase(ctx, client, "native_batch", batchTexts, false)
	if err != nil {
		return nil, fmt.Errorf("native batch: %w", err)
	}

	return &benchmarkResult{
		Machine:   inspectMachine(),
		Provider:  cfg.Provider,
		BaseURL:   cfg.BaseURL,
		Model:     cfg.Model,
		Dimension: cfg.Dimension,
		Timeout:   cfg.Timeout.String(),
		KeepAlive: cfg.KeepAlive,
		Phases:    []phaseResult{cold, warm, batch},
	}, nil
}

func prepareCold(ctx context.Context, client *wireClient) (bool, string, error) {
	if client.cfg.SkipColdReset {
		return false, "reset skipped by operator; first sample is not asserted cold", nil
	}
	if client.cfg.Provider == "ollama" {
		if _, err := client.embedOllama(ctx, []string{"SAGE benchmark unload preparation"}, 0); err != nil {
			return false, "", fmt.Errorf("ollama keep_alive=0 unload request: %w", err)
		}
		return true, "Ollama model unloaded with keep_alive=0 before measurement", nil
	}
	if client.cfg.ColdResetURL == "" {
		return false, "OpenAI-compatible has no standard unload API; pass -cold-reset-url to assert a cold sample", nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.cfg.ColdResetURL, http.NoBody)
	if err != nil {
		return false, "", err
	}
	if client.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+client.cfg.APIKey)
	}
	resp, err := client.http.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("cold reset hook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, "", fmt.Errorf("cold reset hook returned HTTP %d", resp.StatusCode)
	}
	return true, "operator-supplied cold reset hook completed before measurement", nil
}

func measurePhase(ctx context.Context, client *wireClient, name string, texts []string, scalar bool) (phaseResult, error) {
	client.transport.reset()
	samples := make([]float64, 0, len(texts))
	started := time.Now()
	if scalar {
		for _, text := range texts {
			itemStarted := time.Now()
			if _, err := client.embed(ctx, []string{text}); err != nil {
				return phaseResult{}, err
			}
			samples = append(samples, milliseconds(time.Since(itemStarted)))
		}
	} else {
		if _, err := client.embed(ctx, texts); err != nil {
			return phaseResult{}, err
		}
		samples = append(samples, milliseconds(time.Since(started)))
	}
	total := time.Since(started)
	return phaseResult{
		Name:      name,
		Items:     len(texts),
		Requests:  client.transport.count.Load(),
		TotalMS:   milliseconds(total),
		PerItemMS: milliseconds(total) / float64(len(texts)),
		SampleMS:  samples,
	}, nil
}

func validateConfig(cfg config) error {
	if cfg.Provider != "ollama" && cfg.Provider != "openai-compatible" {
		return fmt.Errorf("provider must be ollama or openai-compatible, got %q", cfg.Provider)
	}
	if strings.TrimSpace(cfg.BaseURL) == "" || strings.TrimSpace(cfg.Model) == "" {
		return errors.New("base URL and model are required")
	}
	if cfg.Dimension <= 0 || cfg.Timeout <= 0 || cfg.ScalarRuns <= 0 || cfg.BatchSize <= 0 {
		return errors.New("dimension, timeout, scalar-runs, and batch-size must be positive")
	}
	return nil
}

func inspectMachine() machineContext {
	hostname, _ := os.Hostname()
	return machineContext{
		Hostname: hostname, OS: runtime.GOOS, Arch: runtime.GOARCH,
		CPU: cpuModel(), CPUs: runtime.NumCPU(), GoVersion: runtime.Version(),
	}
}

func cpuModel() string {
	if runtime.GOOS == "darwin" {
		if output, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output(); err == nil {
			return strings.TrimSpace(string(output))
		}
	}
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if key, value, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(key) == "model name" {
				return strings.TrimSpace(value)
			}
		}
	}
	return "unknown"
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration.Microseconds()) / 1000
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err == nil && value > 0 {
		return value
	}
	return fallback
}

func configuredTimeout() time.Duration {
	value := envOr("SAGE_EMBEDDING_TIMEOUT", os.Getenv("SAGE_EMBED_TIMEOUT"))
	if value == "" {
		return 60 * time.Second
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 60 * time.Second
	}
	return duration
}

func configuredKeepAlive(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return "30m"
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return seconds
	}
	return value
}

func main() {
	provider := flag.String("provider", envOr("SAGE_EMBEDDING_PROVIDER", "ollama"), "ollama or openai-compatible")
	baseURL := flag.String("base-url", envOr("SAGE_EMBEDDING_BASE_URL", os.Getenv("OLLAMA_URL")), "embedding server base URL")
	model := flag.String("model", envOr("SAGE_EMBEDDING_MODEL", os.Getenv("OLLAMA_MODEL")), "exact embedding model")
	dimension := flag.Int("dimension", envInt("SAGE_EMBEDDING_DIMENSION", 768), "exact output vector dimension")
	timeout := flag.Duration("timeout", configuredTimeout(), "per-request timeout")
	scalarRuns := flag.Int("scalar-runs", 5, "number of warm scalar requests")
	batchSize := flag.Int("batch-size", 16, "number of inputs in the native batch request")
	keepAlive := flag.String("keep-alive", envOr("OLLAMA_KEEP_ALIVE", "30m"), "Ollama keep_alive duration or integer seconds")
	coldResetURL := flag.String("cold-reset-url", "", "OpenAI-compatible POST hook that unloads/restarts the model")
	skipColdReset := flag.Bool("skip-cold-reset", false, "do not attempt to force a cold model")
	flag.Parse()

	if *baseURL == "" {
		if *provider == "ollama" {
			*baseURL = "http://127.0.0.1:11434"
		} else {
			fmt.Fprintln(os.Stderr, "benchmark failed: -base-url is required for openai-compatible")
			os.Exit(2)
		}
	}
	if *model == "" {
		if *provider == "ollama" {
			*model = "nomic-embed-text"
		} else {
			fmt.Fprintln(os.Stderr, "benchmark failed: -model is required for openai-compatible")
			os.Exit(2)
		}
	}

	result, err := runBenchmark(context.Background(), config{
		Provider: *provider, BaseURL: *baseURL, Model: *model,
		APIKey: os.Getenv("SAGE_EMBEDDING_API_KEY"), Dimension: *dimension,
		Timeout: *timeout, ScalarRuns: *scalarRuns, BatchSize: *batchSize,
		ColdResetURL: *coldResetURL, SkipColdReset: *skipColdReset,
		KeepAlive: configuredKeepAlive(*keepAlive),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "benchmark failed:", err)
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode result:", err)
		os.Exit(1)
	}
	fmt.Println(string(encoded))
}
