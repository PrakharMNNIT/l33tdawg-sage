package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/embedding"
)

func clearAMIDEmbeddingEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"SAGE_EMBEDDING_PROVIDER", "SAGE_EMBEDDING_BASE_URL",
		"SAGE_EMBEDDING_MODEL", "SAGE_EMBEDDING_API_KEY",
		"SAGE_EMBEDDING_DIMENSION", "OLLAMA_URL", "OLLAMA_MODEL",
	} {
		t.Setenv(key, "")
	}
}

func TestAMIDEmbeddingProviderPreservesLegacyDefaultSpace(t *testing.T) {
	clearAMIDEmbeddingEnv(t)

	provider, err := newAMIDEmbeddingProviderFromEnv()

	require.NoError(t, err)
	assert.Equal(t, "ollama", embedding.SpaceID(provider))
	assert.Equal(t, embedding.Dimension, provider.Dimension())
}

func TestAMIDEmbeddingProviderPropagatesCanonicalOllamaModelAndDimension(t *testing.T) {
	clearAMIDEmbeddingEnv(t)
	t.Setenv("OLLAMA_URL", "http://legacy.invalid")
	t.Setenv("OLLAMA_MODEL", "legacy-model")
	t.Setenv("SAGE_EMBEDDING_BASE_URL", "http://canonical.invalid")
	t.Setenv("SAGE_EMBEDDING_MODEL", "snowflake-arctic-embed:xs")
	t.Setenv("SAGE_EMBEDDING_DIMENSION", "384")

	provider, err := newAMIDEmbeddingProviderFromEnv()

	require.NoError(t, err)
	assert.Equal(t, 384, provider.Dimension())
	assert.Equal(t, "ollama:snowflake-arctic-embed:xs:384", embedding.SpaceID(provider))
}

func TestAMIDEmbeddingProviderRejectsSilentFallbacks(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "invalid dimension",
			env:  map[string]string{"SAGE_EMBEDDING_DIMENSION": "three-eighty-four"},
			want: "positive integer",
		},
		{
			name: "unknown provider",
			env:  map[string]string{"SAGE_EMBEDDING_PROVIDER": "mystery"},
			want: "unsupported",
		},
		{
			name: "openai-compatible missing endpoint",
			env: map[string]string{
				"SAGE_EMBEDDING_PROVIDER": "openai-compatible",
				"SAGE_EMBEDDING_MODEL":    "small",
			},
			want: "BASE_URL is required",
		},
		{
			name: "openai-compatible missing model",
			env: map[string]string{
				"SAGE_EMBEDDING_PROVIDER": "openai-compatible",
				"SAGE_EMBEDDING_BASE_URL": "http://embedding.invalid",
			},
			want: "MODEL is required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearAMIDEmbeddingEnv(t)
			for key, value := range tc.env {
				t.Setenv(key, value)
			}

			_, err := newAMIDEmbeddingProviderFromEnv()

			require.ErrorContains(t, err, tc.want)
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func rpcTestResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

type recordingGovernanceDomainBinder struct {
	mu      sync.Mutex
	chainID string
	calls   int
}

type recordingRESTForkAccessors struct {
	postV8  func() bool
	postV17 func() bool
	postV20 func() bool
	postV22 func() bool
	postV23 func() bool
}

func (r *recordingRESTForkAccessors) SetPostV8ForkAccessor(fn func() bool) {
	r.postV8 = fn
}

func (r *recordingRESTForkAccessors) SetPostV17ForNextTxAccessor(fn func() bool) {
	r.postV17 = fn
}

func (r *recordingRESTForkAccessors) SetPostV20ForNextTxAccessor(fn func() bool) {
	r.postV20 = fn
}

func (r *recordingRESTForkAccessors) SetPostV22ForNextTxAccessor(fn func() bool) {
	r.postV22 = fn
}

func (r *recordingRESTForkAccessors) SetPostV23ForNextTxAccessor(fn func() bool) {
	r.postV23 = fn
}

type mutableAppForkAccessors struct {
	postV8  bool
	postV17 bool
	postV20 bool
	postV22 bool
	postV23 bool
}

func (a *mutableAppForkAccessors) IsPostV8Fork() bool            { return a.postV8 }
func (a *mutableAppForkAccessors) IsAppV17ActiveForNextTx() bool { return a.postV17 }
func (a *mutableAppForkAccessors) IsAppV20ActiveForNextTx() bool { return a.postV20 }
func (a *mutableAppForkAccessors) IsAppV22ActiveForNextTx() bool { return a.postV22 }
func (a *mutableAppForkAccessors) IsAppV23ActiveForNextTx() bool { return a.postV23 }

func TestWireRESTForkAccessorsIncludesAppV23AndStaysDynamic(t *testing.T) {
	server := &recordingRESTForkAccessors{}
	app := &mutableAppForkAccessors{}

	wireRESTForkAccessors(server, app)

	if server.postV8 == nil || server.postV17 == nil || server.postV20 == nil ||
		server.postV22 == nil || server.postV23 == nil {
		t.Fatal("amid did not wire every REST fork accessor")
	}
	if server.postV23() {
		t.Fatal("app-v23 accessor unexpectedly active before the app reports activation")
	}
	app.postV23 = true
	if !server.postV23() {
		t.Fatal("app-v23 REST accessor did not track the live app predicate")
	}
}

func (b *recordingGovernanceDomainBinder) SetExpectedGovernanceDelegationDomain(chainID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if b.chainID != "" && b.chainID != chainID {
		return errors.New("governance domain already bound")
	}
	b.chainID = chainID
	return nil
}

func (b *recordingGovernanceDomainBinder) bindCalls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

func (b *recordingGovernanceDomainBinder) boundChainID() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.chainID
}

func TestGovernanceDomainBindingRetriesUntilCometRPCIsReady(t *testing.T) {
	var requests atomic.Int32
	client := newGovernanceDomainHTTPClient()
	client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if requests.Add(1) < 3 {
			return rpcTestResponse(request, http.StatusServiceUnavailable, "starting"), nil
		}
		return rpcTestResponse(request, http.StatusOK, `{"result":{"node_info":{"network":"sage-v11-9-chaos"}}}`), nil
	})

	binder := &recordingGovernanceDomainBinder{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := bindExpectedGovernanceDomainFromRPCUntilReady(
		ctx,
		client,
		binder,
		"http://comet.test",
		time.Millisecond,
		5*time.Millisecond,
		zerolog.Nop(),
	)
	if err != nil {
		t.Fatalf("bind governance domain: %v", err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("RPC requests = %d, want 3", got)
	}
	if got := binder.boundChainID(); got != "sage-v11-9-chaos" {
		t.Fatalf("bound chain ID = %q, want %q", got, "sage-v11-9-chaos")
	}
}

func TestGovernanceDomainBindingStopsOnContextCancellation(t *testing.T) {
	client := newGovernanceDomainHTTPClient()
	client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return rpcTestResponse(request, http.StatusServiceUnavailable, "starting"), nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err := bindExpectedGovernanceDomainFromRPCUntilReady(
		ctx,
		client,
		&recordingGovernanceDomainBinder{},
		"http://comet.test",
		time.Millisecond,
		5*time.Millisecond,
		zerolog.Nop(),
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("binding error = %v, want context deadline exceeded", err)
	}
}

func TestConfigureGovernanceDomainRejectsUnusableRPCResponses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "non-200", status: http.StatusServiceUnavailable, body: "starting"},
		{name: "malformed JSON", status: http.StatusOK, body: `{"result":`},
		{name: "missing network", status: http.StatusOK, body: `{"result":{"node_info":{}}}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := newGovernanceDomainHTTPClient()
			client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return rpcTestResponse(request, tc.status, tc.body), nil
			})
			binder := &recordingGovernanceDomainBinder{}
			_, err := configureExpectedGovernanceDomainFromRPC(
				context.Background(),
				client,
				binder,
				"http://comet.test",
			)
			if err == nil {
				t.Fatal("unusable CometBFT response unexpectedly bound a governance domain")
			}
			if calls := binder.bindCalls(); calls != 0 {
				t.Fatalf("binder calls = %d, want 0", calls)
			}
		})
	}
}

func TestConfigureGovernanceDomainRefusesHTTPRedirects(t *testing.T) {
	var redirectedRequests atomic.Int32
	client := newGovernanceDomainHTTPClient()
	client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "comet.test" {
			response := rpcTestResponse(request, http.StatusTemporaryRedirect, "")
			response.Header.Set("Location", "https://wrong-authority.test/status")
			return response, nil
		}
		redirectedRequests.Add(1)
		return rpcTestResponse(request, http.StatusOK, `{"result":{"node_info":{"network":"wrong-authority"}}}`), nil
	})

	binder := &recordingGovernanceDomainBinder{}
	_, err := configureExpectedGovernanceDomainFromRPC(
		context.Background(),
		client,
		binder,
		"http://comet.test",
	)
	if err == nil {
		t.Fatal("redirected CometBFT authority unexpectedly bound a governance domain")
	}
	if got := redirectedRequests.Load(); got != 0 {
		t.Fatalf("redirect target requests = %d, want 0", got)
	}
	if calls := binder.bindCalls(); calls != 0 {
		t.Fatalf("binder calls = %d, want 0", calls)
	}
}
