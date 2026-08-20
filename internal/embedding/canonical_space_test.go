package embedding

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A model served under two spellings — with and without an organization prefix —
// must canonicalize to one id, while a genuinely different model, provider, or
// dimension must not.
func TestCanonicalSpaceID(t *testing.T) {
	// Same model, org-prefixed vs bare, collapse together.
	assert.Equal(t,
		CanonicalSpaceID("openai-compatible:gte-Qwen2-1.5B-instruct:1536"),
		CanonicalSpaceID("openai-compatible:Alibaba-NLP/gte-Qwen2-1.5B-instruct:1536"),
		"an org prefix on the model must not fork the space")
	// The canonical form is the un-prefixed one.
	assert.Equal(t, "openai-compatible:gte-Qwen2-1.5B-instruct:1536",
		CanonicalSpaceID("openai-compatible:Alibaba-NLP/gte-Qwen2-1.5B-instruct:1536"))

	// A different dimension must NOT collapse.
	assert.NotEqual(t,
		CanonicalSpaceID("openai-compatible:m:1536"),
		CanonicalSpaceID("openai-compatible:m:768"))
	// A different provider name must NOT collapse.
	assert.NotEqual(t,
		CanonicalSpaceID("openai-compatible:m:1536"),
		CanonicalSpaceID("vllm:m:1536"))
	// Two different models sharing an org prefix must NOT collapse.
	assert.NotEqual(t,
		CanonicalSpaceID("openai-compatible:org/a:1536"),
		CanonicalSpaceID("openai-compatible:org/b:1536"))

	// Legacy / no-model spaces are returned unchanged.
	assert.Equal(t, "hash", CanonicalSpaceID("hash"))
	assert.Equal(t, "ollama", CanonicalSpaceID("ollama"))
	assert.Equal(t, "hash:512", CanonicalSpaceID("hash:512"))
	assert.Equal(t, "", CanonicalSpaceID(""))

	// Real default SpaceIDs round-trip cleanly (no model component to touch).
	assert.Equal(t, "hash", CanonicalSpaceID(SpaceID(NewHashProvider(768))))
}
