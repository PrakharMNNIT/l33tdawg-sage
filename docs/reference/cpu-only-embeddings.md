# CPU-only embeddings

CPU-only SAGE is practical when the embedding model, configured dimension, and
request timeout are treated as one deployment contract.

## Choose the model and dimension together

Never change only the model name. Set the exact dimension emitted by that model;
SAGE rejects mismatches so incompatible vector spaces cannot mix.

```bash
export SAGE_EMBEDDING_PROVIDER=ollama
export SAGE_EMBEDDING_BASE_URL=http://127.0.0.1:11434
export SAGE_EMBEDDING_MODEL=snowflake-arctic-embed:m
export SAGE_EMBEDDING_DIMENSION=768
export SAGE_EMBEDDING_TIMEOUT=60s
export OLLAMA_KEEP_ALIVE=24h
```

Examples such as `all-minilm:l6-v2` and `snowflake-arctic-embed:xs` commonly
emit 384 dimensions, while `nomic-embed-text` and
`snowflake-arctic-embed:m` commonly emit 768. Verify the exact artifact you
deploy rather than relying on the example.

## TEI and other OpenAI-compatible servers

Hugging Face Text Embeddings Inference (TEI), vLLM, LiteLLM, and compatible
gateways can use SAGE's OpenAI-compatible provider:

```bash
export SAGE_EMBEDDING_PROVIDER=openai-compatible
export SAGE_EMBEDDING_BASE_URL=http://127.0.0.1:8081
export SAGE_EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2
export SAGE_EMBEDDING_DIMENSION=384
export SAGE_EMBEDDING_TIMEOUT=60s
```

TEI can be a better CPU deployment choice when its chosen model/runtime offers
CPU-optimized or quantized execution. SAGE does not choose quantization for the
server; pin and verify that on the TEI side.

## Reproduce latency and request counts

The benchmark performs no memory writes. It checks every returned vector's
dimension and checks batch cardinality before printing any measurements.
“Warm” means the model is resident in the provider process; SAGE's default
wrapper does not retain completed plaintext embeddings across later callers.
It only coalesces identical requests while they overlap in flight.

```bash
go run ./cmd/sage-embedding-bench \
  -provider ollama \
  -base-url http://127.0.0.1:11434 \
  -model snowflake-arctic-embed:m \
  -dimension 768 \
  -timeout 60s \
  -keep-alive 24h \
  -scalar-runs 5 \
  -batch-size 16
```

For Ollama, the harness first sends a validated `keep_alive=0` embed request so
the next scalar request is a controlled cold load. It then measures warm scalar
requests and one native input-array batch. Use `-skip-cold-reset` when unloading
is undesirable; the output labels that sample `first_observed_scalar` and does
not claim it was cold.

The OpenAI embeddings API has no standard unload operation. The harness therefore
labels its first sample `first_observed_scalar` unless `-cold-reset-url` names an
operator-controlled POST endpoint that unloads or restarts the model. A failed
reset, unreachable provider, wrong dimension, malformed index, or wrong batch
cardinality exits non-zero and prints no benchmark result.

Compare JSON output from otherwise identical runs. Record the machine context,
model, dimension, timeout, scalar request count, batch size, and provider runtime
version alongside results; latency numbers without those fields are not portable.
