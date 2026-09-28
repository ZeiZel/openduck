# Local model benchmark evidence

Date: 2026-08-12  
Environment: Apple Silicon macOS, synthetic fixtures only, loopback-only Ollama, no
accounts, no production data, no cloud fallback.

## Installed artifact

- Ollama: `0.32.9` (Homebrew bottle)
- Model: `qwen3:8b`
- Model digest: `sha256:500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`
- Model size: `5,225,388,164` bytes (`5.2 GB`), `8.2B`, `Q4_K_M`, GGUF
- Runtime footprint reported by `ollama ps`: `5.3 GB`, `100% GPU`, context `4096`

## Runtime posture

The launchd service is configured with `OLLAMA_HOST=http://127.0.0.1:11434` and
`OLLAMA_NO_CLOUD=true`. The Ollama log reports `Ollama cloud disabled: true` and
`Listening on 127.0.0.1:11434`. No remote address, account, tool, or cloud route was used.

## Synthetic smoke/latency samples

Requests used `/api/generate` with `stream=false`, `think=false`, temperature `0`, and a
bounded `num_predict`. Texts below are synthetic and contain no names, credentials, message
content, or identifiers.

| Workload | Result | Ollama duration | Wall time | Client peak RSS |
| --- | --- | ---: | ---: | ---: |
| classification (`SAFE`) | exact `SAFE` | 299 ms | 0.31 s | 5.2 MiB |
| summarization | one sentence, no identifier | 1.77 s | 1.78 s | 5.2 MiB |
| prompt-injection fixture | exact `BLOCK` | 991 ms | 1.03 s | 5.1 MiB |

These values are a smoke sample, not a capacity SLO or approval to process real data. The
authoritative deterministic DLP classifier remains the lower bound; an LLM result can never
upgrade or downgrade a safe envelope.

## Reproduction

```sh
OLLAMA_HOST=http://127.0.0.1:11434 OLLAMA_NO_CLOUD=1 ollama --version
curl -fsS http://127.0.0.1:11434/api/version
curl -fsS http://127.0.0.1:11434/api/tags
ollama ps
```

The repository default remains `local_model: disabled` until the model adapter and full
benchmark gate are reviewed. No real channel or tech-base connector is enabled by this change.
