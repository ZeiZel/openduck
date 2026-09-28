# P2A synthetic local-PD conformance

Status: **VERIFIED — synthetic scope only**.

`scripts/localpd-conformance.sh` exercises the provider-free safety kernel across the detector corpus, encrypted metadata high-water ledger, quarantine restart/opaque references, default-disabled Qwen protocol boundary, LocalPD read-model boundary, and the DSH bridge/Command Center projection boundary. The test corpus contains exact and near-miss markers, hidden Unicode, injection-like text, gaps, rollback/stale decisions, sticky PD classification, replay, and synthetic call counters.

All payloads are synthetic sentinels constructed in memory. Tests assert that raw payload bytes do not enter the encrypted metadata ledger or bridge/read-model responses. Qwen is represented only by the sealed fake protocol/replay store; no Ollama process, model inference, network socket, account, notification, calendar, mail, task mutation, or external effect is used. The test script does not inspect host service state; OpenClaw and Ollama therefore remain **UNVERIFIED by this script** (the separate runtime evidence records them stopped).

The following remain **UNVERIFIED/BLOCKED** and are not implied by this conformance pass: a real Qwen/Ollama runtime and native isolation attestation; native editor provenance and owner authentication; the DR-020 same-UID-resistant monotonic checkpoint authority; real enterprise-chat/Telegram, Outlook, task-tracker, Beads integrations; Codex subscription/app-server connectivity; and live browser iframe rendering.
