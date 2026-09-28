# 16. Наблюдаемость, recovery и retention

## Metrics

Per source: observed/admitted/quarantined/deduped events, authoritative cursor/sequence presence, event/revision-set and high-water versions, `complete|best_effort|unknown`, gap age, backfill lag, auth/rate errors. Per route: LocalPDDispatch/CloudAdmittedPrompt decisions, append `pending|consuming|consumed|uncertain`, receipt/reconcile, stale-snapshot invalidations, exact egress count, DLP/declassification and sentinel violations. Per work: queue/run/review latency, retries, binding/schema rejects, resource/token/context. Per effect: approvals/unknown/reconcile. Per UX: read-model leakage and latency, без raw content.

## Audit

Append-only metadata events reconstruct source→privacy→candidate→spec/order→evidence→review→decision→effect/session lifecycle. Audit хранит IDs/digests/policies/attestations/transitions, not secret/raw body. Hash-chain + signed/checkpointed segments are mandatory before pilot; tamper, reorder or dropped event invalidates derived current state and quarantines affected ledger.

## Health and alerts

- Controller/DSH/Qwen/Codex/sidecar process health and version digests;
- source cursor freshness and coverage gaps;
- credential expiry/consent revocation without token value;
- queue leases/dead letters/quarantine volume;
- storage/keychain/index health;
- DSH profile/config drift, telemetry hard-off, unexpected listeners/ports;
- unexpected DeepSeek/other LLM egress, duplicate Codex turn/context and model/tool network crossover;
- admission stuck `consuming|uncertain`, missing/duplicate append receipt, final-gate snapshot drift and safe-public sockets after revoke;
- failed malicious-DSH isolation probes for any credential/raw-store sidecar;
- DSH/browser JSONL/SQLite/context/search/postMessage/storage cache sentinel leakage;
- resource pressure/swap and concurrency throttling;
- purge overdue and unresolved `UNKNOWN` effects.

Notifications contain safe metadata only. Security/privacy failure can trip route-specific kill switch automatically.

## Recovery matrix

| Failure | Required behavior |
|---|---|
| Sensor restart/sleep | resume cursor/backfill; surface gap; no cloud until complete scan |
| Controller crash | encrypted ledgers/leases recover; no effect without current reservation |
| Crash around cloud append | reconcile admission ID/receipt; exactly one matching append becomes consumed, otherwise uncertain; no retry/egress |
| Conversation change before Codex | new/edit/delete/backfill/hidden-prior/gap/revoke/class bump invalidates prompt at final authoritative re-read |
| DSH/UI crash | reconnect/rebuild projection; canonical state unchanged |
| Qwen unavailable | PD route blocked/local error; no fallback |
| Codex unavailable/context overflow | work paused/blocker; no route to Qwen for non-PD by accident |
| Worker crash | expire lease; inspect partial work; new attempt with new attestation |
| Graph/Kaiten cursor invalid | mark gap; bounded full resync; preserve prior evidence |
| Effect timeout | `UNKNOWN`; reconcile before retry |
| Credential revoked | stop affected source/effector; invalidate queued operations |
| Safe-public revoke | close profile/sockets, reject queued/future request and record bounded network receipt |
| Schema/plugin/DSH mismatch | fail boot/route; rollback pinned profile |
| Audit tamper/reorder/drop | stop affected transition; restore from verified checkpoint or manual reconcile |
| Session archive/delete | archive reversible; purge uses per-store receipts and never overclaims hard erase |

## Retention classes

Specific TTLs are DR-004. Policy must independently cover:

- raw quarantine payload;
- normalized local event and source cache;
- DSH session events/index/client cache;
- Qwen PD session;
- candidates and rejected drafts;
- approved MemoryRecord/tech-base note;
- work evidence and review;
- time events;
- audit and effect receipts;
- logs/metrics/crash reports;
- future backups.

Каждый store объявляет `erasure_capability=hard|logical|none`. Raw PD допускается только в store с verified `hard` capability и TTL. DSH JSONL/SQLite/browser/index/telemetry считаются запрещёнными PD stores независимо от purge claims.

No policy means real ingest blocked. Derived copies inherit at least the source class and expiry unless an approved durable record establishes a new purpose.

## Purge

Purge plan enumerates all materializations, revokes handles, executes only supported operation, records `ErasureReceipt` and verifies observable absence. `hard` means physically/provider-semantically proven for that store; `logical` means hidden/unindexed but bytes may remain; `none` means retained. Overall outcome reports weakest capability. Tombstone/audit may retain non-sensitive digest and authorized deletion fact. Provider deletion is separate effect.

Archive is not purge: upstream DSH archive only hides while retaining log/accounting. Controller session lifecycle tracks archive/unarchive independently from purge request and search/cache/index cleanup.

## Crash-dump and memory posture

App-generated crash/core dumps and automatic crash uploads are disabled for DSH, Controller, Qwen, Codex bridge and sidecars; logs exclude raw buffers. Host launch policy verifies core-dump/resource settings and scans configured crash reporters. Это не доказывает zero residue: raw bytes may remain in RAM/swap and a same-UID malicious DSH process may read addressable files/process state. Real credential/raw-store enablement for Codex, Graph, Kaiten, AX/CuaDriver, Qwen/quarantine and Beads/private stores therefore requires DR-020 per-runtime OS principal/App Sandbox/read-deny/Keychain ACL evidence; process separation alone insufficient, residual RAM risk remains documented.

## Backup posture

`USER DECISION`: сейчас backups не реализуются. Interfaces reserve `BackupManifest/RestoreReceipt`, local encrypted future destination, separate key, outbound-disabled restore drill and RPO/RTO; code/config must not silently create copies. Backup enablement is DR-015 plus dedicated acceptance.

## Disaster/upgrade drills

Synthetic drills: abrupt kill at each transition, disk-full/corruption, ledger tamper/reorder/drop, clock/timezone, cursor loss, auth revoke, rate limit, DSH bundle failure, Codex protocol/auth/network mismatch, malicious UI plugin, Qwen OOM, network partition, duplicate webhook, session archive/purge and unknown effect. Evidence includes pre/post ledger hashes, input/output sentinel scan, no duplicate model/effect and rollback outcome.
