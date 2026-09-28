# 08. Локальная модель и облачная маршрутизация

## Назначение локальной модели

`PROPOSAL`: локальная instruct-модель класса 4–9B через Ollama выполняет ограниченные задачи: urgency/topic classification, suggested sensitive spans, summarization, candidate extraction и pseudonym-safe drafting. Она работает без browser/shell/filesystem/channel tools и возвращает typed JSON.

`ASSUMPTION`: Apple M5/24 GB достаточно для приемлемой 4–9B quantized модели. Выбор делается benchmark на реальных размерах контекста с synthetic/private-safe corpus; не фиксируется заранее на Qwen только по размеру. `VERIFIED`: официальный Ollama registry содержит варианты Qwen3 4B/8B, а OpenClaw документирует локальный Ollama provider. Это подтверждает доступность вариантов, но не качество, latency или privacy.

## Почему LLM не privacy boundary

Модель вероятностна, может пропускать секреты, галлюцинировать классы и подчиняться injection. Поэтому:

- deterministic rules задают нижнюю границу класса и deny;
- model может повысить класс или запросить review, но не снизить deny;
- model output не исполняется как policy/tool call;
- безопасный envelope проходит post-scan;
- local endpoint bind только loopback; Ollama Cloud/hybrid routes запрещены для local privacy role;
- network egress процесса local inference блокируется/проверяется там, где возможно.

## Model selection benchmark

Сравниваются минимум два 4–9B кандидата и deterministic-only baseline:

| Метрика | Требование |
|---|---|
| DLP span recall | высокий приоритет; threshold утверждает Security owner, рекомендовано ≥0.98 на critical synthetic corpus |
| DLP precision | измеряется, но false positive безопаснее false negative |
| Candidate precision/recall | по размеченному русскому/английскому корпусу |
| Deadline non-inference | 100% ambiguous dates дают null/clarification |
| Prompt injection resistance | модель не выдаёт executable actions; schema validator блокирует нарушения |
| Latency/memory | p50/p95 и peak RSS на M5/24 GB |
| Context truncation | явно сигнализируется; не выдаётся full-coverage summary |

Model artifact фиксируется digest, license, source, quantization, context settings и evaluation report.

## Cloud routes

Есть два взаимоисключающих privacy posture:

1. **Strict API route (`PROPOSAL`, предпочтителен для L1):** отдельный OpenAI API project, `store=false` где применимо, endpoint/model eligibility и data controls проверены. Официальная документация указывает, что API content не используется для обучения по умолчанию, а abuse monitoring обычно может храниться до 30 дней; ZDR/MAM требует eligibility/approval. Конкретная конфигурация фиксируется evidence.
2. **ChatGPT/Codex subscription OAuth:** OpenClaw документирует этот auth route, но consumer/business data controls зависят от плана и настроек. Его нельзя считать эквивалентом strict API privacy автоматически.

`CONFLICT`: желание использовать «ChatGPT/тебя» через subscription OAuth противоречит строгой проверяемой API data-control политике. `DECISION REQUIRED / Data owner + Security owner / до Phase 3`: либо strict mode запрещает OAuth для любых classified envelopes, либо пользователь принимает документированный режим плана. Стартовое правило: **если policy posture = strict, OAuth route forbidden**.

## Router decision table

| Условия | Route |
|---|---|
| L3 или secret hit | deny cloud; local/manual only |
| raw L2 | deny cloud по умолчанию |
| L2 exception + точное owner consent | approved configured API route only; никогда silent OAuth fallback |
| L0/L1 + strict policy + API project verified | allow configured API model |
| L0/L1 + OAuth permitted by explicit decision | allow OAuth route с UI label |
| DLP/policy/model unavailable | no cloud; deterministic/local template/manual |
| provider outage/rate limit | queue draft request или local fallback с маркировкой; не менять provider автоматически |
| schema/post-scan failure | deny and ask/revise locally |

## Cloud request controls

- Endpoint allowlist и TLS; custom proxies запрещены до отдельного security review.
- Provider/model/auth profile записываются как metadata; token secret остаётся Keychain/secret store.
- Safe envelope содержит purpose и forbidden actions; tools disabled.
- Minimize message count/length; attachments/URLs/raw headers исключены.
- Response schema ограничивает draft/candidates; response тоже считается untrusted.
- Budget/rate limits предотвращают runaway cost; owner видит usage summary.
- Нет автоматического provider failover, если меняется privacy/retention jurisdiction.

## Local rehydration

Псевдонимы заменяются на реальные значения только после cloud response и только в owner preview. Rehydration parser работает по exact tokens и не интерпретирует model-created похожие placeholders. Unknown pseudonym блокирует ready-to-send state. После rehydration action снова проходит DLP и approval; облачный ответ не получает привилегий.

## Model failure/degraded behavior

- Local model down/OOM: watcher использует deterministic rules и сообщает reduced quality; cloud не получает raw fallback.
- Malformed JSON: один constrained retry локально; затем manual.
- Cloud denied/outage: draft остаётся local/manual, inbound monitoring продолжается.
- Excess context: bounded chunking с coverage manifest; partial summary маркируется incomplete.
- Model upgrade: shadow evaluation, pinned rollout и rollback; никакого auto-pull production model.
