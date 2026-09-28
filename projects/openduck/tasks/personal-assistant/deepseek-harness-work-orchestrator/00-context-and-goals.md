# 00. Контекст, цели и границы

## Исходное состояние

`VERIFIED / repository evidence`: OpenDuck уже содержит deterministic DLP, versioned inbound/safe-envelope contracts, encrypted leased queue, pseudonym mapping, replay/commit-uncertainty handling, локальный Qwen/Ollama и прототипы Controller/CuaDriver/Codex routing. Реальные аккаунты и effects не считаются включёнными самим наличием кода или конфигурации; ссылки — в [source register](20-source-register.md).

`VERIFIED / 2026-08-19`: DSH строит runtime из Cordis plugins, profiles и bundles; session log является источником model context, а upstream формулирует инвариант «model-visible means logged». Web UI по умолчанию работает локально, но продукт находится в developer preview и допускает breaking changes.

`VERIFIED / 2026-08-19`: официальный `dsh-subagent-codex` запускает локальный `codex app-server --stdio`, используя native Codex config/auth, но предоставляет только fresh process/thread/turn и final text. Persistent thread, approvals, progress stream и schema-controlled handoff требуют нашей реализации.

## Проблема

Рабочий контекст распределён между чатами, почтой, календарём, Kaiten, Beads, репозиториями и временем. Ручная сверка теряет договорённости и сроки; прямая загрузка всей истории в Codex загрязняет контекст и создаёт privacy/injection risk. Требуется единый Command Center с разделёнными trust planes и проверяемыми records.

## Цели

| ID | Цель | Измеритель выхода из pilot |
|---|---|---|
| G-01 | Единая DSH surface для входящих, календаря, графика, задач, времени, review и решений | 100% pilot workflows доступны из Command Center без обращения к внутренним worker UI |
| G-02 | Codex только планирует, специфицирует и проверяет bounded artifacts | 0 raw chat/mail/tool logs в root context; каждый dispatch имеет frozen spec |
| G-03 | Локальная и доказуемая обработка ПД | 0 raw PD bytes в DSH persistence/cloud/telemetry/network; LocalPDDispatch never accepted by DSH |
| G-04 | Полное и честное наблюдение разрешённых enterprise-chat/TG/Outlook/task-tracker sources | 100% наблюдаемых gaps/edits/deletes показаны; coverage неизвестен — route quarantined |
| G-05 | Согласованный календарь демо и график работ | каждое событие/зависимость имеет provenance и plan/fact status |
| G-06 | Переиспользуемая Beads memory без смешения с issue tracker | accepted solution records находятся до повторного исследования и имеют freshness/provenance |
| G-07 | Возобновляемая multi-task работа и независимый review | каждый завершённый WorkOrder имеет EvidenceBundle и ReviewVerdict |
| G-08 | Контролируемый учёт времени | план/факт различимы; экспорт отсутствует без отдельного exact approval |
| G-09 | Никаких самовольных effects | 0 mutations без matching grant, approval/policy и effect receipt |
| G-10 | Широкий безопасный public-web/docs research | synthetic first; P7 live GET/navigation only after decision/conformance/revoke, without private payload or effects |
| G-11 | Фиксация consented meetings/calls | local digest has consent/coverage/uncertainty; outward text only strict owner-authored declassification |
| G-12 | Управляемый lifecycle DSH sessions | archive reversible; delete/purge status truthful per store and verified across indexes/caches |

## Пользовательские workflow

1. «Что нового?» — сводка новых сообщений, писем, карточек, сроков и gaps.
2. «Когда демо и успеваем ли?» — календарное событие, critical path, confidence, blockers, plan delta.
3. «Зафиксируй договорённость/решение» — candidate с attribution; запись после подтверждения.
4. «Возьми эти задачи параллельно» — decomposition, dependency-aware dispatch, bounded status, independent review.
5. «Это ПД» — немедленный irreversible-class `LocalPDDispatch` во внешний Qwen/LocalPDView, никогда не DSH/cloud admission.
6. «Начал/закончил задачу» — явный timer event; derived activity только как candidate.
7. «Проведи ревью» — read-only intake, findings, tests/evidence, без push/comment mutation по умолчанию.
8. «Подготовь проект» — reproducible probe/plan; dependency install или mutation только с отдельным grant.
9. «Изучи публичные источники» — synthetic safe-public first; real web/Context7 only P7 after explicit network gate, bounded conformance and revoke proof.
10. «Зафиксируй созвон» — consent/source/coverage → LocalPDDispatch → local Qwen suggestions → blank manual owner release editor → consumed declassification → optional create-only report.
11. «Архивируй/удали сессию» — reversible archive либо explicit per-store purge receipt без false physical-erasure promise.

## Не-цели

- NG-01: DSH, Codex или Qwen не становятся policy/authorization authority.
- NG-02: система не обещает 24/7 на спящем Mac без отдельного always-on host.
- NG-03: не выполняется скрытое чтение неразрешённых чатов, полная запись экрана или обход OS/ToS/admin policy.
- NG-04: не строится юридический timesheet и не делаются HR-выводы из активности.
- NG-05: не копируются Codex OAuth credentials и не подменяется Platform API подпиской ChatGPT.
- NG-06: не включаются backups, real data, message sending, calendar/Kaiten/mail writes или tracker mutations этим пакетом.
- NG-07: не обещается exactly-once у внешнего provider; ambiguous outcome остаётся `UNKNOWN` до reconciliation.
- NG-08: DSH session archive не считается deletion; hard erase не обещается stores с `logical|none` capability.

## Границы доверия

- TB-0: enterprise-chat, Telegram, Outlook, task-tracker, web и attachments — untrusted external data.
- TB-1: native sensors/Graph/Kaiten readers/CuaDriver proxy — sensitive collection boundary.
- TB-2: OpenDuck Controller, DLP, ledgers, capability broker и effect dispatcher — deterministic TCB.
- TB-3: Qwen/Ollama PD plane — local-only, no tools/network/fallback.
- TB-4: DSH host/UI/session plane — replaceable work surface, не privacy boundary.
- TB-5: Codex root/reviewer/worker runtimes — cloud-capable только для approved bounded capsules.
- TB-6: isolated worktrees/sandboxes — task-scoped execution plane.
- TB-7: credentials/effectors — отдельные least-privilege processes.

## Success gates

- 100% cloud paths проходят CloudAdmittedPrompt; 100% local PD paths проходят отдельный LocalPDDispatch и не входят в DSH.
- 100% accepted demo/task/memory/time facts имеют source locator и version.
- 100% provider mutations имеют immutable preview, consumed approval/grant и reconciliation record.
- 100% cloud decisions bind immutable conversation snapshot; final re-read rejects any intervening revision/gap/class change, and authorized live turns have exactly one Codex egress.
- 100% PD input/derived-output sentinels отсутствуют в DSH/session/browser/Codex surfaces; class high-water никогда не снижается.
- ≥99% root turns укладываются в утверждённый context budget; overflow блокирует dispatch.
- Crash/restart не создаёт duplicate append/effect: cloud append receipt reconciles to exactly one consumed record or terminal uncertain without egress.
- P95 synthetic ingress→Command Center ≤60 секунд; отдельные source SLO утверждаются после baseline.
