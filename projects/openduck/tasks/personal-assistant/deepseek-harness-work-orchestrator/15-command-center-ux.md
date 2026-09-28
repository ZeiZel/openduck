# 15. Command Center UX

## Information architecture

DSH становится единой user-facing surface со следующими routes:

1. **Today** — ближайшие meetings/demos, critical tasks, new high-priority inbox, running work, timers, decisions.
2. **Inbox** — enterprise-chat/TG/Outlook changes, digests, candidates, gaps and snooze.
3. **Calendar** — month/week/day, confirmed/candidate/conflicted demos and capacity.
4. **Plan** — Gantt, dependency graph, critical path, plan/fact, PlanDelta.
5. **Tasks** — WorkItems, Kaiten/Beads links, queue, dispatch/review status.
6. **Memory** — scoped search, provenance, stale/conflict/candidate queue.
7. **Time** — active timer, planned/spent/forecast, reconciliation/export candidates.
8. **Review** — incoming targets, findings, evidence and acceptance/rework.
9. **Decisions** — safe launch/status for exact previews, declassification, memory, baseline and effects; strict release editor remains Controller-native, never DSH.
10. **Health** — source coverage/cursors, auth expiry, model/runtime, queues, budgets, kill switches.
11. **Sessions** — active/archived sessions, reversible archive/unarchive, truthful purge state and per-store residuals.

## Core visual grammar

Каждый entity показывает badges:

- `LOCAL/PD`, `SAFE`, `QUARANTINED`, `UNKNOWN`;
- source + coverage/freshness;
- candidate/confirmed/conflicted;
- read/proposal/effect;
- running/blocked/review/accepted;
- estimated/explicit/provider time.

Цвет не единственный носитель смысла. Времена отображаются Europe/Moscow и original source timezone. Raw PD prompt/answer не попадает в DSH route: global search, event bus, postMessage, browser title, notification preview, localStorage/IndexedDB/service-worker cache and client telemetry. PD interaction открывается отдельным Controller-owned `LocalPDView`, не DSH iframe.

## Interaction rules

- command palette вызывает только declared human commands, не arbitrary model tools;
- universal input сначала проходит Controller: safe cloud path получает CloudAdmittedPrompt, PD path открывает LocalPDView через LocalPDDispatch и не создаёт DSH event;
- карточка раскрывает provenance/audit chain и bounded source excerpt согласно class;
- DSH approval affordance только запускает Controller native trusted renderer; exact preview/render receipt/Touch ID не создаются внутри DSH;
- optimistic UI не показывает mutation succeeded до receipt;
- `UNKNOWN` имеет отдельный reconciliation flow, не кнопку blind retry;
- long operations показывают ProgressCard, cancel/interrupt and next checkpoint;
- conflicts никогда не merge’ятся silently.

## Role of DSH UI plugins

`VERIFIED`: DSH поддерживает UI plugins, Conversation Node definitions, keyed renderers and settings cards, но session events являются model/persistence surface. `PROPOSAL`: business state поступает из Controller read-model API по отдельному authenticated local UI channel, не через `session/event`; ephemeral UI cache memory-only. Model context остаётся пустым, кроме explicit admitted Codex turn.

Если штатных extension slots/channel semantics недостаточно для UI-only non-context non-persistent calendar/Gantt/graph/health, DR-018/P1 блокирует rollout и требует isolated web-client fork/bridge. Fork не меняет Controller contracts/admission.

## Search and navigation

Universal search запрашивает Controller index по caller capability и возвращает metadata-first results с source/version/class. Deep link использует stable internal ID; external locator открывается только allowlisted handler. Private global memory возвращает только `PrivateMemoryRef`; quarantined raw payload не индексируется. Public web/Context7 search получает только separately admitted safe query; P3 uses non-routable fixture, real network appears only after P7/DR-022 and revoke evidence.

## Accessibility and anti-fatigue

- keyboard navigation, screen-reader labels, focus management;
- clear recipient/destination and risky diff before approval;
- batch approval запрещён для heterogeneous effects;
- reminders groupable/snoozable, но gaps/security alerts persistent;
- approval frequency/expiry/rejection metrics выявляют habituation;
- Russian default; source text not silently translated in evidence.
- Russian pluralization/date/time formats и Europe/Moscow rendering проверяются, сохраняя source timezone/ISO value.

## Degraded states

UI explicitly distinguishes `offline`, `sleep gap`, `best_effort/unknown coverage`, `source unauthorized`, `cursor invalid`, `Qwen unavailable`, `Codex unavailable`, `Controller unavailable`, `policy missing`, `retention blocked`, `logical/none erasure` and `effects disabled`. DSH loss does not destroy canonical state; Controller loss makes UI read-only/fail-closed.

## Session lifecycle

Archive/unarchive — reversible Controller/UI projection operation. `VERIFIED`: upstream DSH archive hides a session but retains log/accounting; workspace registration delete тоже не удаляет session logs. UI labels say «Архивировать/Вернуть», not «Удалить». Delete request opens retention view with each store’s `hard|logical|none` capability, affected indexes/caches/attachments and tombstone. Success label reflects weakest receipt; unsupported physical erase remains explicit residual.
