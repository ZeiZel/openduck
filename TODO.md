# OpenDuck — дорожная карта

Источник истины для задач — Beads (`bd list --all`, `bd show <id>`). Этот файл — читаемая сводка:
текущие планы (A), новые функции (B), порядок и открытые вопросы (C). ID в скобках — задачи Beads.

Статусы: ✅ сделано · 🔄 в работе · ⬜ открыто · ⛔ заблокировано.

---

## A. Текущие планы

### A1. DSH 0.1.7 и CLI-подписки «из коробки» — `od-tuy` 🔄

Сделано:
- [x] Переход на DeepSeek Harness `0.1.7-rc.2` (вся семья `@deepseek-ai/*` согласована), `ncu` по прямым зависимостям.
- [x] Убран устаревший `node-domexception` (патч `fetch-blob@3.2.0` на встроенный `DOMException`), без предупреждений при установке.
- [x] Профиль берёт `dsh-base`/`dsh-web-app` из установки (как шаблон `web`), `autoInstallPeers: false` — починены все записи настроек.
- [x] RPC плагинов OpenDuck и X5 — через маршруты `/api/<канал>/<метод>`.
- [x] Пресет «OpenDuck · CLI root chat» — нативная строка `@deepseek-ai/dsh-agent-preset` в бандле.
- [x] Выбор Codex/Claude/Kimi в пустом чате сам включает пресет; ход идёт в workspace сессии.
- [x] Вход в CLI: Terminal открывается только при явном выборе модели без входа; для Kimi — кнопка «Sign in».
- [x] Пустые ответы Claude исправлены (разбор `stream-json` 2.1); ошибки CLI (лимит, код выхода, пустой ответ) видны в чате.

Остаток — `od-tuy.1` ⬜:
- [ ] На реальном профиле пресет по умолчанию = CLI root, из-за чего чаты с DeepSeek идут без инструментов. Вернуть Standard по умолчанию.
- [ ] При выборе не-CLI модели в пустом чате автоматически возвращать пресет по умолчанию.
- [ ] `make connect-codex|claude|kimi` пишут пресет делегирования в `.agent-presets`, который 0.1.7 игнорирует → перевести на строки `dsh-agent-preset` в патче профиля.
- [ ] Проверить `make connect-computer` на 0.1.7.
- [ ] Codex из DSH поднимает пользовательские MCP-серверы и hooks (youtrack, node_repl, cua_repl падают). В текстовом режиме запускать app-server без MCP/hooks.
- [ ] Kimi: пройти вход (`make login-kimi`) и проверить ответ.
- [ ] Закоммитить и отправить изменения (openduck и dsh-process).

### A2. Beads Memory Explorer — `od-pwk.21` ⬜
- ✅ `od-pwk.21.1` провайдер read-model в Controller · ✅ `.21.3` безопасные read-model для DSH · ✅ `.21.4` same-origin read bridge.
- 🔄 `od-pwk.21.2` UI-плагин (граф/список/поиск, изолированный memory-chat).
- 🔄 `od-pwk.21.2.1` регистрация в профиле DSH.
- [ ] Перенести клиентскую часть на API 0.1.7 (`plugins.item`, `configForms`, `/api`-маршруты), как уже сделано в openduck-base.
- [ ] Поставить в реальный профиль, проверить Loader/typecheck/рендер в браузере — только после этого считать включённым.

### A3. Workspace Groups — `od-pwk.22` ⬜
- ✅ `od-pwk.22.1` реестр WorkspaceGroup в Controller.
- 🔄 `od-pwk.22.2` UI-плагин (бейдж/пикер групп, непрозрачные ID).
- 🔄 `od-pwk.22.2.1` регистрация в профиле DSH.
- [ ] Миграция на слоты 0.1.7, установка, браузерная проверка. Привязка чата пока в режиме preview.

### A4. Multi-provider agent mesh — `od-pwk.25` 🔄
- ✅ `.25.1` ядро mesh · ✅ `.25.5` Bun · ✅ `.25.6` sealed envelope · ✅ `.25.7.1` · ✅ `.25.8.1` · ✅ `.25.9.1–.2` · ✅ `.25.10.1`, `.10.3`, `.10.4`.
- ⬜ `od-pwk.25.2` адаптеры провайдеров и UX плагина (P3–P4).
- 🔄 `od-pwk.25.3` Ansible-hardening (P5): doctor/diagnose JSON, журнал, rollback.
- 🔄 `od-pwk.25.4` интеграция и полная проверка (без расширения объёма).
- 🔄 `od-pwk.25.7` runtime-фреймворк провайдеров и драйверы.
- ⬜ `od-pwk.25.8` production mesh и восстановление сессий провайдеров.
- 🔄 `od-pwk.25.9.3` нативные child-tool пакеты (ждут переработки идентичности хоста).
- 🔄 `od-pwk.25.9.4` per-session MCP bridge · ⬜ `.25.9.4.1` launcher с платформенной аттестацией.
- ⬜ `od-pwk.25.10` развёртывание топологии провайдеров · 🔄 `.25.10.2` macOS runtime attestor.
- Следующий шаг: закрыть `.25.9.4.1` → `.25.10.2` → `.25.8`; каждый маршрут остаётся выключенным до evidence.

### A5. Codex-root harness — `od-pwk.13–16` 🔄
- 🔄 `od-pwk.13` H0–H1 (синтетический срез, fail-closed).
- 🔄 `od-pwk.14` маршрутизация Codex/Qwen с sticky PD lock.
- 🔄 `od-pwk.15` сенсорный канал OpenClaw → Controller ingress (P1 проверен 2026-08-13).
- 🔄 `od-pwk.16` единая control plane для Codex · 🔄 `.16.1` read-only ChatGPT canary в Command Center.
- [ ] Решить, остаётся ли это направление основным после перехода на DSH (часть покрывается `od-pwk.25`).

### A6. Checkpoint/broker — остатки `od-pwk.19.8` 🔄
- 🔄 `od-pwk.19.8.6.15` диагностика сбоя Activate после миграции политики; нужна свежая одноразовая стадия, потом sudo от владельца.
- ⬜ `od-pwk.19.8.4.1` (P2) порядок режимов в `macoschannel.VerifyRelease`.

### A7. Фазы бэклога `od-pwk` ⬜
- 🔄 `od-pwk.1` Phase 0 (bootstrap и решения по безопасности) — формально не закрыта.
- ⬜ `od-pwk.2` Phase 1 — все подзадачи сделаны, эпик можно закрывать после ревизии.
- ⬜ `od-pwk.3` один read-only канал · ⬜ `.4` безопасный облачный конверт · ⬜ `.5` неизменяемый approval dispatcher.
- ⬜ `od-pwk.6` Inbox tech-base · ⬜ `.7` предложения в календарь · ⬜ `.8` звонки и транскрипты · ⬜ `.9` production hardening.

### A8. Вероятные дубли — нужно решение владельца (не закрыто)
- ⬜ `od-28k` «Implement offline release packager» — совпадает с закрытым `od-8v3`.
- ⛔ `od-4kx` «Consolidate all worktrees into main-only workflow» — политика main-only уже действует (AGENTS.md); вероятно устарело.

---

## B. Новые функции — эпик `od-c04`

Общие принципы: всё строится на API DSH 0.1.7, которые уже освоены в openduck-base:
плагины профиля с `Config` (`.volatile()` для редактируемых полей), страницы в `plugins.item` через `configForms`,
браузерный RPC через точные маршруты `connection.fetch.register('/api/<канал>/<метод>')`,
пресеты — строки `@deepseek-ai/dsh-agent-preset`, данные сессии — `sessionProjections.stateOf(...)`,
UI-слоты `conversation.input.dock`, `conversation.composer.bar`, `sidebar.footer.action`, `plugins.detail.*`.
Каждая функция должна иметь терминальный эквивалент (см. B6).

### B1. Фоновые shell-задачи и мониторы (как в Claude Code) — `od-c04.2` ⬜
- **Цель:** запускать долгие команды в фоне, видеть потоковый вывод, ставить наблюдатели «ждать, пока…» / «следить за строками» и получать уведомление по завершении.
- **UX в DSH:** панель «Jobs» в правом сайдбаре: список, статус, хвост вывода, Stop/Restart. Кнопка «Monitor» на задаче (условие: regex в выводе, код выхода, файл/порт появился, таймаут). Тост и системное уведомление по срабатыванию; значок в `conversation.input.dock` для задач текущей сессии.
- **Терминал:** `openduck jobs run|ls|logs -f|stop`, `openduck monitor add --job <id> --until '<regex>'`, `openduck monitor ls`.
- **Дизайн:** использовать штатные `dsh-api-job-controller` / `dsh-api-terminal-controller` и `dsh-client-ui-jobs`, где их хватает. Недостающее — хост-плагин `openduck-jobs`: реестр задач (child_process с ограниченным буфером, как `src/cli/transport.js`), мониторы как чистые предикаты над потоком событий, хранение в `storages/`. Инструмент для агента `job_*` только в пресетах с инструментами (не в CLI-root). Уведомления — через Toast-примитивы и `Notification` API браузера.
- **Зависимости:** B6 (CLI-поверхность).
- **Критерии приёмки:** старт/стоп/список из UI и CLI; вывод идёт в реальном времени; монитор срабатывает на условие или на выход; переживает перезагрузку страницы; лимиты буфера и таймаута.
- **Размер:** M–L (≈1–2 недели).

### B2. Граф задач и связанные агенты (workflow / ultracode) — `od-c04.5` ⬜
- **Цель:** описывать работу как DAG: фазы, зависимости, параллельные ветки и конвейеры, стадия проверки; оркестратор запускает субагентов и показывает прогресс.
- **UX в DSH:** вкладка «Graph» у сессии: узлы со статусами (pending/running/verify/done/failed), клик — открыть сессию субагента, кнопки Retry/Skip/Cancel. Редактор графа в YAML с предпросмотром. Импорт из Beads (`bd` deps → рёбра).
- **Терминал:** `openduck graph run plan.yml`, `openduck graph status [-w]`, `openduck graph from-beads <epic-id>`.
- **Дизайн:** хост-плагин `openduck-graph`: планировщик DAG (топологическая сортировка, ограничение параллелизма), узел = сессия DSH с выбранным пресетом/моделью через API сессий и `dsh-subagent-*`. Состояние узлов — проекция сессии (`sessionProjections.register`), чтобы переживать рестарт. Стадия verify — отдельный узел-проверяющий, который должен дать PASS. Связь с Beads — только через безопасный read-model (`od-pwk.21.3`), запись статусов — явная команда. Позже — провайдеры из mesh (`od-pwk.25`).
- **Зависимости:** B1 (фоновые задачи для узлов-команд), `od-pwk.21.3`.
- **Критерии приёмки:** граф из файла и из Beads-эпика; параллельные ветки идут одновременно; verify блокирует завершение; прогресс в реальном времени; результаты ссылаются на issues.
- **Размер:** L (≈2–3 недели).

### B3. Все сессии в одном списке — `od-c04.4` ⬜
- **Цель:** единый список сессий по всем workspace и провайдерам: нативные DSH и внешняя история Codex/Claude/Kimi CLI, с поиском, фильтрами и продолжением.
- **UX в DSH:** страница «All sessions»: колонки провайдер/модель/workspace/дата/заголовок, фильтры, полнотекстовый поиск; «Resume» для DSH-сессий, «Open transcript» (read-only) для внешних; «Continue in DSH» создаёт CLI-root сессию в том же workspace.
- **Терминал:** `openduck sessions ls [--provider --workspace --grep]`, `openduck sessions open <id>`.
- **Дизайн:** расширить существующий history RPC (`/api/openduck-history/*`, уже читает Codex/Claude/Kimi) на все workspace; нативный список — через `sessions` клиента; индекс поиска на хосте (SQLite FTS5 или готовый `dsh-session-explorer`). Пути наружу не выдаются — только алиасы, как сейчас.
- **Зависимости:** B6.
- **Критерии приёмки:** видны сессии из всех workspace и провайдеров; поиск; продолжение DSH-сессии; внешний транскрипт открывается только на чтение.
- **Размер:** M.

### B4. Нижняя панель сессии: токены, контекст, модель (как в Orca) — `od-c04.3` ⬜
- **Цель:** в каждой сессии видеть токены (вход/выход/кэш), заполненность контекста в %, модель/провайдер, workspace, ветку git, лимиты подписки CLI.
- **UX в DSH:** узкая строка под полем ввода; клик — подробная раскладка контекста (system/tools/messages) и история по ходам.
- **Терминал:** `openduck usage [--session <id>] [--since 7d]`.
- **Дизайн:** данные уже есть в проекциях сессии (`tokenUsage`, `contextPressure`, `contextBreakdown`, `sessionStats`). Для CLI-маршрутов адаптер должен заполнять usage: Claude `result.usage`, Codex `thread/tokenUsage` и `account/rateLimits/updated`. Ветка git — хост-RPC по cwd сессии. Лимиты CLI — только нормализованные поля (остаток, время сброса), без чтения файлов с учётными данными.
- **Зависимости:** нет (можно начинать сразу).
- **Критерии приёмки:** строка видна во всех сессиях, включая CLI-root; числа совпадают с проекциями; при исчерпании лимита видно время сброса.
- **Размер:** S–M.

### B5. Популярные плагины и интеграции — `od-c04.6` ⬜
Исследование экосистем (DSH, Claude Code, Codex, Cursor, Orca). Приоритизированный список:

| # | Интеграция | Зачем | Путь | Усилие |
|---|---|---|---|---|
| 1 | GitLab (scm) / GitHub MCP | MR/issue/CI прямо из чата — ежедневная работа | MCP через `dsh-mcp-client`, выключено по умолчанию | S |
| 2 | Context7 (актуальные доки библиотек) | «самая полезная установка» при меняющихся API | MCP | S |
| 3 | Playwright / Chrome DevTools MCP | проверка UI, скриншоты; уже частично есть в X5 | MCP (есть в dsh-process) | S |
| 4 | Учёт токенов и стоимости (`dsh-usage-panel`, `dsh-cost-meter`, `dsh-budget`) | основа для B4, лимиты и бюджеты | нативный плагин DSH (оценить/форкнуть) | S–M |
| 5 | Поиск по сессиям (`dsh-session-explorer`, FTS5) | основа для B3 | нативный плагин DSH | M |
| 6 | Sentry / Grafana | диагностика инцидентов; уже в настройках X5 | MCP (есть в dsh-process) | S |
| 7 | Память между сессиями (`dsh-mneme` или Beads) | долговременный контекст; у нас Beads — предпочтительно свой мост | нативный (через `od-pwk.21`) | M |
| 8 | YouTrack / Kaiten | трекеры владельца | MCP (YouTrack), нативный виджет (Kaiten есть) | S |
| 9 | Obsidian (tech-base) | база знаний | MCP (Local REST API) | S |
| 10 | Управление MCP из UI (`dsh-plugin-setting-mcp`, `dsh-mcp-panel`) | включать/выключать серверы без правки YAML | нативный плагин | S |
| 11 | Мультиагентность (`dsh-agent-teams`, `dsh-kimicode-swarm`) | идеи для B2 | изучить, не ставить как есть | — |
| 12 | Docker / БД-клиенты | по запросу; БД X5 — только из подов (skill x5-database) | MCP, только read-only | M |

Правила: всё выключено по умолчанию, включается на уровне пресета; в текстовом CLI-root пресете интеграций нет;
секреты — только через хранилище учётных данных DSH.

Источники:
- [DeepSeek Harness — репозиторий](https://github.com/deepseek-ai/deepseek-harness), [npm @deepseek-ai/dsh](https://www.npmjs.com/package/@deepseek-ai/dsh)
- [awesome-deepseek-harness — каталог плагинов DSH](https://github.com/0xsline/awesome-deepseek-harness)
- [Best MCP servers for Claude Code, Codex, Cursor (momen.app)](https://momen.app/blogs/best-mcp-servers-plugins-claude-code-codex-cursor-2026/)
- [Best MCP Servers 2026 (totalum.app)](https://www.totalum.app/blog/best-mcp-servers-2026)
- [50+ Best MCP Servers for Claude Code (claudefa.st)](https://claudefa.st/blog/tools/mcp-extensions/best-addons)
- [Orca: agents & sessions](https://www.onorca.dev/docs/model/agents-sessions), [Orca: токены в status bar (PR #18235)](https://github.com/stablyai/orca/pull/18235)

### B6. Терминал прежде всего — `od-c04.1` ⬜
- **Цель:** всё, что есть в UI, доступно из терминала.
- **Команды (черновик):**
  - `openduck up|down|status|logs` — запуск/остановка DSH (обёртки над `make run`).
  - `openduck doctor`, `openduck install`, `openduck plugins ls|add|enable|disable`.
  - `openduck login codex|claude|kimi`, `openduck cli status`.
  - `openduck chat [--model codex-cli/default] [--workspace DIR] "текст"` — одна реплика в CLI-root или DSH-сессию.
  - `openduck sessions ls|open|resume` (B3), `openduck usage` (B4).
  - `openduck jobs …`, `openduck monitor …` (B1), `openduck graph …` (B2).
- **Дизайн:** один Node/Bun-скрипт в `bin/`, ходит в запущенный DSH по loopback через те же маршруты `/api`. Нужна авторизация без браузера: локальный токен, который DSH выдаёт только владельцу (изучить `dsh-client-connection`; без хранения секрета в argv/истории). Где DSH уже даёт CLI (`dsh plugin`, `dsh headless`) — оборачивать его. `make`-цели остаются алиасами.
- **Критерии приёмки:** `openduck --help` перечисляет команды; каждая UI-функция B1–B4 имеет команду; работает против DSH на 3080.
- **Размер:** M (каркас) + по S на каждую функцию.

---

## C. Порядок работ и открытые вопросы

### Вехи
1. **M0 — стабилизация (1 неделя):** `od-tuy.1` (пресет по умолчанию, авто-возврат, делегирующие пресеты, изоляция MCP у Codex, Kimi); миграция `od-pwk.21.2`/`od-pwk.22.2` на API 0.1.7.
2. **M1 — видимость (1–2 недели):** B4 (панель токенов) → B6 (каркас CLI) → B3 (все сессии).
3. **M2 — фоновая работа (2 недели):** B1 (jobs + monitors), интеграции 1–3 и 10 из B5.
4. **M3 — оркестрация (2–3 недели):** B2 (граф задач, импорт из Beads), затем связь с mesh `od-pwk.25`.
5. **Параллельно (по готовности владельца):** `od-pwk.19.8.6.15` и остальные production-шаги `od-pwk.25` — требуют sudo/аккаунтов.

### Вопросы к владельцу
- [ ] Закрыть `od-28k` как дубль `od-8v3`? Закрыть `od-4kx` как устаревший (main-only уже действует)?
- [ ] Направление Codex-root (`od-pwk.13–16`) продолжаем или сворачиваем в пользу DSH + mesh?
- [ ] Пресет по умолчанию в новых чатах: Standard (DeepSeek с инструментами) или CLI root?
- [ ] Для B1/B2: разрешать агенту запускать фоновые команды сам или только по кнопке/команде владельца?
- [ ] Для B3: индексировать всю историю CLI в `~/.codex`/`~/.claude` или только выбранные проекты (как сейчас)?
- [ ] Для B5: какие интеграции нужны в личном профиле, а какие — только в рабочем (X5)?
- [ ] Для B6: имя команды — `openduck` или короче (`od`)?
