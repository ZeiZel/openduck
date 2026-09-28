# OpenDuck

Репозиторий содержит спецификацию и локальное synthetic-ядро приватного ассистента. Реальных интеграций OpenClaw, подключённых аккаунтов, исходящих запросов, фоновой слежки и cloud-маршрута пока нет.

Основной пакет: [Private OpenClaw Assistant](projects/openduck/tasks/personal-assistant/private-openclaw-assistant/README.md).

До прохождения decision gates и проверок безопасности запрещено предоставлять системе доступ к реальным чатам, календарям, звонкам и tech-base.

## Monorepo layout

OpenDuck is one Git repository and one root Beads database. The Go Controller is rooted at
`go.mod`; DSH-oriented packages live in `plugins/<name>` and can be versioned and released
independently, while retaining the shared Git history and security policy. The root Bun workspace
deliberately contains only `plugins/*`: the vendored DeepSeek Harness and its synthetic profile
keep their own pinned workspaces under `third_party/` and `profiles/`.

See [the monorepo guide](docs/monorepo.md) for ownership, release boundaries, and rules for local
runtime state.

For the supported signed macOS deployment flow, see
[the Ansible deployment guide](docs/ansible-macos-install.md).

## Main-only Git workflow

This personal repository uses the primary checkout and the `main` branch only. Install local
guardrails with `bun run install:git-hooks`; the installer validates the checkout before setting
the repository-local `core.hooksPath` to `.githooks`. Hooks reject detached or linked worktrees,
topic branch creation and updates, force pushes, deletions, tag pushes, and pushes that are not `main` to
`main`. Local tags may exist and may arrive through fetch/auto-follow, but this workflow never
pushes them. Deleting legacy topic refs is permitted so old branches can be cleaned up. These
hooks are developer guardrails, not an absolute security boundary: a detached worktree can be
created outside a hook, so an external CI or operator check may additionally enforce the
single-worktree policy. The regression suite runs entirely in a temporary repository:
`bun run test:main-only`.

## Synthetic developer quickstart

Требуется Go 1.26. Проверки: `go fmt ./...`, `go vet ./...`, `go test ./...`, `go test -race ./...`.
Foreground-сервис запускается командой `go run ./cmd/openduck`; он слушает только `127.0.0.1:8787`, принимает ручные синтетические события и не выполняет исходящие запросы. Для запуска оператор должен заранее выдать приложению 32-байтный ключ в macOS Keychain под не-секретными ссылками `service=openduck`, `account=queue`. Секрет создаётся и передаётся вне репозитория (интерактивно через Keychain или утверждённым администратором способом); он не должен попадать в shell history, логи или конфигурацию.

Очередь хранится в `.openduck/queue.enc`, каталог создаётся с режимом `0700`, файл — `0600` и зашифрован AES-GCM. Если ключ не provisioned, сервис завершается без запуска. Synthetic-событие должно содержать обязательные `classification` и `provenance` со `schema_version=1.0`; для smoke-теста используйте классификацию `L2` и заведомо тестовые значения.
