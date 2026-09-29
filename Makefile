.DEFAULT_GOAL := help
HOST ?= 127.0.0.1

.PHONY: help install run dump-config doctor deps-check deps-update connect-plugin connect-codex connect-claude connect-kimi connect-computer connect-cli-chat disconnect-cli-chat login-codex login-claude login-kimi disconnect-codex disconnect-claude disconnect-kimi disconnect-computer test test-base typecheck build-client pack-base test-go vet-go verify-dsh deploy-macos

help:
	@printf '%s\n' 'OpenDuck native DSH targets:' '  make install              Install pinned DSH and OpenDuck base bundle' '  make run PORT=3080       Run DSH on loopback (default port is supplied by DSH)' '  make dump-config          Print the composed profile without booting' '  make deps-check           Audit owned manifests with npm-check-updates' '  make deps-update          Update owned manifests and regenerate the Bun lock' '  make connect-{codex,claude,kimi,computer} / make disconnect-{...}' '  make connect-cli-chat     Restore the managed text-only CLI root-chat preset' '  make disconnect-cli-chat  Disable the CLI root-chat route' '  make login-{codex,claude,kimi}  Start the provider’s own subscription sign-in' '  make doctor               Report local DSH/provider executable readiness' '  make connect-plugin PLUGIN=/absolute/path' '  make connect-codex        Install/mount the native Codex delegation overlay' '  make connect-claude       Install/mount the native Claude Code delegation overlay' '  make connect-kimi         Install/mount the native Kimi ACP delegation overlay' '  make connect-computer     Check the explicit CUA MCP command configuration' '  make test                 Run first-party plugin tests' '  make typecheck            Check all first-party plugins' '  make build-client         Rebuild the typed native UI artifact' '  make pack-base            Build a portable base tarball'

install:
	./scripts/dsh-install.sh

run:
	./scripts/dsh-run.sh --host "$(HOST)" $(if $(PORT),--port "$(PORT)")

dump-config:
	./scripts/dsh-run.sh --dump-config

deps-check:
	@set -e; for manifest in package.json plugins/*/package.json profiles/dsh/openduck-synthetic/package.json scripts/dsh-runtime/package.json; do \
		if test "$$manifest" = package.json; then reject='--reject bun'; else reject=''; fi; \
		npx --yes npm-check-updates@23.1.0 --target latest --packageFile "$$manifest" $$reject; \
	done
	@printf '%s\n' 'The root Bun pin and scripts/dsh-runtime DSH pin are audited but intentionally excluded from mass updates.'

deps-update:
	@set -e; for manifest in plugins/*/package.json profiles/dsh/openduck-synthetic/package.json; do \
		npx --yes npm-check-updates@23.1.0 --target latest --packageFile "$$manifest" -u; \
	done
	bun install
	@printf '%s\n' 'The root Bun pin, scripts/dsh-runtime package and third_party/deepseek-harness remain integrity-controlled; run make test and make typecheck.'

doctor:
	./scripts/dsh-doctor.sh

connect-plugin:
	@test -n "$(PLUGIN)" || (printf '%s\n' 'PLUGIN=/absolute/path is required' >&2; exit 2)
	./scripts/dsh-connect.sh plugin "$(PLUGIN)"

connect-codex connect-claude connect-kimi:
	./scripts/dsh-connect.sh $(@:connect-%=%)

connect-computer:
	./scripts/dsh-connect.sh computer

connect-cli-chat:
	./scripts/dsh-connect.sh cli-chat

login-codex login-claude login-kimi:
	./scripts/dsh-connect.sh $@

disconnect-cli-chat:
	./scripts/dsh-connect.sh disconnect-cli-chat

disconnect-codex disconnect-claude disconnect-kimi disconnect-computer:
	./scripts/dsh-connect.sh disconnect-$(@:disconnect-%=%)

test:
	bun run test:plugins

test-base:
	bun run test:openduck-base

typecheck:
	bun run typecheck:plugins

build-client:
	bun run --cwd plugins/openduck-base build:client

test-go:
	bun run test:go

vet-go:
	bun run vet:go

verify-dsh:
	bun run verify:dsh

deploy-macos:
	@test -n "$(ARGS)" || (printf '%s\n' 'ARGS is required; example: make deploy-macos ARGS=--help' >&2; exit 2)
	./scripts/deploy-macos.sh $(ARGS)

pack-base:
	@pack_dir=$$(mktemp -d "$${TMPDIR:-/tmp}/openduck-base-pack.XXXXXX"); (cd plugins/openduck-base && npm pack --pack-destination "$$pack_dir" --ignore-scripts); tar -tzf "$$pack_dir"/*.tgz
