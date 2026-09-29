import { accessSync, constants, statSync } from 'node:fs'
import { delimiter, isAbsolute, join } from 'node:path'

export const CLI_PROVIDERS = Object.freeze({
  'codex-cli': Object.freeze({ id: 'codex', route: 'codex-cli', label: 'Codex CLI', command: 'codex', login: Object.freeze(['login']), status: Object.freeze(['login', 'status']) }),
  'claude-cli': Object.freeze({ id: 'claude', route: 'claude-cli', label: 'Claude Code', command: 'claude', login: Object.freeze(['auth', 'login', '--claudeai']), status: Object.freeze(['auth', 'status', '--json']) }),
  'kimi-acp': Object.freeze({ id: 'kimi', route: 'kimi-acp', label: 'Kimi Code', command: 'kimi', login: Object.freeze(['login']), status: undefined }),
})

const providerById = Object.freeze(Object.fromEntries(Object.values(CLI_PROVIDERS).map(provider => [provider.id, provider])))
export const cliProvider = provider => CLI_PROVIDERS[provider] ?? providerById[provider]

/** Resolve only an executable pathname. It never invokes a CLI or reads its state. */
export function findExecutable(command, path = process.env.PATH ?? '') {
  if (typeof command !== 'string' || command.length === 0 || command.includes('\0')) return undefined
  const candidates = isAbsolute(command) ? [command] : path.split(delimiter).filter(Boolean).map(directory => join(directory, command))
  for (const candidate of candidates) {
    try {
      if (statSync(candidate).isFile()) { accessSync(candidate, constants.X_OK); return candidate }
    } catch {}
  }
  return undefined
}

/** Installed CLIs advertise their own configured default without probing auth state. */
export function createCliAvailability({ resolve = findExecutable } = {}) {
  const executable = provider => {
    const spec = cliProvider(provider)
    return spec === undefined ? undefined : resolve(spec.command)
  }
  return Object.freeze({ executable, installed: provider => executable(provider) !== undefined })
}
