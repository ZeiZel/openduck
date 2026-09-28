import z from '@deepseek-ai/schemastery'
import { installSettingsSection } from '@deepseek-ai/dsh-settings'
import { DEFAULT_SETTINGS, OPENDUCK_SETTINGS_NAMESPACE, OPENDUCK_SERVICE, validateSettings } from './contract.js'
import { createHistoryRpc } from './history/host.js'
import { mountCliRoot } from './cli/index.js'

/** Cordis function-plugin name. */
export const name = OPENDUCK_SERVICE
/** The native settings provider is supplied by dsh-base. */
export const inject = ['settings']

const Settings = z.object({
  controller: z.object({
    enabled: z.boolean().default(false),
    origin: z.string().default(DEFAULT_SETTINGS.controller.origin),
  }).default(DEFAULT_SETTINGS.controller),
  externalPackages: z.array(z.string()).default([]),
  cliRoot: z.object({ enabled: z.boolean().default(false), cwd: z.string().default(''), models: z.object({ codex: z.array(z.string()).default([]), claude: z.array(z.string()).default([]), kimi: z.array(z.string()).default([]) }).default(DEFAULT_SETTINGS.cliRoot.models) }).default(DEFAULT_SETTINGS.cliRoot),
  providers: z.object({
    codexCli: z.object({ enabled: z.boolean().default(false) }).default(DEFAULT_SETTINGS.providers.codexCli),
    claudeCli: z.object({ enabled: z.boolean().default(false) }).default(DEFAULT_SETTINGS.providers.claudeCli),
    kimiAcp: z.object({ enabled: z.boolean().default(false), command: z.string().default('kimi'), args: z.array(z.string()).default(['acp']) }).default(DEFAULT_SETTINGS.providers.kimiAcp),
  }).default(DEFAULT_SETTINGS.providers),
  mcp: z.object({
    computer: z.object({ enabled: z.boolean().default(false), command: z.string().default('cua-driver'), args: z.array(z.string()).default(['mcp']) }).default(DEFAULT_SETTINGS.mcp.computer),
    browser: z.object({ enabled: z.boolean().default(false), command: z.string().default(''), args: z.array(z.string()).default([]) }).default(DEFAULT_SETTINGS.mcp.browser),
  }).default(DEFAULT_SETTINGS.mcp),
  history: z.object({ projects: z.array(z.object({ root: z.string(), displayName: z.string().default('') })).default([]) }).default({ projects: [] }),
})

/**
 * Mount the generic OpenDuck runtime service and register its native settings.
 * No network request or Controller connection is made by this package.
 * @param {import('@deepseek-ai/cordis').Context} ctx - plugin context.
 * @param {object} config - profile composition defaults.
 * @returns {void}
 */
export function apply(ctx, config = {}) {
  const composition = Object.freeze({
    ...DEFAULT_SETTINGS,
    ...config,
    controller: { ...DEFAULT_SETTINGS.controller, ...config.controller },
    providers: { ...DEFAULT_SETTINGS.providers, ...config.providers },
    mcp: { ...DEFAULT_SETTINGS.mcp, ...config.mcp },
    history: { projects: config.history?.projects ?? [] },
    cliRoot: { ...DEFAULT_SETTINGS.cliRoot, ...config.cliRoot, models: { ...DEFAULT_SETTINGS.cliRoot.models, ...config.cliRoot?.models } },
  })
  let current = () => composition
  let refreshHistory = () => {}
  installSettingsSection(ctx, OPENDUCK_SETTINGS_NAMESPACE, Settings, composition, {
    validate: validateSettings,
    setSource: source => { current = source },
    onChange: () => { refreshHistory() },
  })
  const service = Object.freeze({
    settings: () => current(),
    status: () => current().controller.enabled ? 'configured-restart-required' : 'disabled',
    controller: Object.freeze({
      enabled: () => current().controller.enabled,
      origin: () => current().controller.origin,
    }),
    externalPackages: () => [...current().externalPackages],
    providers: () => Object.entries(current().providers).map(([id, value]) => Object.freeze({ id, enabled: value.enabled, lifecycle: value.enabled ? 'restart-required' : 'disabled' })),
    mcp: () => Object.entries(current().mcp).map(([id, value]) => Object.freeze({ id, enabled: value.enabled, lifecycle: value.enabled ? 'restart-required' : 'disabled' })),
  })
  const dispose = ctx.provide(OPENDUCK_SERVICE, service)
  ctx.inject(['llm'], llmCtx => { const release = mountCliRoot(llmCtx, current().cliRoot); llmCtx.effect(() => () => { release() }, 'openduck-base.cli-root') })
  ctx.inject(['connection'], historyCtx => {
    let rpc = createHistoryRpc(current().history)
    refreshHistory = () => { rpc = createHistoryRpc(current().history) }
    const unregister = historyCtx.connection.rpc.handle('/openduck-history', (endpoint, payload) => rpc.handle(endpoint, payload), { authority: 'loopback' })
    historyCtx.provide('openduckHistory', Object.freeze({ handle: (endpoint, payload) => rpc.handle(endpoint, payload) }))
    historyCtx.effect(() => () => { void unregister() }, 'openduck-base.history-rpc')
  })
  ctx.effect(() => () => { if (typeof dispose === 'function') dispose() }, 'openduck-base.service()')
}

export { DEFAULT_SETTINGS, OPENDUCK_SETTINGS_NAMESPACE, OPENDUCK_SERVICE, validateSettings }
