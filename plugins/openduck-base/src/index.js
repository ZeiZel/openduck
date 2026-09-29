import z from '@deepseek-ai/schemastery'
import { DEFAULT_SETTINGS, OPENDUCK_SETTINGS_NAMESPACE, OPENDUCK_SERVICE, validateSettings } from './contract.js'
import { createHistoryRpc } from './history/host.js'
import { mountCliRoot } from './cli/index.js'
import { createCliRootRpc } from './cli/host.js'
import { registerRpcRoutes } from './rpc-routes.js'

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
  cliRoot: z.object({ enabled: z.boolean().default(true), cwd: z.string().default(''), models: z.object({ codex: z.array(z.string()).default([]), claude: z.array(z.string()).default([]), kimi: z.array(z.string()).default([]) }).default(DEFAULT_SETTINGS.cliRoot.models) }).default(DEFAULT_SETTINGS.cliRoot).volatile(),
  providers: z.object({
    codexCli: z.object({ enabled: z.boolean().default(false) }).default(DEFAULT_SETTINGS.providers.codexCli),
    claudeCli: z.object({ enabled: z.boolean().default(false) }).default(DEFAULT_SETTINGS.providers.claudeCli),
    kimiAcp: z.object({ enabled: z.boolean().default(false), command: z.string().default('kimi'), args: z.array(z.string()).default(['acp']) }).default(DEFAULT_SETTINGS.providers.kimiAcp),
  }).default(DEFAULT_SETTINGS.providers),
  mcp: z.object({
    computer: z.object({ enabled: z.boolean().default(false), command: z.string().default('cua-driver'), args: z.array(z.string()).default(['mcp']) }).default(DEFAULT_SETTINGS.mcp.computer),
    browser: z.object({ enabled: z.boolean().default(false), command: z.string().default(''), args: z.array(z.string()).default([]) }).default(DEFAULT_SETTINGS.mcp.browser),
  }).default(DEFAULT_SETTINGS.mcp),
  history: z.object({ projects: z.array(z.object({ root: z.string(), displayName: z.string().default('') })).default([]) }).default({ projects: [] }).volatile(),
})
/** RC2 config-form schema, automatically exposed for this active plugin entry. */
export const Config = Settings

function resolved(value) {
  return value !== null && typeof value === 'object' && typeof value.get === 'function' ? value.get() : value
}

function compositionFor(config) {
  const cliRoot = resolved(config.cliRoot)
  const history = resolved(config.history)
  const composition = Object.freeze({
    ...DEFAULT_SETTINGS,
    ...config,
    controller: { ...DEFAULT_SETTINGS.controller, ...config.controller },
    providers: { ...DEFAULT_SETTINGS.providers, ...config.providers },
    mcp: { ...DEFAULT_SETTINGS.mcp, ...config.mcp },
    history: { projects: history?.projects ?? [] },
    cliRoot: { ...DEFAULT_SETTINGS.cliRoot, ...cliRoot, models: { ...DEFAULT_SETTINGS.cliRoot.models, ...cliRoot?.models } },
  })
  validateSettings(composition)
  return composition
}

/**
 * The CLI adapter's view of one session: its workspace and its *current*
 * agent preset. DSH 0.1.7 records preset switches of a blank session as
 * `agent-preset/selected` events, so the header only holds the creation-time
 * preset; the `agentPreset` projection is authoritative.
 * @param {{ sessions: { get(id: string): any }, sessionProjections?: { stateOf(session: unknown, key: string): unknown } }} ctx - host context.
 * @param {string} sessionId - DSH session id.
 * @returns {{ cwd?: string, agentPreset?: string } | undefined} session view.
 */
export function cliSessionView(ctx, sessionId) {
  const session = ctx.sessions.get(sessionId)
  if (session === undefined || session === null) return undefined
  const header = session.header ?? {}
  let preset
  try {
    const state = ctx.sessionProjections?.stateOf(session, 'agentPreset')
    preset = typeof state === 'string' ? state : typeof state?.current === 'string' ? state.current : undefined
  } catch { preset = undefined }
  return { ...header, agentPreset: preset ?? header.agentPreset }
}

/**
 * Mount the generic OpenDuck runtime service and register its native settings.
 * No network request or Controller connection is made by this package.
 * @param {import('@deepseek-ai/cordis').Context} ctx - plugin context.
 * @param {object} config - profile composition defaults.
 * @returns {void}
 */
export function apply(ctx, config = {}) {
  const current = () => compositionFor(config)
  const initial = current()
  ctx.inject(['settings'], settingsCtx => {
    settingsCtx.effect(() => settingsCtx.settings.configure({ auto: false }, ctx.fiber), 'openduck-base.settings-form')
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
  ctx.inject(['llm', 'sessions', 'sessionProjections'], llmCtx => {
    const release = mountCliRoot(llmCtx, initial.cliRoot, { sessionFor: sessionId => cliSessionView(llmCtx, sessionId) })
    llmCtx.effect(() => () => { release() }, 'openduck-base.cli-root')
  })
  // Browser RPC is served as exact `/api/<channel>/<endpoint>` routes; see rpc-routes.js.
  ctx.inject(['connection'], historyCtx => {
    const rpc = createHistoryRpc(() => current().history)
    const cliRpc = createCliRootRpc()
    const unregister = registerRpcRoutes(historyCtx.connection, 'openduck-history', ['projects', 'sessions', 'messages'], (endpoint, payload) => rpc.handle(endpoint, payload))
    const unregisterCli = registerRpcRoutes(historyCtx.connection, 'openduck-cli', ['status', 'login'], (endpoint, payload) => cliRpc.handle(endpoint, payload))
    historyCtx.provide('openduckHistory', Object.freeze({ handle: (endpoint, payload) => rpc.handle(endpoint, payload) }))
    historyCtx.effect(() => () => { void unregister(); void unregisterCli() }, 'openduck-base.history-rpc')
  })
  ctx.effect(() => () => { if (typeof dispose === 'function') dispose() }, 'openduck-base.service()')
}

export { DEFAULT_SETTINGS, OPENDUCK_SETTINGS_NAMESPACE, OPENDUCK_SERVICE, validateSettings }
