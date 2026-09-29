/** Stable names and defaults shared by OpenDuck bundles. */
import { realpathSync, statSync } from 'node:fs'
export const OPENDUCK_SETTINGS_NAMESPACE = 'openduck'
export const OPENDUCK_SERVICE = 'openduckBase'
export const DEFAULT_SETTINGS = Object.freeze({
  controller: Object.freeze({ enabled: false, origin: 'http://127.0.0.1:8788' }),
  providers: Object.freeze({
    codexCli: Object.freeze({ enabled: false }),
    claudeCli: Object.freeze({ enabled: false }),
    kimiAcp: Object.freeze({ enabled: false, command: 'kimi', args: Object.freeze(['acp']) }),
  }),
  mcp: Object.freeze({
    computer: Object.freeze({ enabled: false, command: 'cua-driver', args: Object.freeze(['mcp']) }),
    browser: Object.freeze({ enabled: false, command: '', args: Object.freeze([]) }),
  }),
  externalPackages: Object.freeze([]),
  cliRoot: Object.freeze({ enabled: true, cwd: '', models: Object.freeze({ codex: Object.freeze([]), claude: Object.freeze([]), kimi: Object.freeze([]) }) }),
})

const CANONICAL_ABSOLUTE_PATH = /^\/(?:[^/\0]+\/?)*$/

function validateHistory(value) {
  if (value.history === undefined) return
  if (value.history === null || typeof value.history !== 'object' || Array.isArray(value.history) || !Array.isArray(value.history.projects)) throw new TypeError('openduck: history.projects must be an array')
  const seen = new Set()
  for (const project of value.history.projects) {
    if (project === null || typeof project !== 'object' || Array.isArray(project) || typeof project.root !== 'string' || !CANONICAL_ABSOLUTE_PATH.test(project.root) || project.root.includes('/../') || project.root.endsWith('/..')) throw new TypeError('openduck: history project root must be an absolute canonical path')
    let canonical
    try { canonical = realpathSync.native(project.root) } catch { throw new TypeError('openduck: history project root must be an existing canonical directory') }
    if (!statSync(canonical).isDirectory() || canonical !== project.root) throw new TypeError('openduck: history project root must be an existing canonical directory')
    if (seen.has(canonical)) throw new TypeError('openduck: history project roots must be unique')
    seen.add(canonical)
    if (project.displayName !== undefined && (typeof project.displayName !== 'string' || project.displayName.length > 200)) throw new TypeError('openduck: history project display name is invalid')
  }
}

/**
 * Validate the deployment-neutral OpenDuck settings.
 * @param {unknown} value - resolved settings value.
 * @returns {void}
 */
export function validateSettings(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('openduck: settings must be an object')
  const controller = value.controller
  if (controller === null || typeof controller !== 'object' || Array.isArray(controller)) throw new TypeError('openduck: controller settings are required')
  if (typeof controller.enabled !== 'boolean') throw new TypeError('openduck: controller.enabled must be boolean')
  if (typeof controller.origin !== 'string') throw new TypeError('openduck: controller.origin must be a loopback HTTP origin')
  const match = /^http:\/\/127\.0\.0\.1:(\d{1,5})$/.exec(controller.origin)
  if (match === null || Number(match[1]) < 1 || Number(match[1]) > 65535) throw new TypeError('openduck: controller.origin must be a loopback HTTP origin')
  if (!Array.isArray(value.externalPackages) || value.externalPackages.some(item => typeof item !== 'string' || item.length === 0 || item.length > 128)) throw new TypeError('openduck: externalPackages must be package names')
  const cliRoot = value.cliRoot
  if (cliRoot === null || typeof cliRoot !== 'object' || typeof cliRoot.enabled !== 'boolean' || typeof cliRoot.cwd !== 'string' || cliRoot.models === null || typeof cliRoot.models !== 'object' || ['codex', 'claude', 'kimi'].some(name => !Array.isArray(cliRoot.models[name]) || cliRoot.models[name].some(model => typeof model !== 'string' || model.length === 0 || model.length > 128))) throw new TypeError('openduck: cliRoot is invalid')
  const providers = value.providers
  if (providers === null || typeof providers !== 'object' || Array.isArray(providers)) throw new TypeError('openduck: providers are required')
  for (const name of ['codexCli', 'claudeCli', 'kimiAcp']) {
    if (providers[name] === null || typeof providers[name] !== 'object' || typeof providers[name].enabled !== 'boolean') throw new TypeError(`openduck: providers.${name}.enabled must be boolean`)
  }
  if (typeof providers.kimiAcp.command !== 'string' || !Array.isArray(providers.kimiAcp.args) || providers.kimiAcp.args.some(arg => typeof arg !== 'string')) throw new TypeError('openduck: Kimi ACP command is invalid')
  const mcp = value.mcp
  if (mcp === null || typeof mcp !== 'object' || Array.isArray(mcp)) throw new TypeError('openduck: mcp settings are required')
  for (const name of ['computer', 'browser']) {
    const entry = mcp[name]
    if (entry === null || typeof entry !== 'object' || typeof entry.enabled !== 'boolean' || typeof entry.command !== 'string' || !Array.isArray(entry.args) || entry.args.some(arg => typeof arg !== 'string')) throw new TypeError(`openduck: mcp.${name} is invalid`)
  }
  validateHistory(value)
}
