import { createDefaultHistoryService } from './index.js'
import { realpathSync, statSync } from 'node:fs'
import { resolve } from 'node:path'

const MAX_LIMIT = 100
const ROOT = /^\/(?:[^/\0]+\/?)*$/

function fail(message) { return { ok: false, error: { code: 'internal', message, details: {} } } }
function ok(value) { return { ok: true, value } }
function canonicalRoot(root) {
  if (!ROOT.test(root) || root.includes('/../') || root.endsWith('/..') || resolve(root) !== root) throw new TypeError('history project root must be an absolute canonical path')
  const canonical = realpathSync.native(root)
  if (!statSync(canonical).isDirectory() || canonical !== root) throw new TypeError('history project root must be an existing canonical directory')
  return canonical
}
function cleanProject(project, index, normalizeRoot) {
  if (project === null || typeof project !== 'object' || Array.isArray(project)) throw new TypeError('history project must be an object')
  if (typeof project.root !== 'string') throw new TypeError('history project root must be an absolute canonical path')
  const root = normalizeRoot(project.root)
  return Object.freeze({ id: `p${index + 1}`, root, displayName: typeof project.displayName === 'string' && project.displayName.length > 0 && project.displayName.length <= 200 ? project.displayName : root.split('/').filter(Boolean).at(-1) || root })
}
function request(payload) {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) throw new TypeError('history request must be an object')
  if (typeof payload.projectId !== 'string' || !/^p[1-9][0-9]*$/.test(payload.projectId)) throw new TypeError('history project is invalid')
  if (typeof payload.provider !== 'string' || !['codex', 'claude', 'kimi'].includes(payload.provider)) throw new TypeError('history provider is invalid')
  if (payload.limit !== undefined && (!Number.isInteger(payload.limit) || payload.limit < 1 || payload.limit > MAX_LIMIT)) throw new TypeError('history limit is invalid')
  if (payload.cursor !== undefined && (typeof payload.cursor !== 'string' || payload.cursor.length > 4096)) throw new TypeError('history cursor is invalid')
  if (payload.sessionId !== undefined && (typeof payload.sessionId !== 'string' || !/^[A-Za-z0-9_.:-]{1,256}$/.test(payload.sessionId))) throw new TypeError('history session is invalid')
  return payload
}

/** Create a loopback-only DSH Connection RPC over an allowlisted history service. */
function publicResult(result, projectId) {
  const items = Array.isArray(result?.items) ? result.items.map(item => {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) return item
    const { project, ...publicItem } = item
    return Object.freeze({ ...publicItem, projectId })
  }) : []
  return Object.freeze({ ...result, items: Object.freeze(items) })
}

export function createHistoryRpc(config, ports, options = {}) {
  const normalizeRoot = options.normalizeRoot ?? canonicalRoot
  const state = () => {
    const resolved = typeof config === 'function' ? config() : config
    const projects = Object.freeze((resolved?.projects ?? []).map((project, index) => cleanProject(project, index, normalizeRoot)))
    return Object.freeze({
      projects,
      byId: new Map(projects.map(project => [project.id, project])),
      history: createDefaultHistoryService({ projects: projects.map(project => ({ root: project.root, displayName: project.displayName })) }, ports),
    })
  }
  // Preserve construction-time rejection for a fixed policy. A resolver is
  // intentionally deferred so an accepted volatile settings update can take
  // effect on the next RPC without retaining a stale allowlist.
  if (typeof config !== 'function') state()
  return Object.freeze({
    projects: () => state().projects.map(({ id, displayName }) => Object.freeze({ id, displayName })),
    async handle(endpoint, payload) {
      try {
        if (endpoint === 'projects') return ok({ items: this.projects() })
        if (endpoint !== 'sessions' && endpoint !== 'messages') return fail('History endpoint is unavailable')
        const input = request(payload)
        const current = state()
        const project = current.byId.get(input.projectId)
        if (project === undefined) return fail('Selected project is unavailable')
        const forwarded = { provider: input.provider, projectRoot: project.root, ...(input.cursor === undefined ? {} : { cursor: input.cursor }), ...(input.limit === undefined ? {} : { limit: input.limit }) }
        if (endpoint === 'sessions') return ok(publicResult(await current.history.list(forwarded), project.id))
        if (input.sessionId === undefined) return fail('Session is required')
        return ok(publicResult(await current.history.read({ ...forwarded, sessionId: input.sessionId }), project.id))
      } catch {
        return fail('History is unavailable')
      }
    },
  })
}
