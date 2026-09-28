export const CONTROLLER_ORIGIN = 'http://127.0.0.1:8788'
export const BOOTSTRAP_PATH = '/v1/ui/bootstrap'
export const PLUGIN_READ_PATHS = Object.freeze({
  'beads/project-graph': '/v1/plugin-reads/beads/project-graph',
  'beads/global-metadata': '/v1/plugin-reads/beads/global-metadata',
  'workspace-groups': '/v1/plugin-reads/workspace-groups',
})
export const MESH_READ_PATH = '/v1/plugin-reads/mesh'
export const PLUGIN_PROPOSAL_PATHS = Object.freeze({
  'selection-revision': '/v1/plugin-proposals/selection-revision',
  'mesh-spawn': '/v1/plugin-proposals/mesh-spawn', 'mesh-spawnBatch': '/v1/plugin-proposals/mesh-spawnBatch',
  'mesh-send': '/v1/plugin-proposals/mesh-send', 'mesh-steer': '/v1/plugin-proposals/mesh-steer',
  'mesh-wait': '/v1/plugin-proposals/mesh-wait', 'mesh-collect': '/v1/plugin-proposals/mesh-collect',
  'mesh-cancel': '/v1/plugin-proposals/mesh-cancel', 'mesh-list': '/v1/plugin-proposals/mesh-list',
  'mesh-status': '/v1/plugin-proposals/mesh-status', 'mesh-result': '/v1/plugin-proposals/mesh-result',
  'mesh-listProfiles': '/v1/plugin-proposals/mesh-listProfiles',
  'provider-directory': '/v1/plugin-proposals/provider-directory', 'ui-session-graph': '/v1/plugin-proposals/ui-session-graph',
  'run-compare': '/v1/plugin-proposals/run-compare', 'run-synthesis': '/v1/plugin-proposals/run-synthesis',
  'run-templates': '/v1/plugin-proposals/run-templates', 'policy-approval-inspector': '/v1/plugin-proposals/policy-approval-inspector',
  'provider-diagnostics': '/v1/plugin-proposals/provider-diagnostics', 'deployment-diagnostics': '/v1/plugin-proposals/deployment-diagnostics',
  'plugin-lifecycle': '/v1/plugin-proposals/plugin-lifecycle',
})
export const MAX_RESPONSE_BYTES = 256 * 1024
const SESSION_SCHEMA = 'ui-channel-session.v1'
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype'])

function fail(code) { throw new TypeError(code) }
function controllerOrigin(value) {
  const parsed = new URL(value)
  if (parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1' || !parsed.port || parsed.pathname !== '/' || parsed.search || parsed.hash) fail('INVALID_CONTROLLER_ORIGIN')
  return { origin: parsed.origin, host: parsed.host }
}
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype
}
function exact(value, keys) {
  if (!plain(value)) fail('INVALID_RESPONSE')
  const own = Object.keys(value)
  if (own.length !== keys.length || own.some(key => FORBIDDEN.has(key) || !keys.includes(key))) fail('INVALID_RESPONSE')
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail('INVALID_RESPONSE')
  }
}
function text(value, max = 256) { if (typeof value !== 'string' || value.length === 0 || value.length > max || /[\0\r\n]/u.test(value)) fail('INVALID_RESPONSE'); return value }
function iso(value) { text(value, 64); if (Number.isNaN(Date.parse(value))) fail('INVALID_RESPONSE'); return value }
function session(value, authority) {
  exact(value, ['schema_version', 'session_id', 'channel_id', 'token', 'client_nonce', 'origin', 'host', 'issued_at', 'expires_at', 'ephemeral', 'persistent'])
  if (value.schema_version !== SESSION_SCHEMA || value.ephemeral !== true || value.persistent !== false) fail('INVALID_RESPONSE')
  for (const key of ['session_id', 'channel_id', 'token', 'client_nonce', 'origin', 'host']) text(value[key])
  if (value.origin !== authority.origin || value.host !== authority.host) fail('INVALID_RESPONSE')
  iso(value.issued_at); iso(value.expires_at)
  if (Date.parse(value.expires_at) <= Date.now()) fail('EXPIRED_SESSION')
  return value
}
function nonce(cryptoApi, used, prefix) {
  const now = Date.now()
  for (const [key, expires] of used) if (expires <= now) used.delete(key)
  if (used.size >= 2048) fail('NONCE_CAPACITY')
  let value
  for (let attempt = 0; attempt < 4; attempt += 1) {
    if (typeof cryptoApi?.randomUUID !== 'function') fail('CSPRNG_UNAVAILABLE')
    value = `${prefix}_${cryptoApi.randomUUID().replaceAll('-', '')}`
    if (!used.has(value) && value.length <= 128) { used.set(value, now + 300_000); return value }
  }
  fail('NONCE_COLLISION')
}
async function jsonResponse(response, expectedOrigin = CONTROLLER_ORIGIN) {
  if (!response || typeof response.ok !== 'boolean' || response.redirected) fail('INVALID_RESPONSE')
  if (response.url) {
    const finalURL = new URL(response.url)
    if (finalURL.origin !== expectedOrigin || finalURL.search || finalURL.hash) fail('INVALID_RESPONSE')
  }
  if (!response.ok) { const error = new Error('HTTP_ERROR'); error.status = response.status; throw error }
  const type = typeof response.headers?.get === 'function' ? response.headers.get('content-type') : null
  if (!type || !/^application\/json(?:\s*;|$)/iu.test(type)) fail('INVALID_CONTENT_TYPE')
  const lengthHeader = response.headers?.get?.('content-length')
  if (typeof lengthHeader !== 'string' || !/^\d+$/u.test(lengthHeader)) fail('INVALID_CONTENT_LENGTH')
  const length = Number(lengthHeader)
  if (!Number.isSafeInteger(length) || length > MAX_RESPONSE_BYTES) fail('RESPONSE_TOO_LARGE')
  let raw
  if (response.body?.getReader) {
    const reader = response.body.getReader(); const chunks = []; let total = 0
    while (true) { const part = await reader.read(); if (part.done) break; total += part.value.byteLength; if (total > MAX_RESPONSE_BYTES) { await reader.cancel(); fail('RESPONSE_TOO_LARGE') }; chunks.push(part.value) }
    const bytes = new Uint8Array(total); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
    raw = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } else { raw = await response.text(); if (new TextEncoder().encode(raw).byteLength > MAX_RESPONSE_BYTES) fail('RESPONSE_TOO_LARGE') }
  const value = JSON.parse(raw)
  if (!plain(value)) fail('INVALID_RESPONSE')
  return value
}

/** Creates a closure-only, read-only Controller client. */
export function createControllerReadBridge({ fetchImpl = globalThis.fetch, cryptoApi = globalThis.crypto, origin = CONTROLLER_ORIGIN } = {}) {
  if (typeof fetchImpl !== 'function') fail('FETCH_UNAVAILABLE')
  const authority = controllerOrigin(origin)
  const used = new Map()
  let auth = null
  let disposed = false
  const clear = () => { auth = null }
  const request = async (url, init, expectedOrigin) => {
    if (disposed) fail('BRIDGE_DISPOSED')
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 10_000)
    try { const headers = new Headers(init.headers ?? {}); headers.set('Origin', expectedOrigin); const response = await fetchImpl(url, { ...init, headers, signal: controller.signal, credentials: 'omit', cache: 'no-store', redirect: 'error' }); return await jsonResponse(response, expectedOrigin) }
    finally { clearTimeout(timer) }
  }
  const bootstrap = async () => {
    if (auth && Date.parse(auth.expires_at) > Date.now()) return true
    clear()
    try {
      const value = await request(`${authority.origin}${BOOTSTRAP_PATH}`, { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify({ client_nonce: nonce(cryptoApi, used, 'client') }) }, authority.origin)
      if (!value || value.schema_version !== SESSION_SCHEMA) return false
      auth = session(value, authority)
      return true
    } catch { clear(); return false }
  }
  const read = async route => {
    if (!Object.hasOwn(PLUGIN_READ_PATHS, route)) fail('INVALID_ROUTE')
    if (!(await bootstrap()) || !auth) return null
    try {
      const current = auth
      const value = await request(`${authority.origin}${PLUGIN_READ_PATHS[route]}`, { method: 'GET', headers: { Accept: 'application/json', Authorization: `Bearer ${current.token}`, 'X-UI-Nonce': current.client_nonce, 'X-UI-Request-Nonce': nonce(cryptoApi, used, 'request') } }, authority.origin)
      return value
    } catch (error) {
      if (error?.status === 401 || error?.status === 403) clear()
      else clear()
      return null
    }
  }
  const readProjection = async route => {
    if (route !== 'mesh') return read(route)
    if (!(await bootstrap()) || !auth) return null
    try {
      const current = auth
      return await request(`${authority.origin}${MESH_READ_PATH}`, { method: 'GET', headers: { Accept: 'application/json', Authorization: `Bearer ${current.token}`, 'X-UI-Nonce': current.client_nonce, 'X-UI-Request-Nonce': nonce(cryptoApi, used, 'mesh-read') } }, authority.origin)
    } catch (error) { clear(); return null }
  }
  const propose = async (kind, value) => {
    if (!Object.hasOwn(PLUGIN_PROPOSAL_PATHS, kind) || !plain(value)) fail('INVALID_PROPOSAL')
    if (!(await bootstrap()) || !auth) fail('CONTROLLER_UNAVAILABLE')
    const current = auth
    try {
      return await request(`${authority.origin}${PLUGIN_PROPOSAL_PATHS[kind]}`, { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json', Authorization: `Bearer ${current.token}`, 'X-UI-Nonce': current.client_nonce, 'X-UI-Request-Nonce': nonce(cryptoApi, used, 'proposal') }, body: JSON.stringify(value) }, authority.origin)
    } catch (error) { clear(); throw error }
  }
  const dispose = () => { disposed = true; clear(); used.clear() }
  return Object.freeze({ bootstrap, read, readProjection, propose, clear, dispose, get authenticated() { return auth !== null } })
}

/** Host-side webServer proxy seam: exact route allowlist, no generic proxy. */
export function createControllerReadWebServer({ bridge }) {
  if (!bridge || typeof bridge.read !== 'function') fail('INVALID_BRIDGE')
  const routes = new Set(Object.values(PLUGIN_READ_PATHS))
  const routeFor = path => Object.entries(PLUGIN_READ_PATHS).find(([, value]) => value === path)?.[0]
  return Object.freeze({
    async handle(request) {
      if (!request || typeof request.method !== 'string' || typeof request.path !== 'string' || request.query || request.body || !routes.has(request.path)) return Object.freeze({ status: 404, body: null })
      if (request.method === 'OPTIONS') return Object.freeze({ status: 204, body: null, allow: 'GET, OPTIONS' })
      if (request.method !== 'GET') return Object.freeze({ status: 405, body: null, allow: 'GET, OPTIONS' })
      const value = await bridge.read(routeFor(request.path))
      return value === null ? Object.freeze({ status: 503, body: null }) : Object.freeze({ status: 200, body: value, contentType: 'application/json' })
    },
  })
}

// Native DSH host half: owns Controller authentication and proxies only the
// exact read routes into the browser's same-origin webServer.
export const inject = ['webServer']
export function apply(ctx) {
  const bridge = createControllerReadBridge({ origin: ctx.controllerOrigin ?? CONTROLLER_ORIGIN })
  const disposers = []
  for (const [route, path] of Object.entries(PLUGIN_READ_PATHS)) {
    if (typeof ctx.webServer?.register !== 'function') fail('WEBSERVER_UNAVAILABLE')
    disposers.push(ctx.webServer.register({ kind: 'exact', path, handler: async (req, res) => {
      let parsed
      try { parsed = new URL(req.url ?? path, 'http://127.0.0.1') } catch { res.statusCode = 400; res.end(); return }
      if (req.method !== 'GET' || parsed.search || Number(req.headers?.['content-length'] ?? 0) > 0 || req.headers?.['content-type']) { res.statusCode = 400; res.end(); return }
      const value = await bridge.read(route)
      if (value === null) { res.statusCode = 503; res.end(); return }
      const body = JSON.stringify(value); res.statusCode = 200; res.setHeader('Content-Type', 'application/json'); res.setHeader('Content-Length', Buffer.byteLength(body)); res.setHeader('Cache-Control', 'no-store'); res.end(body)
    } }))
  }
  const provided = typeof ctx.provide === 'function' ? ctx.provide('controllerReadBridge', bridge) : undefined
  return () => { bridge.dispose(); provided?.(); for (const dispose of disposers) dispose() }
}
