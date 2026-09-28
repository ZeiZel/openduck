import test from 'node:test'
import assert from 'node:assert/strict'
import { createControllerReadBridge, createControllerReadWebServer, CONTROLLER_ORIGIN, PLUGIN_READ_PATHS, MAX_RESPONSE_BYTES } from '../src/index.js'
import { createBrowserReadBridge } from '../src/browser-client.js'

const session = (overrides = {}) => ({ schema_version: 'ui-channel-session.v1', session_id: 's', channel_id: 'c', token: 't'.repeat(44), client_nonce: 'client-server', origin: CONTROLLER_ORIGIN, host: '127.0.0.1:8788', issued_at: '2026-08-20T00:00:00Z', expires_at: '2099-01-01T00:00:00Z', ephemeral: true, persistent: false, ...overrides })
const response = (value, { status = 200, headers = { 'content-type': 'application/json' }, url = '' } = {}) => { const body = JSON.stringify(value); const all = { 'content-type': 'application/json', 'content-length': String(new TextEncoder().encode(body).byteLength), ...headers }; return { ok: status >= 200 && status < 300, status, redirected: false, url, headers: { get: key => all[key] ?? null }, text: async () => body } }
const cryptoApi = { randomUUID: (() => { let i = 0; return () => `00000000-0000-4000-8000-${String(++i).padStart(12, '0')}` })() }

test('bootstraps in memory and reads only the exact loopback routes', async () => {
  const calls = []
  const bridge = createControllerReadBridge({
    cryptoApi,
    fetchImpl: async (url, init) => {
      calls.push({ url, init })
      if (url.endsWith('/v1/ui/bootstrap')) return response(session())
      return response({ schema_version: 'beads-project-graph.v1', project_id: 'project', version: 1, digest: `sha256:${'0'.repeat(64)}`, nodes: [], edges: [] }, { url })
    },
  })
  const value = await bridge.read('beads/project-graph')
  assert.equal(value.project_id, 'project')
  assert.equal(calls[0].url, `${CONTROLLER_ORIGIN}/v1/ui/bootstrap`)
  assert.equal(calls[1].url, `${CONTROLLER_ORIGIN}${PLUGIN_READ_PATHS['beads/project-graph']}`)
  assert.equal(calls[0].init.credentials, 'omit')
  assert.equal(calls[1].init.credentials, 'omit')
  assert.equal(calls[1].init.cache, 'no-store')
  assert.equal(calls[1].init.redirect, 'error')
  assert.match(calls[1].init.headers.get('Authorization'), /^Bearer t+$/)
  assert.ok(calls[1].init.headers.get('X-UI-Request-Nonce'))
  assert.equal(calls[1].init.headers.get('Origin'), CONTROLLER_ORIGIN)
  bridge.dispose()
  assert.equal(bridge.authenticated, false)
})

test('fails closed for redirect, wrong content type, oversized body, and unauthorized response', async () => {
  let mode = 'redirect'
  const bridge = createControllerReadBridge({ cryptoApi, fetchImpl: async (url) => {
    if (url.endsWith('/v1/ui/bootstrap')) return response(session())
    if (mode === 'redirect') return { ...response({}), redirected: true, url: 'http://127.0.0.1:8788/other' }
    if (mode === 'content') return response({}, { headers: { 'content-type': 'text/html' } })
    if (mode === 'large') return { ...response({}), text: async () => 'x'.repeat(MAX_RESPONSE_BYTES + 1) }
    return response({}, { status: 401 })
  } })
  assert.equal(await bridge.read('beads/project-graph'), null)
  mode = 'content'; assert.equal(await bridge.read('beads/project-graph'), null)
  mode = 'large'; assert.equal(await bridge.read('beads/project-graph'), null)
  mode = 'unauthorized'; assert.equal(await bridge.read('beads/project-graph'), null)
  assert.equal(bridge.authenticated, false)
})

test('rejects invalid routes and never touches poisoned durable browser storage', async () => {
  const restore = []
  for (const name of ['localStorage', 'sessionStorage']) {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, name)
    restore.push(() => descriptor ? Object.defineProperty(globalThis, name, descriptor) : delete globalThis[name])
    Object.defineProperty(globalThis, name, { configurable: true, get() { throw new Error(`${name} accessed`) } })
  }
  const bridge = createControllerReadBridge({ cryptoApi, fetchImpl: async () => response(session()) })
  try {
    await assert.rejects(() => bridge.read('beads/project-graph?x=1'), /INVALID_ROUTE/)
    bridge.dispose()
  } finally { restore.reverse().forEach(fn => fn()) }
})

test('host proxy exposes only exact read routes and consumes the injected bridge', async () => {
  const calls = []
  const proxy = createControllerReadWebServer({ bridge: { read: async route => { calls.push(route); return { schema_version: 'fixture' } } } })
  assert.equal((await proxy.handle({ method: 'GET', path: '/v1/plugin-reads/beads/project-graph' })).status, 200)
  assert.equal(calls[0], 'beads/project-graph')
  assert.equal((await proxy.handle({ method: 'OPTIONS', path: '/v1/plugin-reads/beads/project-graph' })).allow, 'GET, OPTIONS')
  assert.equal((await proxy.handle({ method: 'GET', path: '/v1/plugin-reads/beads/project-graph', query: 'x=1' })).status, 404)
  assert.equal((await proxy.handle({ method: 'GET', path: '/v1/plugin-reads/other' })).status, 404)
})

test('origin is injected only from the loopback allowlist and binds session authority', async () => {
  assert.throws(() => createControllerReadBridge({ origin: 'https://evil.example' }), /INVALID_CONTROLLER_ORIGIN/)
  let first = true
  const bridge = createControllerReadBridge({ origin: 'http://127.0.0.1:9876', cryptoApi, fetchImpl: async url => {
    if (first) { first = false; return response(session({ origin: 'http://127.0.0.1:9876', host: '127.0.0.1:9876' })) }
    return response({ schema_version: 'workspace-groups.v1', freshness: 'current', groups: [] }, { url })
  } })
  assert.equal((await bridge.read('workspace-groups')).schema_version, 'workspace-groups.v1')
})

test('browser service fetches only same-origin host proxy routes', async () => {
  const calls = []; const body = JSON.stringify({ schema_version: 'workspace-groups.v1', freshness: 'current', groups: [] })
  const bridge = createBrowserReadBridge({ origin: CONTROLLER_ORIGIN, fetchImpl: async (url, init) => { calls.push({ url, init }); return response(JSON.parse(body), { url: `${CONTROLLER_ORIGIN}/v1/plugin-reads/workspace-groups` }) } })
  assert.equal((await bridge.read('workspace-groups')).schema_version, 'workspace-groups.v1')
  assert.equal(calls[0].url, '/v1/plugin-reads/workspace-groups'); assert.equal(calls[0].init.credentials, 'omit'); assert.equal(calls[0].init.redirect, 'error')
  bridge.dispose(); assert.equal(await bridge.read('workspace-groups'), null)
})

test('mesh UI uses one exact authenticated read and typed proposal allowlist', async () => {
  const calls = []
  const bridge = createControllerReadBridge({ cryptoApi, fetchImpl: async (url, init) => {
    calls.push({ url, init })
    if (url.endsWith('/v1/ui/bootstrap')) return response(session())
    if (url.endsWith('/v1/plugin-reads/mesh')) return response({ schema_version: 'openduck-mesh-ui.v1' }, { url })
    return response({ schema_version: 'selection-revision.v1', revision_id: 'selection-2', active_turn_changed: false }, { url })
  } })
  assert.equal((await bridge.readProjection('mesh')).schema_version, 'openduck-mesh-ui.v1')
  assert.equal((await bridge.propose('selection-revision', { profile_id: 'deepseek.api', operation: 'new-root', base_revision_id: 'selection-1' })).revision_id, 'selection-2')
  assert.equal(calls[1].url, `${CONTROLLER_ORIGIN}/v1/plugin-reads/mesh`)
  assert.equal(calls[2].url, `${CONTROLLER_ORIGIN}/v1/plugin-proposals/selection-revision`)
  await assert.rejects(() => bridge.propose('arbitrary-operation', {}), /INVALID_PROPOSAL/)
})
