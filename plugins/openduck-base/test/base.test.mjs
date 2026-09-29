import test from 'node:test'
import assert from 'node:assert/strict'
import { DEFAULT_SETTINGS, validateSettings } from '../src/contract.js'
import { Config, apply } from '../src/index.js'
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'

test('base settings default to a disabled loopback Controller', () => {
  assert.equal(DEFAULT_SETTINGS.controller.enabled, false)
  assert.equal(DEFAULT_SETTINGS.controller.origin, 'http://127.0.0.1:8788')
})

test('settings validator rejects non-loopback Controller origins', () => {
  assert.throws(() => validateSettings({ controller: { enabled: true, origin: 'https://controller.example' }, externalPackages: [] }), /loopback/)
  assert.throws(() => validateSettings({ controller: { enabled: true, origin: 'http://127.0.0.1:0' }, externalPackages: [] }), /loopback/)
  assert.throws(() => validateSettings({ controller: { enabled: true, origin: 'http://127.0.0.1:65536' }, externalPackages: [] }), /loopback/)
})

test('settings validator accepts an external package composition list', () => {
  assert.doesNotThrow(() => validateSettings(structuredClone(DEFAULT_SETTINGS)))
})

test('Cordis entry configures the RC2 native settings form and provides a read-only runtime service', () => {
  const effects = []
  let provided
  let configure
  const ctx = {
    inject: (services, callback) => {
      if (services.includes('settings')) callback({
        settings: { configure: options => { configure = options } },
        effect: callback => callback(),
      })
    },
    provide: (_name, service) => { provided = service },
    effect: callback => effects.push(callback),
  }
  apply(ctx, { controller: { enabled: false }, externalPackages: ['dsh-process'] })
  assert.equal(provided.status(), 'disabled')
  assert.deepEqual(provided.externalPackages(), ['dsh-process'])
  assert.deepEqual(configure, { auto: false })
  assert.equal(effects.length, 1)
})

test('settings validator rejects nonexistent history directories before saving', () => {
  const settings = structuredClone(DEFAULT_SETTINGS)
  settings.history = { projects: [{ root: '/definitely-not-an-openduck-project' }] }
  assert.throws(() => validateSettings(settings), /existing canonical directory/)
})

test('CLI root accepts legacy fixed-workspace and model fields while routing uses session context', () => {
  const legacyCliRoot = { enabled: true, cwd: '/legacy/project', models: { codex: ['legacy-codex-model'], claude: ['legacy-claude-model'], kimi: ['legacy-kimi-model'] } }
  const settings = { ...structuredClone(DEFAULT_SETTINGS), cliRoot: legacyCliRoot }
  assert.doesNotThrow(() => validateSettings(settings))
  assert.equal(DEFAULT_SETTINGS.cliRoot.enabled, true)

  let provided
  const ctx = {
    inject: (services, callback) => {
      if (services.includes('settings')) callback({ settings: { configure: () => {} }, effect: callback => callback() })
    },
    provide: (_name, service) => { provided = service },
    effect: () => {},
  }
  apply(ctx, { cliRoot: legacyCliRoot })
  assert.deepEqual(provided.settings().cliRoot, legacyCliRoot)
})

test('RC2 bundle entry retains the legacy OpenDuck settings section id', async () => {
  const patch = await readFile(resolve('cordis.patch.yml'), 'utf8')
  assert.match(patch, /- id: openduck\n\s+name: '@openduck\/openduck-base'/)
})

test('RC2 ConfigForms serves the editable CLI and history sections as volatile', () => {
  const document = Config.toJSON()
  const root = document.refs[String(document.uid)]
  assert.equal(document.refs[root.dict.cliRoot].meta.volatile, true)
  assert.equal(document.refs[root.dict.history].meta.volatile, true)
})

test('browser RPC is served as exact /api Fetch routes speaking the Connection envelope', async () => {
  const routes = new Map()
  const ctx = {
    inject: (services, callback) => {
      if (!services.includes('connection')) return
      callback({ connection: { fetch: { register: route => { routes.set(route.path, route); return () => routes.delete(route.path) } } }, provide: () => {}, effect: () => {} })
    },
    provide: () => {},
    effect: () => {},
  }
  apply(ctx, {})
  assert.deepEqual([...routes.keys()].sort(), ['/api/openduck-cli/login', '/api/openduck-cli/status', '/api/openduck-history/messages', '/api/openduck-history/projects', '/api/openduck-history/sessions'])
  const route = routes.get('/api/openduck-history/projects')
  assert.deepEqual(route.methods, ['POST'])
  const request = body => new Request('http://127.0.0.1/api/openduck-history/projects', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  const response = await route.fetch(request({ type: 'client-request', rpcId: 'r1', method: 'openduck-history/projects', payload: {} }))
  assert.deepEqual(await response.json(), { type: 'server-response', rpcId: 'r1', result: { ok: true, value: { items: [] } } })
  assert.equal((await route.fetch(request({ type: 'client-request', rpcId: 'r2', method: 'openduck-cli/status', payload: {} }))).status, 400)
})

test('CLI adapter reads the live agentPreset projection, not only the creation-time header', async () => {
  const { cliSessionView } = await import('../src/index.js')
  const session = { header: { cwd: '/work/one', agentPreset: 'standard' } }
  const ctx = { sessions: { get: id => id === 's1' ? session : undefined }, sessionProjections: { stateOf: (value, key) => value === session && key === 'agentPreset' ? 'openduck-cli-root' : undefined } }
  assert.deepEqual(cliSessionView(ctx, 's1'), { cwd: '/work/one', agentPreset: 'openduck-cli-root' })
  assert.equal(cliSessionView(ctx, 'missing'), undefined)
  assert.equal(cliSessionView({ sessions: ctx.sessions }, 's1').agentPreset, 'standard')
})
