import test from 'node:test'
import assert from 'node:assert/strict'
import { DEFAULT_SETTINGS, validateSettings } from '../src/contract.js'
import { apply } from '../src/index.js'

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

test('Cordis entry provides a read-only runtime service from native settings', () => {
  const effects = []
  let provided
  const ctx = {
    inject: (services, callback) => {
      if (services.includes('settings')) callback({
        settings: { register: (_namespace, _schema, options) => ({ get: () => options.base, watch: () => {} }) },
        effect: () => {},
      })
    },
    provide: (_name, service) => { provided = service },
    effect: callback => effects.push(callback),
  }
  apply(ctx, { controller: { enabled: false }, externalPackages: ['dsh-process'] })
  assert.equal(provided.status(), 'disabled')
  assert.deepEqual(provided.externalPackages(), ['dsh-process'])
  assert.equal(effects.length, 1)
})

test('settings validator rejects nonexistent history directories before saving', () => {
  const settings = structuredClone(DEFAULT_SETTINGS)
  settings.history = { projects: [{ root: '/definitely-not-an-openduck-project' }] }
  assert.throws(() => validateSettings(settings), /existing canonical directory/)
})

test('enabled CLI root chat requires a canonical workspace and an explicit model allowlist', () => {
  const settings = structuredClone(DEFAULT_SETTINGS)
  settings.cliRoot = { enabled: true, cwd: '', models: { codex: [], claude: [], kimi: [] } }
  assert.throws(() => validateSettings(settings), /cliRoot\.cwd/)
  settings.cliRoot = { enabled: true, cwd: process.cwd(), models: { codex: [], claude: [], kimi: [] } }
  assert.throws(() => validateSettings(settings), /explicit model/)
})
