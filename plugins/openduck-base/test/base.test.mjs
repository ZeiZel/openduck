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
  assert.doesNotThrow(() => validateSettings({ controller: { enabled: false, origin: 'http://127.0.0.1:8788' }, externalPackages: ['dsh-process'] }))
})

test('Cordis entry provides a read-only runtime service from native settings', () => {
  const effects = []
  let provided
  const ctx = {
    settings: { register: (_namespace, _schema, options) => ({ get: () => ({ ...DEFAULT_SETTINGS, ...options.base }) }) },
    provide: (_name, service) => { provided = service },
    effect: callback => effects.push(callback),
  }
  apply(ctx, { controller: { enabled: false }, externalPackages: ['dsh-process'] })
  assert.equal(provided.status(), 'disabled')
  assert.deepEqual(provided.externalPackages(), ['dsh-process'])
  assert.equal(effects.length, 1)
})
