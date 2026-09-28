import test from 'node:test'
import assert from 'node:assert/strict'
import { apply as browserApply } from '../src/dsh-client.js'
import { apply as hostApply } from '../src/index.js'

test('registers one additive utility and disposes closure state', () => {
  const entries = []
  const slots = {
    inject(_name, callback) { callback(); return () => {} },
    register(options, factory) { const entry = { ...options, value: factory() }; entries.push(entry); return () => entries.splice(entries.indexOf(entry), 1) },
  }
  const dispose = browserApply({ slots, provide() { return () => {} } })
  assert.equal(entries.length, 1)
  assert.equal(entries[0].id, 'openduck-controller-read-bridge')
  assert.equal(entries[0].name, 'conversation.session.header.utilities')
  dispose()
})

test('host provides controllerReadBridge and registers exact web routes; browser consumes its proxy', async () => {
  const entries = []; const services = new Map()
  const ctx = {
    slots: { inject(_name, callback) { callback(); return () => {} }, register(options, factory) { entries.push({ options, factory }); return () => {} } },
    webServer: { register(route) { entries.push({ route }); return () => entries.pop() } },
    provide(name, value) { services.set(name, value); return () => services.delete(name) },
  }
  const cleanup = hostApply(ctx)
  assert.ok(services.has('controllerReadBridge'))
  assert.deepEqual(entries.filter(item => item.route).map(item => item.route.path), ['/v1/plugin-reads/beads/project-graph', '/v1/plugin-reads/beads/global-metadata', '/v1/plugin-reads/workspace-groups'])
  cleanup(); assert.equal(services.size, 0)
  const browserServices = new Map(); const browserCleanup = browserApply({ slots: { inject(_name, cb) { cb(); return () => {} }, register() { return () => {} } }, provide(name, value) { browserServices.set(name, value); return () => browserServices.delete(name) } })
  assert.ok(browserServices.has('controllerReadBridge')); browserCleanup(); assert.equal(browserServices.size, 0)
})
