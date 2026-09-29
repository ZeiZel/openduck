import test from 'node:test'
import assert from 'node:assert/strict'
import { createCliAvailability } from '../src/cli/availability.js'
import { mountCliRoot } from '../src/cli/index.js'

test('CLI discovery exposes only installed routes and their default model', async () => {
  const availability = createCliAvailability({ resolve: command => command === 'codex' ? '/synthetic/codex' : undefined })
  const registered = []
  mountCliRoot({ llm: { registerAdapter: (routes, adapter) => { registered.push({ routes, adapter }); return () => {} } } }, {}, { availability, sessionFor: () => ({ cwd: '/work/synthetic', agentPreset: 'openduck-cli-root' }) })
  assert.deepEqual(registered[0].routes, ['codex-cli'])
  assert.deepEqual(await registered[0].adapter.listModels('codex-cli'), [{ provider: 'codex-cli', id: 'default', name: 'CLI configured default', inputModalities: ['text'] }])
})

test('no installed CLI produces no provider registration, preserving native key onboarding', () => {
  const availability = createCliAvailability({ resolve: () => undefined })
  let registered = false
  mountCliRoot({ llm: { registerAdapter: () => { registered = true } } }, {}, { availability })
  assert.equal(registered, false)
})
