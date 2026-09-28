import test from 'node:test'
import assert from 'node:assert/strict'
import { createHistoryRpc } from '../src/history/host.js'
const options = { normalizeRoot: root => root }

test('history RPC exposes aliases instead of configured filesystem roots', async () => {
  const rpc = createHistoryRpc({ projects: [{ root: '/work/demo', displayName: 'Demo' }] }, undefined, options)
  const result = await rpc.handle('projects', {})
  assert.deepEqual(result, { ok: true, value: { items: [{ id: 'p1', displayName: 'Demo' }] } })
})

test('history RPC rejects unknown project aliases without forwarding a root', async () => {
  const rpc = createHistoryRpc({ projects: [{ root: '/work/demo' }] }, undefined, options)
  const result = await rpc.handle('sessions', { projectId: 'p2', provider: 'codex', limit: 25 })
  assert.equal(result.ok, false)
  assert.equal(result.error.message, 'Selected project is unavailable')
})

test('history RPC removes configured roots from provider result DTOs', async () => {
  const rpc = createHistoryRpc({ projects: [{ root: '/work/demo' }] }, {
    codexRpc: async () => ({ data: [{ id: 's1', cwd: '/work/demo', name: 'Synthetic', preview: 'hello' }], nextCursor: null }),
  }, options)
  const result = await rpc.handle('sessions', { projectId: 'p1', provider: 'codex', limit: 25 })
  assert.equal(result.ok, true)
  assert.deepEqual(result.value.items[0].project, undefined)
  assert.equal(JSON.stringify(result.value).includes('/work/demo'), false)
  assert.equal(result.value.items[0].projectId, 'p1')
})

test('history RPC refuses non-canonical configured roots before invoking a provider', () => {
  assert.throws(() => createHistoryRpc({ projects: [{ root: '/work/../demo' }] }), /canonical/)
})
