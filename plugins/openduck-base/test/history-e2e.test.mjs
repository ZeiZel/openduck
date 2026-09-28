import test from 'node:test'
import assert from 'node:assert/strict'
import { chmodSync, mkdtempSync, mkdirSync, realpathSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHistoryRpc } from '../src/history/host.js'

const mockCodex = `#!/usr/bin/env node
let buffered = ''
process.stdin.on('data', chunk => {
  buffered += chunk
  for (;;) {
    const newline = buffered.indexOf('\\n'); if (newline < 0) return
    const request = JSON.parse(buffered.slice(0, newline)); buffered = buffered.slice(newline + 1)
    if (!Object.hasOwn(request, 'id')) continue
    let result = {}
    if (request.method === 'thread/list') result = { data: [{ id: 'thread_1', sessionId: 'root_1', name: 'Synthetic turn', preview: 'hello', updatedAt: 1700000000 }], nextCursor: null }
    if (request.method === 'thread/read') result = { thread: { id: 'thread_1', cwd: process.env.OPENDUCK_SYNTHETIC_ROOT, turns: request.params.includeTurns ? [{ items: [{ type: 'userMessage', id: 'u1', content: [{ type: 'text', text: 'hello' }] }, { type: 'agentMessage', id: 'a1', text: 'world' }] }] : [] } }
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }) + '\\n')
  }
})
`

test('host RPC runs a synthetic Codex stdio server and returns bounded list/read pages', async () => {
  const base = mkdtempSync(join(tmpdir(), 'openduck-history-e2e-'))
  const project = join(base, 'project'); mkdirSync(project)
  const canonicalProject = realpathSync.native(project)
  const executable = join(base, 'mock-codex.mjs'); writeFileSync(executable, mockCodex); chmodSync(executable, 0o755)
  const previous = process.env.OPENDUCK_SYNTHETIC_ROOT; process.env.OPENDUCK_SYNTHETIC_ROOT = canonicalProject
  try {
    const rpc = createHistoryRpc({ projects: [{ root: canonicalProject, displayName: 'Synthetic project' }] }, { codex: { command: executable, args: [] } })
    const sessions = await rpc.handle('sessions', { projectId: 'p1', provider: 'codex', limit: 25 })
    assert.equal(sessions.ok, true); assert.equal(sessions.value.items[0].sessionId, 'thread_1'); assert.equal(JSON.stringify(sessions.value).includes(canonicalProject), false)
    const messages = await rpc.handle('messages', { projectId: 'p1', provider: 'codex', sessionId: 'thread_1', limit: 25 })
    assert.equal(messages.ok, true); assert.deepEqual(messages.value.items.map(item => item.text), ['hello', 'world'])
  } finally { if (previous === undefined) delete process.env.OPENDUCK_SYNTHETIC_ROOT; else process.env.OPENDUCK_SYNTHETIC_ROOT = previous }
})
