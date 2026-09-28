import test from 'node:test'
import assert from 'node:assert/strict'
import { createHistoryService } from '../src/history/index.js'
import { EventEmitter } from 'node:events'
import { createClaudeSdkSource, createCodexRpcPort, createJsonRpcChild, createKimiAcpList, createKimiAcpReader } from '../src/history/index.js'

const projectRoot = '/work/rentverse'

function service(sources) {
  return createHistoryService({ projects: [{ root: projectRoot, displayName: 'Rentverse', sources }] })
}

test('Codex adapter sends a bounded read-only list request and normalizes project metadata', async () => {
  const calls = []
  const history = service({ codex: { rpc: async (method, params) => {
    calls.push({ method, params })
    return { data: [{ id: 'thr_1', sessionId: 'thr_root', name: 'Fix list', preview: 'Please fix', createdAt: 1700000000, updatedAt: 1700000001 }], nextCursor: 'opaque-next' }
  } } })
  const page = await history.list({ provider: 'codex', projectRoot, limit: 25 })
  assert.equal(calls[0].method, 'thread/list')
  assert.deepEqual(calls[0].params.cwd, projectRoot)
  assert.equal(page.items[0].sessionRootId, 'thr_root')
  assert.equal(page.items[0].project.displayName, 'Rentverse')
  assert.equal(page.nextCursor, 'opaque-next')
})

test('Codex read projects only user and assistant text from synthetic turns', async () => {
  const history = service({ codex: { rpc: async (_method, params) => ({ thread: { id: 'thr_1', cwd: projectRoot, turns: params.includeTurns ? [{ items: [
    { type: 'userMessage', id: 'u1', content: [{ type: 'text', text: 'hello' }, { type: 'image', url: 'ignored' }] },
    { type: 'agentMessage', id: 'a1', text: 'world' },
  ] }] : [] } }) } })
  const page = await history.read({ provider: 'codex', projectRoot, sessionId: 'thr_1', limit: 1 })
  const next = await history.read({ provider: 'codex', projectRoot, sessionId: 'thr_1', limit: 1, cursor: page.nextCursor })
  assert.deepEqual(page.items.map(item => [item.role, item.text]), [['user', 'hello']])
  assert.deepEqual(next.items.map(item => [item.role, item.text]), [['assistant', 'world']])
})

test('Claude Agent SDK source handles official session summaries and message records', async () => {
  const history = service({ claude: {
    listSessions: async ({ directory }) => { assert.equal(directory, projectRoot); return [{ session_id: '550e8400-e29b-41d4-a716-446655440000', summary: 'Review', first_prompt: 'review it', last_modified: 1700000000000, cwd: projectRoot }] },
    getSessionMessages: async () => [{ type: 'user', uuid: 'u1', timestamp: '2026-09-01T00:00:00Z', session_id: '550e8400-e29b-41d4-a716-446655440000', message: { role: 'user', content: 'review it' } }],
  } })
  const listed = await history.list({ provider: 'claude', projectRoot })
  const read = await history.read({ provider: 'claude', projectRoot, sessionId: '550e8400-e29b-41d4-a716-446655440000' })
  assert.equal(listed.items[0].title, 'Review')
  assert.equal(read.items[0].text, 'review it')
})

test('Kimi ACP session/list uses exact cwd and native cursor fields', async () => {
  const calls = []
  const history = service({ kimi: { listSessions: async value => {
    calls.push(value)
    return { sessions: [{ sessionId: 'session_1', cwd: projectRoot, title: 'Plan', updatedAt: '2026-09-01T00:00:00Z' }], nextCursor: 'opaque-next' }
  }, readTranscript: async () => ({ items: [], nextCursor: null }) } })
  const listed = await history.list({ provider: 'kimi', projectRoot, limit: 1 })
  assert.deepEqual(calls[0], { cwd: projectRoot, cursor: undefined })
  assert.equal(listed.items[0].title, 'Plan')
  assert.equal(listed.nextCursor, 'opaque-next')
  const read = await history.read({ provider: 'kimi', projectRoot, sessionId: 'session_1' })
  assert.equal(read.status, 'ok')
})

test('refuses unallowlisted roots, invalid bounds, and unknown ACP source schemas', async () => {
  let malformed = false
  const history = service({ kimi: { listSessions: async () => malformed ? {} : { sessions: [] } } })
  await assert.rejects(() => history.list({ provider: 'kimi', projectRoot: '/other' }), /allowlisted/)
  await assert.rejects(() => history.list({ provider: 'kimi', projectRoot, limit: 101 }), /limit/)
  malformed = true
  await assert.rejects(() => history.list({ provider: 'kimi', projectRoot }), /unsupported Kimi ACP/)
})

function fakeChild(onWrite) {
  const child = new EventEmitter()
  child.stdout = new EventEmitter()
  child.stderr = new EventEmitter()
  child.stdin = { write: line => onWrite(JSON.parse(line), child) }
  child.kill = () => child.emit('exit', 0)
  return child
}

test('Codex production port performs the stdio handshake before an allowlisted read', async () => {
  const calls = []
  const rpc = createCodexRpcPort({ spawn: () => fakeChild((message, child) => {
    calls.push(message.method)
    if (message.id) child.stdout.emit('data', `${JSON.stringify({ id: message.id, result: message.method === 'thread/list' ? { data: [] } : {} })}\n`)
  }) })
  assert.deepEqual(await rpc('thread/list', { cwd: projectRoot, limit: 1 }), { data: [] })
  assert.deepEqual(calls, ['initialize', 'initialized', 'thread/list'])
  await assert.rejects(() => rpc('thread/delete', {}), /allowlisted/)
})

test('cross-project reads fail before a transcript is returned', async () => {
  let readTurns = false
  const history = service({ codex: { rpc: async (_method, params) => { if (params.includeTurns) readTurns = true; return { thread: { id: 'thr_1', cwd: '/work/other', turns: [] } } } } })
  await assert.rejects(() => history.read({ provider: 'codex', projectRoot, sessionId: 'thr_1' }), /not a member/)
  assert.equal(readTurns, false)
})

test('Kimi ACP list initializes then requests the documented session/list schema', async () => {
  const calls = []
  const list = createKimiAcpList({ spawn: () => fakeChild((message, child) => {
    calls.push(message.method)
    if (message.method === 'initialize') child.stdout.emit('data', `${JSON.stringify({ id: message.id, result: {} })}\n`)
    if (message.method === 'session/list') child.stdout.emit('data', `${JSON.stringify({ id: message.id, result: { sessions: [{ sessionId: 'session_1', cwd: projectRoot, title: 'Plan', updatedAt: '2026-09-01T00:00:00Z' }], nextCursor: 'opaque' } })}\n`)
  }) })
  const result = await list({ cwd: projectRoot, cursor: undefined })
  assert.deepEqual(calls, ['initialize', 'session/list'])
  assert.equal(result.sessions[0].cwd, projectRoot)
  assert.equal(result.nextCursor, 'opaque')
})

test('Kimi ACP reader accepts replayed text chunks without raw wire parsing', async () => {
  const reader = createKimiAcpReader({ spawn: () => fakeChild((message, child) => {
    if (message.method === 'initialize') child.stdout.emit('data', `${JSON.stringify({ id: message.id, result: {} })}\n`)
    if (message.method === 'session/load') {
      child.stdout.emit('data', `${JSON.stringify({ method: 'session/update', params: { update: { sessionUpdate: 'agent_message_chunk', content: { type: 'text', text: 'hello' } } } })}\n`)
      child.stdout.emit('data', `${JSON.stringify({ id: message.id, result: {} })}\n`)
    }
  }) })
  const transcript = await reader({ sessionId: 'session_1', limit: 5 })
  assert.deepEqual(transcript.items[0].message, { role: 'assistant', content: 'hello' })
})

test('Claude loader uses official helper names and remains lazy', async () => {
  let loaded = false
  const source = createClaudeSdkSource(async () => { loaded = true; return { listSessions: ({ dir }) => [{ sessionId: 's', summary: dir }], getSessionMessages: id => [{ type: 'user', uuid: 'm', message: { role: 'user', content: id } }] } })
  assert.equal(loaded, false)
  assert.equal((await source.listSessions({ directory: projectRoot }))[0].summary, projectRoot)
  assert.equal(loaded, true)
  assert.equal((await source.getSessionMessages('s'))[0].message.content, 's')
})

test('child denies unsolicited server requests and times out without exposing child output', async () => {
  const written = []
  const rpc = createJsonRpcChild({ command: 'fake', args: [], timeoutMs: 100, spawn: () => fakeChild((message, child) => {
    written.push(message)
    if (message.method === 'read') child.stdout.emit('data', `${JSON.stringify({ jsonrpc: '2.0', id: 77, method: 'fs/read_text_file', params: {} })}\n`)
  }) })
  await assert.rejects(() => rpc.request('read', {}), /timed out/)
  assert.deepEqual(written.at(-1).error, { code: -32601, message: 'method not allowed' })
})

test('Kimi ACP list rejects a session returned outside the selected project', async () => {
  const history = service({ kimi: { listSessions: async () => ({ sessions: [{ sessionId: 'session_1', cwd: '/work/other', title: 'Wrong root' }] }) } })
  await assert.rejects(() => history.list({ provider: 'kimi', projectRoot }), /not a member/)
})
