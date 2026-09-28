import test from 'node:test'
import assert from 'node:assert/strict'
import { createCodexRunner } from '../src/cli/codex.js'
import { createClaudeRunner } from '../src/cli/claude.js'
import { createKimiRunner } from '../src/cli/kimi.js'

const source = events => ({ events: (async function * () { yield* events })(), result: Promise.resolve(), cancel: () => {} })
const collect = async iterable => { const values = []; for await (const value of iterable) values.push(value); return values }

test('Codex app-server uses the documented thread and turn protocol with its selected model', async () => {
  const calls = []; const sent = []
  const runner = createCodexRunner({ transport: { start: request => { calls.push(request); return { ...source([
    JSON.stringify({ jsonrpc: '2.0', id: 1, result: {} }), JSON.stringify({ jsonrpc: '2.0', id: 2, result: { thread: { id: 'thread-1' } } }), JSON.stringify({ jsonrpc: '2.0', id: 3, result: { turn: { id: 'turn-1' } } }),
    JSON.stringify({ jsonrpc: '2.0', method: 'item/completed', params: { threadId: 'thread-1', turnId: 'turn-1', item: { type: 'agentMessage', phase: 'final_answer', text: 'Codex answer' } } }), JSON.stringify({ jsonrpc: '2.0', method: 'turn/completed', params: { threadId: 'thread-1', turn: { id: 'turn-1', status: 'completed' } } }),
  ]), send: async value => { sent.push(value) } } } } })
  const handle = runner.stream({ prompt: 'synthetic prompt', cwd: '/work/synthetic', model: 'gpt-5-codex' })
  assert.deepEqual(await collect(handle.events), [{ type: 'text', text: 'Codex answer' }])
  const result = await handle.result
  assert.deepEqual(result.continuation, { provider: 'codex', remoteSessionId: 'thread-1' })
  assert.deepEqual(calls[0].args, ['app-server', '--stdio'])
  assert.deepEqual(sent.map(item => item.method), ['initialize', 'initialized', 'thread/start', 'turn/start'])
  assert.equal(sent[2].params.model, 'gpt-5-codex'); assert.equal(sent[3].params.model, 'gpt-5-codex')
  assert.equal(sent[2].params.sandbox, 'read-only'); assert.equal(sent[2].params.approvalPolicy, 'never')
  assert.deepEqual(sent[3].params.sandboxPolicy, { type: 'readOnly', networkAccess: false })
})

test('Claude stream-json emits text and records its CLI-owned session id', async () => {
  const calls = []
  const runner = createClaudeRunner({ transport: { start: request => { calls.push(request); return source([JSON.stringify({ type: 'content_block_delta', session_id: 'session-1', delta: { type: 'text_delta', text: 'Claude answer' } }), JSON.stringify({ type: 'result', is_error: false, session_id: 'session-1' })]) } } })
  const handle = runner.stream({ prompt: 'synthetic prompt', cwd: '/work/synthetic', model: 'sonnet' })
  assert.deepEqual(await collect(handle.events), [{ type: 'text', text: 'Claude answer' }])
  assert.deepEqual((await handle.result).continuation, { provider: 'claude', remoteSessionId: 'session-1' })
  assert.ok(calls[0].args.includes('--restricted')); assert.ok(calls[0].args.includes('--tools')); assert.ok(calls[0].args.includes('dontAsk'))
})

test('Kimi ACP waits for the prompt response before releasing its persistent child', async () => {
  const calls = []; const sent = []
  const runner = createKimiRunner({ transport: { start: request => { calls.push(request); return { ...source([
    JSON.stringify({ id: 1, result: {} }), JSON.stringify({ id: 2, result: { sessionId: 'session-1' } }), JSON.stringify({ method: 'session/update', params: { sessionId: 'session-1', update: { sessionUpdate: 'agent_message_chunk', content: { type: 'text', text: 'Kimi answer' } } } }), JSON.stringify({ id: 3, result: { stopReason: 'end_turn' } }),
  ]), send: async value => { sent.push(value) } } } } })
  const handle = runner.stream({ prompt: 'synthetic prompt', cwd: '/work/synthetic', model: 'kimi-for-coding' })
  assert.deepEqual(await collect(handle.events), [{ type: 'text', text: 'Kimi answer' }])
  assert.deepEqual((await handle.result).continuation, { provider: 'kimi', remoteSessionId: 'session-1' })
  assert.deepEqual(calls[0].args, ['acp'])
  assert.deepEqual(sent.map(item => item.method), ['initialize', 'session/new', 'session/prompt'])
})

test('CLI runners reject invalid continuations before transport launch', () => {
  const runner = createCodexRunner({ transport: { start: () => { throw new Error('must not start') } } })
  assert.throws(() => runner.continue({ continuation: { provider: 'claude', remoteSessionId: 'x' }, prompt: 'next', cwd: '/work/synthetic', model: 'model' }), /continuation/)
})

test('reserved default model delegates selection to each authenticated CLI', async () => {
  const codexCalls = []; const codex = createCodexRunner({ transport: { start: request => { codexCalls.push(request); return { ...source([JSON.stringify({ id: 1, result: {} }), JSON.stringify({ id: 2, result: { thread: { id: 'thread-1' } } }), JSON.stringify({ id: 3, result: { turn: { id: 'turn-1' } } }), JSON.stringify({ method: 'turn/completed', params: { threadId: 'thread-1', turn: { id: 'turn-1', status: 'completed' } } })]), send: async () => {} } } } })
  const codexHandle = codex.stream({ prompt: 'x', cwd: '/work/synthetic', model: 'default' }); await collect(codexHandle.events); await codexHandle.result
  const claudeCalls = []; const claude = createClaudeRunner({ transport: { start: request => { claudeCalls.push(request); return source([JSON.stringify({ type: 'result', is_error: false, session_id: 'session-1' })]) } } })
  const claudeHandle = claude.stream({ prompt: 'x', cwd: '/work/synthetic', model: 'default' }); await collect(claudeHandle.events); await claudeHandle.result
  const kimiCalls = []; const kimi = createKimiRunner({ transport: { start: request => { kimiCalls.push(request); return { ...source([JSON.stringify({ id: 1, result: {} }), JSON.stringify({ id: 2, result: { sessionId: 'session-1' } }), JSON.stringify({ id: 3, result: {} })]), send: async () => {} } } } })
  const kimiHandle = kimi.stream({ prompt: 'x', cwd: '/work/synthetic', model: 'default' }); await collect(kimiHandle.events); await kimiHandle.result
  assert.equal(codexCalls.length, 1); assert.ok(!claudeCalls[0].args.includes('--model')); assert.deepEqual(kimiCalls[0].args, ['acp'])
})

test('Kimi ACP rejects a reverse permission request instead of exposing host capabilities', async () => {
  const sent = []
  const runner = createKimiRunner({ transport: { start: () => ({ ...source([
    JSON.stringify({ id: 1, result: {} }), JSON.stringify({ id: 2, result: { sessionId: 'session-1' } }), JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'session/request_permission', params: { sessionId: 'session-1' } }), JSON.stringify({ id: 3, result: {} }),
  ]), send: async value => { sent.push(value) } }) } })
  const handle = runner.stream({ prompt: 'x', cwd: '/work/synthetic', model: 'default' }); await collect(handle.events); await handle.result
  assert.deepEqual(sent.find(value => value.id === 9), { jsonrpc: '2.0', id: 9, error: { code: -32601, message: 'OpenDuck CLI root chat does not provide filesystem, terminal, permission, or MCP capabilities' } })
})

test('Codex rejects unknown agent-message phases and Claude stops at its terminal result', async () => {
  const codex = createCodexRunner({ transport: { start: () => ({ ...source([
    JSON.stringify({ id: 1, result: {} }), JSON.stringify({ id: 2, result: { thread: { id: 'thread-1' } } }), JSON.stringify({ id: 3, result: { turn: { id: 'turn-1' } } }), JSON.stringify({ method: 'item/completed', params: { threadId: 'thread-1', turnId: 'turn-1', item: { type: 'agentMessage', phase: 'unexpected', text: 'x' } } }),
  ]), send: async () => {} }) } })
  const broken = codex.stream({ prompt: 'x', cwd: '/work/synthetic', model: 'default' }); await assert.rejects(async () => collect(broken.events), /unsupported agent message phase/)
  const claude = createClaudeRunner({ transport: { start: () => source([JSON.stringify({ type: 'result', is_error: false, session_id: 's' }), JSON.stringify({ type: 'content_block_delta', delta: { type: 'text_delta', text: 'late' } })]) } })
  const complete = claude.stream({ prompt: 'x', cwd: '/work/synthetic', model: 'default' }); assert.deepEqual(await collect(complete.events), []); await complete.result
})
