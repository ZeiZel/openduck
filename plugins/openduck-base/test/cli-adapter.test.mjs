import test from 'node:test'
import assert from 'node:assert/strict'
import { CliSubscriptionAdapter } from '../src/cli/adapter.js'
async function* events() { yield { type: 'text', text: 'hello ' }; yield { type: 'text', text: 'world' } }
test('CLI adapter maps a synthetic subscription stream into native LLM chunks', async () => {
  const adapter = new CliSubscriptionAdapter({ 'codex-cli': { stream: () => ({ events: events(), result: Promise.resolve({}), cancel: () => {} }) } }, { 'codex-cli': ['gpt-5-codex'] })
  const chunks = []; for await (const chunk of adapter.stream({ provider: 'codex-cli', model: 'gpt-5-codex', messages: [{ role: 'user', content: [{ type: 'text', text: 'hello' }] }] })) chunks.push(chunk)
  assert.deepEqual(chunks.map(chunk => chunk.type), ['block-start', 'text-delta', 'text-delta', 'block-end', 'finish'])
  assert.equal(chunks[3].block.text, 'hello world')
})
test('CLI adapter discards inherited DSH schemas instead of forwarding host tools to a subscription CLI', async () => {
  let request
  const adapter = new CliSubscriptionAdapter({ 'codex-cli': { stream: value => { request = value; return { events: events(), result: Promise.resolve({}) } } } }, { 'codex-cli': ['default'] })
  for await (const _ of adapter.stream({ provider: 'codex-cli', model: 'default', messages: [{ role: 'user', content: [{ type: 'text', text: 'x' }] }], tools: [{ name: 'host_filesystem_tool' }] })) {}
  assert.equal(Object.hasOwn(request, 'tools'), false)
  assert.equal(request.prompt, 'User:\nx')
  await assert.rejects(async () => {
    for await (const _ of adapter.stream({ provider: 'codex-cli', model: 'default', messages: [{ role: 'user', content: [{ type: 'tool-result', toolCallId: 'host-call', content: [] }] }] })) {}
  }, /tool blocks/)
})

test('CLI adapter continues only an unchanged DSH transcript and resets after an edit', async () => {
  const calls = []
  const runner = {
    stream: request => { calls.push(['stream', request.prompt]); return { events: events(), result: Promise.resolve({ continuation: { provider: 'codex', remoteSessionId: 'remote-1' } }), cancel: () => {} } },
    continue: request => { calls.push(['continue', request.prompt]); return { events: events(), result: Promise.resolve({ continuation: request.continuation }), cancel: () => {} } },
  }
  const adapter = new CliSubscriptionAdapter({ 'codex-cli': runner }, { 'codex-cli': ['gpt-5-codex'] })
  const first = { provider: 'codex-cli', model: 'gpt-5-codex', sessionId: 'dsh-1', messages: [{ role: 'user', content: [{ type: 'text', text: 'first' }] }] }
  for await (const _ of adapter.stream(first)) {}
  const continuation = { ...first, messages: [...first.messages, { role: 'assistant', content: [{ type: 'text', text: 'hello world' }] }, { role: 'user', content: [{ type: 'text', text: 'second' }] }] }
  for await (const _ of adapter.stream(continuation)) {}
  const reset = { ...continuation, messages: [{ role: 'user', content: [{ type: 'text', text: 'edited first' }] }, continuation.messages.at(-1)] }
  for await (const _ of adapter.stream(reset)) {}
  assert.deepEqual(calls.map(([kind]) => kind), ['stream', 'continue', 'stream'])
  assert.equal(calls[1][1], 'second')
  assert.match(calls[2][1], /edited first/)
})

test('CLI adapter clears a failed continuation binding before retry', async () => {
  let fail = true; const calls = []
  const runner = {
    stream: request => { calls.push('stream'); return { events: events(), result: Promise.resolve({ continuation: { provider: 'codex', remoteSessionId: 'remote-1' } }), cancel: () => {} } },
    continue: request => { calls.push('continue'); return { events: events(), result: fail ? Promise.reject(new Error('aborted')) : Promise.resolve({ continuation: request.continuation }), cancel: () => {} } },
  }
  const adapter = new CliSubscriptionAdapter({ 'codex-cli': runner }, { 'codex-cli': ['gpt-5-codex'] })
  const first = { provider: 'codex-cli', model: 'gpt-5-codex', sessionId: 'dsh-1', messages: [{ role: 'user', content: [{ type: 'text', text: 'first' }] }] }
  for await (const _ of adapter.stream(first)) {}
  const next = { ...first, messages: [...first.messages, { role: 'assistant', content: [{ type: 'text', text: 'hello world' }] }, { role: 'user', content: [{ type: 'text', text: 'second' }] }] }
  await assert.rejects(async () => { for await (const _ of adapter.stream(next)) {} }, /aborted/)
  fail = false
  for await (const _ of adapter.stream(next)) {}
  assert.deepEqual(calls, ['stream', 'continue', 'stream'])
})
