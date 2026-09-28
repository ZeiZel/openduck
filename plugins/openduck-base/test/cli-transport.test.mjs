import test from 'node:test'
import assert from 'node:assert/strict'
import { createCliTransport } from '../src/cli/transport.js'

const collect = async iterable => { const values = []; for await (const value of iterable) values.push(value); return values }
test('transport passes cwd and stdin, drains stderr, and preserves a final JSONL frame', async () => {
  const script = "process.stdin.on('data', value => { process.stderr.write('diagnostic'); process.stdout.write(JSON.stringify({ cwd: process.cwd(), input: String(value).trim() })) })"
  const child = createCliTransport().start({ command: process.execPath, args: ['-e', script], cwd: '/tmp', input: 'hello' })
  assert.deepEqual(JSON.parse((await collect(child.events))[0]), { cwd: '/private/tmp', input: 'hello' })
  await child.result
})
test('transport rejects an unbounded stdout producer and cleans its abort listener', async () => {
  const controller = new AbortController()
  const child = createCliTransport({ maxBufferedBytes: 1024, timeoutMs: 10_000 }).start({ command: process.execPath, args: ['-e', "process.stdout.write('x'.repeat(4096))"], signal: controller.signal })
  await assert.rejects(async () => collect(child.events), /bounded stdout buffer/)
  await assert.rejects(child.result, /bounded stdout buffer/)
  controller.abort()
})

test('transport preserves split UTF-8 JSONL and never returns stderr content', async () => {
  const script = "const b=Buffer.from(JSON.stringify({text:'привет 👋'})+'\\n'); process.stdout.write(b.subarray(0,7)); process.stdout.write(b.subarray(7)); process.stderr.write('private diagnostic'); process.exitCode=2"
  const child = createCliTransport().start({ command: process.execPath, args: ['-e', script] })
  const iterator = child.events[Symbol.asyncIterator](); const first = await iterator.next()
  assert.deepEqual(JSON.parse(first.value), { text: 'привет 👋' })
  await assert.rejects(iterator.next(), /exited with code 2/)
  await assert.rejects(child.result, error => /exited with code 2/.test(error.message) && !error.message.includes('private diagnostic'))
})

test('transport settles an already-aborted request without starting a timeout leak', async () => {
  const signal = AbortSignal.abort()
  const child = createCliTransport({ timeoutMs: 1000 }).start({ command: process.execPath, args: ['-e', 'setInterval(() => {}, 1000)'], signal })
  await assert.rejects(async () => collect(child.events), /aborted/)
  await assert.rejects(child.result, /aborted/)
})
