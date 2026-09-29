import test from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import { createCliAuth } from '../src/cli/auth.js'
import { createCliRootRpc } from '../src/cli/host.js'

function child() { const value = new EventEmitter(); value.stdout = new PassThrough(); value.stderr = new PassThrough(); value.kill = () => {}; return value }

test('auth status returns only normalized state and treats failed probes as unknown', async () => {
  const spawned = []
  const auth = createCliAuth({ availability: { executable: provider => provider === 'codex' ? '/synthetic/codex' : provider === 'claude' ? '/synthetic/claude' : '/synthetic/kimi' }, spawnProcess: (command, args) => {
    spawned.push([command, args]); const value = child(); queueMicrotask(() => { if (command.includes('codex')) value.stderr.write('Logged in using ChatGPT'); else value.stdout.write('{"loggedIn":false}'); value.emit('close', 0) }); return value
  } })
  assert.deepEqual(await auth.status('codex'), { installed: true, auth: 'authenticated' })
  assert.deepEqual(await auth.status('claude'), { installed: true, auth: 'not-signed-in' })
  assert.deepEqual(await auth.status('kimi'), { installed: true, auth: 'unknown' })
  const codexSignedOut = createCliAuth({ availability: { executable: () => '/synthetic/codex' }, spawnProcess: () => { const value = child(); queueMicrotask(() => { value.stderr.write('Not logged in'); value.emit('close', 1) }); return value } })
  assert.deepEqual(await codexSignedOut.status('codex'), { installed: true, auth: 'not-signed-in' })
  const nonzeroAuthenticated = createCliAuth({ availability: { executable: () => '/synthetic/claude' }, spawnProcess: () => { const value = child(); queueMicrotask(() => { value.stdout.write('{"loggedIn":true}'); value.emit('close', 1) }); return value } })
  assert.deepEqual(await nonzeroAuthenticated.status('claude'), { installed: true, auth: 'unknown' })
  const failed = createCliAuth({ availability: { executable: () => '/synthetic/codex' }, spawnProcess: () => { const value = child(); queueMicrotask(() => value.emit('close', 1)); return value } })
  assert.deepEqual(await failed.status('codex'), { installed: true, auth: 'unknown' })
  assert.deepEqual(spawned[0], ['/synthetic/codex', ['login', 'status']])
})

test('Terminal login has fixed provider arguments and releases its short launch guard', async () => {
  const calls = []
  const auth = createCliAuth({ availability: { executable: provider => `/synthetic/${provider}` }, platform: 'darwin', spawnProcess: (command, args) => {
    calls.push([command, args]); const value = child(); queueMicrotask(() => { value.emit('spawn'); value.emit('close', 0) }); return value
  } })
  await auth.launch('claude'); await auth.launch('claude')
  assert.equal(calls.length, 2)
  assert.equal(calls[0][0], 'osascript')
  assert.match(calls[0][1].at(-1), /'\/synthetic\/claude' 'auth' 'login' '--claudeai'/)
})

test('Terminal login rejects an osascript failure instead of claiming a launched flow', async () => {
  const auth = createCliAuth({ availability: { executable: () => '/synthetic/codex' }, platform: 'darwin', spawnProcess: () => { const value = child(); queueMicrotask(() => value.emit('close', 1)); return value } })
  await assert.rejects(auth.launch('codex'), /could not open Terminal/)
})

test('CLI RPC accepts only fixed DTOs and never returns probe output', async () => {
  const rpc = createCliRootRpc({ auth: { status: async provider => ({ installed: provider === 'codex', auth: 'authenticated', diagnostic: 'private@example.test' }), launch: async () => ({ launched: true }) } })
  const status = await rpc.handle('status', {})
  assert.equal(status.ok, true)
  assert.equal(JSON.stringify(status).includes('private@example.test'), false)
  assert.equal((await rpc.handle('login', { provider: 'codex', extra: true })).ok, false)
  assert.equal((await rpc.handle('login', { provider: 'codex' })).ok, true)
})
