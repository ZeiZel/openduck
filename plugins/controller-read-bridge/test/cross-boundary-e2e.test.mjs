import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { rm } from 'node:fs/promises'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createControllerReadBridge, CONTROLLER_ORIGIN, PLUGIN_READ_PATHS, apply as hostApply } from '../src/index.js'
import { createBrowserReadBridge } from '../src/browser-client.js'

const root = new URL('../../../', import.meta.url)
// A cold Go build on Node 24 can legitimately populate an empty module/build
// cache. Keep the fixture bounded but do not misclassify it as a product bug.
const PROCESS_TIMEOUT_MS = 120_000
const EXIT_TIMEOUT_MS = 2_000

const waitForExit = (child, timeoutMs) => new Promise(resolve => {
  let settled = false
  const timer = setTimeout(() => { if (!settled) { settled = true; resolve(null) } }, timeoutMs)
  child.once('exit', (code, signal) => { if (!settled) { settled = true; clearTimeout(timer); resolve({ code, signal }) } })
  child.once('error', error => { if (!settled) { settled = true; clearTimeout(timer); resolve({ error }) } })
})

const stopAndWait = async (child, label) => {
  if (child.exitCode !== null || child.signalCode !== null) return { code: child.exitCode, signal: child.signalCode }
  let result = await waitForExit(child, 0)
  if (result) return result
  child.kill('SIGTERM')
  result = await waitForExit(child, EXIT_TIMEOUT_MS)
  if (!result) {
    child.kill('SIGKILL')
    result = await waitForExit(child, EXIT_TIMEOUT_MS)
  }
  assert.ok(result, `${label} did not exit`)
  assert.equal(result.error, undefined, `${label} failed: ${result.error?.message}`)
  return result
}

const makeTempDir = async () => {
  const child = spawn('mktemp', ['-d', join(tmpdir(), 'openduck-plugin-reads-XXXXXX')], { stdio: ['ignore', 'pipe', 'pipe'] })
  let output = ''
  child.stdout.setEncoding('utf8')
  child.stdout.on('data', chunk => { output += chunk })
  const result = await waitForExit(child, PROCESS_TIMEOUT_MS)
  assert.ok(result, 'mktemp timeout')
  assert.equal(result.error, undefined, `mktemp failed: ${result.error?.message}`)
  assert.equal(result.code, 0, `mktemp exited ${result.code}`)
  return output.trim()
}

const buildFixture = async binary => {
  const child = spawn('go', ['build', '-o', binary, './cmd/plugin-reads-fixture'], { cwd: root.pathname, env: { ...process.env, GOCACHE: '/private/tmp/openduck-gocache' }, stdio: ['ignore', 'pipe', 'pipe'] })
  let error = ''
  child.stderr.setEncoding('utf8')
  child.stderr.on('data', chunk => { error += chunk })
  const result = await waitForExit(child, PROCESS_TIMEOUT_MS)
  if (!result) {
    await stopAndWait(child, 'fixture build')
    assert.fail('fixture build timeout')
  }
  assert.equal(result.error, undefined, `fixture build failed: ${result.error?.message}`)
  assert.equal(result.code, 0, `fixture build exited ${result.code}: ${error}`)
}


const waitReady = child => new Promise((resolve, reject) => {
  let text = ''; let error = ''; let settled = false
  const settle = (fn, value) => {
    if (settled) return
    settled = true
    clearTimeout(timer)
    fn(value)
  }
  const timer = setTimeout(() => settle(reject, new Error('fixture timeout')), PROCESS_TIMEOUT_MS)
  child.stdout.on('data', chunk => {
    text += chunk
    const ready = text.match(/^READY (127[.]0[.]0[.]1:[0-9]+)$/m)
    if (ready) settle(resolve, ready[1])
  })
  child.stderr.on('data', chunk => { error += chunk })
  child.once('error', error => settle(reject, error))
  child.once('exit', code => {
    if (code !== null && !text.includes('READY')) settle(reject, new Error(`fixture exited ${code}: ${error}`))
  })
})

const probeLoopbackBinding = async t => {
  const server = createServer()
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject)
      server.listen(0, '127.0.0.1', resolve)
    })
  } catch (error) {
    if (error?.code === 'EACCES' || error?.code === 'EPERM') {
      t.skip(`loopback bind unavailable in this execution sandbox: ${error.code}`)
      return false
    }
    throw error
  } finally {
    if (server.listening) await new Promise(resolve => server.close(resolve))
  }
  return true
}

test('real Go Controller + registered host handlers + browser proxy cross-boundary E2E', async t => {
  if (!await probeLoopbackBinding(t)) return
  let tempDir
  let fixture
  let proxyServer
  try {
    tempDir = await makeTempDir()
    const binary = join(tempDir, 'plugin-reads-fixture')
    await buildFixture(binary)
    fixture = spawn(binary, [], { cwd: root.pathname, stdio: ['ignore', 'pipe', 'pipe'] })
    const controllerHost = await waitReady(fixture); const controllerOrigin = `http://${controllerHost}`
    const routes = new Map(); const provided = new Map()
    const cleanupHost = hostApply({ controllerOrigin, provide: (name, value) => { provided.set(name, value); return () => provided.delete(name) }, webServer: { register(route) { routes.set(route.path, route.handler); return () => routes.delete(route.path) } } })
    assert.equal(routes.size, 3); assert.ok(provided.has('controllerReadBridge'))
    const direct = await provided.get('controllerReadBridge').read('beads/project-graph'); assert.equal(direct?.schema_version, 'beads-project-graph.v1')
    proxyServer = createServer(async (req, res) => {
      const url = new URL(req.url, 'http://127.0.0.1'); const handler = routes.get(url.pathname)
      if (!handler) { res.statusCode = 404; res.end(); return }
      await handler(req, res)
    })
    await new Promise(resolve => proxyServer.listen(0, '127.0.0.1', resolve)); const proxyOrigin = `http://127.0.0.1:${proxyServer.address().port}`
    const browser = createBrowserReadBridge({ origin: proxyOrigin, fetchImpl: (url, options) => globalThis.fetch(new URL(url, proxyOrigin), options) })
    for (const [route, path] of Object.entries(PLUGIN_READ_PATHS)) {
      const value = await browser.read(route); assert.equal(value?.schema_version, route === 'beads/project-graph' ? 'beads-project-graph.v1' : route === 'beads/global-metadata' ? 'beads-global-metadata.v1' : 'workspace-groups.v1'); if (route === 'beads/project-graph') assert.equal(value.nodes.length, 2)
      assert.ok(path.startsWith('/v1/plugin-reads/'))
    }
    browser.dispose(); cleanupHost(); assert.equal(routes.size, 0); assert.equal(provided.size, 0)
  } finally {
    if (proxyServer) await new Promise(resolve => proxyServer.close(resolve))
    if (fixture) await stopAndWait(fixture, 'fixture')
    if (tempDir) await rm(tempDir, { recursive: true, force: true })
  }
})
