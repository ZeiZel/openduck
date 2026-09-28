import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const source = await readFile(new URL('../src/index.js', import.meta.url), 'utf8')
const manifest = JSON.parse(await readFile(new URL('../dsh.disabled.json', import.meta.url), 'utf8'))

test('runtime source excludes persistence, raw transport, local model, and credential markers', () => {
  for (const marker of ['fetch(', 'localStorage', 'indexedDB', 'serviceWorker', 'postMessage', 'Authorization', 'Bearer ', 'qwen', 'PRIVATE', 'child_process', 'node:fs', 'Dolt']) {
    assert.equal(source.includes(marker), false, `forbidden runtime marker: ${marker}`)
  }
})

test('static package cannot claim DSH installation before the bridge exists', () => {
  assert.deepEqual(manifest, {
    schema_version: 'openduck-dsh-static-package.v1',
    package: '@openduck/beads-memory-explorer',
    enabled: false,
    reason_code: 'UPSTREAM_UI_BRIDGE_UNAVAILABLE',
    required_before_enable: [
      'composed Controller typed routes',
      'injected same-origin Controller read client',
      'reviewed package registration and delivery evidence',
    ],
  })
})
