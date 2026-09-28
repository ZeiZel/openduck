import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'))
const source = await readFile(new URL('../src/dsh-client.js', import.meta.url), 'utf8')

test('DSH registration is additive and disabled at the profile layer', () => {
  assert.equal(packageJson.dsh.client.platform, 'web')
  assert.deepEqual(packageJson.dsh.client.inject, ['@deepseek-ai/dsh-client-ui-conversation'])
  assert.match(source, /conversation\.session\.header\.actions/)
  assert.match(source, /conversation\.session\.header\.utilities/)
  assert.match(source, /openduck-beads-memory-explorer/)
  assert.doesNotMatch(source, /SessionHeader\.cwd|session\/event|localStorage|postMessage|telemetry/)
})
