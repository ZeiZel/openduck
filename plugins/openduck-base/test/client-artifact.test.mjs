import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'

test('generated native client uses only the DSH-seeded React and primitive modules', async () => {
  const source = await readFile(resolve('lib/client.js'), 'utf8')
  assert.doesNotMatch(source, /react\/jsx(?:-dev)?-runtime/)
  const requested = [...source.matchAll(/require\("([^"]+)"\)/g)].map(match => match[1])
  assert.deepEqual([...new Set(requested)].sort(), ['@deepseek-ai/dsh-client-ui-primitives', 'react'])
  let registration
  const window = { __ModuleLoader__: { load: value => { registration = value } } }
  new Function('window', source)(window)
  assert.equal(registration.id, '@openduck/openduck-base')
  const known = { react: { default: { createElement: () => ({}) } }, '@deepseek-ai/dsh-client-ui-primitives': { Button: () => null, Input: () => null } }
  const exports = registration.factory(name => { assert.ok(name in known, `unseeded module: ${name}`); return known[name] })
  assert.equal(typeof exports.apply, 'function')
})
