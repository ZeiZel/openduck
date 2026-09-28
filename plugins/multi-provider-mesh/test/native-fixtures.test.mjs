import assert from 'node:assert/strict'
import { readFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'

const root = new URL('../native/', import.meta.url)
const providers = Object.freeze({
  codex: { root: 'codex/openduck-mesh', manifest: '.codex-plugin/plugin.json' },
  claude: { root: 'claude', manifest: '.claude-plugin/plugin.json' },
  qwen: { root: 'qwen', manifest: 'qwen-extension.json' },
  kimi: { root: 'kimi', manifest: 'kimi.plugin.json' },
})
const policyKeys = ['installation_status', 'reason_code', 'runtime_status', 'schema_version']
const dangerousKeys = /(?:^|[._-])(mcp|mcpservers|command|commands|executable|exec|credential|credentials|hook|hooks|agent|agents|system|prompt|enable|install)(?:$|[._-])/iu
const manifestKeys = Object.freeze({
  codex: ['author', 'description', 'interface', 'name', 'version'],
  claude: ['author', 'description', 'name', 'version'],
  qwen: ['description', 'name', 'version'],
  kimi: ['description', 'name', 'version'],
})
const codexInterfaceKeys = ['capabilities', 'category', 'defaultPrompt', 'developerName', 'displayName', 'longDescription', 'shortDescription']

function assertMetadataOnly(value) {
  if (Array.isArray(value)) {
    assert.deepEqual(value, [])
    return
  }
  assert.equal(value !== null && typeof value === 'object' && !Array.isArray(value), true)
  for (const [key, child] of Object.entries(value)) {
    assert.doesNotMatch(key, dangerousKeys)
    if (child !== null && typeof child === 'object') assertMetadataOnly(child)
  }
}

test('native fixtures are exact, metadata-only, and disabled', async () => {
  assert.deepEqual((await readdir(root)).sort(), Object.keys(providers).sort())
  for (const [provider, layout] of Object.entries(providers)) {
    const directory = new URL(`${layout.root}/`, root)
    const files = await readdir(directory)
    assert.deepEqual(files.sort(), [layout.manifest.split('/')[0], 'disabled.json'].sort())
    const json = JSON.parse(await readFile(new URL(`${layout.root}/${layout.manifest}`, root), 'utf8'))
    const policy = JSON.parse(await readFile(new URL(`${layout.root}/disabled.json`, root), 'utf8'))
    assert.equal(json.name, 'openduck-mesh')
    if (provider === 'codex') assert.equal(layout.root.split('/').at(-1), json.name)
    assert.deepEqual(Object.keys(json).sort(), manifestKeys[provider])
    assert.deepEqual(Object.keys(policy).sort(), policyKeys)
    assert.equal(policy.schema_version, 'openduck-native-fixture-policy.v1')
    assert.equal(policy.installation_status, 'not_installed')
    assert.equal(policy.runtime_status, 'disabled')
    assert.equal(policy.reason_code, 'CONTROLLER_NATIVE_TRANSPORT_UNAVAILABLE')
    assertMetadataOnly(json)
    assertMetadataOnly(policy)
    if (provider === 'codex') {
      assert.deepEqual(Object.keys(json.author).sort(), ['name'])
      assert.deepEqual(Object.keys(json.interface).sort(), codexInterfaceKeys)
      assert.deepEqual(json.interface.capabilities, [])
      assert.deepEqual(json.interface.defaultPrompt, [])
    }
  }
})

test('DeepSeek has no native subscription fixture and DSH remains unmounted', async () => {
  await assert.rejects(readFile(new URL('deepseek/', root)), /ENOENT/)
  const dsh = JSON.parse(await readFile(new URL('../dsh.disabled.json', import.meta.url), 'utf8'))
  assert.equal(dsh.enabled, false)
})
