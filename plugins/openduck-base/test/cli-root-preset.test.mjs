import test from 'node:test'
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { access, mkdtemp, readFile, readdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const repository = fileURLToPath(new URL('../../..', import.meta.url))
const connect = join(repository, 'scripts', 'dsh-connect.sh')
const bundlePatch = join(repository, 'plugins', 'openduck-base', 'cordis.patch.yml')
const run = (args, env) => new Promise((resolve, reject) => execFile('bash', [connect, ...args], { env }, (error, _stdout, stderr) => error ? reject(new Error(stderr || error.message)) : resolve()))

test('CLI root preset is a native text-only agent-preset row in the bundle patch', async () => {
  const patch = await readFile(bundlePatch, 'utf8')
  const row = patch.slice(patch.indexOf('- id: preset-openduck-cli-root'))
  assert.match(row, /name: '@deepseek-ai\/dsh-agent-preset'/)
  assert.match(row, /disabled: !!js process\.env\.OPENDUCK_CLI_ROOT_DISABLED === '1'/)
  assert.match(row, /\n\s+id: openduck-cli-root\n/)
  // DSH 0.1.7 dsh-persona requires `prefix`; `text` leaves the preset broken.
  assert.match(row, /\n\s+prefix: /)
  const plugins = row.slice(row.indexOf('plugins:'))
  assert.deepEqual([...plugins.matchAll(/^\s*- id: ([^\n]+)/gm)].map(match => match[1]), ['persona'])
  assert.deepEqual([...plugins.matchAll(/^\s+name: '([^']+)'/gm)].map(match => match[1]), ['@deepseek-ai/dsh-persona'])
})

test('CLI root setup writes no legacy .agent-presets directory', async () => {
  const home = await mkdtemp(join(tmpdir(), 'openduck-cli-root-preset-'))
  await run(['cli-chat'], { PATH: process.env.PATH, DSH_HOME: home })
  assert.deepEqual((await readdir(home)).filter(name => name === '.agent-presets'), [])
})

test('explicit disconnect survives restart intent until managed setup restores the route', async () => {
  const home = await mkdtemp(join(tmpdir(), 'openduck-cli-root-disable-'))
  await run(['cli-chat'], { PATH: process.env.PATH, DSH_HOME: home })
  await run(['disconnect-cli-chat'], { PATH: process.env.PATH, DSH_HOME: home })
  await access(join(home, 'profiles', 'openduck', 'openduck-cli-root.disabled'))
  await run(['cli-chat'], { PATH: process.env.PATH, DSH_HOME: home })
  await assert.rejects(access(join(home, 'profiles', 'openduck', 'openduck-cli-root.disabled')))
})
