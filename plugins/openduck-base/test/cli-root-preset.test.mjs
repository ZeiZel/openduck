import test from 'node:test'
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const repository = fileURLToPath(new URL('../../..', import.meta.url))
const connect = join(repository, 'scripts', 'dsh-connect.sh')
const template = join(repository, 'plugins', 'openduck-base', 'connect', 'cli-root-agent.cordis.yml')
const run = (args, env) => new Promise((resolve, reject) => execFile('bash', [connect, ...args], { env }, (error, _stdout, stderr) => error ? reject(new Error(stderr || error.message)) : resolve()))

test('CLI root preset is a managed text-only composition, not standard with disabled rows', async () => {
  const home = await mkdtemp(join(tmpdir(), 'openduck-cli-root-preset-'))
  await run(['cli-chat'], { PATH: process.env.PATH, DSH_HOME: home })
  const agent = await readFile(join(home, '.agent-presets', 'openduck-cli-root', 'agent.cordis.yml'), 'utf8')
  assert.equal(agent, await readFile(template, 'utf8'))
  assert.deepEqual([...agent.matchAll(/^\s*- id: ([^\n]+)/gm)].map(match => match[1]), ['persona'])
  assert.deepEqual([...agent.matchAll(/^\s+name: '([^']+)'/gm)].map(match => match[1]), ['@deepseek-ai/dsh-persona'])
})

test('CLI root setup repairs the prior standard-derived preset but refuses an unknown composition', async () => {
  const home = await mkdtemp(join(tmpdir(), 'openduck-cli-root-migrate-'))
  const preset = join(home, '.agent-presets', 'openduck-cli-root')
  await run(['cli-chat'], { PATH: process.env.PATH, DSH_HOME: home })
  await writeFile(join(preset, 'agent.cordis.yml'), '# The `standard` agent preset:\n- id: planning\n')
  await run(['cli-chat'], { PATH: process.env.PATH, DSH_HOME: home })
  assert.equal(await readFile(join(preset, 'agent.cordis.yml'), 'utf8'), await readFile(template, 'utf8'))
  await writeFile(join(preset, 'agent.cordis.yml'), '- id: custom\n  name: custom\n')
  await assert.rejects(run(['cli-chat'], { PATH: process.env.PATH, DSH_HOME: home }), /customized/)
})
