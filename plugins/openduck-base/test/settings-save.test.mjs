import test from 'node:test'
import assert from 'node:assert/strict'
import { saveAcceptedHistory, saveAcceptedCliRoot } from '../src/client/settings-save.js'

test('history save reports rejection when scope.set resolves without updating its snapshot', async () => {
  const scope = { set: async () => {}, getSnapshot: () => ({ value: { history: { projects: [] } } }) }
  assert.equal(await saveAcceptedHistory(scope, [{ root: '/project' }]), false)
})

test('history save accepts only the matching normalized settings snapshot', async () => {
  const projects = [{ root: '/project', displayName: '' }]
  const scope = { set: async () => {}, getSnapshot: () => ({ value: { history: { projects } } }) }
  assert.equal(await saveAcceptedHistory(scope, [{ root: '/project' }]), true)
})

test('CLI root save reports a host write that resolved without accepting the value', async () => {
  const cliRoot = { enabled: true, cwd: '/project', models: { codex: ['gpt-5-codex'], claude: [], kimi: [] } }
  const scope = { set: async () => {}, getSnapshot: () => ({ value: { cliRoot: { ...cliRoot, enabled: false } } }) }
  assert.equal(await saveAcceptedCliRoot(scope, cliRoot), false)
})
