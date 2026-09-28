import test from 'node:test'
import assert from 'node:assert/strict'
import { cp, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { apply } from '../src/dsh-client.js'

test('registers both additive seats and rolls them back', () => {
  const entries = []
  const disposers = []
  const slots = {
    inject(key, callback) {
      const dispose = callback()
      disposers.push(() => { dispose(); assert.equal(entries.filter(entry => entry.key === key).length, 0) })
      return () => {}
    },
    register(options) {
      const entry = { key: options.name, id: options.id, order: options.order }
      entries.push(entry)
      return () => { const index = entries.indexOf(entry); if (index !== -1) entries.splice(index, 1) }
    },
  }
  apply({ slots })
  assert.deepEqual(entries, [
    { key: 'conversation.session.header.actions', id: 'openduck-beads-memory-explorer', order: 40 },
    { key: 'conversation.session.header.utilities', id: 'openduck-beads-memory-explorer-utility', order: 40 },
  ])
  for (const dispose of disposers) dispose()
  assert.deepEqual(entries, [])
})

test('profile wiring is reproducible from local package copies', async () => {
  const root = await mkdtemp(join(tmpdir(), 'openduck-dsh-'))
  try {
    const profile = JSON.parse(await readFile(new URL('../../../profiles/dsh/openduck-synthetic/package.json', import.meta.url), 'utf8'))
    assert.equal(profile.dependencies['@openduck/beads-memory-explorer'], 'file:../../../plugins/beads-memory-explorer')
    assert.equal(profile.dependencies['@openduck/workspace-groups'], 'file:../../../plugins/workspace-groups')
    const packageDir = join(root, 'profiles/dsh/openduck-synthetic')
    await mkdir(join(root, 'profiles/dsh'), { recursive: true })
    await mkdir(join(root, 'plugins'), { recursive: true })
    await cp(new URL('../../../profiles/dsh/openduck-synthetic', import.meta.url), packageDir, { recursive: true })
    await cp(new URL('../../workspace-groups', import.meta.url), join(root, 'plugins/workspace-groups'), { recursive: true })
    await cp(new URL('../', import.meta.url), join(root, 'plugins/beads-memory-explorer'), { recursive: true })
    const patch = await readFile(join(packageDir, 'cordis.patch.yml'), 'utf8')
    assert.match(patch, /id: openduck-beads-memory-explorer[\s\S]*disabled: true/)
    assert.match(patch, /id: openduck-workspace-groups[\s\S]*disabled: true/)
    assert.equal(await readFile(join(root, 'plugins/beads-memory-explorer/src/dsh-client.js'), 'utf8').then(Boolean), true)
    assert.equal(await readFile(join(root, 'plugins/workspace-groups/src/dsh-client.js'), 'utf8').then(Boolean), true)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
