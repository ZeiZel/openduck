import assert from 'node:assert/strict'
import test from 'node:test'
import { CONTROLLER_DOWN, createWorkspaceGroups, parseWorkspaceGroups } from '../src/index.js'

const digest = `sha256:${'c'.repeat(64)}`
const current = Object.freeze({
  schema_version: 'workspace-groups.v1', freshness: 'current', groups: [{
    schema_version: 'workspace-group.v1', group_id: 'group-1', display_label: 'Operations', primary_root_id: 'root-1',
    roots: [{ root_id: 'root-1', label: 'Primary', mode: 'write' }, { root_id: 'root-2', label: 'Evidence', mode: 'read' }],
    version: 7, digest, updated_at: '2026-08-20T00:00:00Z',
  }],
})

test('parses only bounded safe labels, opaque IDs, and root modes', () => {
  const parsed = parseWorkspaceGroups(current)
  assert.equal(parsed.groups[0].roots[1].mode, 'read')
  assert.throws(() => parseWorkspaceGroups({ ...current, groups: [{ ...current.groups[0], display_label: '/unsafe' }] }), /INVALID_SAFE_LABEL/)
  assert.throws(() => parseWorkspaceGroups({ ...current, groups: [{ ...current.groups[0], roots: [{ ...current.groups[0].roots[0], mode: 'admin' }] }] }), /INVALID_ROOT_MODE/)
  assert.throws(() => parseWorkspaceGroups({ ...current, groups: Array.from({ length: 33 }, () => current.groups[0]) }), /INVALID_GROUP_COUNT/)
})

test('record parser rejects inherited, polluted, and accessor-backed fields at every level', () => {
  const inherited = Object.assign(Object.create({ schema_version: 'workspace-groups.v1' }), { ...current })
  delete inherited.schema_version
  assert.throws(() => parseWorkspaceGroups(inherited), /INVALID_SHAPE/)

  const inheritedGroup = Object.assign(Object.create({ schema_version: 'workspace-group.v1' }), { ...current.groups[0] })
  delete inheritedGroup.schema_version
  assert.throws(() => parseWorkspaceGroups({ ...current, groups: [inheritedGroup] }), /INVALID_SHAPE/)

  const inheritedRoot = Object.assign(Object.create({ mode: 'read' }), { root_id: 'root-1', label: 'Primary' })
  assert.throws(() => parseWorkspaceGroups({ ...current, groups: [{ ...current.groups[0], roots: [inheritedRoot] }] }), /INVALID_SHAPE/)

  for (const key of ['__proto__', 'constructor', 'prototype']) {
    const polluted = { ...current }
    Object.defineProperty(polluted, key, { value: 'x', enumerable: true })
    assert.throws(() => parseWorkspaceGroups(polluted), /INVALID_SHAPE/)
  }

  const accessor = { ...current }
  Object.defineProperty(accessor, 'freshness', { get: () => 'current', enumerable: true })
  assert.throws(() => parseWorkspaceGroups(accessor), /INVALID_SHAPE/)
})

test('accepts null-prototype records only when their own data-key set is exact', () => {
  const valid = Object.assign(Object.create(null), current)
  assert.equal(parseWorkspaceGroups(valid).freshness, 'current')
  const invalid = Object.assign(Object.create(null), current, { extra: true })
  assert.throws(() => parseWorkspaceGroups(invalid), /INVALID_SHAPE/)
})

test('selection yields an opaque binding and a header model without root locators', async () => {
  const groups = createWorkspaceGroups({ read: async () => current })
  await groups.refresh()
  const selected = groups.select('group-1')
  assert.deepEqual(selected.binding, { group_id: 'group-1', version: 7, digest })
  assert.deepEqual(groups.headerView().roots, [{ label: 'Primary', mode: 'write' }, { label: 'Evidence', mode: 'read' }])
})

test('stale and controller-down states cannot select a group', async () => {
  const stale = createWorkspaceGroups({ read: async () => ({ ...current, freshness: 'stale' }) })
  await stale.refresh()
  assert.deepEqual(stale.select('group-1'), { ok: false, code: 'STALE_GROUP_PROJECTION' })

  const down = createWorkspaceGroups({ read: async () => { throw new Error('down') } })
  const state = await down.refresh()
  assert.equal(state.code, CONTROLLER_DOWN)
  assert.deepEqual(state.groups, [])
  assert.deepEqual(down.select('group-1'), { ok: false, code: CONTROLLER_DOWN })
})
