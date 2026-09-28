import assert from 'node:assert/strict'
import test from 'node:test'
import {
  LOCAL_PD_UNAVAILABLE,
  createBeadsMemoryExplorer,
  openMemoryChat,
  parseGlobalMetadata,
  parseProjectGraph,
  searchGraph,
} from '../src/index.js'

const digest = `sha256:${'a'.repeat(64)}`
const graph = Object.freeze({
  schema_version: 'beads-project-graph.v1', project_id: 'project-1', version: 1, digest,
  nodes: [{ id: 'issue-1', label: 'Safe task', state: 'open' }, { id: 'issue-2', label: 'Closed task', state: 'closed' }],
  edges: [{ from: 'issue-1', to: 'issue-2' }],
})
const global = Object.freeze({
  schema_version: 'beads-global-metadata.v1', version: 3, digest, updated_at: '2026-08-20T00:00:00Z',
  records: [{ record_id: 'record-1', version: 1, updated_at: '2026-08-20T00:00:00Z', availability: LOCAL_PD_UNAVAILABLE }],
})

test('accepts a bounded safe graph and searches only its safe labels', () => {
  const parsed = parseProjectGraph(graph)
  assert.equal(parsed.nodes.length, 2)
  assert.deepEqual(searchGraph(parsed, 'closed'), [parsed.nodes[1]])
  assert.throws(() => searchGraph(parsed, 'x'.repeat(65)), /INVALID_SEARCH_QUERY/)
})

test('rejects unknown graph fields, bad edges, and oversized data', () => {
  assert.throws(() => parseProjectGraph({ ...graph, unexpected: true }), /INVALID_SHAPE/)
  assert.throws(() => parseProjectGraph({ ...graph, edges: [{ from: 'issue-1', to: 'missing' }] }), /INVALID_EDGE/)
  assert.throws(() => parseProjectGraph({ ...graph, nodes: Array.from({ length: 201 }, (_, index) => ({ id: `n-${index}`, label: 'Safe', state: 'open' })), edges: [] }), /TOO_MANY_NODES/)
})

test('record parser rejects inherited, polluted, and accessor-backed fields at every level', () => {
  const inherited = Object.assign(Object.create({ schema_version: 'beads-project-graph.v1' }), { ...graph })
  delete inherited.schema_version
  assert.throws(() => parseProjectGraph(inherited), /INVALID_SHAPE/)

  const inheritedNode = Object.assign(Object.create({ state: 'open' }), { id: 'issue-1', label: 'Safe task' })
  assert.throws(() => parseProjectGraph({ ...graph, nodes: [inheritedNode], edges: [] }), /INVALID_SHAPE/)

  for (const key of ['__proto__', 'constructor', 'prototype']) {
    const polluted = { ...graph }
    Object.defineProperty(polluted, key, { value: 'x', enumerable: true })
    assert.throws(() => parseProjectGraph(polluted), /INVALID_SHAPE/)
  }

  const accessor = { ...graph }
  Object.defineProperty(accessor, 'schema_version', { get: () => 'beads-project-graph.v1', enumerable: true })
  assert.throws(() => parseProjectGraph(accessor), /INVALID_SHAPE/)
})

test('accepts null-prototype records only when their own data-key set is exact', () => {
  const valid = Object.assign(Object.create(null), graph)
  assert.equal(parseProjectGraph(valid).project_id, 'project-1')
  const invalid = Object.assign(Object.create(null), graph, { extra: true })
  assert.throws(() => parseProjectGraph(invalid), /INVALID_SHAPE/)
})

test('accepts only redacted global metadata and blocks the global chat shell', () => {
  assert.equal(parseGlobalMetadata(global).records[0].availability, LOCAL_PD_UNAVAILABLE)
  assert.throws(() => parseGlobalMetadata({ ...global, records: [{ ...global.records[0], value: 'no' }] }), /INVALID_SHAPE/)
  const chat = openMemoryChat('global')
  assert.equal(chat.code, LOCAL_PD_UNAVAILABLE)
  assert.equal(chat.can_submit, false)
  assert.deepEqual(chat.messages, [])
})

test('global nested records reject inherited fields and accessors', () => {
  const inheritedRecord = Object.assign(Object.create({ availability: LOCAL_PD_UNAVAILABLE }), { record_id: 'record-1', version: 1, updated_at: '2026-08-20T00:00:00Z' })
  assert.throws(() => parseGlobalMetadata({ ...global, records: [inheritedRecord] }), /INVALID_SHAPE/)
  const accessorRecord = { ...global.records[0] }
  Object.defineProperty(accessorRecord, 'availability', { get: () => LOCAL_PD_UNAVAILABLE, enumerable: true })
  assert.throws(() => parseGlobalMetadata({ ...global, records: [accessorRecord] }), /INVALID_SHAPE/)
})

test('controller failure clears projections and fails closed', async () => {
  const explorer = createBeadsMemoryExplorer({ read: async () => { throw new Error('unavailable') } })
  const state = await explorer.refresh()
  assert.equal(state.status, 'controller_down')
  assert.equal(state.project, null)
  assert.deepEqual(state.global.records, [])
})

test('injected client is the sole data boundary', async () => {
  const calls = []
  const explorer = createBeadsMemoryExplorer({ read: async route => {
    calls.push(route)
    return route === 'beads/project-graph' ? graph : global
  } })
  const state = await explorer.refresh()
  assert.equal(state.status, 'ready')
  assert.deepEqual(calls, ['beads/project-graph', 'beads/global-metadata'])
})

test('global route failure does not discard a healthy project graph', async () => {
  const explorer = createBeadsMemoryExplorer({ read: async route => {
    if (route === 'beads/project-graph') return graph
    throw new Error('global unavailable')
  } })
  const state = await explorer.refresh()
  assert.equal(state.status, 'ready')
  assert.equal(state.project.project_id, 'project-1')
  assert.deepEqual(state.global.records, [])
  assert.equal(state.global.code, LOCAL_PD_UNAVAILABLE)
})
