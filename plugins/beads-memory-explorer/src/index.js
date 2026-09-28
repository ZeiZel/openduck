/**
 * Framework-neutral state for a future DSH UI-only adapter.
 * The adapter must supply the Controller transport; this module never fetches.
 */

export const PROJECT_GRAPH_ROUTE = 'beads/project-graph'
export const GLOBAL_METADATA_ROUTE = 'beads/global-metadata'
export const LOCAL_PD_UNAVAILABLE = 'LOCAL_PD_UNAVAILABLE'

const MAX_NODES = 200
const MAX_EDGES = 400
const MAX_GLOBAL_RECORDS = 100
const MAX_QUERY_LENGTH = 64
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/
const SAFE_LABEL = /^[A-Za-z0-9][A-Za-z0-9 _.,:;()#-]{0,127}$/
const DIGEST = /^sha256:[0-9a-f]{64}$/
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/
const NODE_STATES = new Set(['open', 'in_progress', 'blocked', 'closed'])
const FORBIDDEN_RECORD_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

function fail(code) {
  throw new TypeError(code)
}

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exact(value, keys) {
  if (!object(value)) fail('INVALID_SHAPE')
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) fail('INVALID_SHAPE')
  const ownKeys = Object.keys(value)
  if (ownKeys.length !== keys.length || Object.getOwnPropertyNames(value).length !== ownKeys.length || Object.getOwnPropertySymbols(value).length !== 0) fail('INVALID_SHAPE')
  if (keys.some(key => !Object.hasOwn(value, key)) || ownKeys.some(key => FORBIDDEN_RECORD_KEYS.has(key) || !keys.includes(key))) fail('INVALID_SHAPE')
  for (const key of ownKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (descriptor === undefined || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail('INVALID_SHAPE')
  }
}

function safeId(value) {
  if (typeof value !== 'string' || !SAFE_ID.test(value)) fail('INVALID_OPAQUE_ID')
  return value
}

function safeLabel(value) {
  if (typeof value !== 'string' || !SAFE_LABEL.test(value)) fail('INVALID_SAFE_LABEL')
  return value
}

function positiveInt(value) {
  if (!Number.isInteger(value) || value < 1 || value > Number.MAX_SAFE_INTEGER) fail('INVALID_VERSION')
  return value
}

function digest(value) {
  if (typeof value !== 'string' || !DIGEST.test(value)) fail('INVALID_DIGEST')
  return value
}

function isoTime(value) {
  if (typeof value !== 'string' || !ISO_TIME.test(value) || Number.isNaN(Date.parse(value))) fail('INVALID_UPDATED_AT')
  return value
}

function boundedArray(value, maximum, code) {
  if (!Array.isArray(value) || value.length > maximum) fail(code)
  return value
}

function projectNode(value) {
  exact(value, ['id', 'label', 'state'])
  const state = value.state
  if (typeof state !== 'string' || !NODE_STATES.has(state)) fail('INVALID_NODE_STATE')
  return Object.freeze({ id: safeId(value.id), label: safeLabel(value.label), state })
}

function projectEdge(value, knownNodeIds) {
  exact(value, ['from', 'to'])
  const from = safeId(value.from)
  const to = safeId(value.to)
  if (from === to || !knownNodeIds.has(from) || !knownNodeIds.has(to)) fail('INVALID_EDGE')
  return Object.freeze({ from, to })
}

/** Validates the complete bounded project graph response before rendering. */
export function parseProjectGraph(value) {
  exact(value, ['schema_version', 'project_id', 'version', 'digest', 'nodes', 'edges'])
  if (value.schema_version !== 'beads-project-graph.v1') fail('INVALID_SCHEMA_VERSION')
  const nodes = boundedArray(value.nodes, MAX_NODES, 'TOO_MANY_NODES').map(projectNode)
  const ids = new Set(nodes.map(node => node.id))
  if (ids.size !== nodes.length) fail('DUPLICATE_NODE_ID')
  const edges = boundedArray(value.edges, MAX_EDGES, 'TOO_MANY_EDGES').map(edge => projectEdge(edge, ids))
  return Object.freeze({
    schema_version: value.schema_version,
    project_id: safeId(value.project_id),
    version: positiveInt(value.version),
    digest: digest(value.digest),
    nodes: Object.freeze(nodes),
    edges: Object.freeze(edges),
  })
}

function globalRecord(value) {
  exact(value, ['record_id', 'version', 'updated_at', 'availability'])
  if (value.availability !== LOCAL_PD_UNAVAILABLE) fail('GLOBAL_RECORD_NOT_BLOCKED')
  return Object.freeze({
    record_id: safeId(value.record_id),
    version: positiveInt(value.version),
    updated_at: isoTime(value.updated_at),
    availability: LOCAL_PD_UNAVAILABLE,
  })
}

/** Validates redacted global metadata; no value-bearing field is accepted. */
export function parseGlobalMetadata(value) {
  exact(value, ['schema_version', 'version', 'digest', 'updated_at', 'records'])
  if (value.schema_version !== 'beads-global-metadata.v1') fail('INVALID_SCHEMA_VERSION')
  const records = boundedArray(value.records, MAX_GLOBAL_RECORDS, 'TOO_MANY_GLOBAL_RECORDS').map(globalRecord)
  const ids = new Set(records.map(record => record.record_id))
  if (ids.size !== records.length) fail('DUPLICATE_GLOBAL_RECORD_ID')
  return Object.freeze({
    schema_version: value.schema_version,
    version: positiveInt(value.version),
    digest: digest(value.digest),
    updated_at: isoTime(value.updated_at),
    records: Object.freeze(records),
  })
}

export function searchGraph(graph, query) {
  if (typeof query !== 'string' || query.length > MAX_QUERY_LENGTH) fail('INVALID_SEARCH_QUERY')
  const needle = query.trim().toLowerCase()
  if (!needle) return Object.freeze([])
  return Object.freeze(graph.nodes.filter(node => node.label.toLowerCase().includes(needle)).slice(0, 50))
}

export function openMemoryChat(scope) {
  if (scope !== 'project' && scope !== 'global') fail('INVALID_MEMORY_SCOPE')
  return Object.freeze({
    scope,
    isolated: true,
    messages: Object.freeze([]),
    can_submit: false,
    status: scope === 'global' ? 'blocked' : 'unavailable',
    code: scope === 'global' ? LOCAL_PD_UNAVAILABLE : 'UI_ROUTE_UNAVAILABLE',
  })
}

function emptyState() {
  return Object.freeze({
    project: null,
    global: Object.freeze({ status: 'blocked', code: LOCAL_PD_UNAVAILABLE, records: Object.freeze([]) }),
    status: 'idle',
  })
}

/**
 * @param {{ read(route: 'beads/project-graph' | 'beads/global-metadata'): Promise<unknown> }} client
 */
export function createBeadsMemoryExplorer(client) {
  if (!object(client) || typeof client.read !== 'function') fail('INVALID_READ_CLIENT')
  let state = emptyState()

  async function refresh() {
    try {
      const [projectResult, globalResult] = await Promise.allSettled([
        client.read(PROJECT_GRAPH_ROUTE),
        client.read(GLOBAL_METADATA_ROUTE),
      ])
      if (projectResult.status !== 'fulfilled') throw projectResult.reason
      const project = parseProjectGraph(projectResult.value)
      let records = Object.freeze([])
      if (globalResult.status === 'fulfilled') {
        try { records = parseGlobalMetadata(globalResult.value).records } catch { records = Object.freeze([]) }
      }
      state = Object.freeze({ project, global: Object.freeze({ status: 'blocked', code: LOCAL_PD_UNAVAILABLE, records }), status: 'ready' })
    } catch {
      state = Object.freeze({ ...emptyState(), status: 'controller_down' })
    }
    return state
  }

  return Object.freeze({
    refresh,
    getState: () => state,
    search: query => state.project === null ? Object.freeze([]) : searchGraph(state.project, query),
    openMemoryChat,
  })
}

/** Inert host entry; Controller delivery is not enabled by the synthetic profile. */
export function apply() {}
