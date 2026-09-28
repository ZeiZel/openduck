/** Framework-neutral state for a future DSH header adapter; it never fetches. */

export const WORKSPACE_GROUPS_ROUTE = 'workspace-groups'
export const CONTROLLER_DOWN = 'CONTROLLER_DOWN'

const MAX_GROUPS = 32
const MAX_ROOTS = 32
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/
const SAFE_LABEL = /^[A-Za-z0-9][A-Za-z0-9 _.,:;()#-]{0,127}$/
const DIGEST = /^sha256:[0-9a-f]{64}$/
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/
const FORBIDDEN_RECORD_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

function fail(code) { throw new TypeError(code) }
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) }
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
function opaqueId(value) {
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
function updatedAt(value) {
  if (typeof value !== 'string' || !ISO_TIME.test(value) || Number.isNaN(Date.parse(value))) fail('INVALID_UPDATED_AT')
  return value
}
function root(value) {
  exact(value, ['root_id', 'label', 'mode'])
  if (value.mode !== 'read' && value.mode !== 'write') fail('INVALID_ROOT_MODE')
  return Object.freeze({ root_id: opaqueId(value.root_id), label: safeLabel(value.label), mode: value.mode })
}
function group(value) {
  exact(value, ['schema_version', 'group_id', 'display_label', 'primary_root_id', 'roots', 'version', 'digest', 'updated_at'])
  if (value.schema_version !== 'workspace-group.v1') fail('INVALID_SCHEMA_VERSION')
  if (!Array.isArray(value.roots) || value.roots.length < 1 || value.roots.length > MAX_ROOTS) fail('INVALID_ROOT_COUNT')
  const roots = value.roots.map(root)
  const ids = new Set(roots.map(item => item.root_id))
  if (ids.size !== roots.length || !ids.has(value.primary_root_id)) fail('INVALID_ROOT_SET')
  return Object.freeze({
    schema_version: value.schema_version,
    group_id: opaqueId(value.group_id),
    display_label: safeLabel(value.display_label),
    primary_root_id: opaqueId(value.primary_root_id),
    roots: Object.freeze(roots),
    version: positiveInt(value.version),
    digest: digest(value.digest),
    updated_at: updatedAt(value.updated_at),
  })
}

/** Parses an allowlisted Controller response without accepting root locators. */
export function parseWorkspaceGroups(value) {
  exact(value, ['schema_version', 'freshness', 'groups'])
  if (value.schema_version !== 'workspace-groups.v1') fail('INVALID_SCHEMA_VERSION')
  if (value.freshness !== 'current' && value.freshness !== 'stale') fail('INVALID_FRESHNESS')
  if (!Array.isArray(value.groups) || value.groups.length > MAX_GROUPS) fail('INVALID_GROUP_COUNT')
  const groups = value.groups.map(group)
  const ids = new Set(groups.map(item => item.group_id))
  if (ids.size !== groups.length) fail('DUPLICATE_GROUP_ID')
  return Object.freeze({ schema_version: value.schema_version, freshness: value.freshness, groups: Object.freeze(groups) })
}

function downState() {
  return Object.freeze({ status: 'controller_down', code: CONTROLLER_DOWN, freshness: 'unknown', groups: Object.freeze([]), selected: null })
}

/**
 * @param {{ read(route: 'workspace-groups'): Promise<unknown> }} client
 */
export function createWorkspaceGroups(client) {
  if (!object(client) || typeof client.read !== 'function') fail('INVALID_READ_CLIENT')
  let state = downState()

  async function refresh() {
    try {
      const projection = parseWorkspaceGroups(await client.read(WORKSPACE_GROUPS_ROUTE))
      state = Object.freeze({ status: projection.freshness === 'current' ? 'ready' : 'stale', code: null, freshness: projection.freshness, groups: projection.groups, selected: null })
    } catch {
      state = downState()
    }
    return state
  }

  function headerView() {
    return Object.freeze({
      status: state.status,
      code: state.code,
      freshness: state.freshness,
      badge_label: state.selected === null ? 'Workspace group unavailable' : state.selected.display_label,
      roots: state.selected === null ? Object.freeze([]) : state.selected.roots.map(root => Object.freeze({ label: root.label, mode: root.mode })),
    })
  }

  function select(groupId) {
    if (state.status !== 'ready') return Object.freeze({ ok: false, code: state.status === 'stale' ? 'STALE_GROUP_PROJECTION' : CONTROLLER_DOWN })
    const selected = state.groups.find(group => group.group_id === groupId)
    if (selected === undefined) return Object.freeze({ ok: false, code: 'UNKNOWN_GROUP' })
    state = Object.freeze({ ...state, selected })
    return Object.freeze({ ok: true, binding: Object.freeze({ group_id: selected.group_id, version: selected.version, digest: selected.digest }) })
  }

  return Object.freeze({ refresh, getState: () => state, headerView, select })
}

/** Inert host entry; Controller delivery is not enabled by the synthetic profile. */
export function apply() {}
